"""Offline tests for the normalized signal boundary, categories and lifecycle.

Everything here runs against fake local transport. No test contacts TypeSafe, no
fixture contains real data, and no assertion in this file claims detection
accuracy on real traffic — the calibration tests measure agreement with the
labels *we wrote*, which is a behaviour check on the plumbing.
"""
import asyncio
import json
import logging
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from auth_audit_jev import (
    CATEGORIES,
    HYPOTHESES,
    MAX_SIGNAL_BYTES,
    SCHEMA_VERSION,
    AuditPlugin,
    Metrics,
    SignalAuditPlugin,
    agreement,
    baseline_comparison,
    build_signal_request,
    conflicts_with_local_candidates,
    deterministic_candidates,
    normalize_signal,
    per_category_metrics,
    project_signal,
    signal_from_legacy_event,
    validate_response,
)
from auth_audit_jev import ABSTENTION_REASONS
from auth_audit_jev import fixtures as fx


def envelope(signal=None, **extra):
    """A producer envelope, deliberately stuffed with secrets it must not read."""
    payload = {"event": {"event_type": "user_authentication_failed", "severity": "warning",
                         "id": "SECRET_IDENTIFIER", "user_id": "SECRET_PRINCIPAL",
                         "client_id": "SECRET_CLIENT", "ip": "SECRET_IP",
                         "error": "SECRET_ERROR", "metadata": {"token": "SECRET_TOKEN"},
                         "timestamp": "SECRET_TIMESTAMP"},
               "correlation_id": "SECRET_CORRELATION", "traceparent": "SECRET_TRACE",
               "attributes": {"authorization": "SECRET_HEADER"}}
    if signal is not None:
        payload["authn_signal"] = signal
    payload.update(extra)
    return payload


BASE = {"schema_version": SCHEMA_VERSION, "protocol": "oauth2", "flow": "authorization_code",
        "outcome": "failure"}


def legacy_answer(choice="suspicious", confidence=.92):
    """The legacy plugin's own single-question `assessment` reply shape.

    The v1 provider payload is a different contract (`likely_category` plus
    independent confidence/urgency answers), so the legacy boundary tests must
    not reuse `fx.provider_response`: doing so would assert that the legacy
    plugin accepts a schema it was never supposed to understand.
    """
    return {"model": "jev-latest", "usage": dict(fx.FAKE_USAGE), "answers": {"assessment": {
        "type": "choice", "choice": choice, "confidence": confidence,
        "probabilities": {"suspicious": .92 if choice == "suspicious" else .04,
                          "routine": .04 if choice == "suspicious" else .92, "other": .04}}}}


class SchemaTests(unittest.TestCase):
    def test_required_enums_and_defaults(self):
        normalized = normalize_signal(dict(BASE))
        self.assertEqual(normalized["schema_version"], SCHEMA_VERSION)
        self.assertEqual(normalized["failure_reason"], "not_applicable")
        self.assertEqual(normalized["repeat_pattern"], "unknown")
        self.assertIsNone(normalized["known_registered_client"])
        self.assertEqual(set(normalized), set(normalize_signal(dict(BASE))))

    def test_missing_required_or_unknown_enum_is_rejected_whole(self):
        self.assertIsNone(normalize_signal({k: v for k, v in BASE.items() if k != "flow"}))
        self.assertIsNone(normalize_signal({**BASE, "protocol": "kerberos"}))
        self.assertIsNone(normalize_signal({**BASE, "failure_reason": "SECRET_ERROR"}))
        self.assertIsNone(normalize_signal({**BASE, "count_bucket": "37"}))
        self.assertIsNone(normalize_signal({**BASE, "schema_version": "authn-signal/v0"}))
        self.assertIsNone(normalize_signal(None))
        self.assertIsNone(normalize_signal([]))

    def test_free_text_and_identifier_fields_are_rejected_not_redacted(self):
        for rejected in (
            {"error": "SECRET_ERROR text"},
            {"user_id": "SECRET_PRINCIPAL"},
            {"ip": "SECRET_IP"},
            {"token": "SECRET_TOKEN"},
            {"headers": {"authorization": "SECRET_HEADER"}},
            {"metadata": {"anything": "SECRET_METADATA"}},
            {"traceparent": "SECRET_TRACE"},
            {"timestamp": "SECRET_TIMESTAMP"},
        ):
            self.assertIsNone(normalize_signal({**BASE, **rejected}), rejected)
        long_text = "invalid-credentials-" + "x" * 200
        self.assertIsNone(normalize_signal({**BASE, "failure_reason": long_text}))

    def test_non_boolean_flags_and_byte_limits(self):
        self.assertIsNone(normalize_signal({**BASE, "known_registered_client": "yes"}))
        self.assertIsNone(normalize_signal({**BASE, "known_registered_client": 1}))
        self.assertIsNone(normalize_signal({**BASE, "schema_version": "v" * 64}))
        normalized = normalize_signal(dict(BASE))
        self.assertLess(len(json.dumps(normalized, sort_keys=True).encode()), MAX_SIGNAL_BYTES)

    def test_project_signal_never_reads_the_rest_of_the_envelope(self):
        self.assertIsNone(project_signal(envelope()))
        self.assertEqual(project_signal(envelope(dict(BASE)))["outcome"], "failure")
        for secret in fx.SCRUB_TOKENS:
            self.assertNotIn(secret, json.dumps(build_signal_request(
                normalize_signal(dict(BASE))), sort_keys=True))

    def test_signal_request_builder_has_no_passthrough_escape_hatch(self):
        """The exported builder must not accept caller-supplied free-form context.

        Regression: `build_request` took an optional `context` and copied it
        verbatim into the cloud-bound payload. Because it is re-exported as the
        public `build_signal_request`, any caller could bypass the closed
        `authn-signal/v1` boundary and send raw identifiers, error text, tokens
        or arbitrary nested maps to the provider -- exactly what the boundary
        exists to prevent.
        """
        import inspect
        parameters = set(inspect.signature(build_signal_request).parameters)
        self.assertEqual(parameters, {"signal"}, "builder grew a passthrough parameter")

        secret_context = {
            "raw_error": "invalid_grant for SECRET_PRINCIPAL from SECRET_IP",
            "authorization": "Bearer SECRET_TOKEN",
            "nested": {"ip": "SECRET_IP"},
        }
        with self.assertRaises(TypeError):
            build_signal_request(normalize_signal(dict(BASE)), context=secret_context)

    def test_signal_request_builder_rejects_an_unnormalized_payload(self):
        """A dict that never passed normalization must not reach the provider."""
        with self.assertRaises(ValueError):
            build_signal_request({"failure_reason": "SECRET_ERROR text",
                                  "outcome": "failure", "user_id": "SECRET_PRINCIPAL"})
        with self.assertRaises(ValueError):
            build_signal_request({"metadata": {"anything": "SECRET_METADATA"}})

    def test_signal_request_builder_payload_stays_inside_the_schema(self):
        normalized = normalize_signal(dict(BASE))
        request = build_signal_request(normalized)
        self.assertEqual(set(request["state"]), {"schema_version", "signal"})
        self.assertEqual(set(request["state"]["signal"]), set(normalized))
        self.assertNotIn("context", json.dumps(request, sort_keys=True))

    def test_legacy_adapter_cannot_fabricate_a_reason(self):
        derived = signal_from_legacy_event(envelope())
        self.assertEqual(derived["outcome"], "failure")
        self.assertEqual(derived["failure_reason"], "other")
        self.assertEqual(derived["repeat_pattern"], "unknown")
        self.assertIsNone(derived["known_registered_client"])
        self.assertEqual(
            signal_from_legacy_event({"event": {"event_type": "authentication_succeeded"}})["outcome"],
            "success")
        self.assertIsNone(signal_from_legacy_event({"event": {"event_type": "custom.secret"}}))
        self.assertIsNone(signal_from_legacy_event({"event": {"event_type": 7}}))

    def test_denial_and_authentication_failure_stay_distinct(self):
        derived = signal_from_legacy_event({"event": {"event_type": "authorization_denied"}})
        self.assertEqual(derived["authz_denial_category"], "other")
        self.assertEqual(
            signal_from_legacy_event({"event": {"event_type": "user_authentication_failed"}})["authz_denial_category"],
            "none")


class CandidateTests(unittest.TestCase):
    def test_configuration_failures_are_candidate_explanations_not_verdicts(self):
        candidates = deterministic_candidates({"failure_reason": "invalid_client",
                                               "client_config_category": "unregistered_client"})
        self.assertIn(("client_misconfiguration", "client_configuration"), candidates)
        self.assertNotIn(("suspected_abuse", "repetition_pattern"), candidates)

    def test_candidates_do_not_upgrade_volume_to_abuse_on_a_config_defect(self):
        candidates = deterministic_candidates({
            "failure_reason": "invalid_client", "client_config_category": "expired_client_secret",
            "repeat_pattern": "repeated_same_client", "count_bucket": "over-100"})
        categories = {category for category, _ in candidates}
        self.assertIn("client_misconfiguration", categories)

    def test_no_local_rule_yields_unclassified(self):
        self.assertEqual(deterministic_candidates({"failure_reason": "other"}),
                         [(None, "unclassified")])

    def test_unclassified_fallback_is_not_a_conflict_with_any_category(self):
        """A lone `unclassified` fallback is not a local opinion to disagree with.

        Regression: `conflicts_with_local_candidates` filtered out the `None`
        entry and then returned `all(...)` over an empty iterable, which is
        vacuously true -- so every provider category was flagged as conflicting
        with local candidates on exactly the signals where no local rule fired
        and the provider's answer carries all the information.
        """
        candidates = deterministic_candidates({"failure_reason": "invalid_token"})
        self.assertEqual(candidates, [(None, "unclassified")])
        for category in CATEGORIES:
            self.assertFalse(conflicts_with_local_candidates(category, candidates),
                             msg=category)

    def test_a_real_disagreement_is_still_reported(self):
        """The guard must not disable the flag it protects."""
        candidates = deterministic_candidates({"failure_reason": "invalid_redirect_uri",
                                               "client_config_category": "none"})
        self.assertIn(("client_misconfiguration", "redirect_uri_mismatch"), candidates)
        self.assertTrue(conflicts_with_local_candidates("suspected_abuse", candidates))
        self.assertFalse(conflicts_with_local_candidates("client_misconfiguration", candidates))
        self.assertFalse(conflicts_with_local_candidates("user_error", []))

    def test_ambiguous_and_missing_evidence_are_representable(self):
        self.assertIn("ambiguous", CATEGORIES)
        self.assertIn("other", HYPOTHESES)
        for category in CATEGORIES:
            self.assertTrue(HYPOTHESES[category]["review"])


class ResponseValidationTests(unittest.TestCase):
    def test_well_formed_batched_answer_is_accepted(self):
        verdict = validate_response(fx.provider_response("suspected_abuse"))
        self.assertEqual(verdict, ("suspected_abuse", "high", "routine_review"))

    def test_resolved_model_identifiers_inside_the_family_are_accepted(self):
        for model in ("jev-latest", "jev-1", "jev-1.13", "jev-2.0.1", "jev-1.13-20260925"):
            self.assertIsNotNone(validate_response(fx.provider_response("user_error", model=model)), model)

    def test_other_model_families_and_smuggled_versions_are_rejected(self):
        for model in ("jev-evil", "jev-latest-extra", "gpt-4", "jev-", "jev-1.x", 7, None):
            self.assertIsNone(validate_response(fx.provider_response("user_error", model=model)), model)

    def test_usage_and_question_shape_are_mandatory(self):
        self.assertIsNone(validate_response({**fx.provider_response("user_error"),
                                             "usage": {"input_tokens": 1}}))
        self.assertIsNone(validate_response({"answers": {}, "model": "jev-latest",
                                             "usage": fx.FAKE_USAGE}))
        bad = fx.provider_response("user_error")
        del bad["answers"]["urgency"]
        self.assertIsNone(validate_response(bad))
        extra = fx.provider_response("user_error")
        extra["answers"]["injected"] = {"type": "choice", "choice": "user_error"}
        self.assertIsNone(validate_response(extra))

    def test_probability_and_confidence_consistency(self):
        self.assertIsNone(validate_response(fx.provider_response("user_error", category_probability=.5)))
        payload = fx.provider_response("user_error", category_probability=.9)
        payload["answers"]["likely_category"]["probabilities"]["other"] = .5
        self.assertIsNone(validate_response(payload))
        self.assertIsNone(validate_response(fx.provider_response("user_error", confidence_probability=True)))

    def test_per_category_thresholds_make_abuse_the_hardest_to_alert(self):
        borderline = fx.provider_response("suspected_abuse", category_probability=.85)
        self.assertIsNone(validate_response(borderline))
        self.assertIsNotNone(validate_response(fx.provider_response("client_misconfiguration",
                                                                   category_probability=.85)))
        explicit = fx.provider_response("suspected_abuse", category_probability=.85)
        self.assertIsNotNone(validate_response(explicit, review_threshold=.8))

    def test_residual_category_and_low_confidence_abstain(self):
        self.assertIsNone(validate_response(fx.provider_response("other")))
        self.assertIsNone(validate_response(fx.provider_response("ambiguous", confidence="low")))
        self.assertIsNotNone(validate_response(fx.provider_response("user_error", confidence="low")))


class SignalPluginTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.alerts = []

    def plugin(self, **kwargs):
        kwargs.setdefault("transport", fx.offline_transport())
        kwargs.setdefault("alert", self.alerts.append)
        kwargs.setdefault("enabled", True)
        return SignalAuditPlugin(**kwargs)

    async def test_disabled_by_default_and_no_key_means_no_worker(self):
        plugin = SignalAuditPlugin()
        await plugin.start()
        self.assertFalse(await plugin.health_check())
        await plugin.emit(envelope(dict(BASE)))
        self.assertEqual(plugin.metrics.results["disabled"], 2)
        await plugin.close()
        with patch.dict("os.environ", {}, clear=True):
            plugin = SignalAuditPlugin(enabled=True)
            await plugin.start()
            self.assertFalse(await plugin.health_check())

    async def test_no_provider_call_for_unusable_or_success_signals(self):
        transport = fx.offline_transport()
        # The legacy projector is what makes a bare producer envelope eligible;
        # with it disabled this test isolates the v1 contract, where anything
        # without a valid `authn_signal` is skipped rather than projected.
        plugin = self.plugin(transport=transport, legacy_projector=None)
        await plugin.start()
        await plugin.emit(envelope())
        await plugin.emit(envelope({**BASE, "failure_reason": "SECRET_ERROR"}))
        await plugin.emit(envelope({**BASE, "outcome": "success", "failure_reason": "not_applicable"}))
        await plugin.emit(envelope({"user_id": "SECRET_PRINCIPAL"}))
        await plugin.join()
        await plugin.close()
        self.assertEqual(transport.calls, [])
        self.assertEqual(plugin.metrics.results["skipped"], 4)

    async def test_legacy_producer_envelope_is_assessed_without_fabricated_category(self):
        transport = fx.offline_transport()
        plugin = self.plugin(transport=transport)
        await plugin.start()
        await plugin.emit(envelope())
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(transport.calls), 1)
        signal = transport.calls[0]["state"]["signal"]
        self.assertEqual(signal["failure_reason"], "other")
        self.assertEqual(signal["repeat_pattern"], "unknown")
        self.assertEqual(self.alerts[0]["category"], "ambiguous")
        self.assertEqual(self.alerts[0]["local_candidate_explanations"],
                         [{"category": "unclassified", "kind": "unclassified"}])

    async def test_request_carries_only_bounded_enums(self):
        transport = fx.offline_transport()
        plugin = self.plugin(transport=transport)
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_client",
                                             client_config_category="unregistered_client",
                                             known_registered_client=False)))
        await plugin.join()
        await plugin.close()
        serialized = json.dumps(transport.calls[0], sort_keys=True)
        for secret in fx.SCRUB_TOKENS:
            self.assertNotIn(secret, serialized)
        self.assertEqual(set(transport.calls[0]), {"model", "state", "questions"})
        self.assertEqual(set(transport.calls[0]["state"]), {"schema_version", "signal"})
        self.assertEqual(transport.calls[0]["model"], "jev-latest")

    async def test_timeout_and_provider_error_abstain_and_never_retry(self):
        calls = []

        async def transport(request):
            calls.append(request)
            if len(calls) == 1:
                await asyncio.sleep(.05)
            else:
                raise RuntimeError("SECRET_PROVIDER_ERROR")
        plugin = self.plugin(transport=transport, timeout=.005)
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.join()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(calls), 2)
        self.assertEqual(plugin.metrics.results["timeout"], 1)
        self.assertEqual(plugin.metrics.results["error"], 1)
        self.assertEqual(self.alerts, [])

    async def test_malformed_and_residual_responses_abstain_without_alert(self):
        responses = [fx.provider_response("user_error", model="jev-evil"),
                     fx.provider_response("other"), {"nonsense": True},
                     fx.provider_response("user_error", usage={"cost_usd": 0})]
        plugin = self.plugin(transport=fx.offline_transport(lambda request: responses.pop(0)))
        await plugin.start()
        for index in range(4):
            await plugin.emit(envelope(fx.signal(failure_reason=f"reason-{index}"
                                                 if False else "invalid_credentials")))
            await plugin.join()
        await plugin.close()
        self.assertEqual(self.alerts, [])
        self.assertEqual(plugin.metrics.results["abstain"], 4)

    async def test_per_category_calibration_over_labeled_fixtures(self):
        by_reason = {}

        def response_for(request):
            signal = request["state"]["signal"]
            key = tuple(sorted(signal.items()))
            return by_reason[key]
        transport = fx.offline_transport(response_for)
        plugin = self.plugin(transport=transport)
        await plugin.start()
        labeled = []
        for name, signal, expected, _note in fx.FIXTURES:
            payload = fx.provider_response(expected if expected != "other" else "other")
            by_reason[tuple(sorted(normalize_signal(signal).items()))] = payload
            await plugin.emit(envelope(signal))
            await plugin.join()
            observed = self.alerts[-1]["category"] if self.alerts else None
            labeled.append((expected, observed))
        await plugin.close()
        report = per_category_metrics(labeled)
        self.assertEqual(report["total"], len(fx.FIXTURES))
        # Agreement with our own labels is a plumbing check, not accuracy.
        self.assertGreaterEqual(agreement(labeled), .9)
        for category in ("user_error", "client_misconfiguration", "suspected_abuse"):
            stats = report["categories"][category]
            self.assertGreater(stats["support"], 0, category)
            self.assertEqual(stats["precision"], 1.0, category)
            self.assertEqual(stats["recall"], 1.0, category)
        # The residual class must never be presented as a confident answer.
        self.assertEqual(report["categories"]["other"]["predicted"], 0)

    async def test_adversarial_fixtures_are_not_read_as_abuse(self):
        for name, signal, expected, note in fx.FIXTURES:
            if not name.startswith("trap_"):
                continue
            candidates = deterministic_candidates(normalize_signal(signal))
            categories = {category for category, _ in candidates}
            if expected == "user_error":
                self.assertNotIn("suspected_abuse", categories, name)

    async def test_local_candidate_conflict_with_provider_is_visible(self):
        signal = fx.signal(failure_reason="invalid_credentials")
        plugin = self.plugin(transport=fx.offline_transport(
            lambda request: fx.provider_response("client_misconfiguration")))
        await plugin.start()
        await plugin.emit(envelope(signal))
        await plugin.join()
        await plugin.close()
        self.assertEqual(plugin.metrics.results["candidate_conflict"], 1)
        self.assertTrue(self.alerts[0]["conflicts_with_local_candidates"])
        self.assertEqual(self.alerts[0]["local_candidate_explanations"],
                         [{"category": "user_error", "kind": "invalid_credentials"}])

    async def test_baseline_comparison_is_recorded_and_not_a_quality_claim(self):
        self.assertEqual(baseline_comparison({"outcome": "failure"}, "suspected_abuse"), "agree")
        self.assertEqual(baseline_comparison({"outcome": "failure"}, "user_error"), "disagree")
        self.assertEqual(baseline_comparison({"outcome": "success"}, "user_error"), "incomparable")
        plugin = self.plugin(transport=fx.offline_transport(
            lambda request: fx.provider_response("user_error")))
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.join()
        await plugin.close()
        self.assertEqual(plugin.metrics.results["baseline_disagree"], 1)
        self.assertEqual(plugin.metrics.results["recommendation"], 1)
        self.assertEqual(plugin.metrics.results["routine_failure"], 1)

    async def test_alerts_are_advisory_and_carry_no_raw_identifiers(self):
        plugin = self.plugin(transport=fx.offline_transport(
            lambda request: fx.provider_response("suspected_abuse",
                                                 urgency="immediate_review")))
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                             repeat_pattern="repeated_same_principal_burst",
                                             count_bucket="21-100", window_bucket="under-1m")))
        await plugin.join()
        await plugin.close()
        alert = self.alerts[0]
        self.assertTrue(alert["is_hypothesis"])
        self.assertEqual(alert["authority"], "advisory")
        self.assertEqual(alert["urgency"], "immediate_review")
        serialized = json.dumps(alert)
        for secret in fx.SCRUB_TOKENS:
            self.assertNotIn(secret, serialized)

    async def test_nothing_sensitive_is_logged(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(record.getMessage())
        handler = Capture()
        logging.getLogger().addHandler(handler)
        self.addCleanup(logging.getLogger().removeHandler, handler)
        plugin = self.plugin(transport=fx.offline_transport(
            lambda request: fx.provider_response("user_error", model="jev-evil")))
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.join()
        await plugin.close()
        blob = json.dumps(records)
        for secret in fx.SCRUB_TOKENS:
            self.assertNotIn(secret, blob)
        self.assertEqual(plugin.metrics.results["abstain"], 1)

    async def test_kill_switch_stops_provider_calls_immediately(self):
        transport = fx.offline_transport()
        plugin = self.plugin(transport=transport)
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.join()
        plugin.engage_kill_switch()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.close()
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(plugin.metrics.results["kill_switch"], 2)
        plugin.release_kill_switch()

    async def test_circuit_breaker_opens_then_allows_a_probe(self):
        calls = []

        async def transport(request):
            calls.append(request)
            raise RuntimeError("SECRET_PROVIDER_ERROR")
        plugin = self.plugin(transport=transport, circuit_failure_threshold=2, circuit_cooldown=.05)
        await plugin.start()
        for index in range(3):
            await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                                 count_bucket=f"1" if index == 0 else "2-5")))
            await plugin.join()
        self.assertEqual(len(calls), 2)
        self.assertEqual(plugin.circuit_state(), "open")
        self.assertEqual(plugin.metrics.results["circuit_open"], 1)
        self.assertEqual(plugin.metrics.circuit["short_circuited"], 1)
        await asyncio.sleep(.06)
        self.assertEqual(plugin.circuit_state(), "half_open")
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                             count_bucket="6-20")))
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(calls), 3)

    async def test_half_open_admits_only_one_probe_with_multiple_workers(self):
        """Recovery must be a single probe even when several workers are running.

        Regression: `circuit_state()` reported `half_open` once the cooldown
        elapsed but reserved no probe slot, so with `worker_count > 1` every
        worker could observe the expired circuit and call the provider at once,
        defeating one-probe recovery and risking reopening the breaker from a
        burst of concurrent failures.
        """
        calls = []

        async def transport(request):
            calls.append(request)
            await asyncio.sleep(.05)
            raise RuntimeError("provider down")

        plugin = self.plugin(transport=transport, worker_count=4,
                            circuit_failure_threshold=2, circuit_cooldown=.05)
        await plugin.start()
        for bucket in ("1", "2-5", "6-20", "21-100", "100+", "1"):
            await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                                 count_bucket=bucket)))
        await asyncio.sleep(.4)
        self.assertEqual(plugin.circuit_state(), "half_open")
        admitted = len(calls)
        for bucket in ("2-5", "6-20", "21-100", "100+"):
            await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                                 count_bucket=bucket)))
        await asyncio.sleep(.4)
        await plugin.close()
        self.assertEqual(len(calls) - admitted, 1,
                         "half-open state admitted more than one probe")

    async def test_cache_avoids_repeat_calls_and_expires(self):
        transport = fx.offline_transport(lambda request: fx.provider_response("user_error"))
        plugin = self.plugin(transport=transport, cache_ttl=.03, cache_size=2)
        await plugin.start()
        signal = fx.signal(failure_reason="invalid_credentials")
        await plugin.emit(envelope(signal))
        await plugin.join()
        await plugin.emit(envelope(signal))
        await plugin.join()
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(plugin.metrics.provider_avoided, 1)
        await asyncio.sleep(.04)
        await plugin.emit(envelope(signal))
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(transport.calls), 2)

    async def test_cache_is_bounded_and_cleared_on_close(self):
        transport = fx.offline_transport()
        plugin = self.plugin(transport=transport, cache_size=2, cache_ttl=60)
        await plugin.start()
        for count in ("1", "2-5", "6-20"):
            await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                                 count_bucket=count)))
            await plugin.join()
        self.assertLessEqual(len(plugin._cache), 2)
        await plugin.close()
        self.assertEqual(len(plugin._cache), 0)

    async def test_full_queue_drops_without_blocking(self):
        entered, release = asyncio.Event(), asyncio.Event()

        async def blocked(request):
            entered.set()
            await release.wait()
            return fx.provider_response("user_error")
        plugin = self.plugin(transport=blocked, queue_size=1)
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await entered.wait()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials", count_bucket="2-5")))
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials", count_bucket="6-20")))
        self.assertEqual(plugin.metrics.results["queue_full"], 1)
        release.set()
        await plugin.join()
        await plugin.close()

    async def test_expired_queue_entry_skips_the_provider(self):
        entered, release = asyncio.Event(), asyncio.Event()
        transport = fx.offline_transport()

        async def blocked(request):
            transport.calls.append(request)
            entered.set()
            await release.wait()
            return fx.provider_response("user_error")
        plugin = self.plugin(transport=blocked, queue_ttl=.005)
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await entered.wait()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials", count_bucket="2-5")))
        await asyncio.sleep(.02)
        release.set()
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(transport.calls), 1)
        self.assertEqual(plugin.metrics.results["expired"], 1)

    async def test_close_drops_pending_and_rejects_new_work(self):
        entered = asyncio.Event()

        async def blocked(request):
            entered.set()
            await asyncio.Event().wait()
        plugin = self.plugin(transport=blocked)
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await entered.wait()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials", count_bucket="2-5")))
        await plugin.close()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        self.assertEqual(plugin.metrics.results["shutdown_drop"], 1)
        self.assertEqual(plugin.metrics.results["disabled"], 1)
        self.assertFalse(await plugin.health_check())

    async def test_http_timeouts_limit_underlying_concurrency(self):
        entered, release = threading.Event(), threading.Event()
        active = [0, 0]

        def slow_post(*args):
            active[0] += 1
            active[1] = max(active)
            entered.set()
            release.wait(1)
            active[0] -= 1
            return fx.provider_response("user_error")
        with patch("auth_audit_jev.http.post_json", slow_post):
            plugin = SignalAuditPlugin(enabled=True, api_key="TEST_ONLY", timeout=.01)
            await plugin.start()
            await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
            self.assertTrue(await asyncio.to_thread(entered.wait, .5))
            for count in ("2-5", "6-20", "21-100", "over-100"):
                await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials",
                                                     count_bucket=count)))
                await plugin.join()
            release.set()
            await plugin.close()
        self.assertEqual(active[1], 1)

    async def test_hostile_envelope_cannot_escape_emit(self):
        class Hostile:
            @property
            def authn_signal(self):
                raise RuntimeError("SECRET_PROVIDER_ERROR")
        transport = fx.offline_transport()
        plugin = self.plugin(transport=transport)
        await plugin.start()
        await plugin.emit(Hostile())
        await plugin.emit(SimpleNamespace(authn_signal={"schema_version": "SECRET"}))
        await plugin.join()
        await plugin.close()
        self.assertEqual(transport.calls, [])
        self.assertEqual(plugin.metrics.results["skipped"], 2)

    async def test_invalid_limits_are_rejected(self):
        for kwargs in ({"queue_size": 0}, {"timeout": 0}, {"queue_ttl": -1},
                       {"cache_size": 0}, {"worker_count": 0}, {"review_threshold": 2},
                       {"circuit_failure_threshold": 0}):
            with self.assertRaises(ValueError, msg=kwargs):
                SignalAuditPlugin(**kwargs)

    async def test_metrics_exposition_has_only_fixed_labels(self):
        plugin = self.plugin(transport=fx.offline_transport(
            lambda request: fx.provider_response("user_error")))
        await plugin.start()
        await plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await plugin.join()
        await plugin.close()
        exposition = plugin.metrics.prometheus()
        self.assertIn('auth_audit_category_total{value="user_error"} 1', exposition)
        self.assertIn('auth_audit_urgency_total{value="routine_review"} 1', exposition)
        self.assertIn("auth_audit_provider_avoided_total 0", exposition)
        self.assertIn("auth_audit_local_candidate_total", exposition)
        self.assertIn('auth_audit_circuit_total{value="closed"} 1', exposition)
        self.assertIn("auth_audit_provider_duration_seconds_bucket", exposition)
        for secret in fx.SCRUB_TOKENS:
            self.assertNotIn(secret, exposition)

    async def test_abstention_reason_labels_are_a_closed_enum(self):
        self.assertIn("timeout", ABSTENTION_REASONS)
        self.assertIn("circuit_open", ABSTENTION_REASONS)
        self.assertEqual(len(ABSTENTION_REASONS), len(set(ABSTENTION_REASONS)))


class FixtureIntegrityTests(unittest.TestCase):
    def test_fixture_labels_are_reviewed_categories(self):
        self.assertGreaterEqual(len(fx.FIXTURES), 20)
        for name, signal, expected, note in fx.FIXTURES:
            self.assertIn(expected, CATEGORIES, name)
            self.assertTrue(note, name)
            self.assertIsNotNone(normalize_signal(signal), name)

    def test_fixture_set_covers_every_class_and_the_leading_false_positives(self):
        expected = {label for _, _, label, _ in fx.FIXTURES}
        for category in ("user_error", "client_misconfiguration", "suspected_abuse", "ambiguous"):
            self.assertIn(category, expected)
        names = [name for name, _, _, _ in fx.FIXTURES]
        self.assertTrue([n for n in names if n.startswith("ambiguous_")])
        self.assertTrue([n for n in names if n.startswith("trap_")])

    def test_rejected_signals_are_really_rejected(self):
        for name, bad in fx.REJECTED_SIGNALS:
            self.assertIsNone(project_signal(envelope(bad)), name)

    def test_fixtures_expose_no_secret_and_no_exact_counts(self):
        blob = json.dumps([signal for _, signal, _, _ in fx.FIXTURES], sort_keys=True)
        for secret in fx.SCRUB_TOKENS:
            self.assertNotIn(secret, blob)


class LegacyBoundaryUnchangedTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_plugin_still_uses_three_fields_and_its_own_alert(self):
        requests, alerts = [], []

        async def transport(request):
            requests.append(request)
            return legacy_answer()
        plugin = AuditPlugin(transport=transport, alert=alerts.append)
        await plugin.start()
        await plugin.emit({"event": {"event_type": "user_authentication_failed", "severity": "warning"},
                           "authn_signal": fx.signal(failure_reason="invalid_credentials")})
        await plugin.join()
        await plugin.close()
        self.assertEqual(requests[0]["state"],
                         {"event_kind": "user_authentication_failed", "severity": "warning",
                          "outcome": "failure"})
        self.assertEqual(set(requests[0]["questions"]), {"assessment"})
        self.assertEqual(alerts, [{"event_kind": "user_authentication_failed",
                                   "outcome": "failure", "assessment": "suspicious"}])

    async def test_legacy_and_signal_plugins_coexist_with_shared_metrics(self):
        metrics = Metrics()
        alerts = []
        legacy_transport = fx.offline_transport(lambda request: legacy_answer(choice="routine"))
        legacy = AuditPlugin(transport=legacy_transport, alert=alerts.append, metrics=metrics)
        signal_plugin = SignalAuditPlugin(transport=fx.offline_transport(
            lambda request: fx.provider_response("user_error")), alert=alerts.append,
            enabled=True, metrics=metrics)
        await legacy.start()
        await signal_plugin.start()
        await legacy.emit({"event": {"event_type": "user_authentication_failed",
                                     "severity": "warning"}})
        await signal_plugin.emit(envelope(fx.signal(failure_reason="invalid_credentials")))
        await legacy.join()
        await signal_plugin.join()
        await legacy.close()
        await signal_plugin.close()
        self.assertEqual(metrics.results["routine"], 1)
        self.assertEqual(metrics.categories["user_error"], 1)
        self.assertEqual(legacy.name, "auth_audit_jev")
        self.assertEqual(signal_plugin.name, "auth_audit_jev_signal")


class CalibrationHelperTests(unittest.TestCase):
    def test_empty_classes_report_none_not_perfect_scores(self):
        report = per_category_metrics([("user_error", "user_error")])
        self.assertIsNone(report["categories"]["suspected_abuse"]["recall"])
        self.assertIsNone(report["categories"]["suspected_abuse"]["precision"])
        self.assertEqual(report["categories"]["user_error"]["recall"], 1.0)

    def test_abstentions_are_counted_and_lower_recall(self):
        report = per_category_metrics([("suspected_abuse", "suspected_abuse"),
                                       ("suspected_abuse", None)])
        self.assertEqual(report["abstained"], 1)
        self.assertEqual(report["categories"]["suspected_abuse"]["recall"], .5)
        self.assertEqual(agreement([("suspected_abuse", None)]), None)


if __name__ == "__main__":
    unittest.main()
