"""Contract tests for the Rust ``oauth2-events`` producer adapter.

Every fixture is a real Rust envelope shape, validated against the wire contract
in ``crates/oauth2-events``. The tests assert the two non-negotiable properties
of a shadow adapter:

* an event that can be reviewed is projected to the allowlisted subset, and
  never carries identifiers, metadata, error text, or trace/correlation context
  out of the process; and
* an event that cannot be observed from the Rust crate — an invalid-token or
  introspection failure, an authz denial, or an out-of-contract string — abstains
  rather than being mapped to a fabricated verdict.
"""
import json
import unittest
from collections import Counter

from auth_audit_jev.rust_events import (
    ENVELOPE_PROVENANCE_FIELDS,
    RUST_FAILURES,
    RUST_SUCCESSES,
    SAFE_ATTRIBUTE_KEYS,
    RustEventsAuditAdapter,
    RustEventsDropAccountant,
    outcome_for,
    project_rust_envelope,
)


def _envelope(event_type, severity, extra_event=None, extra_envelope=None):
    event = {
        "id": "evt-1",
        "event_type": event_type,
        "timestamp": "2026-09-28T12:00:00Z",
        "severity": severity,
        "user_id": "user-123",
        "client_id": "client-456",
        "metadata": {"ip": "10.0.0.1"},
        "error": "boom",
    }
    if extra_event:
        event.update(extra_event)
    env = {
        "event": event,
        "idempotency_key": "idem-1",
        "correlation_id": "corr-1",
        "producer": "rust-oauth2-server",
        "produced_at": "2026-09-28T12:00:00.001Z",
        "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        "tracestate": "vendor=value",
        "attributes": {"region": "us-east-1", "grant_type": "authorization_code"},
    }
    if extra_envelope:
        env.update(extra_envelope)
    return env


def _flat(projection):
    """All string values reachable in a projection, for leak detection."""
    out = []
    for value in projection.values():
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, dict):
            out.extend(str(v) for v in value.values())
    return out


class TestAllowedAndObserved(unittest.TestCase):
    def test_success_events_project_to_success(self):
        for event_type in sorted(RUST_SUCCESSES):
            fields, _ = project_rust_envelope(_envelope(event_type, "info"))
            self.assertEqual(fields["event_kind"], event_type)
            self.assertEqual(outcome_for(event_type), "success")

    def test_failure_events_project_to_failure(self):
        for event_type in sorted(RUST_FAILURES):
            fields, _ = project_rust_envelope(_envelope(event_type, "warning"))
            self.assertEqual(fields["event_kind"], event_type)
            self.assertEqual(outcome_for(event_type), "failure")

    def test_neutral_events_are_observed_not_failure(self):
        self.assertEqual(outcome_for("token_revoked"), "observed")
        self.assertEqual(outcome_for("token_expired"), "observed")
        self.assertEqual(outcome_for("user_logout"), "observed")


class TestAbstention(unittest.TestCase):
    def test_invalid_token_signals_abstain(self):
        for event_type in ("token_rejected", "token_introspection_failed"):
            self.assertNotIn(event_type, RUST_FAILURES)
            self.assertIsNone(project_rust_envelope(_envelope(event_type, "error")))

    def test_authz_signals_abstain(self):
        for event_type in ("authorization_denied", "authorization_allowed",
                           "permission_denied", "access_denied"):
            self.assertIsNone(project_rust_envelope(_envelope(event_type, "error")))

    def test_missing_event_type_abstains(self):
        env = _envelope("user_authentication_failed", "warning")
        del env["event"]["event_type"]
        self.assertIsNone(project_rust_envelope(env))

    def test_out_of_contract_string_abstains(self):
        env = _envelope("user_authentication_failed", "warning")
        env["event"]["event_type"] = "PasswordMismatch"
        self.assertIsNone(project_rust_envelope(env))


class TestPrivacy(unittest.TestCase):
    def test_no_sensitive_strings_in_projection(self):
        fields, dropped = project_rust_envelope(_envelope("user_authentication_failed", "warning"))
        flat = _flat(fields)
        for secret in ("user-123", "client-456", "boom", "10.0.0.1",
                       "idem-1", "corr-1", "rust-oauth2-server", "evt-1",
                       "2026-09-28T12:00:00Z"):
            self.assertNotIn(secret, flat)
        self.assertGreater(dropped["identifier_or_context"], 0)

    def test_unknown_attribute_keys_are_dropped_not_exported(self):
        env = _envelope("user_authenticated", "info")
        env["attributes"]["session_id"] = "SECRET_SESSION"
        env["attributes"]["raw_input"] = "SECRET_INPUT"
        fields, _ = project_rust_envelope(env)
        self.assertTrue(set(fields["attributes"]) <= SAFE_ATTRIBUTE_KEYS)
        self.assertNotIn("session_id", fields["attributes"])
        self.assertNotIn("raw_input", fields["attributes"])

    def test_allowlisted_key_with_private_value_is_dropped(self):
        env = _envelope("user_authenticated", "info")
        env["attributes"].update({
            "auth_method": "password-for-user-123",
            "grant_type": "client-456",
            "endpoint": "/users/user-123/tokens",
            "operation": "token-SECRET_INPUT",
            "region": "user-123",
        })
        fields, dropped = project_rust_envelope(env)
        self.assertNotIn("attributes", fields)
        self.assertNotIn("user-123", _flat(fields))
        self.assertNotIn("client-456", _flat(fields))
        self.assertGreaterEqual(dropped["unreviewed_attribute_value"], 5)

    def test_envelope_provenance_fields_are_all_gated(self):
        hostile = {k: "SECRET" for k in ENVELOPE_PROVENANCE_FIELDS}
        env = _envelope("user_authenticated", "info")
        env.update(hostile)
        fields, _ = project_rust_envelope(env)
        self.assertNotIn("SECRET", _flat(fields))

    def test_projection_never_contains_event_metadata_error_ids(self):
        fields, _ = project_rust_envelope(_envelope("token_validated", "info"))
        for key in ("id", "timestamp", "user_id", "metadata", "error"):
            self.assertNotIn(key, fields)


class TestAdapter(unittest.TestCase):
    class _Q:
        def __init__(self):
            self.items = []
        def put_nowait(self, item):
            self.items.append(item)
        def qsize(self):
            return len(self.items)
        def full(self):
            return False

    class _Metrics:
        # Mirrors the real auth_audit_jev.Metrics surface (results Counter +
        # queue_depth) so the fake plugin cannot mask an incompatibility with
        # the shipped plugin the way the prior fake did.
        def __init__(self):
            self.results = Counter()
            self.queue_depth = 0

    def _plugin(self):
        plugin = type("P", (), {"queue": self._Q(), "metrics": self._Metrics()})()
        return plugin

    def test_adapter_constructs_enqueues_and_accounts(self):
        plugin = self._plugin()
        adapter = RustEventsAuditAdapter(plugin, enabled=True)
        outcome = adapter.emit_envelope(_envelope("user_authentication_failed", "warning"))
        self.assertEqual(outcome, "accepted")
        self.assertTrue(plugin.queue.items)
        state, _ = plugin.queue.items[0]
        self.assertEqual(state["event_kind"], "user_authentication_failed")
        self.assertEqual(state["outcome"], "failure")
        for secret in ("user-123", "boom", "idem-1", "corr-1"):
            self.assertNotIn(secret, _flat(state))

    def test_adapter_disabled_abstains(self):
        plugin = self._plugin()
        adapter = RustEventsAuditAdapter(plugin, enabled=False)
        self.assertEqual(adapter.emit_envelope(_envelope("user_authenticated", "info")), "disabled")
        self.assertEqual(plugin.queue.items, [])

    def test_drop_accountant_counts_privacy_and_attribute_drops(self):
        acc = RustEventsDropAccountant()
        env = _envelope("user_authentication_failed", "warning")
        env["attributes"]["unreviewed"] = "x"
        fields, outcome = acc.observe(env)
        self.assertEqual(outcome, "accepted")
        self.assertGreater(acc.privacy_drops, 0)
        self.assertGreater(acc.attribute_drops, 0)
        self.assertIsNotNone(fields)

    def test_drop_accountant_abstains_on_unknown_event(self):
        acc = RustEventsDropAccountant()
        fields, outcome = acc.observe(_envelope("authorization_denied", "error"))
        self.assertIsNone(fields)
        self.assertEqual(outcome, "unknown_event")


class TestAdapterAgainstRealPlugin(unittest.IsolatedAsyncioTestCase):
    """Exercises RustEventsAuditAdapter against the real AuditPlugin.

    The adapter must enqueue into the actual plugin queue and produce a
    projected state that the plugin's worker can transport, without depending
    on any plugin metric attribute beyond the ones that truly exist
    (Metrics.results and Metrics.queue_depth).
    """

    async def test_emit_envelope_reaches_real_plugin_transport(self):
        from auth_audit_jev import AuditPlugin

        captured = []

        async def fake_transport(request):
            captured.append(request)
            # A well-formed provider response that validates as "routine".
            return {
                "model": "jev-latest",
                "usage": {"input_tokens": 3, "output_tokens": 1, "cost_usd": 0.0},
                "answers": {"assessment": {
                    "type": "choice",
                    "choice": "routine",
                    "confidence": 0.95,
                    "probabilities": {"suspicious": 0.02, "routine": 0.95, "other": 0.03},
                }},
            }

        plugin = AuditPlugin(transport=fake_transport, enabled=True)
        await plugin.start()
        adapter = RustEventsAuditAdapter(plugin, enabled=True)

        outcome = adapter.emit_envelope(_envelope("user_authentication_failed", "warning"))
        self.assertEqual(outcome, "accepted")

        # The projected state must reach the provider with no secret strings.
        await plugin.join()
        self.assertEqual(len(captured), 1)
        for secret in ("user-123", "client-456", "boom", "10.0.0.1",
                       "idem-1", "corr-1", "rust-oauth2-server", "evt-1"):
            self.assertNotIn(secret, json.dumps(captured[0]))

        # Drop accounting is observable on the adapter's own accountant.
        self.assertGreater(adapter.metrics.privacy_drops, 0)
        self.assertEqual(adapter.metrics.counts["accepted"], 1)
        # The real Metrics had no dropped_* attributes to corrupt.
        self.assertFalse(hasattr(plugin.metrics, "dropped_metadata"))
        self.assertFalse(hasattr(plugin.metrics, "dropped_attributes"))
        await plugin.close()

    async def test_disabled_adapter_does_not_touch_real_plugin(self):
        from auth_audit_jev import AuditPlugin

        plugin = AuditPlugin(transport=None, enabled=False)
        adapter = RustEventsAuditAdapter(plugin, enabled=False)
        outcome = adapter.emit_envelope(_envelope("user_authenticated", "info"))
        self.assertEqual(outcome, "disabled")
        self.assertEqual(plugin.queue.qsize(), 0)


if __name__ == "__main__":
    unittest.main()
