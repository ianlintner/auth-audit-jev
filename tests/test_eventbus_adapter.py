"""Contract tests for the opt-in Python OAuth2 `EventBus` adapter.

The tests are written against *serialized* envelopes — the shape a real
`oauth2_server.services.events_bus.EventEnvelope.model_dump(mode="json")`
produces (nested `event` object plus delivery/tracing metadata) — and a
local stand-in `EventBus` that mirrors the server's fan-out semantics
(`plugins` list, `publish_best_effort` spawning a task and returning
immediately). No server import, no network, and no Jev call.

Covered here:

* failed login, token rejection, scope/permission denial and success
* privacy negative test: no raw identifier, IP, credential, token,
  metadata/error text or trace context reaches the request, queue, logs or
  metric labels
* the plugin is opt-in, off the request path, and leaves an events-disabled
  bus unchanged
* bounded queue and failure handling
* rollback removes the consumer without touching other plugins
"""

import asyncio
import json
import logging
import unittest
from types import SimpleNamespace

from auth_audit_jev import AuditPlugin, build_request, project_event
from auth_audit_jev.eventbus_adapter import (
    contract_state,
    envelope_from_state,
    install_audit_plugin,
    remove_audit_plugin,
)

SECRETS = (
    "SECRET_EVENT_ID",
    "SECRET_USER",
    "SECRET_CLIENT",
    "SECRET_IP",
    "SECRET_TOKEN",
    "SECRET_ERROR",
    "SECRET_TIMESTAMP",
    "SECRET_CORRELATION",
    "SECRET_TRACE",
    "SECRET_TRACESTATE",
    "SECRET_HEADER",
    "SECRET_IDEMPOTENCY",
    "SECRET_PRODUCER",
)


def serialized_envelope(kind, severity="warning"):
    """A faithful stand-in for the server's `EventEnvelope.model_dump(mode="json")`.

    Field-for-field the same JSON the server produces, including every field
    the projection must NOT copy: `AuthEvent` keeps `None`s (no `skip_serializing_if`)
    and the envelope omits only `idempotency_key`/`traceparent`/`tracestate`
    when `None` and `attributes` when empty.
    """
    return {
        "event": {
            "id": "SECRET_EVENT_ID",
            "event_type": kind,
            "timestamp": "SECRET_TIMESTAMP",
            "severity": severity,
            "user_id": "SECRET_USER",
            "client_id": "SECRET_CLIENT",
            "metadata": {"ip": "SECRET_IP", "authorization": "SECRET_HEADER", "token": "SECRET_TOKEN"},
            "error": "SECRET_ERROR",
        },
        "idempotency_key": "SECRET_IDEMPOTENCY",
        "traceparent": "SECRET_TRACE",
        "tracestate": "SECRET_TRACESTATE",
        "correlation_id": "SECRET_CORRELATION",
        "producer": "SECRET_PRODUCER",
        "produced_at": "SECRET_TIMESTAMP",
        "attributes": {"authorization": "SECRET_HEADER"},
    }


def answer(choice="suspicious", confidence=.92):
    return {
        "model": "jev-latest",
        "usage": {"input_tokens": 12, "output_tokens": 2, "cost_usd": .0001},
        "answers": {
            "assessment": {
                "type": "choice",
                "choice": choice,
                "confidence": confidence,
                "probabilities": {
                    "suspicious": .92 if choice == "suspicious" else .04,
                    "routine": .04 if choice == "suspicious" else .92,
                    "other": .04,
                },
            }
        },
    }


class FakeEventBus:
    """Mirrors `EventBus` fan-out: append-only plugin list, fire-and-forget publish."""

    def __init__(self, plugins=None, event_filter=None):
        self.plugins = list(plugins or [])
        self._filter = event_filter
        self._tasks = set()
        self.published = 0

    def publish_best_effort(self, envelope):
        if self._filter is not None and not self._filter(envelope):
            return
        self.published += 1
        task = asyncio.create_task(self._fan_out(envelope))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _fan_out(self, envelope):
        for plugin in list(self.plugins):
            try:
                await plugin.emit(envelope)
            except Exception:  # bus catches per-plugin, never propagates
                pass

    async def drain(self):
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


class RecordingPlugin:
    """Represents an unrelated, pre-existing bus plugin."""

    name = "console"

    def __init__(self):
        self.seen = []

    async def emit(self, envelope):
        self.seen.append(envelope)

    async def health_check(self):
        return True


class ContractTests(unittest.IsolatedAsyncioTestCase):
    async def _amap(self, kind, severity="warning", transport=None, **kwargs):
        """Publish one serialized envelope; return (requests, alerts, plugin)."""
        requests, alerts = [], []
        async def fake(request):
            requests.append(request)
            return (transport or answer)() if callable(transport) else answer()
        plugin = AuditPlugin(transport=fake, alert=alerts.append, **kwargs)
        await plugin.start()
        bus = FakeEventBus()
        install_audit_plugin(bus, plugin)
        bus.publish_best_effort(serialized_envelope(kind, severity))
        await bus.drain()
        await plugin.join()
        await plugin.close()
        return requests, alerts, plugin

    async def test_failed_login_is_suspicious_eligible(self):
        requests, alerts, plugin = await self._amap("user_authentication_failed")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["state"], {
            "event_kind": "user_authentication_failed", "severity": "warning", "outcome": "failure"})
        self.assertEqual(alerts, [{"event_kind": "user_authentication_failed",
                                   "outcome": "failure", "assessment": "suspicious"}])

    async def test_token_rejection_is_observed_including_expiry_and_revocation(self):
        # `observed` never alerts *because of the kind*: with a routine provider
        # answer there is no recommendation. A suspicious answer on any
        # allowlisted kind is advisory-only and still cannot change access.
        for kind in ("token_expired", "token_revoked", "authorization_code_expired"):
            with self.subTest(kind=kind):
                requests, alerts, plugin = await self._amap(kind, transport=lambda: answer("routine", .95))
                self.assertEqual(requests[0]["state"]["outcome"], "observed")
                self.assertEqual(alerts, [])
                self.assertEqual(plugin.metrics.results["recommendation"], 0)
                self.assertEqual(plugin.metrics.results["routine"], 1)

    async def test_scope_and_permission_denial_is_a_failure(self):
        for kind in ("permission_denied", "authorization_denied", "access_denied"):
            with self.subTest(kind=kind):
                requests, _, _ = await self._amap(kind)
                self.assertEqual(requests[0]["state"], {
                    "event_kind": kind, "severity": "warning", "outcome": "failure"})

    async def test_success_is_labelled_success_and_never_alerts(self):
        for kind in ("user_authenticated", "authentication_succeeded", "authorization_allowed"):
            with self.subTest(kind=kind):
                requests, alerts, plugin = await self._amap(kind, transport=lambda: answer("routine", .95))
                self.assertEqual(requests[0]["state"]["outcome"], "success")
                self.assertEqual(alerts, [])
                self.assertEqual(plugin.metrics.results["routine"], 1)

    async def test_contract_state_matches_plugin_projection_on_serialized_envelope(self):
        cases = {
            "user_authentication_failed": "failure",
            "authentication_failed": "failure",
            "token_expired": "observed",
            "token_revoked": "observed",
            "authorization_code_expired": "observed",
            "permission_denied": "failure",
            "authorization_denied": "failure",
            "access_denied": "failure",
            "user_authenticated": "success",
            "authentication_succeeded": "success",
            "authorization_allowed": "success",
            "token_validated": "success",
            "authorization_code_validated": "success",
        }
        for kind, outcome in cases.items():
            with self.subTest(kind=kind):
                envelope = serialized_envelope(kind)
                self.assertEqual(project_event(envelope),
                                 contract_state(envelope))
                self.assertEqual(project_event(envelope)["outcome"], outcome)

    async def test_unrecognised_kind_and_severity_are_skipped(self):
        for envelope in (
            serialized_envelope("custom.secret"),
            serialized_envelope("user_authenticated", severity="SECRET_SEVERITY"),
            serialized_envelope(None),
        ):
            with self.subTest(envelope=envelope):
                self.assertIsNone(contract_state(envelope))
                self.assertIsNone(project_event(envelope))


class PrivacyTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_raw_field_reaches_request_queue_logs_or_metrics(self):
        requests, alerts = [], []
        async def fake(request):
            requests.append(request)
            return answer()
        plugin = AuditPlugin(transport=fake, alert=alerts.append)
        await plugin.start()
        bus = FakeEventBus()
        install_audit_plugin(bus, plugin)
        # Capture any logs the publish path emits — the happy path is silent by
        # design (content is never logged), so tolerate zero records rather than
        # asserting that a line was written.
        class _Capture(logging.Handler):
            def __init__(self):
                super().__init__(level=logging.DEBUG)
                self.records = []

            def emit(self, record):
                self.records.append(record)

        captured = _Capture()
        logging.getLogger().addHandler(captured)
        try:
            for kind in ("user_authentication_failed", "token_expired",
                         "permission_denied", "user_authenticated"):
                bus.publish_best_effort(serialized_envelope(kind))
            await bus.drain()
            await plugin.join()
            logs = "\n".join(r.getMessage() for r in captured.records)
        finally:
            logging.getLogger().removeHandler(captured)
        await plugin.close()

        # Outbound provider payload: only the three allowlisted fields.
        self.assertEqual(len(requests), 4)
        outbound = json.dumps(requests)
        for request in requests:
            self.assertEqual(sorted(request["state"]), ["event_kind", "outcome", "severity"])
        # Alert callback payload is the fixed three-field advisory, one per
        # suspicious recommendation (the default `answer()` is suspicious on
        # every kind here).
        self.assertEqual(len(alerts), 4)
        for alert in alerts:
            self.assertEqual(sorted(alert), ["assessment", "event_kind", "outcome"])
            self.assertEqual(alert["assessment"], "suspicious")
        # Metric labels are fixed strings, never input-derived.
        exposition = plugin.metrics.prometheus()
        snapshots = json.dumps(plugin.metrics.snapshot())

        for surface in (outbound, json.dumps(alerts), exposition, snapshots, logs):
            for secret in SECRETS:
                self.assertNotIn(secret, surface, f"{secret} leaked")

    async def test_envelope_from_state_drops_everything_except_kind_and_severity(self):
        minimal = envelope_from_state({
            "event_type": "user_authentication_failed", "severity": "warning",
            "user_id": "SECRET_USER", "client_id": "SECRET_CLIENT",
            "metadata": {"ip": "SECRET_IP"}, "error": "SECRET_ERROR",
            "traceparent": "SECRET_TRACE",
        })
        self.assertEqual(minimal, {"event": {"event_type": "user_authentication_failed", "severity": "warning"}})
        self.assertNotIn("SECRET", json.dumps(minimal))
        self.assertEqual(envelope_from_state({"event_kind": "token_expired"}),
                         {"event": {"event_type": "token_expired", "severity": "info"}})
        with self.assertRaises(ValueError):
            envelope_from_state({"severity": "warning"})
        with self.assertRaises(TypeError):
            envelope_from_state("user_authentication_failed")

    async def test_provider_request_never_contains_envelope_attributes(self):
        requests = []
        async def fake(request):
            requests.append(request)
            return answer()
        plugin = AuditPlugin(transport=fake)
        await plugin.start()
        await plugin.emit({**serialized_envelope("permission_denied"),
                           "attributes": {"authorization": "SECRET_HEADER"},
                           "tracestate": "SECRET_TRACESTATE"})
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["state"], {"event_kind": "permission_denied",
                                                "severity": "warning", "outcome": "failure"})
        self.assertNotIn("SECRET", json.dumps(requests[0]))


class OptInAndOffPathTests(unittest.IsolatedAsyncioTestCase):
    async def test_default_install_is_disabled_and_does_not_call_provider(self):
        bus = FakeEventBus()
        plugin = install_audit_plugin(bus)
        await plugin.start()
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()
        await plugin.close()
        self.assertEqual(plugin.metrics.results["disabled"], 1)
        self.assertEqual(plugin.metrics.provider_calls, 0)
        self.assertFalse(await plugin.health_check())

    async def test_bus_with_events_disabled_is_unchanged(self):
        recorder = RecordingPlugin()
        bus = FakeEventBus(plugins=[recorder])
        original = list(bus.plugins)
        install_audit_plugin(bus)
        self.assertEqual(bus.plugins[0], recorder)
        self.assertEqual(original, bus.plugins[:1])
        bus.publish_best_effort(serialized_envelope("user_authenticated"))
        await bus.drain()
        self.assertEqual(len(recorder.seen), 1)
        self.assertEqual(recorder.seen[0]["event"]["event_type"], "user_authenticated")

    async def test_publish_returns_before_the_provider_answers(self):
        release = asyncio.Event()
        entered = asyncio.Event()
        async def slow(request):
            entered.set()
            await release.wait()
            return answer()
        plugin = AuditPlugin(transport=slow)
        await plugin.start()
        bus = FakeEventBus()
        install_audit_plugin(bus, plugin)
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        # The publish call already returned; the worker may still be waiting.
        await asyncio.wait_for(entered.wait(), timeout=1)
        self.assertFalse(release.is_set())
        # The worker is blocked on `release`, so the provider has not yet been
        # called — publish returned off the caller's stack without waiting for
        # the provider answer.
        self.assertEqual(plugin.metrics.provider_calls, 0, "fan-out must run off the caller's stack")
        release.set()
        await bus.drain()
        await plugin.join()
        await plugin.close()

    async def test_a_broken_audit_plugin_cannot_break_the_bus(self):
        class Exploding(AuditPlugin):
            async def emit(self, envelope):
                raise RuntimeError("SECRET_PROVIDER_ERROR")
        recorder = RecordingPlugin()
        plugin = Exploding(transport=lambda: answer())
        await plugin.start()
        bus = FakeEventBus(plugins=[recorder])
        install_audit_plugin(bus, plugin)
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()  # never raises
        self.assertEqual(len(recorder.seen), 1)
        await plugin.close()

    async def test_second_install_does_not_duplicate_fan_out(self):
        requests = []
        async def fake(request):
            requests.append(request)
            return answer()
        plugin = AuditPlugin(transport=fake)
        await plugin.start()
        bus = FakeEventBus()
        self.assertIs(install_audit_plugin(bus, plugin), plugin)
        self.assertIs(install_audit_plugin(bus, plugin), plugin)
        self.assertEqual(len(bus.plugins), 1)
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(requests), 1)


class BoundsAndFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_full_queue_drops_instead_of_blocking_the_bus(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def blocked(request):
            entered.set()
            await release.wait()
            return answer("routine")
        plugin = AuditPlugin(transport=blocked, queue_size=1)
        await plugin.start()
        bus = FakeEventBus()
        install_audit_plugin(bus, plugin)
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await asyncio.wait_for(entered.wait(), timeout=1)  # bounded: never hang on a worker bug
        for _ in range(5):
            bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()
        self.assertEqual(plugin.metrics.results["queue_full"], 4)
        self.assertEqual(plugin.metrics.queue_depth, 1)
        release.set()
        await plugin.join()
        await plugin.close()
        self.assertEqual(plugin.metrics.results["routine"], 2)

    async def test_provider_timeout_and_error_abstain_without_retry(self):
        calls = []
        async def fake(request):
            calls.append(request)
            if len(calls) == 1:
                await asyncio.sleep(.05)
            else:
                raise RuntimeError("SECRET_PROVIDER_ERROR")
        plugin = AuditPlugin(transport=fake, timeout=.005)
        await plugin.start()
        bus = FakeEventBus()
        install_audit_plugin(bus, plugin)
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()
        await plugin.join()
        bus.publish_best_effort(serialized_envelope("permission_denied"))
        await bus.drain()
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(calls), 2)
        self.assertEqual(plugin.metrics.results["timeout"], 1)
        self.assertEqual(plugin.metrics.results["error"], 1)
        self.assertEqual(plugin.metrics.results["recommendation"], 0)
        self.assertNotIn("SECRET", plugin.metrics.prometheus())

    async def test_stopped_plugin_never_raises_into_publish_path(self):
        plugin = AuditPlugin(transport=lambda: answer())
        bus = FakeEventBus()
        install_audit_plugin(bus, plugin)
        # Never started: emit() must count `disabled` and return.
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()
        self.assertEqual(plugin.metrics.results["disabled"], 1)


class RollbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_remove_plugin_restores_original_plugin_list(self):
        recorder = RecordingPlugin()
        bus = FakeEventBus(plugins=[recorder])
        plugin = AuditPlugin(transport=lambda: answer())
        await plugin.start()
        install_audit_plugin(bus, plugin)
        self.assertTrue(remove_audit_plugin(bus, plugin))
        self.assertEqual(bus.plugins, [recorder])
        await plugin.close()
        # Bus still fans out to the pre-existing plugin exactly as before.
        bus.publish_best_effort(serialized_envelope("user_authentication_failed"))
        await bus.drain()
        self.assertEqual(len(recorder.seen), 1)

    async def test_remove_is_idempotent_and_tolerates_foreign_objects(self):
        bus = FakeEventBus()
        plugin = AuditPlugin(transport=lambda: answer())
        self.assertFalse(remove_audit_plugin(bus, plugin))
        install_audit_plugin(bus, plugin)
        self.assertTrue(remove_audit_plugin(bus, plugin))
        self.assertFalse(remove_audit_plugin(bus, plugin))
        self.assertFalse(remove_audit_plugin(SimpleNamespace(), plugin))


if __name__ == "__main__":
    unittest.main()
