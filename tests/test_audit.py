import asyncio
import json
import unittest
import threading
from unittest.mock import patch
from types import SimpleNamespace

from auth_audit_jev import AuditPlugin, Metrics, project_event, validate_answer, build_request


def envelope(kind="user_authentication_failed", severity="warning"):
    return SimpleNamespace(event=SimpleNamespace(
        event_type=kind, severity=severity, id="SECRET_EVENT", user_id="SECRET_USER",
        client_id="SECRET_CLIENT", metadata={"ip": "SECRET_IP", "token": "SECRET_TOKEN"},
        error="SECRET_ERROR", timestamp="SECRET_TIME"),
        correlation_id="SECRET_CORRELATION", traceparent="SECRET_TRACE",
        attributes={"authorization": "SECRET_HEADER"})


def answer(choice="suspicious", confidence=.92):
    return {"model": "jev-latest", "usage": {"input_tokens": 12, "output_tokens": 2, "cost_usd": .0001}, "answers": {"assessment": {
        "type": "choice", "choice": choice, "confidence": confidence,
        "probabilities": {"suspicious": .92 if choice == "suspicious" else .04,
                          "routine": .04 if choice == "suspicious" else .92, "other": .04}}}}


class ProjectionTests(unittest.TestCase):
    def test_only_approved_enums_reach_request(self):
        request = build_request(project_event(envelope()))
        serialized = json.dumps(request)
        self.assertEqual(request["state"], {"event_kind": "user_authentication_failed",
                                           "severity": "warning", "outcome": "failure"})
        for secret in ("SECRET_EVENT", "SECRET_USER", "SECRET_CLIENT", "SECRET_IP",
                       "SECRET_TOKEN", "SECRET_ERROR", "SECRET_TIME", "SECRET_CORRELATION",
                       "SECRET_TRACE", "SECRET_HEADER"):
            self.assertNotIn(secret, serialized)
        self.assertEqual(request["model"], "jev-latest")
        self.assertIn("other", request["questions"]["assessment"]["criteria"])

    def test_unknown_or_malformed_event_abstains(self):
        self.assertIsNone(project_event(envelope("custom.secret")))
        self.assertIsNone(project_event(envelope(severity="SECRET")))
        self.assertIsNone(project_event({"event": {"event_type": "token_created", "severity": ["info"]}}))
        self.assertIsNone(project_event({"event_type": "token_created"}))

    def test_authz_denial_and_neutral_events_are_not_misclassified(self):
        self.assertEqual(project_event(envelope("authorization_denied"))["outcome"], "failure")
        self.assertEqual(project_event(envelope("permission_denied"))["outcome"], "failure")
        self.assertEqual(project_event(envelope("token_revoked"))["outcome"], "observed")
        self.assertEqual(project_event(envelope("user_authenticated"))["outcome"], "success")

    def test_choice_validation_rejects_uncertain_and_invalid(self):
        self.assertEqual(validate_answer(answer()), "suspicious")
        self.assertIsNone(validate_answer(answer(confidence=.4)))
        self.assertIsNone(validate_answer(answer(choice="other", confidence=.92)))
        self.assertIsNone(validate_answer({"answers": {"assessment": {"choice": "suspicious"}}}))
        self.assertIsNone(validate_answer({**answer(), "model": "jev-evil"}))
        self.assertEqual(validate_answer({**answer(), "model": "jev-1.13"}), "suspicious")
        self.assertIsNone(validate_answer({**answer(), "usage": {"input_tokens": 1}}))
        self.assertIsNone(validate_answer({**answer(), "answers": {"assessment": {**answer()["answers"]["assessment"], "confidence": True}}}))


class PluginTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_and_unknown_never_call_provider(self):
        requests = []
        async def fake(request):
            requests.append(request)
            return answer()
        plugin = AuditPlugin(transport=fake, enabled=False)
        await plugin.start()
        await plugin.emit(envelope())
        self.assertFalse(await plugin.health_check())
        self.assertEqual(plugin.metrics.results["disabled"], 1)
        await plugin.close()
        plugin = AuditPlugin(transport=fake)
        await plugin.start()
        await plugin.emit(envelope("SECRET_EVENT"))
        await plugin.join()
        await plugin.close()
        self.assertEqual(plugin.metrics.results["skipped"], 1)
        self.assertEqual(requests, [])

    async def test_full_queue_drops_without_blocking(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def blocked(request):
            entered.set()
            await release.wait()
            return answer("routine")
        plugin = AuditPlugin(transport=blocked, queue_size=1)
        await plugin.start()
        await plugin.emit(envelope())
        await entered.wait()
        await plugin.emit(envelope())
        await plugin.emit(envelope())
        self.assertEqual(plugin.metrics.results["queue_full"], 1)
        self.assertEqual(plugin.metrics.queue_depth, 1)
        release.set()
        await plugin.join()
        await plugin.close()
        self.assertEqual(plugin.metrics.results["routine"], 2)

    async def test_timeout_and_exception_abstain_without_retry(self):
        calls, alerts = [], []
        async def fake(request):
            calls.append(request)
            if len(calls) == 1:
                await asyncio.sleep(.05)
            else:
                raise RuntimeError("SECRET_PROVIDER_ERROR")
        plugin = AuditPlugin(transport=fake, timeout=.005, alert=alerts.append)
        await plugin.start()
        await plugin.emit(envelope())
        await plugin.join()
        await plugin.emit(envelope())
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(calls), 2)
        self.assertEqual(plugin.metrics.results["timeout"], 1)
        self.assertEqual(plugin.metrics.results["error"], 1)
        self.assertEqual(alerts, [])
        self.assertEqual(plugin.metrics.provider_calls, 2)
        self.assertGreater(plugin.metrics.provider_latency_sum_seconds, 0)

    async def test_malformed_low_confidence_and_other_never_alert(self):
        replies = [answer(confidence=.2), answer("other"), {"not": "an answer"}]
        alerts = []
        async def fake(request):
            return replies.pop(0)
        plugin = AuditPlugin(transport=fake, alert=alerts.append)
        await plugin.start()
        for _ in range(3):
            await plugin.emit(envelope())
            await plugin.join()
        await plugin.close()
        self.assertEqual(alerts, [])
        self.assertEqual(plugin.metrics.results["abstain"], 3)
        self.assertEqual(plugin.metrics.results["routine"], 0)

    async def test_close_discards_pending_and_rejects_new_jobs(self):
        entered = asyncio.Event()
        async def blocked(request):
            entered.set()
            await asyncio.Event().wait()
        plugin = AuditPlugin(transport=blocked)
        await plugin.start()
        await plugin.emit(envelope())
        await entered.wait()
        await plugin.emit(envelope())
        await plugin.close()
        await plugin.join()
        await plugin.emit(envelope())
        self.assertEqual(plugin.metrics.results["shutdown_drop"], 1)
        self.assertEqual(plugin.metrics.results["disabled"], 1)
        self.assertEqual(plugin.metrics.queue_depth, 0)
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
            return answer()
        with patch("auth_audit_jev._post_jev", slow_post):
            plugin = AuditPlugin(api_key="TEST_ONLY", timeout=.01)
            await plugin.start()
            await plugin.emit(envelope())
            self.assertTrue(await asyncio.to_thread(entered.wait, .5))
            for _ in range(5):
                await plugin.emit(envelope())
                await plugin.join()
            release.set()
            await plugin.close()
        self.assertEqual(active[1], 1)

    async def test_hostile_event_object_cannot_escape_emit(self):
        class Hostile:
            @property
            def event(self):
                raise RuntimeError("SECRET_EXCEPTION")
        requests = []
        async def fake(request):
            requests.append(request)
            return answer()
        plugin = AuditPlugin(transport=fake)
        await plugin.start()
        await plugin.emit(Hostile())
        await plugin.close()
        self.assertEqual(requests, [])
        self.assertEqual(plugin.metrics.results["skipped"], 1)

    async def test_expired_queued_event_does_not_call_provider(self):
        entered, release = asyncio.Event(), asyncio.Event()
        requests = []
        async def fake(request):
            requests.append(request)
            entered.set()
            await release.wait()
            return answer("routine")
        plugin = AuditPlugin(transport=fake, queue_ttl=.005)
        await plugin.start()
        await plugin.emit(envelope())
        await entered.wait()
        await plugin.emit(envelope())
        await asyncio.sleep(.02)
        release.set()
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(requests), 1)
        self.assertEqual(plugin.metrics.results["expired"], 1)

    async def test_alert_only_on_high_confidence_suspicious(self):
        requests, alerts = [], []
        async def fake(request):
            requests.append(request)
            return answer()
        plugin = AuditPlugin(transport=fake, alert=alerts.append)
        await plugin.start()
        await plugin.emit(envelope())
        await plugin.join()
        await plugin.close()
        self.assertEqual(len(requests), 1)
        self.assertEqual(alerts, [{"event_kind": "user_authentication_failed", "outcome": "failure", "assessment": "suspicious"}])
        self.assertEqual(plugin.metrics.results["alerted"], 1)
        self.assertEqual(plugin.metrics.results["recommendation"], 1)
        self.assertEqual(plugin.metrics.input_tokens, 12)
        self.assertEqual(plugin.metrics.output_tokens, 2)
        self.assertGreater(plugin.metrics.last_success_timestamp_seconds, 0)
        exposition = plugin.metrics.prometheus()
        self.assertIn('auth_audit_events_total{outcome="alerted"} 1', exposition)
        self.assertIn('auth_audit_provider_duration_seconds_bucket{le="+Inf"} 1', exposition)
        self.assertIn('auth_audit_cost_usd_total 0.0001', exposition)


if __name__ == "__main__":
    unittest.main()
