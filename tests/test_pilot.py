import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from auth_audit_jev import pilot as P


class FakeBus:
    """Same surface as the producer EventBus: plugins list + fire-and-forget publish."""

    def __init__(self):
        self.plugins, self.tasks = [], set()

    def publish_best_effort(self, envelope):
        task = asyncio.create_task(self._fan(envelope))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def _fan(self, envelope):
        for plugin in list(self.plugins):
            try:
                await plugin.emit(envelope)
            except Exception:
                pass


def publish(bus, event_type, severity):
    c = P.CANARIES
    bus.publish_best_effort(SimpleNamespace(
        event=SimpleNamespace(event_type=event_type, severity=severity, id=c[0], user_id=c[0],
                              client_id=c[1], metadata={"ip": c[2], "token": c[3]}, error=c[4], timestamp=c[4]),
        correlation_id=c[5], traceparent=c[5], attributes={"authorization": c[3]}))


def answer(choice="suspicious"):
    s = choice == "suspicious"
    return {"model": "jev-latest", "usage": {"input_tokens": 3, "output_tokens": 1, "cost_usd": 0},
            "answers": {"assessment": {"type": "choice", "choice": choice, "confidence": .95,
                                       "probabilities": {"suspicious": .95 if s else .025,
                                                         "routine": .025 if s else .95, "other": .025}}}}


def make(transport=None, **kw):
    return P.Pilot(transport=transport, bus=FakeBus(), publish=publish, metrics_token="m" * 16,
                   admin_token="a" * 16, **kw)


class PilotTests(unittest.IsolatedAsyncioTestCase):
    async def test_percentile_nearest_rank(self):
        self.assertIsNone(P.percentile([], 50))
        data = list(range(1, 101))
        self.assertEqual((P.percentile(data, 50), P.percentile(data, 95), P.percentile(data, 99)), (50, 95, 99))

    async def test_decisions_identical_with_audit_on_killed_and_failing(self):
        async def ok(request):
            return answer()

        async def boom(request):
            raise RuntimeError("provider down")

        results = []
        for transport, kill in ((ok, False), (boom, False), (ok, True)):
            p = make(transport)
            await p.start()
            if kill:
                await p.disable()
            results.append([(await p.synthetic(s, sync=True))["decision"] for s in P.SCENARIOS])
            await p.stop()
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])
        self.assertEqual(results[0], ["deny", "deny", "allow", "allow"])

    async def test_synthetic_failure_and_denial_reach_alert_with_timing(self):
        async def slow(request):
            await asyncio.sleep(.02)
            return answer()

        p = make(slow)
        await p.start()
        for scenario in ("authn_failure", "authz_denial"):
            r = await p.synthetic(scenario, sync=True)
            self.assertTrue(r["alerted"])
        self.assertEqual(p.plugin.metrics.results["alerted"], 2)
        self.assertEqual(len(p.e2a), 2)
        self.assertGreaterEqual(min(p.e2a), .02)
        self.assertEqual({a["event_kind"] for a in p.alerts}, {"user_authentication_failed", "authorization_denied"})
        await p.stop()

    async def test_canaries_never_reach_provider_metrics_state_or_alerts(self):
        seen = []

        async def capture(request):
            seen.append(json.dumps(request))
            return answer()

        p = make(capture)
        await p.start()
        for scenario in P.SCENARIOS:
            await p.synthetic(scenario, sync=True)
        await p.stop()
        blob = "".join(seen) + p.metrics_text() + json.dumps(p.state_json()) + json.dumps(list(p.alerts))
        for canary in P.CANARIES:
            self.assertNotIn(canary, blob)
        self.assertEqual(p.canary_leaks, 0)
        self.assertEqual(len(seen), 4)

    async def test_kill_switch_detaches_and_blocks_provider_calls(self):
        calls = []

        async def t(request):
            calls.append(request)
            return answer()

        with tempfile.TemporaryDirectory() as d:
            kill = Path(d) / "KILL"
            p = make(t, kill_file=kill)
            await p.start()
            self.assertEqual(len(p.bus.plugins), 1)
            await p.synthetic("authn_failure", sync=True)
            await p.disable("killed")
            self.assertEqual(p.bus.plugins, [])
            await p.synthetic("authn_failure", sync=True)
            await asyncio.sleep(.02)
            self.assertEqual(len(calls), 1)
            kill.touch()
            self.assertEqual(await p.enable(), "killed")
            kill.unlink()
            self.assertEqual(await p.enable(), "enabled")
            await p.synthetic("authz_denial", sync=True)
            self.assertEqual(len(calls), 2)
            kill.touch()
            await p.synthetic("authn_failure", sync=True)   # file kill takes effect on next event
            self.assertEqual((p.state, p.bus.plugins, len(calls)), ("killed", [], 2))

    async def test_no_key_means_no_audit(self):
        p = make(None)
        await p.start()
        self.assertEqual((p.state, p.bus.plugins), ("no_key", []))
        self.assertEqual((await p.synthetic("authn_failure", sync=True))["decision"], "deny")

    async def test_call_budget_is_enforced(self):
        async def t(request):
            return answer()

        p = make(t, max_live_calls=1)
        await p.start()
        await p.synthetic("authn_failure", sync=True)
        await p.synthetic("authn_failure", sync=True)
        self.assertEqual(p.live_calls, 1)
        self.assertEqual(p.plugin.metrics.results["error"], 1)
        await p.stop()

    async def test_burst_drops_without_blocking_callers(self):
        async def slow(request):
            await asyncio.sleep(.2)
            return answer("routine")

        p = make(slow, queue_size=2)
        await p.start()
        began = time.monotonic()
        for _ in range(30):
            await p.synthetic("authn_failure")
        self.assertLess(time.monotonic() - began, .15)    # callers never wait on the provider
        await asyncio.sleep(.05)
        self.assertGreater(p.plugin.metrics.results["queue_full"], 20)
        await p.stop()
        self.assertEqual(p.bus.plugins, [])

    async def test_http_surface_auth_and_scenarios(self):
        async def t(request):
            return answer()

        p = make(t)
        server = await asyncio.start_server(lambda r, w: P.handle_http(p, r, w), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        await p.start()

        async def call(method, path, token=None):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            auth = f"Authorization: Bearer {token}\r\n" if token else ""
            w.write(f"{method} {path} HTTP/1.1\r\nHost: x\r\n{auth}\r\n".encode())
            await w.drain()
            raw = await r.read()
            w.close()
            head, _, body = raw.partition(b"\r\n\r\n")
            return int(head.split()[1]), body.decode()

        self.assertEqual((await call("GET", "/healthz"))[0], 200)
        self.assertEqual((await call("GET", "/metrics"))[0], 401)
        self.assertEqual((await call("GET", "/metrics", "wrong"))[0], 401)
        code, text = await call("GET", "/metrics", "m" * 16)
        self.assertEqual(code, 200)
        self.assertIn("auth_audit_pilot_enabled 1", text)
        self.assertEqual((await call("POST", "/pilot/synthetic?scenario=authn_failure", "m" * 16))[0], 401)
        self.assertEqual((await call("POST", "/pilot/synthetic?scenario=nope", "a" * 16))[0], 400)
        code, text = await call("POST", "/pilot/synthetic?scenario=authz_denial&sync=1", "a" * 16)
        self.assertEqual((code, json.loads(text)["decision"], json.loads(text)["alerted"]), (200, "deny", True))
        self.assertEqual((await call("POST", "/pilot/kill", "a" * 16))[0], 200)
        self.assertEqual(json.loads((await call("GET", "/readyz"))[1])["audit"], "killed")
        self.assertEqual(p.auth_failures, 3)
        server.close()
        await p.stop()

    async def test_repeated_resume_keeps_enabled_gauge_and_plugin(self):
        async def t(request):
            return answer()

        p = make(t)
        server = await asyncio.start_server(lambda r, w: P.handle_http(p, r, w), "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        await p.start()
        plugin = p.plugin

        async def post(path):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(f"POST {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {'a' * 16}\r\n\r\n".encode())
            await w.drain()
            raw = await r.read()
            w.close()
            return json.loads(raw.partition(b"\r\n\r\n")[2])

        for _ in range(3):
            self.assertEqual(await post("/pilot/resume"), {"audit": "enabled"})
            self.assertEqual(p.state, "enabled")
            self.assertIs(p.plugin, plugin)
            self.assertEqual(len(p.bus.plugins), 1)
            self.assertIn("auth_audit_pilot_enabled 1", p.metrics_text())
        await p.synthetic("authn_failure", sync=True)
        self.assertEqual(p.live_calls, 1)
        # kill then resume still works and the gauge follows the real state
        await post("/pilot/kill")
        self.assertIn("auth_audit_pilot_enabled 0", p.metrics_text())
        self.assertEqual(await post("/pilot/resume"), {"audit": "enabled"})
        self.assertIn("auth_audit_pilot_enabled 1", p.metrics_text())
        server.close()
        await p.stop()


if __name__ == "__main__":
    unittest.main()
