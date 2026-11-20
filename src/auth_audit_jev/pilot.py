"""Contained, loopback-only shadow pilot service (synthetic events only).

What it is: a tiny process that owns an in-process OAuth2-style `EventBus`
(the real `oauth2_server.services.events_bus.EventBus` when importable), a
deterministic *synthetic* access-decision stub, and the opt-in audit adapter.
`POST /pilot/synthetic` makes a decision, returns it, and only then publishes an
event on the bus (fire-and-forget). The audit result can never feed back.

What it is not: an OAuth server, a security control, or a path for real data.
Only synthetic scenarios exist; there is no endpoint that accepts an event body.

Controls: loopback bind; bearer `metrics` token for `/metrics`; separate bearer
`admin` token for control endpoints; kill switch by endpoint, by KILL file, or by
stopping the unit; hard cap on live Jev calls; key read from a 0600 file.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import signal
import time
from collections import Counter, deque
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from . import AuditPlugin, URL, build_request  # noqa: F401  (build_request re-exported for tests)
from .eventbus_adapter import AuditEventBridge, install_audit_plugin, remove_audit_plugin
from .http import bounded_transport, post_json

log = logging.getLogger("auth_audit_jev.pilot")

BUCKETS = (.05, .1, .25, .5, 1, 2, 3, 5, 10)
CANARIES = ("CANARY_USER_7f3a", "CANARY_CLIENT_7f3a", "CANARY_IP_7f3a",
            "CANARY_TOKEN_7f3a", "CANARY_ERROR_7f3a", "CANARY_TRACE_7f3a")

# scenario -> (event_type, severity, synthetic decision). The decision is a pure
# function of the scenario and is computed BEFORE the event is published.
SCENARIOS = {
    "authn_failure": ("user_authentication_failed", "warning", "deny"),
    "authz_denial": ("authorization_denied", "warning", "deny"),
    "authn_success": ("user_authenticated", "info", "allow"),
    "authz_allow": ("authorization_allowed", "info", "allow"),
}


def percentile(sorted_values, q):
    """Nearest-rank percentile of an already sorted list; None if empty."""
    if not sorted_values:
        return None
    rank = max(1, -(-len(sorted_values) * q // 100))
    return sorted_values[int(rank) - 1]


def summarize(values):
    ordered = sorted(values)
    return {"n": len(ordered), "p50": percentile(ordered, 50), "p95": percentile(ordered, 95),
            "p99": percentile(ordered, 99), "max": ordered[-1] if ordered else None}


class Histogram:
    def __init__(self, name):
        self.name, self.counts, self.sum, self.n = name, Counter(), 0.0, 0

    def observe(self, seconds):
        self.n += 1
        self.sum += seconds
        for bound in BUCKETS:
            if seconds <= bound:
                self.counts[bound] += 1

    def lines(self):
        out = [f"# TYPE {self.name} histogram"]
        out += [f'{self.name}_bucket{{le="{b}"}} {self.counts[b]}' for b in BUCKETS]
        out += [f'{self.name}_bucket{{le="+Inf"}} {self.n}', f"{self.name}_sum {self.sum}",
                f"{self.name}_count {self.n}"]
        return out


def _default_bus():
    try:
        from oauth2_server.services.events_bus import EventBus
    except ImportError as exc:  # pragma: no cover - exercised only without the producer
        raise SystemExit("producer package oauth2_server not importable; set PYTHONPATH") from exc
    return EventBus([])


def _publish(bus, event_type, severity):
    """Publish via the producer's own helper, with canary identifiers attached.

    The canaries sit in every field a careless exporter might forward. The leak
    test proves none of them reach the provider request, metrics, state or logs.
    """
    from oauth2_server.services.events_bus import emit_event
    emit_event(bus, event_type, severity=severity, user_id=CANARIES[0], client_id=CANARIES[1],
               metadata={"ip": CANARIES[2], "token": CANARIES[3], "traceparent": CANARIES[5]},
               error=CANARIES[4])


class Pilot:
    def __init__(self, *, key=None, transport=None, bus=None, publish=None, kill_file=None,
                 alert_file=None, max_live_calls=200, queue_size=16, timeout=3.0, queue_ttl=5.0,
                 metrics_token=None, admin_token=None):
        self.bus = bus if bus is not None else _default_bus()
        self._publish = publish or _publish
        self.kill_file = Path(kill_file) if kill_file else None
        self.alert_file = Path(alert_file) if alert_file else None
        self.max_live_calls = max_live_calls
        self.metrics_token, self.admin_token = metrics_token, admin_token
        self.key, self._fake_transport = key, transport
        self.plugin_args = dict(queue_size=queue_size, timeout=timeout, queue_ttl=queue_ttl)
        self.live_calls = 0
        self.canary_leaks = 0
        self.jev_seconds = deque(maxlen=5000)
        self.alert_times = []          # monotonic times of alert callbacks
        self.alerts = deque(maxlen=50)
        self.decisions = Counter()
        self.injected = Counter()
        self.auth_failures = 0
        self.h_alert, self.h_result = Histogram("auth_audit_pilot_event_to_alert_seconds"), Histogram("auth_audit_pilot_event_to_result_seconds")
        self.e2a, self.e2r = deque(maxlen=5000), deque(maxlen=5000)
        self.h_call = Histogram("auth_audit_pilot_jev_call_seconds")
        self.state = "stopped"          # stopped | enabled | killed | no_key
        self.bridge = self.plugin = self._close_transport = None
        self.started_at = None

    # -- audit lifecycle ---------------------------------------------------
    def _killed_by_file(self):
        return bool(self.kill_file and self.kill_file.exists())

    async def _transport(self, request):
        # Hard budget and leak canary check wrap the provider call; neither logs content.
        if self.live_calls >= self.max_live_calls:
            raise RuntimeError("call budget exhausted")
        self.live_calls += 1
        if any(c in json.dumps(request) for c in CANARIES):
            self.canary_leaks += 1
            raise RuntimeError("canary leak blocked")
        began = time.monotonic()
        try:
            return await self._inner(request)
        finally:
            elapsed = time.monotonic() - began
            self.jev_seconds.append(elapsed)
            self.h_call.observe(elapsed)

    def _alert(self, fixed_fields):
        self.alert_times.append(time.monotonic())
        self.alerts.append(dict(fixed_fields, at=time.time()))
        if self.alert_file:
            with self.alert_file.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(self.alerts[-1], sort_keys=True) + "\n")

    async def enable(self):
        """Install the audit consumer and start its worker. Idempotent."""
        if self.plugin is not None:
            return self.state
        if self._killed_by_file():
            self.state = "killed"
            return self.state
        if self._fake_transport is not None:
            self._inner = self._fake_transport
        elif self.key:
            post = lambda request, timeout, max_bytes: post_json(URL, request, self.key, timeout, max_bytes)  # noqa: E731
            self._inner, self._close_transport = bounded_transport(post, self.plugin_args["timeout"], 16384, "pilot-jev")
        else:
            self.state = "no_key"
            return self.state
        self.plugin = AuditPlugin(transport=self._transport, alert=self._alert, enabled=True, **self.plugin_args)
        self.bridge = AuditEventBridge(self.plugin)
        await self.bridge.start()
        install_audit_plugin(self.bus, self.bridge)
        self.state = "enabled"
        log.info("audit plugin started")
        return self.state

    async def disable(self, state="killed"):
        """Kill switch: detach from the bus first, then drop queued work and stop the worker."""
        if self.bridge is not None:
            remove_audit_plugin(self.bus, self.bridge)
            await self.bridge.close()
            if self._close_transport:
                self._close_transport()
            self.bridge = self.plugin = self._close_transport = None
            log.info("audit plugin stopped")
        self.state = state

    async def start(self):
        self.started_at = time.time()
        await self.enable()

    async def stop(self):
        await self.disable("stopped")

    # -- synthetic traffic ---------------------------------------------------
    async def synthetic(self, scenario, sync=False):
        if self._killed_by_file() and self.plugin is not None:
            await self.disable("killed")
        event_type, severity, decision = SCENARIOS[scenario]
        self.decisions[(scenario, decision)] += 1      # decision first; the audit has no input into it
        self.injected[scenario] += 1
        t0 = time.monotonic()
        alerts_before = len(self.alert_times)
        self._publish(self.bus, event_type, severity)
        result = {"scenario": scenario, "decision": decision}
        if sync and self.plugin is not None:
            await asyncio.sleep(0)                     # let the bus fan-out task enqueue
            await self.plugin.join()
            done = time.monotonic()
            self.h_result.observe(done - t0)
            self.e2r.append(done - t0)
            if len(self.alert_times) > alerts_before:
                self.h_alert.observe(self.alert_times[-1] - t0)
                self.e2a.append(self.alert_times[-1] - t0)
                result["alerted"] = True
            result["event_to_result_seconds"] = round(done - t0, 6)
        return result

    # -- observability -------------------------------------------------------
    def metrics_text(self):
        lines = []
        if self.plugin is not None:
            lines.append(self.plugin.metrics.prometheus().rstrip("\n"))
        lines += ["# TYPE auth_audit_pilot_enabled gauge", f"auth_audit_pilot_enabled {int(self.state == 'enabled')}",
                  "# TYPE auth_audit_pilot_fake_transport gauge", f"auth_audit_pilot_fake_transport {int(self._fake_transport is not None)}",
                  "# TYPE auth_audit_pilot_killed gauge", f"auth_audit_pilot_killed {int(self.state == 'killed')}",
                  "# TYPE auth_audit_pilot_live_calls_total counter", f"auth_audit_pilot_live_calls_total {self.live_calls}",
                  "# TYPE auth_audit_pilot_call_budget gauge", f"auth_audit_pilot_call_budget {self.max_live_calls}",
                  "# TYPE auth_audit_pilot_canary_leaks_total counter", f"auth_audit_pilot_canary_leaks_total {self.canary_leaks}",
                  "# TYPE auth_audit_pilot_auth_failures_total counter", f"auth_audit_pilot_auth_failures_total {self.auth_failures}",
                  "# TYPE auth_audit_pilot_decisions_total counter"]
        for scenario, (_, _, decision) in SCENARIOS.items():
            lines.append(f'auth_audit_pilot_decisions_total{{scenario="{scenario}",decision="{decision}"}} {self.decisions[(scenario, decision)]}')
        for hist in (self.h_call, self.h_alert, self.h_result):
            lines += hist.lines()
        return "\n".join(lines) + "\n"

    def state_json(self):
        snap = self.plugin.metrics.snapshot() if self.plugin is not None else {}
        return {"state": self.state, "live_calls": self.live_calls, "call_budget": self.max_live_calls,
                "canary_leaks": self.canary_leaks, "results": snap.get("results", {}),
                "jev_call_seconds": summarize(self.jev_seconds), "event_to_alert_seconds": summarize(self.e2a),
                "event_to_result_seconds": summarize(self.e2r), "plugins_on_bus": [getattr(p, "name", "?") for p in self.bus.plugins],
                "samples": {"jev_call": list(self.jev_seconds), "event_to_alert": list(self.e2a), "event_to_result": list(self.e2r)}}


async def handle_http(pilot, reader, writer):
    code, body, ctype = 404, b'{"error":"not_found"}', "application/json"
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
        if len(head) > 8192:
            raise ValueError("head too large")
        lines = head.decode("latin-1").split("\r\n")
        method, target, _ = lines[0].split(" ", 2)
        headers = {k.strip().lower(): v.strip() for k, v in (l.split(":", 1) for l in lines[1:] if ":" in l)}
        url = urlsplit(target)
        query = {k: v[0] for k, v in parse_qs(url.query).items()}
        bearer = headers.get("authorization", "")[7:] if headers.get("authorization", "").lower().startswith("bearer ") else ""

        def ok(expected):
            return bool(expected) and secrets.compare_digest(bearer.encode(), expected.encode())

        def j(obj, status=200):
            return status, json.dumps(obj).encode(), "application/json"

        if method == "GET" and url.path == "/healthz":
            code, body, ctype = j({"ok": True})
        elif method == "GET" and url.path == "/readyz":
            code, body, ctype = j({"ready": True, "audit": pilot.state})
        elif url.path == "/metrics" and method == "GET":
            if ok(pilot.metrics_token) or ok(pilot.admin_token):
                code, body, ctype = 200, pilot.metrics_text().encode(), "text/plain; version=0.0.4"
            else:
                pilot.auth_failures += 1
                code, body, ctype = j({"error": "unauthorized"}, 401)
        elif url.path.startswith("/pilot/"):
            if not ok(pilot.admin_token):
                pilot.auth_failures += 1
                code, body, ctype = j({"error": "unauthorized"}, 401)
            elif method == "GET" and url.path == "/pilot/state":
                code, body, ctype = j(pilot.state_json())
            elif method == "POST" and url.path == "/pilot/synthetic":
                if query.get("scenario") in SCENARIOS:
                    code, body, ctype = j(await pilot.synthetic(query["scenario"], query.get("sync") == "1"))
                else:
                    code, body, ctype = j({"error": "unknown_scenario", "allowed": sorted(SCENARIOS)}, 400)
            elif method == "POST" and url.path == "/pilot/kill":
                await pilot.disable("killed")
                code, body, ctype = j({"audit": pilot.state})
            elif method == "POST" and url.path == "/pilot/resume":
                code, body, ctype = j({"audit": await pilot.enable()})
        writer.write((f"HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
                      "Connection: close\r\n\r\n").encode("ascii") + body)
        await writer.drain()
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, TimeoutError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()
        await writer.wait_closed()


def _read(path):
    return Path(path).read_text(encoding="utf-8").strip() if path and Path(path).exists() else None


async def serve(pilot, host="127.0.0.1", port=4021, ready=None):
    server = await asyncio.start_server(lambda r, w: handle_http(pilot, r, w), host, port)
    await pilot.start()
    if ready is not None:
        ready.set()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # pragma: no cover
            pass

    async def watch_kill_file():
        while True:
            await asyncio.sleep(1)
            if pilot._killed_by_file() and pilot.plugin is not None:
                await pilot.disable("killed")
    watcher = asyncio.create_task(watch_kill_file())
    try:
        await stop.wait()
    finally:
        watcher.cancel()
        server.close()
        await pilot.stop()
        await server.wait_closed()


def main():  # pragma: no cover - thin env wiring, exercised by the live deployment
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
    cfg = Path(os.environ.get("AUDIT_PILOT_CONFIG_DIR", Path.home() / ".config/auth-audit-jev"))
    state = Path(os.environ.get("AUDIT_PILOT_STATE_DIR", Path.home() / ".local/state/auth-audit-jev"))
    state.mkdir(parents=True, exist_ok=True)
    fake = None
    if os.environ.get("AUDIT_PILOT_FAKE_JEV") == "suspicious":
        # Alert-path exercise only: a loopback stand-in for Jev, never used by the deployed unit.
        async def fake_jev(request):
            await asyncio.sleep(.1)
            return {"model": "jev-latest", "usage": {"input_tokens": 0, "output_tokens": 0},
                    "answers": {"assessment": {"type": "choice", "choice": "suspicious", "confidence": .95,
                                               "probabilities": {"suspicious": .95, "routine": .025, "other": .025}}}}
        fake = fake_jev
    pilot = Pilot(key=_read(cfg / "typesafe.key"), transport=fake, kill_file=cfg / "KILL", alert_file=state / "alerts.jsonl",
                  metrics_token=_read(cfg / "metrics.token"), admin_token=_read(cfg / "admin.token"),
                  max_live_calls=int(os.environ.get("AUDIT_PILOT_MAX_LIVE_CALLS", "200")))
    asyncio.run(serve(pilot, "127.0.0.1", int(os.environ.get("AUDIT_PILOT_PORT", "4021"))))


if __name__ == "__main__":  # pragma: no cover
    main()
