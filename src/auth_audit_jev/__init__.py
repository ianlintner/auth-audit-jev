"""Shadow-only auth audit: safe projection, bounded asynchronous Jev assessment."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from collections import Counter
import json
import math
import os
import re
import threading
import time
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler, HTTPRedirectHandler

MODEL = "jev-latest"
URL = "https://api.typesafe.ai/v1/systemone"
EVENTS = frozenset({
    "authorization_code_created", "authorization_code_validated", "authorization_code_expired",
    "token_created", "token_validated", "token_revoked", "token_expired",
    "client_registered", "client_validated", "client_deleted",
    "user_authenticated", "user_authentication_failed", "user_logout",
    "authentication_failed", "authentication_succeeded", "authorization_denied",
    "authorization_allowed", "permission_denied", "access_denied",
})
SEVERITIES = frozenset({"info", "warning", "error"})
FAILURES = frozenset({"user_authentication_failed", "authentication_failed",
                      "authorization_denied", "permission_denied", "access_denied"})
SUCCESSES = frozenset({"user_authenticated", "authentication_succeeded",
                       "authorization_allowed", "authorization_code_validated",
                       "token_validated", "client_validated"})
QUESTIONS = {"assessment": {"type": "choice",
    "instructions": "Assess suspicious authentication/authorization outcome from the limited state only. Never infer identity. Choose other if evidence is insufficient.",
    "criteria": {"suspicious": "Potentially suspicious authn/authz outcome needing human review.",
                 "routine": "Routine authn/authz outcome with no indicated concern.",
                 "other": "Insufficient evidence or neither category applies."}}}


def _field(obj, key):
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def project_event(envelope):
    """Allowlist only known enum fields; never copy arbitrary envelope data."""
    event = _field(envelope, "event")
    kind = _field(event, "event_type")
    severity = _field(event, "severity")
    if type(kind) is not str or kind not in EVENTS or type(severity) is not str or severity not in SEVERITIES:
        return None
    outcome = "failure" if kind in FAILURES else ("success" if kind in SUCCESSES else "observed")
    return {"event_kind": kind, "severity": severity, "outcome": outcome}


def build_request(state):
    return {"model": MODEL, "state": state, "questions": QUESTIONS}


def validate_answer(payload, min_confidence=.8):
    """Return an allowed category or abstain on any ambiguous provider data."""
    try:
        model = payload.get("model") if isinstance(payload, dict) else None
        if not isinstance(model, str) or not re.fullmatch(r"jev-(?:latest|[0-9]+(?:\.[0-9]+)*(?:-[0-9]{8})?)", model):
            return None
        usage = payload.get("usage")
        if not isinstance(usage, dict) or any(type(usage.get(k)) not in (int, float) or
            not math.isfinite(usage[k]) or usage[k] < 0 for k in
            ("input_tokens", "output_tokens", "cost_usd")):
            return None
        answers = payload["answers"]
        if not isinstance(answers, dict) or set(answers) != {"assessment"}:
            return None
        a = answers["assessment"]
        if not isinstance(a, dict) or a.get("type") != "choice":
            return None
        choice, confidence, probabilities = a.get("choice"), a.get("confidence"), a.get("probabilities")
        options = QUESTIONS["assessment"]["criteria"]
        if type(choice) is not str or choice not in options:
            return None
        if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            return None
        if not isinstance(probabilities, dict) or set(probabilities) != set(options):
            return None
        if any(type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1 for p in probabilities.values()):
            return None
        if abs(sum(probabilities.values()) - 1) > .02 or probabilities[choice] < max(probabilities.values()):
            return None
        if confidence < min_confidence or choice == "other":
            return None
        return choice
    except (KeyError, TypeError, ValueError):
        return None


class Metrics:
    """In-process aggregate measurements; no labels from input or provider."""
    def __init__(self):
        self.results = Counter()
        self.queue_depth = 0
        self.inflight = 0
        self.provider_calls = 0
        self.provider_latency_sum_seconds = 0.0
        self.provider_latency_max_seconds = 0.0
        self.latency_buckets = Counter()
        self.input_tokens = 0
        self.output_tokens = 0
        self.cost_usd = 0.0
        self.last_success_timestamp_seconds = 0.0

    def observe(self, seconds):
        self.provider_calls += 1
        self.provider_latency_sum_seconds += seconds
        self.provider_latency_max_seconds = max(self.provider_latency_max_seconds, seconds)
        for bound in (.01, .025, .05, .1, .25, .5, 1, 2, 5):
            if seconds <= bound:
                self.latency_buckets[bound] += 1

    def prometheus(self):
        """Prometheus text exposition; serve behind your protected metrics endpoint."""
        lines = ["# TYPE auth_audit_events_total counter"]
        for outcome in ("disabled", "skipped", "queue_full", "expired", "abstain",
                        "recommendation", "alerted", "alert_error", "routine", "timeout", "error", "shutdown_drop"):
            lines.append(f'auth_audit_events_total{{outcome="{outcome}"}} {self.results[outcome]}')
        for name, value in (("queue_depth", self.queue_depth), ("inflight", self.inflight),
                            ("input_tokens_total", self.input_tokens),
                            ("output_tokens_total", self.output_tokens),
                            ("cost_usd_total", self.cost_usd),
                            ("last_success_timestamp_seconds", self.last_success_timestamp_seconds)):
            lines.extend((f"# TYPE auth_audit_{name} {'counter' if name.endswith('_total') else 'gauge'}",
                          f"auth_audit_{name} {value}"))
        lines.append("# TYPE auth_audit_provider_duration_seconds histogram")
        for bound in (.01, .025, .05, .1, .25, .5, 1, 2, 5):
            lines.append(f'auth_audit_provider_duration_seconds_bucket{{le="{bound}"}} {self.latency_buckets[bound]}')
        lines += [f'auth_audit_provider_duration_seconds_bucket{{le="+Inf"}} {self.provider_calls}',
                  f"auth_audit_provider_duration_seconds_sum {self.provider_latency_sum_seconds}",
                  f"auth_audit_provider_duration_seconds_count {self.provider_calls}"]
        return "\n".join(lines) + "\n"

    def snapshot(self):
        return {"results": dict(self.results), "queue_depth": self.queue_depth,
                "inflight": self.inflight, "provider_calls": self.provider_calls,
                "provider_latency_sum_seconds": self.provider_latency_sum_seconds,
                "provider_latency_max_seconds": self.provider_latency_max_seconds,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cost_usd": self.cost_usd}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _post_jev(request, api_key, timeout, max_bytes):
    payload = json.dumps(request, separators=(",", ":")).encode("utf-8")
    req = Request(URL, payload, headers={"Authorization": "Bearer " + api_key,
                                          "Content-Type": "application/json", "Accept-Encoding": "identity"}, method="POST")
    opener = build_opener(ProxyHandler({}), HTTPSHandler(), _NoRedirect())
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("oversized response")
    def reject_constant(_):
        raise ValueError("nonfinite response")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate response key")
            result[key] = value
        return result
    return json.loads(raw, parse_constant=reject_constant, object_pairs_hook=unique)


class AuditPlugin:
    """EventPlugin-compatible, at-most-once and advisory. start/close on app lifecycle."""
    name = "auth_audit_jev"

    def __init__(self, *, transport=None, alert=None, enabled=True, api_key=None,
                 queue_size=64, timeout=1.0, queue_ttl=2.0, min_confidence=.8,
                 max_response_bytes=16384, metrics=None):
        if queue_size < 1 or timeout <= 0 or queue_ttl <= 0 or max_response_bytes < 1 or not 0 <= min_confidence <= 1:
            raise ValueError("invalid audit limits")
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.metrics = metrics or Metrics()
        self.alert = alert
        self.enabled = enabled
        self.api_key = api_key
        self.transport = transport
        self.timeout = timeout
        self.queue_ttl = queue_ttl
        self.min_confidence = min_confidence
        self.max_response_bytes = max_response_bytes
        self._worker = None
        self._executor = None
        self._stopping = False

    async def start(self):
        if self._worker is not None:
            return
        self._stopping = False
        if self.enabled and (self.transport is not None or self.api_key or os.environ.get("TYPESAFE_API_KEY")):
            if self.transport is None:
                key = self.api_key or os.environ["TYPESAFE_API_KEY"]
                self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="auth-audit-jev")
                executor = self._executor
                slot = threading.BoundedSemaphore(1)
                def bounded_post(request):
                    try:
                        return _post_jev(request, key, self.timeout, self.max_response_bytes)
                    finally:
                        slot.release()
                async def http_transport(request):
                    # A cancelled wait_for cannot kill a socket thread. Do not enqueue
                    # more work into ThreadPoolExecutor's unbounded internal queue.
                    if not slot.acquire(blocking=False):
                        raise RuntimeError("transport busy")
                    loop = asyncio.get_running_loop()
                    try:
                        future = loop.run_in_executor(executor, bounded_post, request)
                    except RuntimeError:
                        slot.release()
                        raise
                    return await future
                self.transport = http_transport
            self._worker = asyncio.create_task(self._run())

    async def health_check(self):
        return self._worker is not None and not self._worker.done() and not self._stopping

    async def emit(self, envelope):
        if self._worker is None or self._worker.done() or self._stopping:
            self.metrics.results["disabled"] += 1
            return
        try:
            state = project_event(envelope)
        except Exception:
            state = None
        if state is None:
            self.metrics.results["skipped"] += 1
            return
        try:
            self.queue.put_nowait((state, time.monotonic()))
            self.metrics.queue_depth = self.queue.qsize()
        except asyncio.QueueFull:
            self.metrics.results["queue_full"] += 1

    async def _run(self):
        while True:
            state, enqueued = await self.queue.get()
            self.metrics.queue_depth = self.queue.qsize()
            try:
                if time.monotonic() - enqueued > self.queue_ttl:
                    self.metrics.results["expired"] += 1
                    continue
                self.metrics.inflight = 1
                began = time.monotonic()
                try:
                    response = await asyncio.wait_for(self.transport(build_request(state)), self.timeout)
                    decision = validate_answer(response, self.min_confidence)
                    if decision is None:
                        self.metrics.results["abstain"] += 1
                    else:
                        usage = response["usage"]
                        self.metrics.input_tokens += usage["input_tokens"]
                        self.metrics.output_tokens += usage["output_tokens"]
                        self.metrics.cost_usd += usage["cost_usd"]
                        self.metrics.last_success_timestamp_seconds = time.time()
                    if decision == "suspicious":
                        self.metrics.results["recommendation"] += 1
                        if self.alert is not None:
                            try:
                                self.alert({"event_kind": state["event_kind"], "outcome": state["outcome"], "assessment": decision})
                            except Exception:
                                self.metrics.results["alert_error"] += 1
                            else:
                                self.metrics.results["alerted"] += 1
                    elif decision == "routine":
                        self.metrics.results["routine"] += 1
                except asyncio.TimeoutError:
                    self.metrics.results["timeout"] += 1
                except Exception:
                    # Do not log exception text, provider payload, headers, or original event.
                    self.metrics.results["error"] += 1
                finally:
                    elapsed = time.monotonic() - began
                    self.metrics.observe(elapsed)
                    self.metrics.inflight = 0
            finally:
                self.queue.task_done()

    async def join(self):
        """Wait for accepted jobs (testing/graceful operational drain only)."""
        await self.queue.join()

    async def close(self):
        self._stopping = True
        if self._worker is not None:
            self._worker.cancel()
            await asyncio.gather(self._worker, return_exceptions=True)
            self._worker = None
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()
            self.metrics.results["shutdown_drop"] += 1
        self.metrics.queue_depth = 0
        self.metrics.inflight = 0
        if self._executor is not None:
            self._executor.shutdown(wait=False, cancel_futures=True)
            self._executor = None
