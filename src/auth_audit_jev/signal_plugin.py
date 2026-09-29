"""Opt-in shadow worker for categorized authn/authz failure assessment.

This is the v1 counterpart to the legacy three-field plugin. It is:

- **shadow only** — the caller never awaits a provider result and nothing here
  can block, deny or alter an access path;
- **opt-in** — `enabled=False` (the default) and no transport means every emit is
  counted `disabled` and no request is built;
- **abstaining** — disabled state, kill switch, open circuit, timeout, payment or
  authentication failure, invalid provider response, missing usage, low
  confidence and the residual `other` category all produce an abstention, never
  a guess;
- **bounded** — fixed worker count, finite queue, short queue TTL, short request
  timeout, response-size cap, cache TTL, kill switch and circuit breaker. There
  is no automatic retry anywhere, because no idempotency model has been
  demonstrated for this provider.

Scope is deliberately narrower than the legacy plugin: only `outcome` `failure`
signals are assessed. A successful authentication is not evidence about a
failure's cause, so sending it would widen the privacy boundary for nothing.

The alert sink receives a fixed-shape advisory record built in
`classify.hypothesis`. Coarse enums that were already validated may appear;
identifiers, error text, headers, tokens and trace context never do, because
they are never read.
"""
from __future__ import annotations

import asyncio
from collections import OrderedDict
import os
import time

from .classify import (
    CATEGORY_REVIEW_THRESHOLD,
    baseline_comparison,
    build_request as build_signal_request,
    conflicts_with_local_candidates,
    deterministic_candidates,
    hypothesis,
    validate_response,
)
from . import http
from .dedup import DEDUP_COUNTERS, DECISION_EVALUATE, DedupLayer
from .http import bounded_transport
from .metrics import Metrics
from .signal import SIGNAL_KEY, project_signal, signal_from_legacy_event

PROVIDER_URL = "https://api.typesafe.ai/v1/systemone"

# The only reasons this layer ever records for not producing a category. Fixed
# enum: no provider text, exception message or input value can enter metrics.
ABSTENTION_REASONS = frozenset({
    "disabled", "kill_switch", "circuit_open", "invalid_signal", "queue_full",
    "expired", "timeout", "provider_error", "auth_error", "payment_error",
    "invalid_response", "low_confidence", "residual_category", "not_a_failure",
})


def _positive(**limits):
    if any(value <= 0 for value in limits.values()):
        raise ValueError("invalid audit limits")


def _field(obj, key):
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _attached(envelope):
    """True when the producer attached an `authn_signal` at all.

    A hostile envelope that raises on attribute access counts as attached, so it
    is rejected by the contract instead of falling back to projection.
    """
    try:
        if isinstance(envelope, dict):
            return SIGNAL_KEY in envelope
        return hasattr(envelope, SIGNAL_KEY)
    except Exception:
        return True


class SignalAuditPlugin:
    """EventPlugin-compatible shadow categorizer for normalized authn signals.

    `name` is distinct from the legacy plugin so both can be registered while the
    producer contract is rolled out, and so a reviewer can tell which alerts came
    from which boundary.
    """

    name = "auth_audit_jev_signal"

    def __init__(self, *, transport=None, alert=None, enabled=False, api_key=None,
                 review_threshold=None, queue_size=32, timeout=1.5, queue_ttl=2.0,
                 max_response_bytes=16384, cache_ttl=30.0, cache_size=64,
                 circuit_failure_threshold=5, circuit_cooldown=30.0,
                 worker_count=1, metrics=None, legacy_projector=signal_from_legacy_event,
                 dedup=None, tenant=None):
        _positive(queue_size=queue_size, timeout=timeout, queue_ttl=queue_ttl,
                  max_response_bytes=max_response_bytes, cache_size=cache_size,
                  circuit_failure_threshold=circuit_failure_threshold)
        if cache_ttl < 0 or circuit_cooldown < 0 or worker_count < 1:
            raise ValueError("invalid audit limits")
        if review_threshold is not None and not 0 <= review_threshold <= 1:
            raise ValueError("invalid audit limits")
        self.queue = asyncio.Queue(maxsize=queue_size)
        self.metrics = metrics or Metrics()
        self.alert = alert
        self.enabled = enabled
        self.api_key = api_key
        self.transport = transport
        self.review_threshold = review_threshold
        self.timeout = timeout
        self.queue_ttl = queue_ttl
        self.max_response_bytes = max_response_bytes
        self.cache_ttl = cache_ttl
        self.cache_size = cache_size
        self.circuit_failure_threshold = circuit_failure_threshold
        self.circuit_cooldown = circuit_cooldown
        self.worker_count = worker_count
        self.legacy_projector = legacy_projector
        self.dedup = dedup if dedup is not None else DedupLayer()
        self.tenant = tenant
        # Bounded TTL cache keyed by the normalized signal only — never by an
        # identifier — and cleared on close so no verdict survives a schema or
        # model change.
        self._cache: OrderedDict = OrderedDict()
        self._workers: list[asyncio.Task] = []
        self._close_transport = None
        self._stopping = False
        self._kill_switch = False
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    # -- lifecycle ------------------------------------------------------------
    async def start(self):
        if self._workers:
            return
        self._stopping = False
        if not self.enabled or self._kill_switch:
            self.metrics.results["disabled"] += 1
            return
        if self.transport is None:
            key = self.api_key or os.environ.get("TYPESAFE_API_KEY")
            if not key:
                self.metrics.results["disabled"] += 1
                return
            self.transport, self._close_transport = bounded_transport(
                lambda request, timeout, max_bytes: http.post_json(
                    PROVIDER_URL, request, key, timeout, max_bytes),
                self.timeout, self.max_response_bytes, "auth-audit-signal")
        self._workers = [asyncio.create_task(self._run()) for _ in range(self.worker_count)]

    async def health_check(self):
        return bool(self._workers) and all(not w.done() for w in self._workers) and not self._stopping

    async def close(self):
        self._stopping = True
        for worker in self._workers:
            worker.cancel()
        if self._workers:
            await asyncio.gather(*self._workers, return_exceptions=True)
        self._workers = []
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()
            self.metrics.results["shutdown_drop"] += 1
        self.metrics.queue_depth = 0
        self.metrics.inflight = 0
        self.clear_cache()
        if self._close_transport is not None:
            self._close_transport()
            self._close_transport = None

    async def join(self):
        """Drain accepted jobs; for tests and graceful administration only."""
        await self.queue.join()

    # -- controls ------------------------------------------------------------
    def engage_kill_switch(self):
        """Immediately stop contacting the provider; pending jobs are dropped."""
        self._kill_switch = True
        self.metrics.results["kill_switch"] += 1
        self._drop_pending()
        # Release any open circuit: with cloud off there is nothing to protect.
        self._consecutive_failures = 0
        self._circuit_open_until = 0.0

    def release_kill_switch(self):
        self._kill_switch = False

    def circuit_state(self, now=None):
        now = time.monotonic() if now is None else now
        if self._consecutive_failures < self.circuit_failure_threshold:
            return "closed"
        return "open" if now < self._circuit_open_until else "half_open"

    def clear_cache(self):
        self._cache.clear()

    def _drop_pending(self):
        while not self.queue.empty():
            self.queue.get_nowait()
            self.queue.task_done()
            self.metrics.results["shutdown_drop"] += 1
        self.metrics.queue_depth = 0

    # -- ingest --------------------------------------------------------------
    @staticmethod
    def _scope(envelope):
        """Producer-owned, opt-in dedup scope: only ``principal``/``client``/
        ``session`` string keys, read solely to key the in-process fingerprint.

        The scope never leaves this process, is never logged and never sent to
        the provider. A hostile or malformed envelope yields ``None`` (which is
        indistinguishable from "no scope provided"), so nothing here can force a
        merge of unrelated failures.
        """
        try:
            raw = _field(envelope, "dedup_scope")
        except Exception:
            return None
        if not isinstance(raw, dict):
            return None
        scope = {}
        for key in ("principal", "client", "session"):
            value = raw.get(key)
            if value is None:
                continue
            if not isinstance(value, str):
                return None
            scope[key] = value
        return scope or None

    async def emit(self, envelope):
        """Never blocks the caller and never awaits a provider result."""
        if not self.enabled:
            self.metrics.results["disabled"] += 1
            return
        if self._kill_switch:
            self.metrics.results["kill_switch"] += 1
            return
        if not self._workers or self._stopping:
            self.metrics.results["disabled"] += 1
            return
        try:
            signal = project_signal(envelope)
            if signal is None and not _attached(envelope) and self.legacy_projector is not None:
                # Fall back to the coarsest derivable signal so the boundary can
                # be evaluated against existing producers before they emit
                # `authn_signal` themselves. That path leaves the reason at
                # `other`, so it cannot fabricate a category — and it is only
                # taken when the producer attached no signal at all. An attached
                # but invalid `authn_signal` is a producer contract violation and
                # must be rejected outright, never silently downgraded to the
                # legacy projection.
                signal = self.legacy_projector(envelope)
            scope = self._scope(envelope)
        except Exception:
            signal = None
            scope = None
        if signal is None:
            self.metrics.results["skipped"] += 1
            return
        if signal["outcome"] != "failure":
            # Successes and neutral events carry no evidence about a failure's
            # cause; do not widen the boundary to assess them.
            self.metrics.results["skipped"] += 1
            return
        try:
            self.queue.put_nowait((signal, scope, time.monotonic()))
            self.metrics.queue_depth = self.queue.qsize()
        except asyncio.QueueFull:
            self.metrics.results["queue_full"] += 1

    # -- worker --------------------------------------------------------------
    async def _run(self):
        while True:
            signal, scope, enqueued = await self.queue.get()
            self.metrics.queue_depth = self.queue.qsize()
            try:
                if time.monotonic() - enqueued > self.queue_ttl:
                    self.metrics.results["expired"] += 1
                    continue
                await self._assess(signal, scope)
            except Exception:
                # Never surface exception text, provider payload or signal values.
                self.dedup.forget(signal, tenant=self.tenant, context=scope)
                self.metrics.results["error"] += 1
            finally:
                self.queue.task_done()

    async def _assess(self, signal, scope=None):
        now = time.monotonic()
        if self._kill_switch:
            self.metrics.results["kill_switch"] += 1
            return
        if self.circuit_state(now) == "open":
            self.metrics.circuit["short_circuited"] += 1
            self.metrics.results["circuit_open"] += 1
            return
        if self._should_suppress(signal, scope, now):
            return
        # A signal-only verdict cache can merge different principals. Preserve
        # the legacy cache only when tenant-scoped dedup is not configured;
        # dedup itself handles exact repeats safely in the opt-in mode.
        use_verdict_cache = self.tenant is None
        key = self._cache_key(signal) if use_verdict_cache else None
        cached = self._cache_get(key, now) if use_verdict_cache else None
        if cached is not None:
            self.metrics.provider_avoided += 1
            self._handle_verdict(signal, cached)
            return
        candidates = deterministic_candidates(signal)
        for _, kind in sorted(candidates, key=lambda item: item[1]):
            self.metrics.local_candidate_kinds[kind] += 1
        request = build_signal_request(signal)
        self.metrics.inflight = min(self.metrics.inflight + 1, self.worker_count)
        began = time.monotonic()
        try:
            response = await asyncio.wait_for(self.transport(request), self.timeout)
            if not isinstance(response, dict):
                raise ValueError("invalid provider response")
            verdict = validate_response(response, self.review_threshold)
            if verdict is None:
                self.metrics.results["abstain"] += 1
                self._record_provider_failure(signal, scope)
                return
            usage = response["usage"]
            self.metrics.input_tokens += usage["input_tokens"]
            self.metrics.output_tokens += usage["output_tokens"]
            self.metrics.cost_usd += usage["cost_usd"]
            self.metrics.last_success_timestamp_seconds = time.time()
            self._consecutive_failures = 0
            self.metrics.circuit["closed"] += 1
            if use_verdict_cache:
                self._cache_put(key, verdict, time.monotonic())
            self._handle_verdict(signal, verdict, candidates)
        except asyncio.TimeoutError:
            self.metrics.results["timeout"] += 1
            self._record_provider_failure(signal, scope)
        except Exception:
            self.metrics.results["error"] += 1
            self._record_provider_failure(signal, scope)
        finally:
            self.metrics.observe(time.monotonic() - began)
            self.metrics.inflight = max(self.metrics.inflight - 1, 0)

    def _should_suppress(self, signal, scope, now):
        """Ask the dedup layer; suppress the provider call only on exact repeats.

        The dedup decision is local-only and shadow-safe: a ``suppress`` skips
        the provider for this exact repeat, while every subtle difference — a new
        scope, a changed reason/flow, a crossed threshold — yields ``evaluate``
        and proceeds to the provider unchanged. When no tenant is configured the
        layer abstains (evaluates, counting ``abstain_from_dedup``) rather than
        merging across tenants.
        """
        # Always ask, even with no tenant, so the abstention is observed and
        # counted rather than silently bypassing the metric surface.
        decision = self.dedup.decide(signal, tenant=self.tenant, context=scope, now=now)
        # Mirror the dedup layer's fixed-label counters into the shared metric
        # surface so one scrape endpoint reports them. Labels are the closed
        # DEDUP_COUNTERS enum, never a fingerprint or input value.
        for label in DEDUP_COUNTERS:
            self.metrics.dedup[label] = self.dedup.counters()[label]
        return decision != DECISION_EVALUATE

    def _record_provider_failure(self, signal, scope):
        """Forget unassessed repeats, count failure and trip the breaker."""
        self.dedup.forget(signal, tenant=self.tenant, context=scope)
        self._consecutive_failures += 1
        if self._consecutive_failures >= self.circuit_failure_threshold:
            self._circuit_open_until = max(self._circuit_open_until,
                                           time.monotonic() + self.circuit_cooldown)
            self.metrics.circuit["opened"] += 1

    def _handle_verdict(self, signal, verdict, candidates=None):
        category, confidence_level, urgency = verdict
        candidates = deterministic_candidates(signal) if candidates is None else candidates
        conflict = conflicts_with_local_candidates(category, candidates)
        self.metrics.categories[category] += 1
        self.metrics.confidence_levels[confidence_level] += 1
        self.metrics.urgency_levels[urgency] += 1
        self.metrics.results["recommendation"] += 1
        if category == "user_error":
            # `routine` belongs to the legacy plugin's assessment vocabulary; a
            # v1 categorized routine failure is a distinct observation and gets
            # its own label so the two layers never collide on one counter.
            self.metrics.results["routine_failure"] += 1
        observed = baseline_comparison(signal, category)
        self.metrics.results["baseline_" + observed] += 1
        if conflict:
            self.metrics.results["candidate_conflict"] += 1
            self.metrics.local_candidate_kinds["conflict_with_provider"] += 1
        if self.alert is None:
            return
        advisory = hypothesis(category, candidates)
        advisory["confidence_level"] = confidence_level
        advisory["urgency"] = urgency
        advisory["conflicts_with_local_candidates"] = conflict
        advisory["baseline_agreement"] = observed
        try:
            self.alert(advisory)
        except Exception:
            self.metrics.results["alert_error"] += 1
        else:
            self.metrics.results["alerted"] += 1

    # -- bounded cache -------------------------------------------------------
    @staticmethod
    def _cache_key(signal):
        return tuple(sorted(signal.items(), key=lambda item: item[0]))

    def _cache_get(self, key, now):
        entry = self._cache.get(key)
        if entry is None:
            return None
        verdict, stored = entry
        if self.cache_ttl <= 0 or now - stored > self.cache_ttl:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return verdict

    def _cache_put(self, key, verdict, now):
        self._cache[key] = (verdict, now)
        self._cache.move_to_end(key)
        while len(self._cache) > self.cache_size:
            self._cache.popitem(last=False)
