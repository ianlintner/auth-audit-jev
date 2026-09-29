"""Reproducible offline synthetic evaluation for the shadow auth-audit layer.

This module is the measurement harness the repository was missing. It runs the
**real** dedup -> provider-validation -> metric plumbing against a **deterministic
in-process fake provider** over a fixed, reviewed synthetic corpus, and reports
only the quantities that such an offline run can actually establish:

- baseline provider-call count (no dedup) vs dedup-on call count,
- suppression rate and calls saved,
- false positives / false negatives / abstains / queue drops against the corpus
  labels,
- per-category precision/recall with honest ``None`` for empty support,
- observed worker-side latency of the offline path.

It deliberately does **not** and cannot measure anything about the live service:

- no Jev confidence for a real event,
- no event-to-alert latency (there is no event source, no bus, no wall clock),
- no real provider accuracy, cost or p99,
- no inline request-path effect.

Those are reported as ``MEASURED = False`` / ``not_measured`` with the reason, so
a reader cannot mistake an offline plumbing number for a production claim. The
fake provider carries no network access and no paid API call is made; the run is
byte-for-byte reproducible for a fixed corpus + seed (timings excluded, which are
recorded separately as observed-not-guaranteed).

Grid/seed note: the corpus is fixed and enumerated (not randomly sampled), so the
evaluation is deterministic by construction. A ``seed`` is accepted and recorded
only so that any future randomized scenario generation is pinned; today it does
not change the corpus, and the report says so.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Optional

from .calibration import agreement, per_category_metrics
from .dedup import DedupLayer
from .fixtures import FAKE_USAGE, provider_response
from .signal import SCHEMA_VERSION, normalize_signal

# Bumped whenever the corpus, labels or scoring change, so a stored report can be
# tied to the exact evaluation definition that produced it.
EVALUATION_VERSION = "synthetic-eval/v1"

# Explicit, auditable statement of what an offline run cannot observe. Every key
# here is emitted into the report as not_measured with this reason.
NOT_MEASURED = {
    "live_jev_confidence": "no live provider call is made; the fake provider returns fixed labels",
    "event_to_alert_latency": "no event source, bus, or wall clock is attached in offline mode",
    "live_provider_accuracy": "synthetic fixture labels are not ground truth about real traffic",
    "provider_cost_usd": "offline fake usage is zero; no paid request occurs",
    "inline_request_path_effect": "shadow-only; nothing here touches an authorization decision",
    "production_p99_latency": "worker-side offline durations are a plumbing proxy, not request p99",
    "real_traffic_precision_recall": "corpus is invented and small; not a population estimate",
}


class SyntheticProvider:
    """Deterministic fake Jev transport keyed by an explicit scenario label.

    The response is selected by the scenario's declared ``provider_choice`` (what
    the simulated provider "says"), never by the scenario's ground-truth label,
    so the evaluator can model a provider that is wrong and measure the resulting
    false positives/negatives. No sockets, no keys, no retries: a pure function of
    the request.
    """

    def __init__(self, choices: dict, *, model: str = "jev-latest",
                 confidence: float = .93, urgency: str = "routine_review",
                 usage: Optional[dict] = None):
        self._choices = choices
        self._model = model
        self._confidence = confidence
        self._urgency = urgency
        self._usage = dict(FAKE_USAGE if usage is None else usage)
        self.calls: list = []

    def response_for(self, request) -> dict:
        signal = request["state"]["signal"]
        # Key on the exact normalized signal so two scenarios with the same signal
        # cannot silently share an answer; the first match wins deterministically.
        key = json.dumps(signal, sort_keys=True, separators=(",", ":"))
        choice = self._choices.get(key)
        if choice is None:
            raise AssertionError("scenario missing from provider choices")
        if choice == "abstain":
            # A malformed / low-confidence payload is what makes the plugin abstain.
            return {"model": "jev-evil", "usage": dict(self._usage), "answers": {}}
        return provider_response(choice, confidence="high",
                                 urgency=self._urgency, model=self._model,
                                 usage=self._usage,
                                 category_probability=self._confidence)

    async def __call__(self, request):
        self.calls.append(request)
        return self.response_for(request)


@dataclass
class Scenario:
    """One labeled synthetic event.

    ``expected`` is the ground-truth advisory category the *evaluator* asserts,
    or ``None`` when the correct behavior is to abstain. ``provider_choice`` is
    what the simulated provider answers (a category, or ``"abstain"``). They are
    intentionally independent: when they differ the evaluator measures a wrong
    provider answer instead of asserting the provider is always right.
    """

    name: str
    signal: dict
    expected: Optional[str]
    provider_choice: str
    note: str
    # Repetition group: scenarios sharing a group share an exact dedup key and a
    # scope, so the 2nd..Nth members are exact repeats the dedup layer may
    # suppress. ``None`` means a standalone/one-shot event.
    repeat_group: Optional[str] = None
    scope: Optional[dict] = None
    tenant: Optional[str] = "tenant-a"
    # When True the evaluator asserts that a suppressed repeat still carried an
    # escalation (changed buckets) and therefore MUST have been evaluated. Used
    # for the "never hide an escalation" gate.
    must_evaluate: bool = False
    # Expected classification verdict given the provider_choice (used only for the
    # offline classifier scoring). None => expect abstain/no alert.
    expected_verdict: Optional[str] = None

    def normalized(self) -> dict:
        normalized = normalize_signal(self.signal)
        if normalized is None:
            raise AssertionError(f"scenario {self.name} does not normalize")
        return normalized


def _sig(**overrides) -> dict:
    base = {"schema_version": SCHEMA_VERSION, "protocol": "oauth2",
            "flow": "authorization_code", "outcome": "failure"}
    base.update(overrides)
    return base


def _scenario_provider_choice_for_corpus() -> dict:
    """Return {normalized-signal-json: provider_choice} built from the corpus."""
    choices = {}
    for scenario in CORPUS:
        key = json.dumps(scenario.normalized(), sort_keys=True, separators=(",", ":"))
        # Repeat-group members after the first reuse the first member's choice so
        # the same exact key always maps to one deterministic answer.
        choices.setdefault(key, scenario.provider_choice)
    return choices


# ---------------------------------------------------------------------------
# Corpus. Fixed, enumerated, invented. No real identifiers, traffic or customers.
# ---------------------------------------------------------------------------
CORPUS: list[Scenario] = []


def _add(*scenarios: Scenario) -> None:
    CORPUS.extend(scenarios)


# --- ordinary user error: correctly identified, must NOT alert as abuse -------
_add(
    Scenario("user_error_single_typo",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             "user_error", "user_error",
             "one mistyped password, registered client",
             expected_verdict="user_error"),
    Scenario("user_error_expired_credential",
             _sig(failure_reason="expired_credential", repeat_pattern="not_repeated",
                  known_registered_client=True),
             "user_error", "user_error",
             "stale credential, no repetition",
             expected_verdict="user_error"),
    Scenario("user_error_lockout_after_typos",
             _sig(failure_reason="account_locked", repeat_pattern="repeated_same_principal_slow",
                  count_bucket="6-20", window_bucket="1-24h", same_principal_repeated=True,
                  known_registered_client=True),
             "user_error", "user_error",
             "lockout policy after ordinary typos; must not read as abuse",
             expected_verdict="user_error"),
)

# --- client misconfiguration --------------------------------------------------
_add(
    Scenario("misconfig_unregistered_client",
             _sig(failure_reason="invalid_client", client_config_category="unregistered_client",
                  flow="client_credentials", known_registered_client=False),
             "client_misconfiguration", "client_misconfiguration",
             "client id unknown to this tenant",
             expected_verdict="client_misconfiguration"),
    Scenario("misconfig_expired_client_secret",
             _sig(failure_reason="invalid_client", client_config_category="expired_client_secret",
                  flow="client_credentials", known_registered_client=True),
             "client_misconfiguration", "client_misconfiguration",
             "rotated secret not deployed",
             expected_verdict="client_misconfiguration"),
    Scenario("misconfig_missing_redirect_uri",
             _sig(failure_reason="invalid_redirect_uri", client_config_category="missing_redirect_uri",
                  flow="authorization_code"),
             "client_misconfiguration", "client_misconfiguration",
             "client did not send redirect_uri",
             expected_verdict="client_misconfiguration"),
)

# --- suspected abuse: the provider is right and we must alert -----------------
_add(
    Scenario("abuse_credential_stuffing_burst",
             _sig(failure_reason="invalid_credentials",
                  repeat_pattern="repeated_same_principal_burst", count_bucket="21-100",
                  window_bucket="under-1m", same_principal_repeated=True,
                  multiple_distinct_principals=True, known_registered_client=False),
             "suspected_abuse", "suspected_abuse",
             "high-rate repeated failures across principals",
             expected_verdict="suspected_abuse"),
    Scenario("abuse_distributed_spray",
             _sig(failure_reason="invalid_credentials",
                  repeat_pattern="distributed_many_principals", count_bucket="over-100",
                  window_bucket="1-5m", multiple_distinct_principals=True),
             "suspected_abuse", "suspected_abuse",
             "one source spraying many principals",
             expected_verdict="suspected_abuse"),
    Scenario("abuse_token_replay",
             _sig(failure_reason="invalid_token", flow="refresh_token",
                  token_replay_indicator=True, repeat_pattern="repeated_same_principal_burst",
                  count_bucket="6-20", window_bucket="1-5m"),
             "suspected_abuse", "suspected_abuse",
             "refreshed token replay",
             expected_verdict="suspected_abuse"),
)

# --- ambiguous: provider low-confidence / residual must abstain ----------------
_add(
    Scenario("abstain_provider_returns_residual",
             _sig(failure_reason="other", flow="unknown", repeat_pattern="unknown",
                  count_bucket="1", window_bucket="unknown"),
             None, "other",
             "residual category must abstain, never alert",
             expected_verdict=None),
    Scenario("abstain_provider_malformed",
             _sig(failure_reason="invalid_scope", client_config_category="missing_scope_registration",
                  flow="authorization_code", known_registered_client=True),
             "client_misconfiguration", "abstain",
             "malformed/low-confidence provider payload must abstain",
             expected_verdict=None),
)

# --- false-positive trap: provider says abuse but the label says boring --------
_add(
    Scenario("fp_trap_provider_says_abuse_on_stale_secret",
             _sig(failure_reason="invalid_client", client_config_category="expired_client_secret",
                  flow="client_credentials", repeat_pattern="repeated_same_client",
                  count_bucket="over-100", window_bucket="1-24h", known_registered_client=True,
                  token_replay_indicator=False),
             "client_misconfiguration", "suspected_abuse",
             "adversarial: a stale secret retried loudly looks like replay; label is misconfig",
             expected_verdict="suspected_abuse"),
)

# --- false-negative trap: provider says boring but label is abuse --------------
_add(
    Scenario("fn_trap_provider_says_user_error_on_spray",
             _sig(failure_reason="invalid_credentials",
                  repeat_pattern="distributed_many_principals", count_bucket="over-100",
                  window_bucket="under-1m", multiple_distinct_principals=True),
             "suspected_abuse", "user_error",
             "adversarial: provider under-calls a clear distributed spray; label is abuse",
             expected_verdict="user_error"),
)

# --- repeat groups for dedup: exact repeats vs an escalation -------------------
_REPEAT_SCOPE = {"principal": "alpha", "client": "web"}
_add(
    Scenario("repeat_first_observation",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             "user_error", "user_error",
             "first observation of a repeat group; must reach the provider",
             repeat_group="g1", scope=dict(_REPEAT_SCOPE), expected_verdict="user_error"),
    Scenario("repeat_exact_repeat_1",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             None, "user_error",
             "exact repeat within TTL; dedup may suppress (no provider call)",
             repeat_group="g1", scope=dict(_REPEAT_SCOPE), expected_verdict=None),
    Scenario("repeat_exact_repeat_2",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             None, "user_error",
             "second exact repeat within TTL; dedup may suppress (no provider call)",
             repeat_group="g1", scope=dict(_REPEAT_SCOPE), expected_verdict=None),
)

_ESCALATION_SCOPE = {"principal": "bravo", "client": "web"}
_add(
    Scenario("escalation_first_observation",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             "user_error", "user_error",
             "benign first observation that opens an escalation group",
             repeat_group="g2", scope=dict(_ESCALATION_SCOPE), expected_verdict="user_error"),
    Scenario("escalation_crossed_threshold",
             _sig(failure_reason="invalid_credentials",
                  repeat_pattern="repeated_same_principal_burst", count_bucket="21-100",
                  window_bucket="under-1m", same_principal_repeated=True,
                  multiple_distinct_principals=True, known_registered_client=False),
             "suspected_abuse", "suspected_abuse",
             "same scope but escalation-bearing buckets changed; must be evaluated, never hidden",
             repeat_group="g2", scope=dict(_ESCALATION_SCOPE), must_evaluate=True,
             expected_verdict="suspected_abuse"),
)

_STRANGER_SCOPE = {"principal": "different-user", "client": "web"}
_add(
    Scenario("stranger_same_signal_new_principal",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             "user_error", "user_error",
             "identical coarse fields but a different principal; must NOT be suppressed",
             repeat_group="g1", scope=dict(_STRANGER_SCOPE), expected_verdict="user_error"),
)

# --- no-tenant abstention: dedup must refuse to collapse across tenants --------
_add(
    Scenario("no_tenant_first",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             "user_error", "user_error",
             "no tenant configured; first observation still evaluated",
             repeat_group="g3", scope={"principal": "charlie", "client": "cli"},
             tenant=None, expected_verdict="user_error"),
    Scenario("no_tenant_exact_repeat",
             _sig(failure_reason="invalid_credentials", repeat_pattern="first_observed",
                  count_bucket="1", window_bucket="under-1m", known_registered_client=True),
             "user_error", "user_error",
             "no tenant configured; dedup must abstain and evaluate rather than suppress",
             repeat_group="g3", scope={"principal": "charlie", "client": "cli"},
             tenant=None, must_evaluate=True, expected_verdict="user_error"),
)


@dataclass
class ScenarioResult:
    name: str
    category: Optional[str]  # observed advisory category from the alert, else None
    verdict: Optional[str]
    provider_called: bool
    provider_choice: str
    suppressed: bool
    expected: Optional[str]
    expected_verdict: Optional[str]
    queue_dropped: bool = False
    no_tenant: bool = False


@dataclass
class EvaluationReport:
    version: str = EVALUATION_VERSION
    scenarios: int = 0
    provider_calls_baseline: int = 0       # calls if dedup were disabled
    provider_calls_dedup: int = 0          # calls actually made with dedup enabled
    provider_calls_saved: int = 0
    suppression_rate: float = 0.0
    queue_drops: int = 0
    abstains: int = 0
    no_alert_outcomes: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    false_positive_events: list = field(default_factory=list)
    false_negative_events: list = field(default_factory=list)
    escalations_evaluated: int = 0
    escalations_must_evaluate: int = 0
    escalations_hidden: list = field(default_factory=list)
    per_category: dict = field(default_factory=dict)
    agreement: Optional[float] = None
    # Observed worker-side offline durations for the provider call hop + full path.
    offline_latency: dict = field(default_factory=dict)
    dedup_counters: dict = field(default_factory=dict)
    metrics_snapshot: dict = field(default_factory=dict)
    queue_pressure: dict = field(default_factory=dict)
    state_bounds: dict = field(default_factory=dict)
    scenario_verdicts: list = field(default_factory=list)
    not_measured: dict = field(default_factory=lambda: dict(NOT_MEASURED))
    seed: int = 0
    simulated: bool = True


async def _run_one_plugin_pass(scenarios, *, dedup_enabled: bool):
    """Drive the real SignalAuditPlugin over the corpus with a deterministic fake.

    The plugin is configured with ONE tenant, so scenarios are partitioned by
    their declared tenant and each partition is driven through its own plugin
    instance. That keeps the "no tenant => dedup abstains" scenarios honest instead
    of silently giving them a tenant they were not declared with.

    Returns (results, provider_call_count, metrics) for the dedup-on partition set.
    """
    from .metrics import Metrics

    results: list[ScenarioResult] = []
    total_calls = 0
    combined_metrics = Metrics()

    for tenant in sorted({s.tenant for s in scenarios}, key=lambda t: (t is None, t)):
        group = [s for s in scenarios if s.tenant == tenant]
        group_results, calls, metrics = await _run_tenant_group(
            group, tenant=tenant, dedup_enabled=dedup_enabled)
        results.extend(group_results)
        total_calls += calls
        for name in ("results", "categories", "confidence_levels", "urgency_levels",
                     "circuit", "local_candidate_kinds", "dedup", "latency_buckets"):
            getattr(combined_metrics, name).update(getattr(metrics, name))
        for name in ("provider_calls", "provider_avoided", "provider_latency_sum_seconds",
                     "input_tokens", "output_tokens", "cost_usd"):
            setattr(combined_metrics, name,
                    getattr(combined_metrics, name) + getattr(metrics, name))
        combined_metrics.provider_latency_max_seconds = max(
            combined_metrics.provider_latency_max_seconds,
            metrics.provider_latency_max_seconds)
        combined_metrics.last_success_timestamp_seconds = max(
            combined_metrics.last_success_timestamp_seconds,
            metrics.last_success_timestamp_seconds)
    return results, total_calls, combined_metrics


async def _run_tenant_group(scenarios, *, tenant, dedup_enabled: bool):
    """Run one tenant's scenarios through one real SignalAuditPlugin instance."""
    # Map normalized-signal-json -> provider_choice. First scenario wins so a
    # repeat group's members share one deterministic answer.
    choices: dict[str, str] = {}
    for scenario in scenarios:
        key = json.dumps(scenario.normalized(), sort_keys=True, separators=(",", ":"))
        choices.setdefault(key, scenario.provider_choice)
    provider = SyntheticProvider(choices)

    from .signal_plugin import SignalAuditPlugin
    from .metrics import Metrics

    dedup = DedupLayer(capacity=256, ttl_seconds=300.0, max_suppress_before_refresh=50,
                       tenant_key=b"fixed-eval-tenant-key")
    if not dedup_enabled:
        dedup.engage_kill_switch()

    alerts: list = []
    metrics = Metrics()
    plugin = SignalAuditPlugin(
        transport=provider, enabled=True, metrics=metrics,
        dedup=dedup, tenant=tenant,
        review_threshold=None,  # use each category's own threshold from classify.py
        timeout=1.0, queue_ttl=5.0, cache_ttl=0.0, worker_count=1,
        alert=lambda advisory: alerts.append(advisory),
    )

    results: list[ScenarioResult] = []
    await plugin.start()
    # Drain each event before attributing it. These are actual transport calls,
    # dedup counters and alert callbacks, not predictions replayed from fixtures.
    # Queue saturation is measured separately by _queue_pressure_probe.
    for scenario in scenarios:
        before_calls = len(provider.calls)
        before_alerts = len(alerts)
        before_suppressed = dedup.counters()["suppressed"]
        before_drops = metrics.results["queue_full"]
        envelope = {"authn_signal": scenario.signal}
        if scenario.scope is not None:
            envelope["dedup_scope"] = scenario.scope
        await plugin.emit(envelope)
        await plugin.join()
        provider_called = len(provider.calls) > before_calls
        suppressed = dedup.counters()["suppressed"] > before_suppressed
        observed = alerts[-1]["category"] if len(alerts) > before_alerts else None
        results.append(ScenarioResult(
            name=scenario.name,
            category=observed,
            verdict=observed,
            provider_called=provider_called,
            provider_choice=choices[json.dumps(scenario.normalized(), sort_keys=True,
                                               separators=(",", ":"))],
            suppressed=suppressed,
            expected=scenario.expected,
            expected_verdict=scenario.expected_verdict,
            queue_dropped=metrics.results["queue_full"] > before_drops,
            no_tenant=scenario.tenant is None,
        ))
    await plugin.close()
    return results, len(provider.calls), metrics


async def run_evaluation(seed: int = 0, *, dedup_enabled: bool = True) -> EvaluationReport:
    """Run the full offline synthetic evaluation and return a report object."""
    # Warm the loop once (no corpus) so first-call import cost is not charged to
    # the measured path.
    report = EvaluationReport(seed=seed)

    pass_results, calls_dedup, metrics = await _run_one_plugin_pass(
        CORPUS, dedup_enabled=dedup_enabled)

    # Baseline: same corpus with dedup disabled (every event hits the provider).
    baseline_results, calls_baseline, _ = await _run_one_plugin_pass(
        CORPUS, dedup_enabled=False)

    report.scenarios = len(CORPUS)
    report.provider_calls_baseline = calls_baseline
    report.provider_calls_dedup = calls_dedup
    report.provider_calls_saved = calls_baseline - calls_dedup
    report.suppression_rate = (report.provider_calls_saved / calls_baseline
                               if calls_baseline else 0.0)

    labeled = [(r.expected, r.category) for r in pass_results
               if r.expected is not None or r.category is not None]
    report.agreement = agreement(labeled)
    report.per_category = per_category_metrics(labeled)

    # False positives / negatives compare the ADVISORY ALERT against the label.
    # An alert exists only when the observed category is a real category (not None
    # and not the residual `other`, which never alerts). Rules:
    #   - should have abstained (expected_verdict is None) but alerted => FP
    #   - alerted `suspected_abuse` on a non-abuse label            => FP
    #   - label is abuse but no abuse alert (abstained or downgraded) => FN
    for r in pass_results:
        observed = r.category
        alerted = observed is not None and observed != "other"
        if r.expected_verdict is None and alerted:
            report.false_positives += 1
            report.false_positive_events.append(r.name + " (should have abstained)")
            continue
        if not alerted:
            if r.expected == "suspected_abuse":
                report.false_negatives += 1
                report.false_negative_events.append(r.name)
            continue
        alerting_abuse = observed == "suspected_abuse"
        expected_abuse = r.expected == "suspected_abuse"
        if alerting_abuse and not expected_abuse:
            report.false_positives += 1
            report.false_positive_events.append(r.name)
        elif expected_abuse and not alerting_abuse:
            report.false_negatives += 1
            report.false_negative_events.append(r.name)

    report.abstains = metrics.results["abstain"]
    report.no_alert_outcomes = sum(r.category is None for r in pass_results)
    report.queue_drops = metrics.results.get("queue_full", 0)

    # Escalation gate: every must_evaluate scenario must have been evaluated.
    report.escalations_must_evaluate = sum(1 for s in CORPUS if s.must_evaluate)
    for r in pass_results:
        scenario = next(s for s in CORPUS if s.name == r.name)
        if scenario.must_evaluate and not r.provider_called:
            report.escalations_hidden.append(r.name)
        elif scenario.must_evaluate and r.provider_called:
            report.escalations_evaluated += 1

    report.dedup_counters = dict(metrics.dedup)
    report.metrics_snapshot = metrics.snapshot()
    report.scenario_verdicts = [
        {"name": r.name, "expected": r.expected, "observed": r.category,
         "provider_choice": r.provider_choice, "evaluated": r.provider_called,
         "suppressed": r.suppressed}
        for r in pass_results
    ]
    report.offline_latency = _summarize_latency(metrics)
    report.queue_pressure = await _queue_pressure_probe()
    report.state_bounds = _state_bound_probe()
    return report


def _probe_signal(**overrides) -> dict:
    """A normalized one-off failure signal for the bounded probes."""
    raw = {"schema_version": SCHEMA_VERSION, "protocol": "oauth2",
           "flow": "authorization_code", "outcome": "failure",
           "failure_reason": "invalid_credentials", "repeat_pattern": "first_observed"}
    raw.update(overrides)
    normalized = normalize_signal(raw)
    if normalized is None:
        raise AssertionError("probe signal does not normalize")
    return normalized


async def _queue_pressure_probe() -> dict:
    """Drive a deliberately tiny queue to exercise the drop path, offline.

    A shadow layer's failure mode is silently dropping observations when the
    provider is slow. This measures whether a full queue drops without blocking
    the caller and whether the drop is counted. It uses the deterministic fake
    provider and never the network.
    """
    from .signal_plugin import SignalAuditPlugin
    from .metrics import Metrics

    block = asyncio.Event()

    async def stalled(_request):
        await block.wait()
        return provider_response("user_error")

    signal = _probe_signal()
    metrics = Metrics()
    # No dedup scope => dedup abstains, every event is evaluated, so the queue is
    # the only thing bounding the work.
    plugin = SignalAuditPlugin(transport=stalled, enabled=True, metrics=metrics,
                               tenant="tenant-a", queue_size=2, worker_count=1,
                               queue_ttl=5.0)
    await plugin.start()
    # Two events occupy the queue+worker; further emits must be dropped, not block.
    emit_elapsed = []
    for index in range(10):
        began = time.perf_counter()
        await plugin.emit({"authn_signal": dict(signal)})
        emit_elapsed.append(time.perf_counter() - began)
        if index == 0:
            # Let the worker take the first item and wait on the fake provider;
            # then the remaining emits fill the bounded queue behind it.
            await asyncio.sleep(0)
    block.set()
    await plugin.close()
    max_emit_seconds = max(emit_elapsed)
    return {
        "queue_size": 2,
        "emits": 10,
        "queue_drops": int(metrics.results.get("queue_full", 0)),
        "max_emit_seconds": max_emit_seconds,
        "emit_never_blocked": max_emit_seconds < 0.2,
        "note": "offline probe with a stalled fake provider; no network",
    }


def _state_bound_probe() -> dict:
    """Confirm the dedup registry stays within capacity under many distinct keys."""
    layer = DedupLayer(capacity=8, ttl_seconds=300.0, max_suppress_before_refresh=50,
                       tenant_key=b"fixed-eval-tenant-key")
    signal = _probe_signal(repeat_pattern="not_repeated")
    for index in range(100):
        layer.decide(signal, tenant="tenant-a",
                     context={"principal": f"principal-{index}"}, now=1000.0 + index)
    counters = layer.counters()
    return {
        "capacity": 8,
        "distinct_principals": 100,
        "final_size": layer.size,
        "evicted": counters["evicted"],
        "potential_missed_signal": counters["potential_missed_signal"],
        "bounded": layer.size <= 8,
    }


def _summarize_latency(metrics) -> dict:
    """Summarize observed offline worker durations. Not a p99 claim."""
    count = metrics.provider_calls
    if count == 0:
        return {"samples": 0, "mean_seconds": None, "max_seconds": None,
                "note": "no provider calls observed"}
    return {
        "samples": count,
        "sum_seconds": round(metrics.provider_latency_sum_seconds, 9),
        "mean_seconds": round(metrics.provider_latency_sum_seconds / count, 9),
        "max_seconds": round(metrics.provider_latency_max_seconds, 9),
        "note": "observed offline worker-side durations; NOT production request p99",
    }


def run_evaluation_sync(seed: int = 0, *, dedup_enabled: bool = True) -> EvaluationReport:
    """Blocking entry point for tests and the CLI runner."""
    return asyncio.run(run_evaluation(seed=seed, dedup_enabled=dedup_enabled))


def report_to_json(report: EvaluationReport) -> str:
    payload = report.__dict__.copy()
    payload["not_measured"] = dict(report.not_measured)
    payload["disclaimer"] = (
        "SIMULATION: offline, deterministic synthetic evaluation. "
        "No live service is contacted and no paid provider request is made."
    )
    return json.dumps(payload, indent=2, sort_keys=True)
