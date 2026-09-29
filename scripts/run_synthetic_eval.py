#!/usr/bin/env python3
"""Run the offline synthetic evaluation and print/save a report.

No network, no provider key, no paid API call. Deterministic for a fixed corpus.

    python3 scripts/run_synthetic_eval.py            # human-readable
    python3 scripts/run_synthetic_eval.py --json OUT # machine-readable JSON

Exit code is 0 when the measured gates pass, 1 when a gate fails, 2 on a setup
error. Gates are defined in `GATES` below and only reference metrics that this
offline run actually produces.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from auth_audit_jev.evaluation import (  # noqa: E402
    EVALUATION_VERSION,
    Scenario,
    report_to_json,
    run_evaluation_sync,
)
from auth_audit_jev.evaluation import CORPUS  # noqa: E402

# Gates are only defined on metrics the OFFLINE run produces. Anything about the
# live service is intentionally excluded: it cannot be measured here.
GATES = {
    "escalations_never_hidden": lambda r: len(r.escalations_hidden) == 0,
    # With dedup on, repeat suppression should save real provider calls vs baseline.
    "dedup_saves_calls": lambda r: r.provider_calls_saved >= 2,
    # A conservative layer must abstain rather than guess on the residual/malformed cases.
    "abstains_present": lambda r: r.abstains >= 2,
    # Deliberate wrong-answer fixtures must register as errors. These are
    # instrumentation gates, not accuracy acceptance thresholds for a pilot.
    "false_positive_trap_detected": lambda r: (
        r.false_positive_events == ["fp_trap_provider_says_abuse_on_stale_secret"]),
    "false_negative_trap_detected": lambda r: (
        r.false_negative_events == ["fn_trap_provider_says_user_error_on_spray"]),
    # The evaluator must refuse to report that it measured unavailable metrics.
    "unavailable_metrics_marked": lambda r: (
        isinstance(r.not_measured, dict) and len(r.not_measured) >= 5
        and "event_to_alert_latency" in r.not_measured
    ),
    # A full queue must drop without blocking the caller and must be counted.
    "queue_drops_are_counted_not_blocking": lambda r: (
        r.queue_pressure.get("queue_drops", 0) > 0
        and r.queue_pressure.get("emit_never_blocked") is True
    ),
    # The dedup registry must stay within its configured capacity.
    "dedup_state_is_bounded": lambda r: r.state_bounds.get("bounded") is True,
    # A stranger's identical coarse signal must not be suppressed as a repeat.
    "no_cross_principal_collapse": lambda r: (
        next((s for s in r.scenario_verdicts if s["name"] == "stranger_same_signal_new_principal"),
             {}).get("evaluated") is True
    ),
}


def _fmt(value):
    if value is None:
        return "None (no support)"
    if isinstance(value, float):
        return f"{value:.4f}"
    return value


def render(report) -> str:
    lines = []
    lines.append("=" * 78)
    lines.append(f"Offline synthetic evaluation report  [{EVALUATION_VERSION}]")
    lines.append("SIMULATION — no live Jev call; only the in-process fake provider ran.")
    lines.append("=" * 78)
    lines.append(f"scenarios                     : {report.scenarios}")
    lines.append(f"provider calls (dedup off)    : {report.provider_calls_baseline}  (baseline)")
    lines.append(f"provider calls (dedup on)     : {report.provider_calls_dedup}")
    lines.append(f"provider calls saved          : {report.provider_calls_saved}")
    lines.append(f"suppression rate              : {_fmt(report.suppression_rate)}")
    lines.append("")
    lines.append(f"provider abstentions             : {report.abstains}")
    lines.append(f"dedup abstentions (all reasons)  : {report.dedup_counters.get('abstain_from_dedup', 0)}")
    lines.append(f"no-alert outcomes (incl suppressed): {report.no_alert_outcomes}")
    lines.append(f"queue drops (corpus run)      : {report.queue_drops}"
                 "  (corpus never overflows; see probe below)")
    lines.append(f"false positives (abuse alert) : {report.false_positives}")
    if report.false_positive_events:
        lines.append(f"  fp events                   : {report.false_positive_events}")
    lines.append(f"false negatives (missed abuse): {report.false_negatives}")
    if report.false_negative_events:
        lines.append(f"  fn events                   : {report.false_negative_events}")
    lines.append(f"escalations evaluated         : {report.escalations_evaluated}"
                 f" / {report.escalations_must_evaluate} required")
    if report.escalations_hidden:
        lines.append(f"  HIDDEN ESCALATIONS          : {report.escalations_hidden}")
    lines.append(f"label agreement (offline)     : {_fmt(report.agreement)}")
    lines.append("")
    lines.append("per-category (offline, synthetic labels):")
    for category, stats in report.per_category.get("categories", {}).items():
        lines.append(f"  {category:24s} support={stats['support']:<3} "
                     f"predicted={stats['predicted']:<3} "
                     f"precision={_fmt(stats['precision'])} recall={_fmt(stats['recall'])}")
    lines.append("")
    lat = report.offline_latency
    lines.append("observed offline worker latency (NOT request p99):")
    lines.append(f"  samples={lat.get('samples')} mean={_fmt(lat.get('mean_seconds'))}s "
                 f"max={_fmt(lat.get('max_seconds'))}s")
    lines.append("")
    lines.append("queue pressure probe (offline, stalled fake provider):")
    qp = report.queue_pressure
    lines.append(f"  queue_size={qp.get('queue_size')} emits={qp.get('emits')} "
                 f"drops={qp.get('queue_drops')} emit_never_blocked={qp.get('emit_never_blocked')}")
    lines.append("")
    lines.append("dedup state bound probe (offline):")
    sb = report.state_bounds
    lines.append(f"  capacity={sb.get('capacity')} distinct_keys={sb.get('distinct_principals')} "
                 f"final_size={sb.get('final_size')} evicted={sb.get('evicted')} bounded={sb.get('bounded')}")
    lines.append("")
    lines.append("dedup counters:")
    for name, value in sorted(report.dedup_counters.items()):
        lines.append(f"  {name:24s}: {value}")
    lines.append("")
    lines.append("NOT MEASURED (unavailable offline — reported as such):")
    for name, reason in sorted(report.not_measured.items()):
        lines.append(f"  - {name}: {reason}")
    lines.append("")
    lines.append("OFFLINE HARNESS GATES (not pilot readiness):")
    all_ok = True
    for name, check in GATES.items():
        try:
            ok = bool(check(report))
        except Exception:  # a malformed report must fail closed
            ok = False
        all_ok = all_ok and ok
        lines.append(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    lines.append("=" * 78)
    lines.append(f"GATE RESULT: {'PASS' if all_ok else 'FAIL'} (offline harness only)")
    lines.append("PILOT READINESS: NOT ESTABLISHED — no live/consented calibration or owner approval")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=None,
                        help="write the machine-readable report JSON here")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--dedup-off", action="store_true",
                        help="disable dedup to observe the baseline path")
    args = parser.parse_args()

    report = run_evaluation_sync(seed=args.seed, dedup_enabled=not args.dedup_off)
    gates = {name: bool(check(report)) for name, check in GATES.items()}
    gates_ok = all(gates.values())
    print(render(report))

    if args.json is not None:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        payload = json.loads(report_to_json(report))
        payload["gates"] = gates
        payload["gate_result"] = "PASS" if gates_ok else "FAIL"
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        print(f"\nwrote report JSON -> {args.json}")

    return 0 if gates_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
