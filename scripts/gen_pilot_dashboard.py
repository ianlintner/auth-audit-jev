#!/usr/bin/env python3
"""Generate deploy/observability/auth-audit-jev-pilot.json (Grafana dashboard).

Every PromQL target uses a metric the running pilot actually exports (see
docs/pilot.md). Panels show observed counters only: no savings estimate, no
quality or accuracy claim, and abstentions are never plotted as "healthy".
"""
import json
import sys
from pathlib import Path

J = 'job="auth_audit_jev_pilot"'
panels = []


def panel(title, kind, targets, x, y, w, h, desc="", unit="short"):
    panels.append({"id": len(panels) + 1, "title": title, "type": kind, "description": desc,
                   "datasource": "Prometheus", "gridPos": {"x": x, "y": y, "w": w, "h": h},
                   "targets": [{"refId": chr(65 + i), "expr": e, "legendFormat": l,
                                "instant": kind in ("stat", "gauge", "bargauge"), "range": kind == "timeseries"}
                               for i, (e, l) in enumerate(targets)],
                   "fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
                   "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}} if kind != "timeseries" else {}})


def q(metric, p):
    return f'histogram_quantile({p}, sum by (le) (rate({metric}_bucket{{{J}}}[5m])))'


panel("Pilot state (1=yes; no data = unknown)", "stat",
      [(f"up{{{J}}}", "scrape up"), (f"auth_audit_pilot_enabled{{{J}}}", "audit enabled"),
       (f"auth_audit_pilot_killed{{{J}}}", "kill switch engaged"), (f"auth_audit_pilot_fake_transport{{{J}}}", "fake transport (must be 0)")],
      0, 0, 12, 5, "Shadow/advisory only. No enforcement exists in this deployment.")
panel("Safety counters", "stat",
      [(f"auth_audit_pilot_canary_leaks_total{{{J}}}", "canary leaks (must be 0)"),
       (f"auth_audit_pilot_auth_failures_total{{{J}}}", "rejected scrapes/admin calls"),
       (f"auth_audit_pilot_live_calls_total{{{J}}} / auth_audit_pilot_call_budget{{{J}}}", "live call budget used")],
      12, 0, 12, 5, "Budget is a hard per-process cap on live Jev calls.", "short")
panel("Jev call duration p50/p95/p99", "timeseries",
      [(q("auth_audit_pilot_jev_call_seconds", 0.5), "p50"), (q("auth_audit_pilot_jev_call_seconds", 0.95), "p95"),
       (q("auth_audit_pilot_jev_call_seconds", 0.99), "p99")], 0, 5, 12, 8,
      "Provider call time measured in the pilot transport. Histogram-bucket estimates, 5m window; empty when there are no calls.", "s")
panel("Event to alert / result (sync probes only)", "timeseries",
      [(q("auth_audit_pilot_event_to_alert_seconds", 0.95), "event->alert p95"),
       (q("auth_audit_pilot_event_to_result_seconds", 0.5), "event->result p50"),
       (q("auth_audit_pilot_event_to_result_seconds", 0.95), "event->result p95")], 12, 5, 12, 8,
      "Only recorded for ?sync=1 probes (queue otherwise empty). Under live Jev, alerts need a high-confidence suspicious verdict, so this can legitimately be empty.", "s")
panel("Outcomes per 5m (counters)", "timeseries",
      [(f'sum by (outcome) (increase(auth_audit_events_total{{{J},outcome=~"recommendation|alerted|alert_error|routine|abstain|timeout|error|queue_full|expired|skipped|disabled|shutdown_drop"}}[5m]))', "{{outcome}}")],
      0, 13, 12, 8, "abstain/timeout/error/queue_full/expired are blind spots, not benign traffic. Not a measure of task or detection quality.")
panel("Queue depth and in-flight", "timeseries",
      [(f"auth_audit_queue_depth{{{J}}}", "queue depth"), (f"auth_audit_inflight{{{J}}}", "in flight")], 12, 13, 12, 8,
      "Queue is bounded (16) with a 5s TTL; one worker.")
panel("Provider tokens (reported) per 15m", "timeseries",
      [(f"increase(auth_audit_input_tokens_total{{{J}}}[15m])", "input"), (f"increase(auth_audit_output_tokens_total{{{J}}}[15m])", "output")],
      0, 21, 8, 7, "api.typesafe.ai reports tokens but no cost_usd; absence of cost is not evidence of zero cost.")
panel("Access decisions by scenario (unchanged by audit)", "timeseries",
      [(f"sum by (scenario, decision) (increase(auth_audit_pilot_decisions_total{{{J}}}[15m]))", "{{scenario}} {{decision}}")],
      8, 21, 8, 7, "The synthetic decision stub is computed before events publish; killing/failing audit must not change this.")
panel("Seconds since last validated verdict", "stat",
      [(f"time() - auth_audit_last_success_timestamp_seconds{{{J}}} > 0", "age")], 16, 21, 8, 7,
      "Informational only; idle is not a fault.", "s")

dash = {"title": "Auth Audit Jev Pilot (shadow, synthetic)", "uid": "auth-audit-jev-pilot", "schemaVersion": 39,
        "version": 1, "refresh": "30s", "time": {"from": "now-6h", "to": "now"}, "tags": ["auth-audit-jev", "shadow"],
        "panels": panels}
out = Path(sys.argv[1] if len(sys.argv) > 1 else "deploy/observability/auth-audit-jev-pilot.json")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(dash, indent=2) + "\n")
print(f"wrote {out} ({len(panels)} panels)")
