"""In-process aggregate measurements.

Every label here is a literal from a closed enum defined in this repo. No input
field, provider field, identifier, error string or exception text ever becomes a
label: an observability system is a data-export channel, so the metric surface is
treated as part of the privacy boundary.
"""
from __future__ import annotations

from collections import Counter

LATENCY_BOUNDS = (.01, .025, .05, .1, .25, .5, 1, 2, 5)

# Base outcome labels. Keep this list low-cardinality and reviewed.
OUTCOMES = (
    "disabled", "skipped", "queue_full", "expired", "abstain", "recommendation",
    "alerted", "alert_error", "routine", "routine_failure", "timeout", "error",
    "shutdown_drop", "circuit_open", "kill_switch", "baseline_agree",
    "baseline_disagree", "baseline_incomparable", "candidate_conflict",
)
CATEGORY_LABELS = ("user_error", "client_misconfiguration", "suspected_abuse", "ambiguous", "other")
CONFIDENCE_LABELS = ("low", "medium", "high")
URGENCY_LABELS = ("routine_review", "elevated_review", "immediate_review", "unknown")
CIRCUIT_LABELS = ("opened", "closed", "half_open", "short_circuited")
# Dedup decision counters. Every label is a literal from a closed enum in
# `dedup.py`; never a fingerprint, identifier or input value.
DEDUP_LABELS = ("observed", "suppressed", "refreshed", "evicted", "expired",
                "potential_missed_signal", "abstain_from_dedup")


class Metrics:
    """Aggregate measurements only; no labels from input or provider."""

    def __init__(self):
        self.results = Counter()
        self.categories = Counter()
        self.confidence_levels = Counter()
        self.urgency_levels = Counter()
        self.circuit = Counter()
        self.local_candidate_kinds = Counter()
        self.dedup = Counter()
        self.queue_depth = 0
        self.inflight = 0
        self.provider_calls = 0
        self.provider_avoided = 0
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
        for bound in LATENCY_BOUNDS:
            if seconds <= bound:
                self.latency_buckets[bound] += 1

    def prometheus(self):
        """Prometheus text exposition; serve behind your protected metrics endpoint."""
        lines = ["# TYPE auth_audit_events_total counter"]
        for outcome in OUTCOMES:
            lines.append(f'auth_audit_events_total{{outcome="{outcome}"}} {self.results[outcome]}')
        for name, counter, labels in (("category", self.categories, CATEGORY_LABELS),
                                      ("confidence", self.confidence_levels, CONFIDENCE_LABELS),
                                      ("urgency", self.urgency_levels, URGENCY_LABELS),
                                      ("circuit", self.circuit, CIRCUIT_LABELS)):
            lines.append(f"# TYPE auth_audit_{name}_total counter")
            for label in labels:
                lines.append(f'auth_audit_{name}_total{{value="{label}"}} {counter[label]}')
        lines.append("# TYPE auth_audit_local_candidate_total counter")
        for label, value in sorted(self.local_candidate_kinds.items()):
            lines.append(f'auth_audit_local_candidate_total{{value="{label}"}} {value}')
        lines.append("# TYPE auth_audit_dedup_total counter")
        for label in DEDUP_LABELS:
            lines.append(f'auth_audit_dedup_total{{outcome="{label}"}} {self.dedup[label]}')
        for name, value in (("queue_depth", self.queue_depth), ("inflight", self.inflight),
                            ("input_tokens_total", self.input_tokens),
                            ("output_tokens_total", self.output_tokens),
                            ("cost_usd_total", self.cost_usd),
                            ("provider_calls_total", self.provider_calls),
                            ("provider_avoided_total", self.provider_avoided),
                            ("last_success_timestamp_seconds", self.last_success_timestamp_seconds)):
            lines.extend((f"# TYPE auth_audit_{name} {'gauge' if name in ('queue_depth', 'inflight', 'last_success_timestamp_seconds') else 'counter'}",
                          f"auth_audit_{name} {value}"))
        lines.append("# TYPE auth_audit_provider_duration_seconds histogram")
        for bound in LATENCY_BOUNDS:
            lines.append(f'auth_audit_provider_duration_seconds_bucket{{le="{bound}"}} {self.latency_buckets[bound]}')
        lines += [f'auth_audit_provider_duration_seconds_bucket{{le="+Inf"}} {self.provider_calls}',
                  f"auth_audit_provider_duration_seconds_sum {self.provider_latency_sum_seconds}",
                  f"auth_audit_provider_duration_seconds_count {self.provider_calls}"]
        return "\n".join(lines) + "\n"

    def snapshot(self):
        return {"results": dict(self.results), "categories": dict(self.categories),
                "confidence_levels": dict(self.confidence_levels),
                "urgency_levels": dict(self.urgency_levels), "circuit": dict(self.circuit),
                "local_candidate_kinds": dict(self.local_candidate_kinds),
                "dedup": dict(self.dedup),
                "queue_depth": self.queue_depth, "inflight": self.inflight,
                "provider_calls": self.provider_calls, "provider_avoided": self.provider_avoided,
                "provider_latency_sum_seconds": self.provider_latency_sum_seconds,
                "provider_latency_max_seconds": self.provider_latency_max_seconds,
                "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cost_usd": self.cost_usd}
