"""Rust ``oauth2-events`` producer/transport contract for the shadow audit.

This module is *not* an installed hook. It is the reviewed, executable contract
for a future opt-in Rust adapter that carries ``oauth2-events`` envelopes into
this repository's shadow audit, plus the pure-Python plumbing that contract is
tested against.

Two rules shape everything here:

* The **decision plane is separate from the execution plane**. A projection
  produced here is advisory telemetry. It never gates, delays, retries, or
  authorizes an OAuth request, and :meth:`RustEventsAuditAdapter.emit_envelope`
  returns immediately in every case.
* The **wire boundary is the only export boundary**. Only the reviewed envelope
  JSON is accepted. Private identifiers, correlation keys, trace context,
  free-form metadata, error strings, precise timing, and unknown attributes are
  dropped before anything is queued, and each drop is counted under a
  low-cardinality key.

Wire shape verified against ``rust-oauth2-server`` ``crates/oauth2-events``
``src/envelope.rs`` and ``src/event_types.rs``:

.. code-block:: json

    {
      "event": {
        "id": "...", "event_type": "user_authentication_failed",
        "timestamp": "2026-09-28T12:00:00Z", "severity": "warning",
        "user_id": "...", "client_id": "...",
        "metadata": {...}, "error": "..."
      },
      "idempotency_key": "optional", "traceparent": "optional",
      "tracestate": "optional", "correlation_id": "...",
      "producer": "...", "produced_at": "...", "attributes": {...}
    }

Rust producers serialize the envelope to JSON and hand the text (or the parsed
object) to this module's adapter; see ``docs/rust-oauth2-events.md``. The
adapter never forwards trace context, correlation keys, identifiers, metadata,
error text, or precise timing to the provider: those fields are recognized, then
stripped by :func:`project_rust_envelope` and counted as redaction.
"""
from __future__ import annotations

from collections import Counter
import json
import time

#: Exact ``EventType`` wire spellings the Rust crate can emit. Verified against
#: ``event_types.rs``: ``#[serde(rename_all = "snake_case")]`` over the 13
#: variants below. This is deliberately narrower than
#: :data:`auth_audit_jev.EVENTS`, so a producer cannot fabricate a signal the
#: Rust crate cannot observe (there is no authz-denial or invalid-token variant).
RUST_EVENT_TYPES = frozenset({
    "authorization_code_created", "authorization_code_validated",
    "authorization_code_expired",
    "token_created", "token_validated", "token_revoked", "token_expired",
    "client_registered", "client_validated", "client_deleted",
    "user_authenticated", "user_authentication_failed", "user_logout",
})

#: Rust event kinds whose outcome is a failure. Only ``user_authentication_failed``
#: exists in the Rust crate today; authz-denial and invalid-token/introspection
#: signals are absent by construction and must abstain rather than be mapped.
RUST_FAILURES = frozenset({"user_authentication_failed"})

#: Rust event kinds that indicate a completed positive validation.
RUST_SUCCESSES = frozenset({
    "user_authenticated", "authorization_code_validated",
    "token_validated", "client_validated",
})

#: ``EventSeverity`` wire spellings: ``#[serde(rename_all = "lowercase")]``.
RUST_SEVERITIES = frozenset({"info", "warning", "error"})

#: Recognized top-level envelope keys. Anything else is dropped and counted, so
#: the contract cannot silently widen.
ENVELOPE_KEYS = frozenset({
    "event", "idempotency_key", "traceparent", "tracestate",
    "correlation_id", "producer", "produced_at", "attributes",
})

#: ``AuthEvent`` keys recognized on the wire.
AUTH_EVENT_KEYS = frozenset({
    "id", "event_type", "timestamp", "severity",
    "user_id", "client_id", "metadata", "error",
})

#: ``AuthEvent`` fields that are per-event identifiers, precise timing,
#: free-form context, or error text. Never exported; each is counted as a
#: redaction.
IDENTIFIER_OR_CONTEXT_FIELDS = (
    "id", "timestamp", "user_id", "client_id", "metadata", "error",
)

#: Envelope provenance fields that are correlation keys, trace context, or
#: producer identifiers. Never exported; each is counted as a redaction.
ENVELOPE_PROVENANCE_FIELDS = (
    "idempotency_key", "correlation_id", "producer",
    "produced_at", "traceparent", "tracestate",
)

#: Attribute keys that may be exported. Low-cardinality and reviewed; extending
#: this set is a privacy change: it needs review and a test, not just a code edit.
#: Keys AND values are allowlisted. A bounded arbitrary string remains private:
#: for example ``auth_method='password-for-user-123'`` must not escape.
SAFE_ATTRIBUTE_VALUES = {
    "auth_method": frozenset({"password", "client_secret_basic", "client_secret_post",
                               "private_key_jwt", "none"}),
    "grant_type": frozenset({"authorization_code", "client_credentials", "refresh_token",
                              "device_code", "password"}),
    "endpoint": frozenset({"authorize", "token", "introspect", "revoke", "userinfo"}),
    "operation": frozenset({"login", "logout", "refresh", "token_issue", "validate"}),
    "region": frozenset({"us-east-1", "us-east-2", "us-west-1", "us-west-2",
                          "eu-west-1", "eu-central-1"}),
}
SAFE_ATTRIBUTE_KEYS = frozenset(SAFE_ATTRIBUTE_VALUES)

#: Outcome vocabulary of the adapter's own accounting. Closed and
#: low-cardinality; ``accepted`` is the only outcome that permits a queue write.
OUTCOMES = (
    "accepted",          # projection accepted and enqueued
    "disabled",          # adapter switched off, or no audit worker running
    "malformed",         # body was not a parseable envelope object
    "unknown_event",     # event type missing or outside the Rust emit set
    "unknown_severity",  # severity missing or outside its allowlist
    "oversized",         # body, field, or projection over the byte ceiling
    "queue_full",        # bounded queue rejected the projection
)

#: Default ceiling for one exported envelope body, in UTF-8 bytes.
MAX_WIRE_BYTES = 4096

#: Default ceiling for one exported string field.
MAX_FIELD_BYTES = 256


def _size(value):
    """UTF-8 byte length. Limits are enforced in bytes, not characters."""
    return len(value.encode("utf-8"))


def _bounded_string(value, key, dropped):
    """Return a bounded non-empty string, or ``None`` recording why not."""
    if value is None:
        return None
    if type(value) is not str:
        dropped["type:" + key] += 1
        return None
    if not value.strip():
        dropped["empty:" + key] += 1
        return None
    if _size(value) > MAX_FIELD_BYTES:
        dropped["oversized:" + key] += 1
        return None
    return value


def outcome_for(event_kind):
    """Map a reviewable Rust event kind to the coarse outcome label.

    The label is an allowlist heuristic local to this repository, not an
    observed access verdict: ``token_revoked`` is ``observed``, not a failure.
    """
    if event_kind in RUST_FAILURES:
        return "failure"
    if event_kind in RUST_SUCCESSES:
        return "success"
    return "observed"


def _parse_wire(envelope, max_wire_bytes):
    """Return an envelope dict, or ``None`` when the body is unusable."""
    if isinstance(envelope, bytes):
        if len(envelope) > max_wire_bytes:
            return None
        try:
            envelope = envelope.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if isinstance(envelope, str):
        if _size(envelope) > max_wire_bytes:
            return None
        try:
            envelope = json.loads(envelope)
        except (ValueError, TypeError):
            return None
    return envelope if isinstance(envelope, dict) else None


def project_rust_envelope(envelope, *, max_wire_bytes=MAX_WIRE_BYTES):
    """Project a Rust ``EventEnvelope`` into safe auditable fields.

    Returns ``(fields, dropped)`` or ``None``. ``None`` is the documented
    abstention, used for an unknown/missing event type, an out-of-contract
    severity, a malformed body, an over-limit body or field, or a projection
    whose exported attributes exceed the byte ceiling.

    ``fields`` holds the allowlisted ``event_kind`` and ``severity`` plus an
    ``attributes`` mapping drawn only from :data:`SAFE_ATTRIBUTE_KEYS`. Every
    identifier, correlation key, trace field, metadata entry, error string, and
    precise-timing field is stripped and counted in ``dropped`` under the
    ``identifier_or_context`` key. ``dropped`` is a :class:`~collections.Counter`
    of bounded keys only — never content.

    This function never sees a caller-supplied event identifier, correlation
    key, or trace context in its return value: the export is the reviewed subset
    and nothing else.
    """
    dropped = Counter()
    wire = _parse_wire(envelope, max_wire_bytes)
    if wire is None:
        dropped["malformed"] += 1
        return None

    for key in wire:
        if key not in ENVELOPE_KEYS:
            dropped["unknown_envelope_key"] += 1

    event = wire.get("event")
    if not isinstance(event, dict):
        dropped["malformed"] += 1
        return None

    kind, severity = event.get("event_type"), event.get("severity")
    if type(kind) is not str or kind not in RUST_EVENT_TYPES:
        dropped["unknown_event_type"] += 1
        return None
    if type(severity) is not str or severity not in RUST_SEVERITIES:
        dropped["unknown_severity"] += 1
        return None

    # Private identifiers and free-form context never leave the process.
    for key in IDENTIFIER_OR_CONTEXT_FIELDS:
        if key in event:
            dropped["identifier_or_context"] += 1

    # Correlation keys, trace context, and producer identifiers never leave.
    for key in ENVELOPE_PROVENANCE_FIELDS:
        if key in wire:
            dropped["identifier_or_context"] += 1

    attributes = {}
    raw = wire.get("attributes")
    if raw is not None:
        if not isinstance(raw, dict):
            dropped["attributes"] += 1
        else:
            for key in sorted(raw):
                if key not in SAFE_ATTRIBUTE_KEYS:
                    dropped["attribute:" + key] += 1
                    continue
                value = _bounded_string(raw[key], "attribute:" + key, dropped)
                if value is not None:
                    if value not in SAFE_ATTRIBUTE_VALUES[key]:
                        dropped["unreviewed_attribute_value"] += 1
                        continue
                    attributes[key] = value

    if _size(json.dumps(attributes, separators=(",", ":"))) > max_wire_bytes:
        dropped["oversized_projection"] += 1
        return None
    fields = {"event_kind": kind, "severity": severity}
    if attributes:
        fields["attributes"] = attributes
    return fields, dropped


class RustEventsDropAccountant:
    """Accounts for every adapter observation with bounded keys only.

    Nothing derived from the envelope — event type included — is ever used as a
    metric key, so no value that came from the wire can leak through metrics.
    """

    def __init__(self):
        self.counts = Counter()
        #: Aggregate count of stripped identifier/context/trace fields.
        self.privacy_drops = 0
        #: Aggregate count of stripped unknown attribute keys.
        self.attribute_drops = 0

    def record(self, outcome):
        if outcome not in OUTCOMES:
            raise ValueError("unknown adapter outcome")
        self.counts[outcome] += 1
        return outcome

    def observe(self, envelope, *, max_wire_bytes=MAX_WIRE_BYTES):
        """Return ``(projection, outcome)`` for one envelope.

        ``projection`` is ``None`` unless the outcome is ``accepted``. A valid,
        reviewable envelope always has its identifiers and trace context
        stripped; that redaction is measured in :attr:`privacy_drops` and
        :attr:`attribute_drops`, it is not itself an outcome. A queue write is
        only permitted when this returns the ``accepted`` outcome.
        """
        wire = _parse_wire(envelope, max_wire_bytes)
        if wire is None:
            return None, self.record("malformed")

        result = project_rust_envelope(wire, max_wire_bytes=max_wire_bytes)
        if result is None:
            return None, self.record(_primary_outcome(wire, Counter()))

        fields, dropped = result
        if dropped.get("oversized_projection"):
            return None, self.record("oversized")

        self.privacy_drops += dropped.get("identifier_or_context", 0)
        self.attribute_drops += sum(
            count for key, count in dropped.items()
            if key.startswith("attribute:")
        )
        return fields, self.record("accepted")

    def prometheus(self):
        lines = ["# TYPE auth_audit_adapter_events_total counter"]
        for outcome in OUTCOMES:
            lines.append(f'auth_audit_adapter_events_total{{outcome="{outcome}"}} {self.counts[outcome]}')
        lines += ["# TYPE auth_audit_adapter_redacted_fields_total counter",
                  f'auth_audit_adapter_redacted_fields_total{{kind="identifier_or_context"}} {self.privacy_drops}',
                  f'auth_audit_adapter_redacted_fields_total{{kind="unknown_attribute"}} {self.attribute_drops}']
        return "\n".join(lines) + "\n"

    def snapshot(self):
        return {"counts": dict(self.counts), "privacy_drops": self.privacy_drops,
                "attribute_drops": self.attribute_drops}


def _primary_outcome(wire, dropped):
    """Pick the single accounting outcome for a rejected envelope."""
    event = wire.get("event")
    if not isinstance(event, dict):
        return "malformed"
    if type(event.get("event_type")) is not str or event.get("event_type") not in RUST_EVENT_TYPES:
        return "unknown_event"
    if type(event.get("severity")) is not str or event.get("severity") not in RUST_SEVERITIES:
        return "unknown_severity"
    if dropped.get("oversized_projection") or any(key.startswith("oversized:") for key in dropped):
        return "oversized"
    return "malformed"


class RustEventsAuditAdapter:
    """Non-blocking, bounded, opt-in producer adapter for Rust ``oauth2-events``.

    ``emit_envelope`` never blocks and never raises. It projects the envelope,
    attempts a single ``put_nowait`` on the wrapped
    :class:`~auth_audit_jev.AuditPlugin` queue, and accounts for the result. The
    plugin keeps the only worker, the request timeout, the queue TTL, the cloud
    kill switch and the circuit behaviour, so this adapter adds no second path
    to the provider and no retry of its own.

    The queue item pushed is a ``(state, enqueued_at)`` two-tuple — the exact
    shape :meth:`auth_audit_jev.AuditPlugin._run` consumes — so the adapter reuses
    the plugin's worker verbatim without a parallel transport.

    Rollback is total: stop calling ``emit_envelope`` (one call site in the
    embedding service), or build the adapter with ``enabled=False``, which
    returns ``disabled`` without touching the queue, the plugin, or the provider.
    """

    def __init__(self, plugin, *, enabled=True, max_wire_bytes=MAX_WIRE_BYTES, metrics=None):
        if plugin is None:
            raise ValueError("plugin is required")
        self.plugin = plugin
        self.enabled = enabled
        self.max_wire_bytes = max_wire_bytes
        self.metrics = metrics if metrics is not None else RustEventsDropAccountant()

    def emit_envelope(self, envelope):
        """Project one Rust envelope; return its accounting outcome.

        Never raises: every path either enqueues one bounded ``put_nowait`` or
        records a single accounting outcome. No provider call, no retry, no
        re-raise, no blocking wait.
        """
        if not self.enabled:
            return self.metrics.record("disabled")
        try:
            fields, outcome = self.metrics.observe(envelope, max_wire_bytes=self.max_wire_bytes)
            if fields is None:
                return outcome
            state = {
                "event_kind": fields["event_kind"],
                "severity": fields["severity"],
                "outcome": outcome_for(fields["event_kind"]),
            }
            if "attributes" in fields:
                state["attributes"] = dict(fields["attributes"])
            self.plugin.queue.put_nowait((state, time.monotonic()))
            # Only touch plugin fields that exist on the real AuditPlugin: the
            # queue and Metrics.queue_depth. Redaction counts stay in this
            # adapter's own RustEventsDropAccountant (privacy_drops /
            # attribute_drops), never written into plugin.metrics.
            self.plugin.metrics.queue_depth = self.plugin.queue.qsize()
        except Exception:
            # Provably bounded: no provider call, no retry, no re-raise. Do not
            # assert on optional plugin internals here; classify the rejection
            # from the queue's own state only when it exposes a bounded check.
            try:
                full = self.plugin.queue.full()
            except AttributeError:
                full = False
            return self.metrics.record("queue_full" if full else "disabled")
        return outcome
