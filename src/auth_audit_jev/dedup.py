"""Bounded, local-only, per-tenant dedup/aggregation for opt-in typed failures.

The goal is narrow: do not spend a Jev decision on every *exact repeat* of an
unchanged failure, without hiding an escalating attack. This layer decides two
things per event:

- ``evaluate`` — send this event to the provider (first observation, a new key,
  a meaningful change, a crossed threshold, or a burst/milestone re-evaluation).
- ``suppress`` — an exact repeat of an already-assessed key within the TTL;
  update local counters and skip the provider.

Equivalence is deliberately **not** the three cloud-bound fields alone. Two
events are "the same" only when both the reviewed structured reason/flow and a
tenant-scoped, in-process keyed fingerprint of the producer's own client and
principal scope match. Without enough trusted scope to separate unrelated
principals, the layer abstains from dedup (returns ``evaluate``) rather than
collapsing strangers' failed logins together.

Everything here is in-process and volatile. There is no durable storage, no
provider result cache and no unbounded state: the registry is an LRU with a
bounded capacity and a per-entry TTL, a kill switch disables dedup entirely
(forcing every event to the provider, which is the safe direction), and a
process restart simply starts empty.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from collections import OrderedDict

from .signal import ENUM_FIELDS

# The reviewed, closed enum fields that describe *what kind* of failure it is.
# These are the "trusted structured reason/flow" the equivalence rule requires.
# Everything here is already validated to be in a closed enum, so it can never
# carry an identifier, error string or free text.
STRUCTURED_FIELDS = (
    "protocol", "flow", "failure_reason", "client_config_category",
    "authz_denial_category", "outcome",
    # Escalation-bearing fields. These encode the *magnitude and shape* of the
    # repetition (bucketed count, time window, and the detected pattern). They
    # must be part of equivalence: a signal that crosses a count threshold or
    # flips from `not_repeated` to `repeated_same_principal_burst` or
    # `distributed_many_principals` is a meaningful change — an escalating
    # attack — not an exact repeat, and must force a fresh assessment rather
    # than being suppressed.
    "repeat_pattern", "count_bucket", "window_bucket",
)

# Fixed outcome vocabulary for the decision and the metric labels. Closed enum:
# no provider text, fingerprint bytes or input value can ever enter a label.
DECISION_EVALUATE = "evaluate"
DECISION_SUPPRESS = "suppress"
DECISIONS = frozenset({DECISION_EVALUATE, DECISION_SUPPRESS})

# Low-cardinality counter names for the dedup path.
DEDUP_COUNTERS = (
    "observed", "suppressed", "refreshed", "evicted", "expired",
    "potential_missed_signal", "abstain_from_dedup",
)


def _bounded_text(value, what, max_bytes):
    """A prodecure-scope string is bounded in UTF-8 bytes before it is keyed.

    The fingerprint key components never leave the process, but a malicious
    producer must not be able to grow them without bound and exhaust the in-
    process registry. Enforce the same byte ceiling at the boundary as the
    signal schema does, so every over-limit scope is rejected up front.
    """
    if not isinstance(value, str):
        return None
    if len(value.encode("utf-8")) > max_bytes:
        return None
    return value


class DedupLayer:
    """Per-tenant, in-process exact-repeat suppression for typed failures.

    Keys are scoped by ``tenant`` first (two tenants can never collide), then by
    the structured field tuple, then by a keyed HMAC fingerprint of the
    producer-scope ``context``. The fingerprint is computed in-process and never
    stored, exported or logged — it is a cache key component only.
    """

    def __init__(self, *, capacity=1024, ttl_seconds=300.0, max_scope_bytes=256,
                 max_suppress_before_refresh=100, tenant_key=b""):
        if capacity < 1:
            raise ValueError("invalid dedup capacity")
        if ttl_seconds <= 0:
            raise ValueError("invalid dedup ttl")
        if max_scope_bytes < 1:
            raise ValueError("invalid dedup scope limit")
        if max_suppress_before_refresh < 1:
            raise ValueError("invalid dedup refresh threshold")
        self.capacity = capacity
        self.ttl_seconds = ttl_seconds
        self.max_scope_bytes = max_scope_bytes
        self.max_suppress_before_refresh = max_suppress_before_refresh
        self._tenant_key = tenant_key or secrets.token_bytes(32)
        self._registry: OrderedDict = OrderedDict()
        self._counters = {name: 0 for name in DEDUP_COUNTERS}
        self._enabled = True

    # -- controls -------------------------------------------------------------
    def engage_kill_switch(self):
        """Disable dedup: every subsequent event is ``evaluate`` (safe floor)."""
        self._enabled = False

    def release_kill_switch(self):
        self._enabled = True

    @property
    def enabled(self):
        return self._enabled

    @property
    def size(self):
        return len(self._registry)

    def counters(self):
        return dict(self._counters)

    def clear(self):
        self._registry.clear()

    def forget(self, signal, *, tenant, context=None):
        """Discard an unassessed key after a provider failure or abstention.

        Dedup may only suppress repeats of a successfully assessed event. A
        timeout, invalid verdict or transport error cannot establish that fact.
        """
        tenant = _bounded_text(tenant, "tenant", self.max_scope_bytes)
        structured = self._structured(signal)
        if not tenant or structured is None:
            return
        fingerprint = self._fingerprint(tenant, context)
        if fingerprint is not None:
            self._registry.pop((structured, fingerprint), None)

    # -- scope fingerprint ----------------------------------------------------
    def _fingerprint(self, tenant, context):
        """Keyed in-process HMAC of the producer-scope context.

        Returns ``None`` when the context is absent or unusable, which is the
        caller's signal to abstain rather than to fabricate a scope. Only the
        digest is held in the bounded volatile registry; raw scope is never
        exported or logged.
        """
        if not isinstance(context, dict):
            return None
        parts = []
        # Only a closed, producer-owned set of scope keys is meaningful. Read a
        # reviewed allowlist, in a fixed order, so ordering cannot matter.
        for key in ("principal", "client", "session"):
            value = context.get(key)
            if value is None:
                continue
            bounded = _bounded_text(value, key, self.max_scope_bytes)
            if bounded is None:
                continue
            parts.append((key, bounded))
        if not parts:
            return None
        # Structured encoding prevents delimiter injection in producer strings
        # from collapsing distinct principal/client combinations to one key.
        payload = json.dumps([tenant, parts], separators=(",", ":")).encode("utf-8")
        return hmac.new(self._tenant_key, payload, hashlib.sha256).digest()

    def _structured(self, signal):
        """The reviewed reason/flow tuple; ``None`` if any field is missing.

        Missing structured fields mean we cannot trust the equivalence, so we
        abstain (evaluate) instead of deduping on a partial tuple.
        """
        try:
            values = tuple(signal[field] for field in STRUCTURED_FIELDS)
            for field, value in zip(STRUCTURED_FIELDS, values):
                if value is None:
                    if field != "authz_denial_category":
                        return None
                elif value not in ENUM_FIELDS[field]:
                    return None
            return values
        except (KeyError, TypeError, ValueError):
            return None

    # -- decision -------------------------------------------------------------
    def decide(self, signal, *, tenant, context=None, now=None):
        """Return ``evaluate`` or ``suppress`` for one typed failure signal.

        ``tenant`` is a required scope key (bounded text). ``context`` is the
        optional producer-owned client/principal context used only to key the
        fingerprint. Neither is exported; ``now`` is injectable for tests.
        """
        now = time.monotonic() if now is None else now
        self._counters["observed"] += 1

        if not self._enabled:
            return DECISION_EVALUATE

        tenant = _bounded_text(tenant, "tenant", self.max_scope_bytes)
        if not tenant:
            # No valid tenant means we cannot scope the key at all. A missing or
            # empty tenant must not collapse events across tenants.
            self._counters["abstain_from_dedup"] += 1
            return DECISION_EVALUATE

        structured = self._structured(signal)
        if structured is None:
            self._counters["abstain_from_dedup"] += 1
            return DECISION_EVALUATE

        # Even non-credential failure categories may span principals. A client
        # or browser session alone must not suppress another user's failure.
        principal = context.get("principal") if isinstance(context, dict) else None
        if not _bounded_text(principal, "principal", self.max_scope_bytes):
            self._counters["abstain_from_dedup"] += 1
            return DECISION_EVALUATE

        fingerprint = self._fingerprint(tenant, context)
        if fingerprint is None:
            # A bucket/category is never an individual client or principal.
            self._counters["abstain_from_dedup"] += 1
            return DECISION_EVALUATE

        key = (structured, fingerprint)

        self._evict_expired(now)

        entry = self._registry.get(key)
        if entry is None:
            # First observation (or a key we have since evicted/expired):
            # evaluate, and record the key for future repeats.
            self._store(key, now)
            return DECISION_EVALUATE

        suppressed_count, first_seen, _last_seen = entry
        # Milestone re-evaluation: never suppress a persistent repetition
        # forever. After too many suppressed repeats, force a fresh assessment
        # so a slow-burn or long-running burst is re-surfaced.
        if suppressed_count + 1 >= self.max_suppress_before_refresh:
            self._counters["refreshed"] += 1
            self._store(key, now)
            return DECISION_EVALUATE

        # Exact repeat within TTL: suppress and bump the local counter.
        self._counters["suppressed"] += 1
        entry[0] = suppressed_count + 1
        entry[2] = now
        self._registry.move_to_end(key)
        return DECISION_SUPPRESS

    # -- registry -------------------------------------------------------------
    def _store(self, key, now):
        self._registry[key] = [0, now, now]
        self._registry.move_to_end(key)
        while len(self._registry) > self.capacity:
            self._registry.popitem(last=False)
            self._counters["evicted"] += 1
            # An evicted key means a difference the provider never saw as a
            # fresh assessment. Honest signal, never a quality claim.
            self._counters["potential_missed_signal"] += 1

    def _evict_expired(self, now):
        expired = 0
        while self._registry:
            _, entry = next(iter(self._registry.items()))
            # Expiry keys off last activity so a key that keeps being repeated
            # (bumping entry[2]) stays alive, while a key whose repeats stopped
            # ages out on its own. first_seen (entry[1]) is monotonic and would
            # evict a still-active key; last_seen (entry[2]) is the boundary.
            if now - entry[2] <= self.ttl_seconds:
                break
            self._registry.popitem(last=False)
            expired += 1
        if expired:
            self._counters["expired"] += expired

    def expire(self, now=None):
        """Explicitly drop every entry past its TTL; returns the count removed.

        Exposed so an operator (or a test running against a frozen clock) can
        force expiry deterministically without waiting for the next decision.
        """
        now = time.monotonic() if now is None else now
        before = len(self._registry)
        self._evict_expired(now)
        return before - self.size
