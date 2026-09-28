"""Versioned normalized authn/authz signal schema (producer contract v1).

The legacy three-field projection (`event_kind`, `severity`, `outcome`) cannot
separate a mistyped password from an unregistered OAuth client or from
credential stuffing. `authn-signal/v1` is the reviewed, bounded replacement:
producers compute coarse enums, bounded count/time buckets and tri-state
booleans, and this module is the only place they are validated.

Nothing here accepts free text. Every field is a closed enum or a boolean, so
an envelope carrying raw error strings, identifiers, IPs, tokens, headers,
metadata or trace context is rejected wholesale instead of being copied and
then redacted.
"""
from __future__ import annotations

import json

SCHEMA_VERSION = "authn-signal/v1"

# Hard ceiling for the serialized normalized signal. The enums already bound
# every value; this cap exists so a future field cannot grow the payload the
# provider sees without another reviewed schema version. It is deliberately set
# above the worst case the *reviewed* enums can produce together (the widest
# literal of every enum field plus all six booleans is 565 bytes serialized), so
# a legitimate signal is never rejected for size while an unreviewed growth
# still is.
MAX_SIGNAL_BYTES = 1024
MAX_SCHEMA_VERSION_BYTES = 32

PROTOCOLS = frozenset({"oauth2", "oidc", "saml", "iam", "unknown"})
FLOWS = frozenset({
    "authorization_code", "client_credentials", "refresh_token", "device_code",
    "resource_owner_password", "implicit", "token_introspection", "token_revocation",
    "session_login", "session_refresh", "client_registration", "unknown",
})
OUTCOMES = frozenset({"failure", "success", "observed"})
FAILURE_REASONS = frozenset({
    "invalid_credentials", "expired_credential", "unknown_principal", "malformed_request",
    "mfa_failed", "account_locked", "consent_required", "invalid_client",
    "invalid_redirect_uri", "invalid_scope", "unsupported_grant_type", "invalid_token",
    "expired_token", "insufficient_privilege", "scope_not_permitted", "resource_not_owned",
    "tenant_boundary", "explicit_policy_deny", "unauthenticated", "protocol_error",
    "other", "not_applicable",
})
CLIENT_CONFIG_CATEGORIES = frozenset({
    "none", "unregistered_client", "missing_redirect_uri", "redirect_uri_not_registered",
    "expired_client_secret", "invalid_client_secret", "missing_grant_registration",
    "missing_scope_registration", "clock_skew_suspected", "other",
})
REPEAT_PATTERNS = frozenset({
    "not_repeated", "first_observed", "repeated_same_principal_slow",
    "repeated_same_principal_burst", "repeated_same_client", "distributed_many_principals",
    "unknown",
})
# Coarse buckets. Never send an exact count: exact counts plus time are a
# fingerprint, buckets are not.
COUNT_BUCKETS = frozenset({"1", "2-5", "6-20", "21-100", "over-100"})
WINDOW_BUCKETS = frozenset({"under-1m", "1-5m", "5-60m", "1-24h", "over-24h", "unknown"})
AUTHZ_DENIAL_CATEGORIES = frozenset({
    "none", "not_authenticated", "insufficient_privilege", "scope_mismatch",
    "resource_not_owned", "tenant_boundary", "explicit_policy_deny", "other",
})
BOOLEAN_FIELDS = frozenset({
    "known_registered_client", "redirect_uri_matches_registration", "same_principal_repeated",
    "multiple_distinct_principals", "token_replay_indicator", "authorization_probe_indicator",
})
ENUM_FIELDS = {
    "protocol": PROTOCOLS,
    "flow": FLOWS,
    "outcome": OUTCOMES,
    "failure_reason": FAILURE_REASONS,
    "client_config_category": CLIENT_CONFIG_CATEGORIES,
    "repeat_pattern": REPEAT_PATTERNS,
    "count_bucket": COUNT_BUCKETS,
    "window_bucket": WINDOW_BUCKETS,
    "authz_denial_category": AUTHZ_DENIAL_CATEGORIES,
}
REQUIRED_FIELDS = frozenset({"protocol", "flow", "outcome"})
DEFAULTS = {
    "failure_reason": "not_applicable",
    "client_config_category": "none",
    "repeat_pattern": "unknown",
    "count_bucket": "1",
    "window_bucket": "unknown",
    "authz_denial_category": "none",
}
ALLOWED_FIELDS = frozenset({"schema_version"}) | frozenset(ENUM_FIELDS) | BOOLEAN_FIELDS
SIGNAL_KEY = "authn_signal"

# Coarse reasons that are routinely a person mistyping, a credential aging out,
# or a lockout policy. Advisory ordering input only — never intent.
ROUTINE_USER_ERROR_REASONS = frozenset({
    "invalid_credentials", "expired_credential", "unknown_principal", "mfa_failed",
    "malformed_request",
})
# Reasons a producer must classify itself; they are not mapped to a cause here.
AUTHZ_REASONS = frozenset({
    "insufficient_privilege", "scope_not_permitted", "resource_not_owned",
    "tenant_boundary", "explicit_policy_deny", "unauthenticated",
})

# Legacy Rust/Python OAuth event kinds, mapped to the coarsest possible signal.
# They carry no failure reason, no client-configuration category and no
# repetition evidence, which is exactly the upstream gap documented in
# docs/signal-schema.md.
LEGACY_FAILURE_KINDS = frozenset({
    "user_authentication_failed", "authentication_failed", "authorization_denied",
    "permission_denied", "access_denied",
})
LEGACY_SUCCESS_KINDS = frozenset({
    "user_authenticated", "authentication_succeeded", "authorization_allowed",
    "authorization_code_validated", "token_validated", "client_validated",
})


def _field(obj, key):
    return obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)


def _serialize(normalized):
    return json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode("utf-8")


def normalize_signal(raw):
    """Return the fixed-shape normalized signal, or None if it is unusable.

    Rejection is total: an unknown key, an unknown enum literal, a non-boolean
    value, a missing required field, a non-string value or an over-limit
    serialization all yield None so the caller abstains and nothing partial is
    forwarded.
    """
    if not isinstance(raw, dict):
        return None
    if not set(raw) <= ALLOWED_FIELDS:
        return None
    version = raw.get("schema_version")
    if type(version) is not str or len(version.encode("utf-8")) > MAX_SCHEMA_VERSION_BYTES:
        return None
    if version != SCHEMA_VERSION:
        return None
    for name in REQUIRED_FIELDS:
        if name not in raw or type(raw[name]) is not str or raw[name] not in ENUM_FIELDS[name]:
            return None
    for name, allowed in ENUM_FIELDS.items():
        if name in raw and (type(raw[name]) is not str or raw[name] not in allowed):
            return None
    for name in BOOLEAN_FIELDS:
        if name in raw and raw[name] is not None and type(raw[name]) is not bool:
            return None
    normalized: dict[str, object] = {"schema_version": version}
    for name, allowed in ENUM_FIELDS.items():
        # Required fields were validated above; optional ones fall back to the
        # documented default so the shape never varies between producers.
        normalized[name] = raw[name] if name in REQUIRED_FIELDS else raw.get(name, DEFAULTS[name])
    for name in sorted(BOOLEAN_FIELDS):
        normalized[name] = raw.get(name)
    if len(_serialize(normalized)) > MAX_SIGNAL_BYTES:
        return None
    return normalized


def project_signal(envelope, key=SIGNAL_KEY):
    """Extract and validate the producer-supplied normalized signal.

    The producer must attach ``authn_signal`` explicitly. Anything else on the
    envelope — identifiers, error text, metadata, tracing — is never read.
    """
    return normalize_signal(_field(envelope, key))


def signal_from_legacy_event(envelope):
    """Derive the coarsest v1 signal from an existing OAuth event envelope.

    This exists so operators can see what the boundary looks like before they
    ship producer changes. It intentionally leaves `failure_reason` at `other`
    and the repetition booleans unset: the legacy event carries no such
    evidence, so the classifier abstains instead of inventing a cause.
    """
    event = _field(envelope, "event")
    kind = _field(event, "event_type")
    if type(kind) is not str:
        return None
    if kind in LEGACY_FAILURE_KINDS:
        outcome = "failure"
    elif kind in LEGACY_SUCCESS_KINDS:
        outcome = "success"
    elif isinstance(kind, str):
        return None
    else:
        return None
    return normalize_signal({
        "schema_version": SCHEMA_VERSION,
        "protocol": "oauth2",
        "flow": "unknown",
        "outcome": outcome,
        "failure_reason": "other" if outcome == "failure" else "not_applicable",
        "authz_denial_category": "other" if kind in {"authorization_denied", "permission_denied",
                                                     "access_denied"} else "none",
    })
