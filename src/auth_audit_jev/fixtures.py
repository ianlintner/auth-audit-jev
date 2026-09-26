"""Synthetic labeled fixtures for offline calibration.

Every fixture in this file is invented for the repository. None contains real
identifiers, traffic, customers or provider traffic, and none is a claim about
real-world detection quality. The set covers four things a category label must
survive:

- ordinary class examples (typo, expired credential, unregistered client);
- **ambiguous** examples where two categories genuinely compete;
- **adversarial** sequences — repeated/uniform failures designed to look like
  one class while being labeled another;
- **false-positive traps** — inputs that a careless classifier would flag as
  abuse although they are boring, or clear it although they are not.

`offline_transport()` is a deterministic stand-in for the provider: it answers
the batched questions from the fixture's own label, so tests exercise the
plumbing, the validation and the abstention paths without any cloud call.
"""
from __future__ import annotations

from .classify import CATEGORIES
from .signal import SCHEMA_VERSION

FAKE_USAGE = {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}

SCRUB_TOKENS = (
    "SECRET_IDENTIFIER", "SECRET_PRINCIPAL", "SECRET_CLIENT", "SECRET_IP", "SECRET_TOKEN",
    "SECRET_HEADER", "SECRET_ERROR", "SECRET_TRACE", "SECRET_METADATA", "SECRET_TIMESTAMP",
    "SECRET_CORRELATION", "SECRET_PASSWORD", "SECRET_CLIENT_SECRET", "SECRET_ASSERTION",
)


def signal(**overrides):
    base = {
        "schema_version": SCHEMA_VERSION,
        "protocol": "oauth2",
        "flow": "authorization_code",
        "outcome": "failure",
    }
    base.update(overrides)
    return base


# (name, signal, expected category or None for "should abstain", note)
FIXTURES = [
    # --- ordinary user error -------------------------------------------------
    ("user_error_typo_single",
     signal(failure_reason="invalid_credentials", repeat_pattern="first_observed",
            count_bucket="1", window_bucket="under-1m", known_registered_client=True,
            redirect_uri_matches_registration=True),
     "user_error", "one mistyped password for a registered client"),
    ("user_error_expired_credential",
     signal(failure_reason="expired_credential", repeat_pattern="not_repeated",
            known_registered_client=True),
     "user_error", "stale password, no repetition"),
    ("user_error_lockout_after_typos",
     signal(failure_reason="account_locked", repeat_pattern="repeated_same_principal_slow",
            count_bucket="6-20", window_bucket="1-24h", same_principal_repeated=True,
            known_registered_client=True),
     "user_error", "lockout policy after ordinary typos; must NOT read as abuse"),
    ("user_error_unknown_principal",
     signal(failure_reason="unknown_principal", repeat_pattern="first_observed",
            count_bucket="1", known_registered_client=True),
     "user_error", "user typed the wrong account name once"),

    # --- client misconfiguration ---------------------------------------------
    ("misconfig_missing_redirect_uri",
     signal(failure_reason="invalid_redirect_uri", client_config_category="missing_redirect_uri",
            flow="authorization_code"),
     "client_misconfiguration", "client did not send redirect_uri"),
    ("misconfig_unregistered_redirect_uri",
     signal(failure_reason="invalid_redirect_uri",
            client_config_category="redirect_uri_not_registered",
            redirect_uri_matches_registration=False, known_registered_client=True),
     "client_misconfiguration", "redirect URI absent from registration"),
    ("misconfig_unregistered_client",
     signal(failure_reason="invalid_client", client_config_category="unregistered_client",
            flow="client_credentials", known_registered_client=False),
     "client_misconfiguration", "client id unknown to this tenant"),
    ("misconfig_expired_client_secret",
     signal(failure_reason="invalid_client", client_config_category="expired_client_secret",
            flow="client_credentials", known_registered_client=True),
     "client_misconfiguration", "rotated secret not deployed"),
    ("misconfig_missing_scope_registration",
     signal(failure_reason="invalid_scope", client_config_category="missing_scope_registration",
            flow="authorization_code", known_registered_client=True),
     "client_misconfiguration", "requested scope not registered for the client"),
    ("misconfig_clock_skew",
     signal(failure_reason="invalid_token", client_config_category="clock_skew_suspected",
            flow="token_introspection"),
     "client_misconfiguration", "environmental clock skew, not an attacker"),

    # --- suspected abuse -----------------------------------------------------
    ("abuse_stuffing_burst",
     signal(failure_reason="invalid_credentials", repeat_pattern="repeated_same_principal_burst",
            count_bucket="21-100", window_bucket="under-1m", same_principal_repeated=True,
            multiple_distinct_principals=True, known_registered_client=False),
     "suspected_abuse", "high-rate repeated failures across principals"),
    ("abuse_distributed_spray",
     signal(failure_reason="invalid_credentials",
            repeat_pattern="distributed_many_principals", count_bucket="over-100",
            window_bucket="1-5m", multiple_distinct_principals=True),
     "suspected_abuse", "one source spraying many principals"),
    ("abuse_token_replay",
     signal(failure_reason="invalid_token", flow="refresh_token",
            token_replay_indicator=True, repeat_pattern="repeated_same_principal_burst",
            count_bucket="6-20", window_bucket="1-5m"),
     "suspected_abuse", "refreshed token replay"),
    ("abuse_privilege_probing",
     signal(failure_reason="insufficient_privilege", flow="session_login",
            outcome="failure", authz_denial_category="insufficient_privilege",
            authorization_probe_indicator=True, repeat_pattern="repeated_same_client",
            count_bucket="21-100", window_bucket="5-60m"),
     "suspected_abuse", "sequential scope escalation attempts"),

    # --- ambiguous: two classes genuinely compete -----------------------------
    ("ambiguous_burst_on_misconfigured_client",
     signal(failure_reason="invalid_client", client_config_category="unregistered_client",
            flow="client_credentials", known_registered_client=False,
            repeat_pattern="repeated_same_client", count_bucket="21-100",
            window_bucket="under-1m"),
     "ambiguous", "a fat-fingered deployment retrying fast looks exactly like probing"),
    ("ambiguous_repeat_without_context",
     signal(failure_reason="invalid_credentials", repeat_pattern="repeated_same_principal_slow",
            count_bucket="2-5", window_bucket="5-60m"),
     "ambiguous", "a few repeats, no client registration fact available"),
    ("ambiguous_authz_denial_single",
     signal(failure_reason="insufficient_privilege", flow="session_login",
            authz_denial_category="insufficient_privilege", repeat_pattern="first_observed",
            count_bucket="1"),
     "ambiguous", "one denial could be a user hitting a link they lack rights to"),
    ("ambiguous_unknown_flow",
     signal(failure_reason="other", flow="unknown", repeat_pattern="unknown",
            count_bucket="1", window_bucket="unknown"),
     "ambiguous", "coarse signal carries no usable reason"),

    # --- adversarial / false-positive traps ----------------------------------
    ("trap_uniform_burst_actually_typo",
     signal(failure_reason="invalid_credentials", repeat_pattern="repeated_same_principal_burst",
            count_bucket="6-20", window_bucket="1-5m", same_principal_repeated=True,
            multiple_distinct_principals=False, known_registered_client=True,
            redirect_uri_matches_registration=True),
     "user_error", "adversarial: burst shape but single principal, registered client, no spray"),
    ("trap_expired_secret_repeated_looks_like_replay",
     signal(failure_reason="invalid_client", client_config_category="expired_client_secret",
            flow="client_credentials", repeat_pattern="repeated_same_client",
            count_bucket="over-100", window_bucket="1-24h", known_registered_client=True,
            token_replay_indicator=False),
     "client_misconfiguration",
     "adversarial: over-100 repeats of a stale secret; volume alone must not mean abuse"),
    ("trap_clock_skew_many_tokens",
     signal(failure_reason="invalid_token", client_config_category="clock_skew_suspected",
            flow="token_introspection", count_bucket="21-100", window_bucket="1-5m",
            repeat_pattern="repeated_same_client"),
     "client_misconfiguration", "adversarial: many invalid tokens from a skewed host clock"),
    ("trap_denial_is_not_authentication_failure",
     signal(failure_reason="tenant_boundary", flow="session_login", outcome="failure",
            authz_denial_category="tenant_boundary", repeat_pattern="first_observed",
            count_bucket="1", window_bucket="under-1m"),
     "ambiguous", "false-positive guard: an authz denial is not evidence of credential attack"),
    ("trap_success_never_classified_as_abuse",
     signal(outcome="success", failure_reason="not_applicable",
            repeat_pattern="not_repeated", count_bucket="1"),
     "other", "label guard: a success event is not abuse evidence"),

    # --- must abstain: insufficient evidence ---------------------------------
    ("abstain_bare_signal",
     signal(failure_reason="other", repeat_pattern="unknown", count_bucket="1",
            window_bucket="unknown", authz_denial_category="none"),
     "ambiguous", "nothing but a bare failure must not produce a confident category"),
]

# Signals that must never reach the provider at all.
REJECTED_SIGNALS = [
    ("unknown_enum_reason", signal(failure_reason="SECRET_ERROR")),
    ("unknown_extra_field", dict(signal(), user_id="SECRET_PRINCIPAL")),
    ("raw_metadata_field", dict(signal(), metadata={"ip": "SECRET_IP"})),
    ("raw_error_text", dict(signal(), error="SECRET_ERROR text with spaces")),
    ("unbounded_string_reason", signal(failure_reason="invalid-credentials-please-check-"
                                                    "your-entered-username-and-password")),
    ("wrong_schema_version", {**signal(), "schema_version": "authn-signal/v0"}),
    ("missing_required_field", {k: v for k, v in signal().items() if k != "flow"}),
    ("non_boolean_flag", signal(known_registered_client="yes")),
    ("exact_count_instead_of_bucket", signal(count_bucket="37")),
    ("trace_context_field", dict(signal(), traceparent="SECRET_TRACE")),
]


def provider_response(category, confidence="high", urgency="routine_review",
                      model="jev-latest", usage=None, category_probability=None,
                      confidence_probability=None, urgency_probability=None):
    """Deterministic fake provider payload for a fixture label."""
    probabilities = _distribute(CATEGORIES, category,
                                category_probability if category_probability is not None else .92)
    return {
        "model": model,
        "usage": dict(usage if usage is not None else FAKE_USAGE),
        "answers": {
            "likely_category": {"type": "choice", "choice": category,
                                "confidence": .92 if category_probability is None else category_probability,
                                "probabilities": probabilities},
            "confidence": {"type": "choice", "choice": confidence,
                           "confidence": .9 if confidence_probability is None else confidence_probability,
                           "probabilities": _three(confidence, confidence_probability)},
            "urgency": {"type": "choice", "choice": urgency,
                        "confidence": .9 if urgency_probability is None else urgency_probability,
                        "probabilities": _four(urgency, urgency_probability)},
        },
    }


def _distribute(options, chosen, value):
    """Spread the remainder evenly so the probabilities still sum to 1.

    A fixture that sets a non-default category probability must not also break
    the sum-to-one invariant the validator enforces, or the test would be
    measuring the fixture's arithmetic instead of the validator's policy.
    """
    remainder = (1.0 - value) / (len(options) - 1)
    return {option: (value if option == chosen else remainder) for option in options}


def _three(chosen, value=None):
    values = {"low": .05, "medium": .05, "high": .05}
    values[chosen] = .9 if value is None else value
    return values


def _four(chosen, value=None):
    values = {"routine_review": .03, "elevated_review": .03,
              "immediate_review": .03, "unknown": .03}
    values[chosen] = .91 if value is None else value
    return values


class OfflineTransport:
    """A fake local upstream: answers from the fixture label, never the network.

    `response_for` may be a callable taking the request, or a mapping from the
    signal's `failure_reason` to a provider payload. The default answers
    `ambiguous` for everything, which is the conservative floor.
    """

    def __init__(self, response_for=None):
        self.response_for = response_for
        self.calls = []

    async def __call__(self, request):
        self.calls.append(request)
        if callable(self.response_for):
            return self.response_for(request)
        if isinstance(self.response_for, dict):
            reason = request["state"]["signal"]["failure_reason"]
            return self.response_for[reason]
        return provider_response("ambiguous")


def offline_transport(response_for=None):
    return OfflineTransport(response_for)
