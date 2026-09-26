"""Advisory categorization of a normalized authn/authz signal.

Layering, in order of authority:

1. **Producer facts.** The normalized signal is trusted only to the degree it is
   a closed enum: `failure_reason`, `client_config_category`, `outcome`, bounded
   repetition buckets.
2. **Deterministic local candidate explanations.** A handful of reasons have a
   documented, boring explanation (an unregistered client, a missing redirect
   URI, a clock skew). These are computed in code and attached as *candidate*
   explanations. They never authorize an alert and they never override the
   provider: they are one independent, auditable opinion.
3. **One batched Jev request**, single-shot, with several atomic choice
   questions: the likely category plus independent confidence and urgency
   signals. Not a calculator, not an authorization system, and never the sole
   basis for alerting.

Every category is a hypothesis. `user_error`, `client_misconfiguration` and
`suspected_abuse` are advisory labels, not statements about intent, and
`other`/abstain always remains available.
"""
from __future__ import annotations

import math
import re

from .signal import (
    SCHEMA_VERSION,
    AUTHZ_REASONS,
    ROUTINE_USER_ERROR_REASONS,
)

CATEGORIES = ("user_error", "client_misconfiguration", "suspected_abuse", "ambiguous", "other")
CONFIDENCE_LEVELS = ("low", "medium", "high")
URGENCY_LEVELS = ("routine_review", "elevated_review", "immediate_review", "unknown")

# Local, deterministic candidate explanations keyed by (reason, config category).
# These describe *configuration* states, so they can explain a failure without
# asserting that anything was attempted.
CLIENT_CONFIG_REASONS = {
    "unregistered_client": "client_configuration",
    "missing_redirect_uri": "client_configuration",
    "redirect_uri_not_registered": "client_configuration",
    "expired_client_secret": "configuration_expiry",
    "invalid_client_secret": "credential_mismatch",
    "missing_grant_registration": "configuration_gap",
    "missing_scope_registration": "configuration_gap",
    "clock_skew_suspected": "environmental",
    "other": "unclassified_configuration",
}

HYPOTHESES = {
    "user_error": {
        "summary": "A likely ordinary human or credential-lifecycle failure (typo, expired "
                   "credential, lockout). No repetition or attack-shaped evidence observed.",
        "review": "No action required beyond normal helpdesk handling; do not treat as incident.",
    },
    "client_misconfiguration": {
        "summary": "A likely OAuth client or tenant configuration defect: the client, redirect URI, "
                   "secret or grant is not what the authorization server expects.",
        "review": "Check client registration, redirect URIs, secret rotation and environment "
                  "alignment before any security escalation.",
    },
    "suspected_abuse": {
        "summary": "Signals are consistent with possibly intentional credential guessing, stuffing, "
                   "replay or privilege probing. This is a hypothesis, not established intent.",
        "review": "Correlate with independently governed internal evidence before acting; do not "
                  "block users from this signal alone.",
    },
    "ambiguous": {
        "summary": "Evidence does not separate a routine failure from a misconfiguration or abuse "
                   "attempt; more bounded context is required.",
        "review": "Treat as unknown. Collect the missing bounded signal fields rather than guessing.",
    },
    "other": {
        "summary": "The supplied bounded signal does not map to a reviewed category.",
        "review": "Leave the existing alert meaning unchanged and review the producer mapping.",
    },
}

# Per-category minimum confidence. A category whose evidence is often thin needs
# a higher bar than a bare typo, and abuse is the most expensive to get wrong.
DEFAULT_REVIEW_THRESHOLD = .8
CATEGORY_REVIEW_THRESHOLD = {
    "user_error": .85,
    "client_misconfiguration": .8,
    "suspected_abuse": .9,
    # `ambiguous` is an actionable answer — it says "the bounded signal could not
    # separate the classes, collect the missing fields" — so it must clear a
    # higher bar than a configuration explanation, but it is still answerable.
    "ambiguous": .9,
    "other": 1.01,  # never alert on the residual category
}

QUESTIONS = {
    "likely_category": {
        "type": "choice",
        "instructions": (
            "Classify the likely nature of this authn/authz failure from the bounded signal only. "
            "Never infer identity, intent, geolocation or account ownership. Choose "
            "'user_error' only for an ordinary user or credential-lifecycle failure, "
            "'client_misconfiguration' for a client/tenant configuration defect, "
            "'suspected_abuse' only when repetition or probe evidence supports a possibly "
            "intentional attempt, and 'ambiguous' or 'other' when evidence is insufficient."
        ),
        "criteria": {
            "user_error": "Ordinary user or credential-lifecycle failure with no attack-shaped evidence.",
            "client_misconfiguration": "Client or tenant configuration defect explains the failure.",
            "suspected_abuse": "Repetition, replay or probing is consistent with a possibly intentional attempt.",
            "ambiguous": "Evidence is insufficient to separate the categories.",
            "other": "Signal does not map to any reviewed category.",
        },
    },
    "confidence": {
        "type": "choice",
        "instructions": "State confidence in the category answer alone, independent of urgency.",
        "criteria": {
            "low": "Weak or partly missing evidence.",
            "medium": "Plausible but not well separated from the alternatives.",
            "high": "Clear supporting bounded evidence for this category.",
        },
    },
    "urgency": {
        "type": "choice",
        "instructions": "State human review urgency independently of the category answer.",
        "criteria": {
            "routine_review": "Review during normal business handling.",
            "elevated_review": "Review sooner than normal.",
            "immediate_review": "Review promptly.",
            "unknown": "Urgency cannot be judged from the signal.",
        },
    },
}
QUESTION_NAMES = frozenset(QUESTIONS)
MODEL_FAMILY = re.compile(r"jev-(?:latest|[0-9]+(?:\.[0-9]+)*(?:-[0-9]{8})?)")


def deterministic_candidates(signal):
    """Rule-based candidate explanations derived only from trusted enum fields.

    Returned as candidates, deliberately separate from the provider answer, and
    never sufficient on their own to raise an alert. A missing or mismatched
    redirect URI, for example, is a client registration problem far more often
    than it is an attack, so it is a candidate cause, not a verdict.

    A reason that maps to nothing here yields `unclassified`, which is honest:
    the local rules did not explain it, so the category depends entirely on the
    provider plus abstention.
    """
    reason = signal.get("failure_reason")
    config = signal.get("client_config_category")
    candidates = []
    if config in CLIENT_CONFIG_REASONS and config != "none":
        candidates.append(("client_misconfiguration", CLIENT_CONFIG_REASONS[config]))
    if reason == "invalid_client":
        candidates.append(("client_misconfiguration", "invalid_client_registration"))
    if reason == "invalid_redirect_uri":
        candidates.append(("client_misconfiguration", "redirect_uri_mismatch"))
    if reason in ROUTINE_USER_ERROR_REASONS:
        candidates.append(("user_error", reason))
    if signal.get("token_replay_indicator") is True:
        candidates.append(("suspected_abuse", "token_replay_indicator"))
    if signal.get("authorization_probe_indicator") is True:
        candidates.append(("suspected_abuse", "authorization_probe_indicator"))
    repeat = signal.get("repeat_pattern")
    if signal.get("multiple_distinct_principals") is True or repeat == "distributed_many_principals":
        # Only repetition *across principals* is candidate abuse evidence. A
        # burst of failures against one principal is what a lockout policy, a
        # retrying client or one person with a stale password looks like, and
        # volume alone must never be upgraded to an attack hypothesis.
        candidates.append(("suspected_abuse", "distributed_repetition"))
    if not candidates:
        candidates.append((None, "unclassified"))
    return candidates


def is_authorization_denial(signal):
    """True when the failure is an access denial rather than an authentication failure.

    An authorization denial means the credential was accepted and the access
    decision went the other way, so it is not evidence of credential guessing.
    Callers use this to keep the two classes separate instead of reading every
    `failure` as an attack signal.
    """
    return signal.get("failure_reason") in AUTHZ_REASONS or \
        signal.get("authz_denial_category", "none") != "none"


def build_request(signal, context=None):
    """Batched, single-shot decision request for one normalized signal."""
    state = {"schema_version": SCHEMA_VERSION, "signal": signal}
    if context:
        state["context"] = context
    return {"model": "jev-latest", "state": state, "questions": QUESTIONS}


def validate_response(payload, review_threshold=None):
    """Validate shape and return `(category, confidence_level, urgency)` or None.

    Nothing about the model's category is trusted on shape alone: the answer name
    set must be exactly the batched question set, the model identifier must stay
    inside the pinned Jev family, usage must be provider-reported and finite, and
    the category confidence must clear that category's own threshold.
    """
    try:
        if not isinstance(payload, dict):
            return None
        model = payload.get("model")
        if not isinstance(model, str) or not MODEL_FAMILY.fullmatch(model):
            return None
        usage = payload.get("usage")
        if not isinstance(usage, dict) or any(
                type(usage.get(k)) not in (int, float) or not math.isfinite(usage[k]) or usage[k] < 0
                for k in ("input_tokens", "output_tokens", "cost_usd")):
            return None
        answers = payload.get("answers")
        if not isinstance(answers, dict) or set(answers) != QUESTION_NAMES:
            return None
        parsed = {}
        for name in QUESTION_NAMES:
            answer = answers[name]
            if not isinstance(answer, dict) or answer.get("type") != "choice":
                return None
            options = QUESTIONS[name]["criteria"]
            choice = answer.get("choice")
            confidence = answer.get("confidence")
            probabilities = answer.get("probabilities")
            if type(choice) is not str or choice not in options:
                return None
            if type(confidence) not in (int, float) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
                return None
            if not isinstance(probabilities, dict) or set(probabilities) != set(options):
                return None
            if any(type(p) not in (int, float) or not math.isfinite(p) or not 0 <= p <= 1
                   for p in probabilities.values()):
                return None
            if abs(sum(probabilities.values()) - 1) > .02 or probabilities[choice] < max(probabilities.values()):
                return None
            parsed[name] = (choice, float(confidence))
        category, confidence = parsed["likely_category"]
        if category == "other":
            return None
        if parsed["confidence"][0] == "low" and category != "user_error":
            # A provider that declares low confidence must not produce a
            # category that would drive review. Only the conservative
            # `user_error` answer survives a low self-declared confidence, and
            # it still has to clear its own category threshold below.
            return None
        threshold = review_threshold
        if threshold is None:
            threshold = CATEGORY_REVIEW_THRESHOLD.get(category, DEFAULT_REVIEW_THRESHOLD)
        if confidence < threshold:
            return None
        return category, parsed["confidence"][0], parsed["urgency"][0]
    except (KeyError, TypeError, ValueError):
        return None


def hypothesis(category, candidates):
    """Assemble the advisory record handed to a caller-supplied sink."""
    info = HYPOTHESES[category]
    config_candidate = next((c for c in candidates if c[0] == "client_misconfiguration"), None)
    return {
        "category": category,
        "is_hypothesis": True,
        "summary": info["summary"],
        "review_guidance": info["review"],
        "local_candidate_explanations": [
            {"category": c[0] if c[0] else "unclassified", "kind": c[1]} for c in candidates
        ],
        "client_configuration_explains": config_candidate is not None,
        "authority": "advisory",
    }


def conflicts_with_local_candidates(category, candidates):
    """True when the provider's category disagrees with every local candidate.

    Surfaced as metadata so a reviewer can see the disagreement instead of the
    alert silently picking a side.
    """
    if not candidates:
        return False
    return all(c[0] != category for c in candidates if c[0] is not None)


# How the legacy three-field boundary would have read the same signal. It only
# knows "the event kind was a failure", so it flags every failure; the v1 layer
# is supposed to explain which failures are boring. Comparing the two is how a
# rollout can show sensitivity that would be *lost* as well as friction removed,
# and it is explicitly not a quality measurement of the category.
LEGACY_BASELINE_LABELS = ("agree", "disagree", "incomparable")


def baseline_comparison(signal, category):
    """Compare a v1 category with what the legacy failure/severity heuristic says."""
    if signal.get("outcome") != "failure":
        return "incomparable"
    if category == "suspected_abuse":
        return "agree"
    if category in ("user_error", "client_misconfiguration"):
        return "disagree"
    return "incomparable"
