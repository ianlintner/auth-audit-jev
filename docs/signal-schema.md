# The `authn-signal/v1` producer contract

The legacy projection sends exactly three fields — `event_kind`, `severity`, an
outcome enum — and that is not enough to tell a mistyped password from an
unregistered OAuth client from credential stuffing. All three look like
"authentication failed, warning".

`authn-signal/v1` is the reviewed replacement: a producer computes coarse enums,
bounded count/time buckets and tri-state booleans, attaches them to the event as
`authn_signal`, and `signal.py` validates them. Nothing free-text is accepted, so
an envelope carrying raw error strings, identifiers, IPs, tokens, headers,
metadata or trace context is rejected **wholesale** instead of being copied and
then redacted.

## Why the schema is coarse on purpose

Every field is a closed enum or a boolean. There is no string field, no number
field, and no free-form map. That is a privacy decision, not a modelling
limitation: a schema with a `details: dict` escape hatch becomes a serializer for
whatever the caller puts in it. Bounded buckets are used instead of exact counts
because *an exact count plus a timestamp is a fingerprint; a bucket is not.*

## Fields

`schema_version` must be the literal `authn-signal/v1`. A different version is
rejected, so a future schema change cannot be silently reinterpreted under v1
rules.

Required (`protocol`, `flow`, `outcome` are the minimum usable signal):

| Field | Values |
| --- | --- |
| `protocol` | `oauth2`, `oidc`, `saml`, `iam`, `unknown` |
| `flow` | `authorization_code`, `client_credentials`, `refresh_token`, `device_code`, `resource_owner_password`, `implicit`, `token_introspection`, `token_revocation`, `session_login`, `session_refresh`, `client_registration`, `unknown` |
| `outcome` | `failure`, `success`, `observed` |

Optional enums — omitted optional fields are filled from a documented default so
the serialized shape never varies between producers:

| Field | Default | Values |
| --- | --- | --- |
| `failure_reason` | `not_applicable` | `invalid_credentials`, `expired_credential`, `unknown_principal`, `malformed_request`, `mfa_failed`, `account_locked`, `consent_required`, `invalid_client`, `invalid_redirect_uri`, `invalid_scope`, `unsupported_grant_type`, `invalid_token`, `expired_token`, `insufficient_privilege`, `scope_not_permitted`, `resource_not_owned`, `tenant_boundary`, `explicit_policy_deny`, `unauthenticated`, `protocol_error`, `other`, `not_applicable` |
| `client_config_category` | `none` | `none`, `unregistered_client`, `missing_redirect_uri`, `redirect_uri_not_registered`, `expired_client_secret`, `invalid_client_secret`, `missing_grant_registration`, `missing_scope_registration`, `clock_skew_suspected`, `other` |
| `repeat_pattern` | `unknown` | `not_repeated`, `first_observed`, `repeated_same_principal_slow`, `repeated_same_principal_burst`, `repeated_same_client`, `distributed_many_principals`, `unknown` |
| `count_bucket` | `1` | `1`, `2-5`, `6-20`, `21-100`, `over-100` |
| `window_bucket` | `unknown` | `under-1m`, `1-5m`, `5-60m`, `1-24h`, `over-24h`, `unknown` |
| `authz_denial_category` | `none` | `none`, `not_authenticated`, `insufficient_privilege`, `scope_mismatch`, `resource_not_owned`, `tenant_boundary`, `explicit_policy_deny`, `other` |

Optional tri-state booleans — `true`, `false` or absent (`None`). `None` means
"the producer did not evaluate this", which is honest and is *not* the same as
`false`:

`known_registered_client`, `redirect_uri_matches_registration`,
`same_principal_repeated`, `multiple_distinct_principals`,
`token_replay_indicator`, `authorization_probe_indicator`

The serialized signal is capped at `MAX_SIGNAL_BYTES` (1024). The cap is
deliberately above the worst case the reviewed enums can produce together (565
bytes), so a legitimate signal is never rejected for size while unreviewed growth
still is.

## A complete example

```python
envelope = {
    "event": {"event_type": "user_authentication_failed", "severity": "warning"},
    "authn_signal": {
        "schema_version": "authn-signal/v1",
        "protocol": "oauth2",
        "flow": "authorization_code",
        "outcome": "failure",
        "failure_reason": "invalid_credentials",
        "repeat_pattern": "first_observed",
        "count_bucket": "1",
        "window_bucket": "under-1m",
        "known_registered_client": True,
    },
}
```

## Producer rules

- Emit only enum literals from this document. Do not invent literals; an unknown
  literal rejects the whole signal.
- Use `None` for a boolean you did not evaluate. Do not guess `False`.
- Never include an identifier, IP, token, header, error string, trace context or
  free-form metadata — not in `authn_signal` and not beside it.
- Compute the buckets upstream, where the raw counts already exist. Do not add an
  exact-count field "for now".
- A producer that cannot supply evidence for a field should omit it. The
  classifier abstains on insufficient evidence, which is a better outcome than a
  fabricated category.

## Upstream fields that do **not** exist yet

The Rust `oauth2-events::EventEnvelope` and the Python OAuth servers currently
carry event type, severity, and private IDs/metadata/tracing. They do **not**
compute any of the fields above. This is the real gap, and it is why the schema
is a producer contract rather than a parsing change:

| Needed field | Why upstream cannot supply it today |
| --- | --- |
| `failure_reason` | The servers emit `user_authentication_failed` without a reason code. The distinction between a wrong password, an expired credential and an unknown principal is discarded at the source. |
| `client_config_category` | Client-registration state is not consulted at event emission; `invalid_client` and `invalid_redirect_uri` are not subdivided. |
| `repeat_pattern`, `count_bucket`, `window_bucket` | These are aggregates over a window. A per-event emitter has no window; the producer needs bounded local aggregation before emission. |
| `known_registered_client`, `redirect_uri_matches_registration` | Requires a lookup against registration state at emit time. |
| `multiple_distinct_principals`, `token_replay_indicator`, `authorization_probe_indicator` | Requires cross-event correlation, which the current per-event fan-out does not have. |

## Reading the two boundaries side by side

`SignalAuditPlugin` falls back to the legacy projection **only when the producer
attached no `authn_signal` at all**. That lets an operator see what the boundary
would look like before shipping producer changes. An attached-but-invalid
`authn_signal` is a contract violation and is rejected outright — it is never
quietly downgraded to the three-field projection, because that would hide the
producer bug that produced it.

The projection fallback leaves `failure_reason` at `other` and the repetition
booleans unset, so it cannot fabricate a category: the classifier abstains.

## Validation of the provider response

One batched request is sent with several atomic choice questions: the likely
category, plus independent confidence and urgency answers. A category is
accepted only when the response is well formed — Jev-family model identifier,
provider-reported finite usage, exactly the batched answer names, valid choice
and probability fields — **and** the category confidence clears that category's
own threshold:

| Category | Threshold |
| --- | --- |
| `user_error` | 0.85 |
| `client_misconfiguration` | 0.80 |
| `suspected_abuse` | 0.90 |
| `ambiguous` | 0.90 |
| `other` | never alerts |

`suspected_abuse` has the highest threshold because a false abuse flag is the
most expensive error here. A provider that self-declares `low` confidence may
only return `user_error`, the conservative answer; every other category abstains.
The residual `other` category never alerts.

Per-category thresholds and the local candidate rules are calibrated on
**synthetic fixtures only** (`fixtures.py`). Those fixtures contain no real
identifiers, traffic or provider data, and agreement with their labels is a
plumbing check — not accuracy, and not a claim about real-world detection.

## Rollout

1. Keep `SignalAuditPlugin` disabled (`enabled=False`, the default).
2. Ship producer changes that attach `authn_signal` behind a feature flag.
3. Enable the shadow worker with a test transport and confirm `skipped`,
   `abstain` and `candidate_conflict` counters behave.
4. Only then attach a real provider key, and only after `docs/privacy.md`
   review. Existing alert meaning is unchanged until this is validated.
