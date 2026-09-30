Producer/transport adapter for Rust ``oauth2-events``: verified wire contract.

This document is the *only* supported way to feed Rust ``oauth2-events``
envelopes into this repository's shadow audit. It is written against the Rust
sources at ``crates/oauth2-events`` and every claim below is asserted by
``tests/test_rust_events.py``.

## What the Rust producer actually emits

``EventEnvelope`` (``src/envelope.rs``) serializes to:

```json
{
  "event": {
    "id": "…",
    "event_type": "user_authentication_failed",
    "timestamp": "2026-09-28T12:00:00Z",
    "severity": "warning",
    "user_id": "…", "client_id": "…",
    "metadata": { "…": "…" }, "error": "…"
  },
  "idempotency_key": "…", "traceparent": "…", "tracestate": "…",
  "correlation_id": "…", "producer": "…", "produced_at": "…",
  "attributes": { "…": "…" }
}
```

``EventType`` and ``EventSeverity`` use ``#[serde(rename_all = "snake_case")]``
and ``#[serde(rename_all = "lowercase")]``, so the wire spellings are exactly:

| Rust variant | wire string |
| --- | --- |
| ``UserAuthenticationFailed`` | ``user_authentication_failed`` |
| ``UserAuthenticated`` | ``user_authenticated`` |
| ``TokenValidated`` / ``TokenRevoked`` / ``TokenExpired`` | ``token_validated`` / ``token_revoked`` / ``token_expired`` |
| ``AuthorizationCodeCreated`` | ``authorization_code_created`` |
| ``AuthorizationCodeValidated`` | ``authorization_code_validated`` |
| ``AuthorizationCodeExpired`` | ``authorization_code_expired`` |
| ``TokenCreated`` | ``token_created`` |
| ``ClientValidated`` / ``ClientRegistered`` / ``ClientDeleted`` | ``client_validated`` / ``client_registered`` / ``client_deleted`` |
| ``UserLogout`` | ``user_logout`` |

Severity literals are ``info``, ``warning``, ``error``.

## The authz-gap you must know about

``EventType`` has **no** authorization-denial variant. The Rust crate today can
express authentication failure and token/client/code lifecycle events, but not
``authorization_denied``. The allowlist in ``auth_audit_jev`` accepts
``authorization_denied``/``authorization_allowed`` for other producers, so a
Rust producer that needs authz-denial coverage must first add an event variant
in ``rust-oauth2-server`` — a separate, reviewed change in that repository, not
something this adapter can paper over. Mapping a token/client event onto
``authorization_denied`` would fabricate a signal that was never observed.

## What may leave the process

Only the projection produced by ``project_rust_envelope`` travels:

```python
{"event_kind": "user_authentication_failed", "severity": "warning",
 "attributes": {"region": "us-east-1"}}
```

Never exported, and actively counted as a drop when present on the wire:

| Wire field | Why it is dropped |
| --- | --- |
| ``event.id`` | per-event identifier |
| ``event.user_id``, ``event.client_id`` | subject/client identifiers |
| ``event.metadata`` | free-form, may hold IP/token/header/UA |
| ``event.error`` | free-form, may embed credentials or subject data |
| ``event.timestamp`` | precise per-event timing |
| ``idempotency_key`` | stable per-event correlation key |
| ``correlation_id`` | per-request identifier |
| ``producer`` | producer/logical-origin identifier |
| ``produced_at`` | precise per-event timing |
| ``traceparent`` / ``tracestate`` | distributed-trace context |
| unknown ``attributes`` keys | not privacy-reviewed |

Both attribute keys **and values** must match finite enums in
`SAFE_ATTRIBUTE_VALUES` (`auth_method`, `grant_type`, `endpoint`, `operation`,
`region`). Unknown values are dropped, even for a known key: a bounded string
could still contain a user ID, token, IP address, or other private data.
Expanding either enum is a privacy change requiring review and a negative test.

The trailing-``Z`` timestamp parsing is deliberately not interpreted: the
adapter never reads ``timestamp`` or ``produced_at``, it only refuses them, so
no clock or format assumption is baked into the export.

## Rolling it out

1. Build the plugin with no provider credential and ``enabled=False``. The
   adapter is constructed with ``enabled=False`` and returns ``disabled`` for
   every call without touching the queue write path.
2. Enable the plugin only after metrics show the adapter is not dropping the
   event kinds you expect. The relevant counters are
   ``auth_audit_adapter_events_total{outcome=…}`` and
   ``auth_audit_adapter_redacted_fields_total{kind=…}``.
3. Roll back by constructing the adapter with ``enabled=False``, or by
   deleting its single call site at the fan-out boundary. There is no second
   code path, no provider retry, and no persisted state to unwind.

## What this adapter never does

* It never blocks. ``emit_envelope`` performs one ``put_nowait`` and returns.
* It never authorizes or denies traffic. The projection is advisory telemetry;
  no result routes back to an OAuth decision.
* It never retries. A full queue, an expired entry, or a provider failure is
  accounted and dropped.
