"""Opt-in, off-path `EventPlugin` adapter for the Python OAuth2 event bus.

The OAuth2 server (`python-oauth2-server`) already ships an in-process,
fire-and-forget event bus: `oauth2_server/services/events_bus.py` defines
`AuthEvent`, `EventEnvelope`, the `EventPlugin` Protocol (`name`, `emit`,
`health_check`), `EventFilter`, `EventBus.publish_best_effort` and the
`emit_event` helper. Enabling the bus is a server-side decision
(`OAUTH2_EVENTS_BACKEND`); nothing here needs it to be on.

Three things live in this module:

* :func:`project_event` — the *single* allowlist boundary. It is the only
  function that reads a raw envelope, and it returns a fresh dict of three
  reviewed fields or `None`. Long, idempotent, side-effect free.
* :class:`AuditEventBridge` / :class:`AuditEventConsumer` —
  `EventPlugin`-shaped objects the server's bus can hold. The bridge accepts
  the *full* envelope (a bus plugin cannot ask the server for a pre-trimmed
  event), projects it at ingress to count `skipped`/`oversized`, and hands the
  raw envelope to the :class:`~auth_audit_jev.AuditPlugin`, which applies its
  own `project_event` boundary. The consumer takes an already-projected
  mapping, re-derives the projection, and rebuilds a minimal envelope before
  handing it to the plugin.
* :func:`install_audit_plugin` / :func:`remove_audit_plugin` — append or
  detach that consumer on an existing `EventBus.plugins` list, leaving
  every other plugin and `EventBus._fan_out` untouched.

The call path
-------------

`EventBus.publish_best_effort` spawns one `asyncio.create_task` per event and
returns immediately. Inside that task the bus calls `bridge.emit`, which does
one dict read plus one `put_nowait`; the worker task inside `AuditPlugin` does
the provider call. The OAuth request therefore never awaits this module.

The import direction matters: this module imports the library, never the
reverse, so the adapter can be deleted, uninstalled or simply never imported
without changing what the server does.

Pinned contract
---------------

`project_event` reads exactly two attributes off the envelope — the event's
`event_type` and `severity` — and copies both into a new dict with a derived
`outcome`:

===========================  ============================  ===============
OAuth scenario               `event_type`                  `outcome`
===========================  ============================  ===============
failed login                 `user_authentication_failed`  failure
                             `authentication_failed`
token rejection              `token_expired`               observed
                             `token_revoked`
                             `authorization_code_expired`
scope/permission denial      `permission_denied`           failure
                             `authorization_denied`
                             `access_denied`
success                      `user_authenticated`          success
                             `authentication_succeeded`
                             `authorization_allowed`
                             `token_validated`
                             `authorization_code_validated`
===========================  ============================  ===============

Exactly three fields leave the process towards Jev:
`{"event_kind", "severity", "outcome"}`. Everything else on the envelope —
`id`, `user_id`, `client_id`, `metadata` (IP, headers, tokens), `error`,
`timestamp`, `correlation_id`, `idempotency_key`, `traceparent`,
`tracestate`, `attributes`, `producer`, `produced_at` — is never read,
copied, hashed or serialized.

Enforced by `tests/test_eventbus_adapter.py`.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Iterable

from . import EVENTS, FAILURES, SEVERITIES, SUCCESSES, AuditPlugin

logger = logging.getLogger("auth_audit_jev.eventbus")

__all__ = [
    "ADAPTER_NAME",
    "ENABLE_ENV_VAR",
    "MAX_ENUM_BYTES",
    "MAX_ENVELOPE_BYTES",
    "SUPPORTED_EVENT_TYPES",
    "AuditEventBridge",
    "AuditEventConsumer",
    "contract_state",
    "envelope_from_state",
    "install_audit_plugin",
    "project_event",
    "registered_event_types",
    "remove_audit_plugin",
]

ADAPTER_NAME = "auth_audit_jev"

#: Environment variable an operator sets to opt in to cloud export. The
#: adapter never reads the environment itself: the *server's* wiring decides,
#: so enabling it is one explicit, reviewable line at the call site.
ENABLE_ENV_VAR = "AUTH_AUDIT_DEV_ENABLED"

#: Maximum UTF-8 byte length of a single projected enum value. Enforced at
#: ingress, before the plugin queue, so an oversized capture is counted as
#: `oversized` instead of travelling further into the decision path or into a
#: provider request. A real `EventEnvelope` never trips this: the longest
#: allowlisted kind is 30 bytes.
MAX_ENUM_BYTES = 64

#: Cap on a producer-built envelope handed to
#: :func:`envelope_from_state`. Defined here as well as on the server side so
#: the adapter has a documented local bound and never builds an oversized
#: payload by accident.
MAX_ENVELOPE_BYTES = 8192

#: Event kinds the projection recognises, grouped by the OAuth scenario the
#: contract tests pin. Everything outside this set is skipped. Do not widen
#: this set without a privacy review and a matching test case.
SUPPORTED_EVENT_TYPES: frozenset[str] = frozenset(
    {
        # failed login
        "user_authentication_failed",
        "authentication_failed",
        # token rejection / expiry / revocation
        "token_expired",
        "token_revoked",
        "authorization_code_expired",
        # scope / permission denial
        "permission_denied",
        "authorization_denied",
        "access_denied",
        # success
        "user_authenticated",
        "authentication_succeeded",
        "authorization_allowed",
        "token_validated",
        "authorization_code_validated",
    }
)


def _field(obj: Any, key: str) -> Any:
    """Read `key` from a mapping or an object, mirroring the server's models.

    Used only for the two `AuthEvent` enums. Never applied to a container
    field (`metadata`, `attributes`) — those are not read at all.
    """
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def project_event(envelope: Any) -> dict[str, str] | None:
    """Typed, allowlisted projection of an `EventEnvelope` or its serialized form.

    Returns a fresh three-field dict (`event_kind`, `severity`, `outcome`) or
    `None`. `None` means "skip": no provider call, no queue entry, no log line
    with event content, and the caller counts a fixed outcome bucket. It is
    returned when the envelope is malformed, uses an unknown event kind,
    carries an unrecognised severity, or carries an enum over `MAX_ENUM_BYTES`
    UTF-8 bytes.

    This is the pinned contract: `contract_state` below, `AuditEventBridge`,
    the `AuditPlugin` it drives and `tests/test_eventbus_adapter.py` all
    produce or assert the same result for the same envelope.

    Accepts both an object with `.event` / `.event_type` attributes (the
    server's pydantic models) and a mapping with those keys (a
    `model_dump(mode="json")` result or a hand-built test fixture).

    Distinct from `AuditPlugin.emit` in one way only: `emit` reports every
    unprojectable event as `skipped`, whereas the bridge counts an
    over-limit capture as `oversized`. The returned value is identical, which
    `tests/test_eventbus_adapter.py` pins by comparing the two on the same
    serialized envelopes.
    """
    event = _field(envelope, "event")
    kind = _field(event, "event_type")
    severity = _field(event, "severity")
    if type(kind) is not str or type(severity) is not str:
        return None
    if kind not in EVENTS or severity not in SEVERITIES:
        return None
    if len(kind.encode("utf-8")) > MAX_ENUM_BYTES:
        return None
    if len(severity.encode("utf-8")) > MAX_ENUM_BYTES:
        return None
    outcome = "failure" if kind in FAILURES else ("success" if kind in SUCCESSES else "observed")
    return {"event_kind": kind, "severity": severity, "outcome": outcome}


def ingest_event(payload: Any) -> dict[str, str] | None:
    """Project *either* boundary shape into the three-field state.

    This is the function every entry point uses. It exists because two shapes
    legitimately arrive at an `EventPlugin`:

    * a full `EventEnvelope` (object or `model_dump(mode="json")` mapping) —
      what the server's `EventBus` hands a plugin; and
    * an already-projected state mapping (`{"event_kind", "severity"}` or a
      producer's `{"event_type", "severity"}`) — what
      :class:`AuditEventBridge` passes on after it has applied the allowlist.

    Both are re-derived here rather than trusted, so a caller that has
    already trimmed its payload cannot widen the contract, and a caller
    that hands over the raw envelope cannot leak through it. Reads at most
    two enum fields; never touches `metadata`, `attributes`, identifiers,
    `error` or trace context.
    """
    event = _field(payload, "event")
    if event is not None:
        return project_event(payload)
    # No nested `event`: accept the projected/producer shape.
    kind = _field(payload, "event_kind")
    if kind is None:
        kind = _field(payload, "event_type")
    severity = _field(payload, "severity")
    if severity is None:
        severity = "info"
    if type(kind) is not str or type(severity) is not str:
        return None
    if kind not in EVENTS or severity not in SEVERITIES:
        return None
    if len(kind.encode("utf-8")) > MAX_ENUM_BYTES or len(severity.encode("utf-8")) > MAX_ENUM_BYTES:
        return None
    outcome = "failure" if kind in FAILURES else ("success" if kind in SUCCESSES else "observed")
    return {"event_kind": kind, "severity": severity, "outcome": outcome}


def contract_state(envelope: Any) -> dict[str, str] | None:
    """The pinned producer/consumer contract: `project_event` under one name.

    `project_event` is the allowlist boundary; this alias exists so the
    *producer* and the *consumer* cite the same named contract even though
    they live in different packages. A producer that mirrors this projection
    locally (see `docs/eventbus-adapter.md`) documents its serialized
    envelopes as `contract_state`-shaped, and a consumer can assert
    `project_event(envelope) == contract_state(envelope)` — which is what the
    contract tests do.

    There is deliberately no second implementation: an alias cannot drift
    from the boundary it names, whereas a copied function can. `None` means
    skip, exactly as in :func:`project_event`.
    """
    return project_event(envelope)


def envelope_from_state(state: Any) -> dict[str, Any]:
    """Build a minimal serialized `EventEnvelope` from a producer state mapping.

    The other half of the pinned contract, for a *standalone producer*: a
    bridge or adapter process that holds an already-projected mapping (or a
    legacy `AuditPlugin`-style `{"event_type" | "event_kind", "severity"}`
    dict) and wants a bus-shaped envelope to publish. Accepts either spelling
    of the kind, because both spellings reach the same projection, and an
    optional `severity` defaulting to `"info"` — the server's own
    `AuthEvent.severity` default.

    The output carries **only** `event_type` and `severity`:

    ``{"event": {"event_type": ..., "severity": ...}}``

    Every other key the caller passes — identifiers, `metadata`, `error`,
    `attributes`, trace context — is dropped, not forwarded, because this
    function reads two keys and builds a fresh dict. A producer that leaks a
    field into its own envelope therefore still cannot leak it here. The keys
    the server's `AuthEvent` keeps as `None` (`user_id`, `client_id`,
    `error`) are omitted rather than nulled: absence is the narrowest
    possible envelope and the projection reads neither field.

    Raises `TypeError` when `state` is not a mapping and `ValueError` when the
    projection rejects the result — i.e. an unknown kind or severity, or a
    value over `MAX_ENUM_BYTES` UTF-8 bytes — so a producer learns about a bad
    mapping at construction time instead of silently counting `skipped`
    forever. No exception message contains the rejected value.

    The built envelope is capped at `MAX_ENVELOPE_BYTES` when serialized. A
    valid two-enum envelope is ~60 bytes, so the cap only ever trips on a
    programming error.
    """
    if not isinstance(state, dict):
        raise TypeError("state must be a mapping")

    kind = state.get("event_type")
    if kind is None:
        kind = state.get("event_kind")
    severity = state.get("severity")
    if severity is None:
        severity = "info"

    envelope = {"event": {"event_type": kind, "severity": severity}}
    if project_event(envelope) is None:
        raise ValueError("state does not project to an allowlisted event")
    if len(json.dumps(envelope).encode("utf-8")) > MAX_ENVELOPE_BYTES:
        raise ValueError("envelope exceeds MAX_ENVELOPE_BYTES")
    return envelope


def _declared_enum_bytes(envelope: Any) -> int:
    """UTF-8 byte length of the largest declared enum field, else 0.

    Diagnostics only: reads two fields and returns an integer, so no captured
    text can escape through an exception message, a log record or a metric
    label.
    """
    event = _field(envelope, "event")
    largest = 0
    for value in (_field(event, "event_type"), _field(event, "severity")):
        if type(value) is str:
            largest = max(largest, len(value.encode("utf-8")))
    return largest


class AuditEventBridge:
    """`EventPlugin` that adapts a *server* envelope into the audit plugin.

    This is the object to register when the server owns the envelope model
    (its `EventBus` hands plugins the full `EventEnvelope`, including
    identifiers, metadata, error text and trace context). The allowlist is
    applied here, at ingress:

    * the envelope is projected with :func:`project_event`;
    * a projection that is missing, malformed, oversized or unrecognised is
      counted (`oversized` when the declared enum exceeded `MAX_ENUM_BYTES`,
      else `skipped`) and never reaches the queue or the provider;
    * the raw envelope object and its string values are never stored on the
      bridge, never logged, and never attached to a metric label.

    Every failure mode of the server's envelope — a raising property, a
    non-mapping `metadata`, an unexpected model change — collapses into the
    same counted outcome, so this plugin cannot raise into the bus.
    """

    name = ADAPTER_NAME

    def __init__(self, plugin: AuditPlugin) -> None:
        self.plugin = plugin

    @property
    def metrics(self) -> Any:
        """The wrapped plugin's counters, for the installer and for tests."""
        return self.plugin.metrics

    async def start(self) -> None:
        """Start the wrapped plugin's worker. Idempotent, per `AuditPlugin`."""
        await self.plugin.start()

    async def close(self) -> None:
        """Stop the worker and drop queued work."""
        await self.plugin.close()

    async def emit(self, envelope: Any) -> None:
        try:
            state = ingest_event(envelope)
            oversized = state is None and _declared_enum_bytes(envelope) > MAX_ENUM_BYTES
        except Exception:
            # Never surface an exception (or its text) into the bus: the bus
            # logs per-plugin and the audit would be blamed for it.
            state, oversized = None, False
        if state is None:
            self.plugin.metrics.results["oversized" if oversized else "skipped"] += 1
            return
        # Hand the plugin the full envelope, not the projected state:
        # `AuditPlugin.emit` applies its own `project_event` boundary, which
        # reads the nested `event.event_type`, and cannot consume a bare
        # three-field mapping.
        await self.plugin.emit(envelope)

    async def health_check(self) -> bool:
        return await self.plugin.health_check()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditEventBridge plugin={self.plugin!r}>"


class AuditEventConsumer:
    """`EventPlugin` for a producer that hands over an already-projected event.

    Use this instead of :class:`AuditEventBridge` when the caller builds the
    payload itself (see `examples/`), e.g. a bridge process that has already
    dropped the identifiers. It accepts a mapping carrying `event_type` or
    `event_kind` plus an optional `severity`, and re-derives the projection
    with :func:`project_event` rather than trusting the caller: the adapter is
    the boundary, so a caller that accidentally forwards `metadata`, `error`
    or a trace header has those keys dropped, not exported.

    An optional `alert` callback with the same signature as
    `AuditPlugin(alert=...)` is accepted to keep setup mistakes visible — if
    it never fires, no alert is delivered.
    """

    name = ADAPTER_NAME

    def __init__(self, *, enabled: bool = False, alert: Any = None, **plugin_kwargs: Any) -> None:
        # `enabled=False` by default: the adapter is opt-in per install site,
        # never because the package happens to be imported.
        self.plugin = AuditPlugin(enabled=enabled, alert=alert, **plugin_kwargs)

    @property
    def metrics(self) -> Any:
        return self.plugin.metrics

    async def start(self) -> None:
        await self.plugin.start()

    async def close(self) -> None:
        await self.plugin.close()

    async def emit(self, envelope: Any) -> None:
        try:
            state = ingest_event(envelope)
        except Exception:
            state = None
        if state is None:
            self.plugin.metrics.results["skipped"] += 1
            return
        # Rebuild the envelope shape `AuditPlugin.emit` expects: its
        # `project_event` reads the nested `event.event_type`, so hand it a
        # minimal envelope rather than the bare projected mapping.
        await self.plugin.emit(envelope_from_state(state))

    async def health_check(self) -> bool:
        return await self.plugin.health_check()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<AuditEventConsumer plugin={self.plugin!r}>"


def install_audit_plugin(
    event_bus: Any,
    consumer: Any = None,
    *,
    enabled: bool = False,
    wrap: bool = True,
    **plugin_kwargs: Any,
) -> Any:
    """Append an audit consumer to an existing `EventBus`, opt-in and off-path.

    Behaviour:

    * `event_bus` must expose a mutable `plugins` list (the server's
      `EventBus` does). A `None` bus — events disabled — is a no-op returning
      `None`, matching the server's own `emit_event(None, ...)` convention, so
      the wiring can be written without a second branch.
    * With `consumer=None` a new `AuditPlugin` is built from `enabled` and
      `plugin_kwargs`. Calling this with no arguments therefore attaches a
      consumer whose plugin is *disabled*: it counts `disabled` and never
      builds a request. Enabling is explicit (`enabled=True`), and offline
      work should inject a `transport` instead of using an API key.
    * `wrap=True` (default) puts an :class:`AuditEventBridge` in front of the
      plugin, which is what a real server bus needs because it passes the full
      envelope. `wrap=False` appends the plugin itself and is only correct
      when the bus already delivers projected events.
    * An `AuditPlugin`, an `AuditEventBridge` or an `AuditEventConsumer`
      passed as `consumer` is attached as given. A bare `AuditPlugin` is
      already `EventPlugin`-shaped and applies its own `project_event`
      boundary, so it is registered directly and returned as-is (identity
      preserved, so re-installing returns the same object without a second
      fan-out).
    * Existing plugins are left untouched and `EventBus.publish_best_effort`
      keeps its `asyncio.create_task` fire-and-forget fan-out, so a slow or
      failing audit consumer can never delay or fail an OAuth flow.
    * `start()` is **not** called here and nothing in the request path awaits
      the plugin. The caller owns the application lifespan:
      `await plugin_or_bridge.start()` at startup and `await close()` at
      shutdown in a *different* task — never in the shutdown handler of the
      same task that emitted. A consumer that was never started still returns
      immediately from `emit()` and counts `disabled`, so a mis-ordered
      lifespan cannot raise into the bus.
    * Registration is idempotent per bus: installing the same plugin twice
      appends one consumer and returns the one already attached.

    Returns the object to register — the bridge when `wrap=True`, else the
    plugin — so the caller can start/close it, expose `metrics`, or pass it to
    :func:`remove_audit_plugin` on rollback.
    """
    if event_bus is None:
        return None
    plugins = getattr(event_bus, "plugins", None)
    if not isinstance(plugins, list):
        raise TypeError("event_bus must expose a mutable `plugins` list")

    if consumer is None:
        if not wrap:
            raise TypeError("wrap=False requires an explicit consumer")
        consumer = AuditEventBridge(AuditPlugin(enabled=enabled, **plugin_kwargs))
    elif plugin_kwargs:
        raise TypeError("plugin_kwargs are only valid when consumer is omitted")
    elif not isinstance(consumer, (AuditPlugin, AuditEventBridge, AuditEventConsumer)):
        raise TypeError("consumer must be an AuditPlugin, AuditEventBridge or AuditEventConsumer")

    target = consumer.plugin if isinstance(consumer, (AuditEventBridge, AuditEventConsumer)) else consumer
    for attached in plugins:
        if attached is consumer or getattr(attached, "plugin", None) is target:
            return attached
    plugins.append(consumer)
    return consumer


def remove_audit_plugin(event_bus: Any, consumer: Any) -> bool:
    """Detach a previously installed consumer. Returns `True` when removed.

    Accepts whatever :func:`install_audit_plugin` returned, the underlying
    `AuditPlugin`, or an `AuditEventBridge`/`AuditEventConsumer` wrapping it,
    because an operator rolling back may hold any of those references. Matching
    is by identity, so an unrelated plugin is never removed and a double
    removal is a no-op returning `False`.

    This is the library-side half of rollback: removing the consumer takes the
    audit out of the bus's fan-out immediately and no other plugin or bus
    behaviour changes. The caller should still `await close()` afterwards to
    drop queued work and stop the worker. See `docs/eventbus-adapter.md`.
    """
    plugins = getattr(event_bus, "plugins", None)
    if not isinstance(plugins, list):
        return False
    target = getattr(consumer, "plugin", consumer)
    for attached in list(plugins):
        if attached is consumer or getattr(attached, "plugin", None) is target:
            plugins.remove(attached)
            return True
    return False


def registered_event_types() -> Iterable[str]:
    """Sorted view of the allowlisted event kinds (for docs and tests)."""
    return tuple(sorted(SUPPORTED_EVENT_TYPES))
