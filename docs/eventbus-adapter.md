# Opt-in Python OAuth2 event-bus adapter

`auth_audit_jev.eventbus_adapter` attaches the shadow audit to the **existing** in-process event bus of `python-oauth2-server` (`oauth2_server/services/events_bus.py`). Nothing in this repository imports, patches, or requires that server: the adapter imports *this* library, so deleting the wiring — or never importing it — restores the server's original behaviour exactly.

!!! warning "Opt-in, off-path, observation only"
    Registering the adapter adds one fan-out consumer. It never awaits a provider call in a request path, never raises into the bus, and never changes an OAuth outcome. Rollback is [two steps](#rollback), and the bus keeps working if the adapter is broken, stopped, or absent.

## What the server already gives us

| Server object | Role |
| --- | --- |
| `AuthEvent` | `event_type`, `severity`, `user_id`, `client_id`, `metadata`, `error` |
| `EventEnvelope` | wraps an `AuthEvent` plus `idempotency_key`, `traceparent`, `tracestate`, `correlation_id`, `producer`, `produced_at`, `attributes` |
| `EventPlugin` (Protocol) | `name`, `async emit(envelope)`, `async health_check()` |
| `EventBus.publish_best_effort` | `asyncio.create_task` fan-out; **spawns and returns immediately** |
| `emit_event(bus, ...)` | no-op when `event_bus is None`, i.e. when events are disabled |

`publish_best_effort` is the only public emit entry point and it is already fire-and-forget, so the request path never waits on any plugin. The adapter adds no `await` of its own outside that task.

## Projection: the only boundary that reads an envelope

`project_event(envelope)` is the single allowlist. It reads exactly two attributes — `event.event_type` and `event.severity` — and returns a **fresh** three-field dict, or `None` to mean *skip*:

```python
{"event_kind": "user_authentication_failed", "severity": "warning", "outcome": "failure"}
```

| Scenario | `event_type` | `outcome` |
| --- | --- | --- |
| failed login | `user_authentication_failed`, `authentication_failed` | `failure` |
| token rejection | `token_expired`, `token_revoked`, `authorization_code_expired` | `observed` |
| scope / permission denial | `permission_denied`, `authorization_denied`, `access_denied` | `failure` |
| success | `user_authenticated`, `authentication_succeeded`, `authorization_allowed`, `token_validated`, `authorization_code_validated` | `success` |

Anything else — an unknown kind, an unrecognised severity, a non-string value, a value over 64 UTF-8 bytes — projects to `None` and is counted, never sent.

Never read, hashed, copied, logged or serialised: `id`, `user_id`, `client_id`, `metadata` (IP, headers, tokens), `error`, `timestamp`, `correlation_id`, `idempotency_key`, `traceparent`, `tracestate`, `attributes`, `producer`, `produced_at`. There is no field-name configuration and no generic passthrough; widening the view means a reviewed allowlist change plus tests, see [privacy](privacy.md).

The `outcome` value is derived from the event kind alone. It is **not** a verdict on whether access was correct, and a `failure` kind on a success event is simply a skipped/neutral observation to the model — the audit never sees the decision.

## Setup (exact steps)

**1. Install the library into the server's environment.** The package has no runtime dependencies outside the standard library.

```sh
/path/to/oauth2-server/.venv/bin/python -m pip install -e /path/to/auth-audit-jev
```

This is the only change to the server's build; it adds a package, not an import.

**2. Add one wiring module to the server deployment** (not to this repository). Create `oauth2_server/services/auth_audit_wiring.py` next to `events_bus.py`:

```python
"""Opt-in shadow audit consumer for the OAuth2 event bus — delete to roll back."""
from auth_audit_jev.eventbus_adapter import install_audit_plugin

_consumer = None


def attach(event_bus) -> None:
    """Append the audit consumer to an existing bus. No-op when events are off."""
    global _consumer
    _consumer = install_audit_plugin(event_bus, enabled=True)


async def start() -> None:
    if _consumer is not None:
        await _consumer.start()


async def close() -> None:
    if _consumer is not None:
        await _consumer.close()
```

**3. Call it from the existing lifespan.** Two lines, after the bus is built and before the app starts serving:

```python
from oauth2_server.services import auth_audit_wiring

# existing: app.state.event_bus = build_event_bus(config, recent_events_store)
auth_audit_wiring.attach(app.state.event_bus)
app.add_event_handler("startup", auth_audit_wiring.start)
```

`install_audit_plugin(None, ...)` returns `None`, so a deployment with `OAUTH2_EVENTS_BACKEND` unset/disabled simply does nothing — no second branch needed.

**4. Prove it is off-path and review the config before enabling cloud export.**

- `await app.state.event_bus.health()` must still list every pre-existing plugin (`console`, `in_memory`, `recent_events`) with the audit appended.
- Your provider key stays in a secret manager as `TYPESAFE_API_KEY`. The adapter never reads the environment itself — the server wiring decides.
- Note the server's **existing** plugins are independent loggers. `ConsoleEventLogger` writes full envelope JSON to the server log; assess that separately, since this adapter does not change it.

**5. Enable, then watch.** Start with a low-traffic window, inject a `transport=` for the first smoke, and only then use a real key. Observe `auth_audit_events_total{outcome="disabled|skipped|oversized|queue_full|expired|abstain|timeout|error"}` — a rising `error`/`timeout` with stable request latency is the expected shape of a healthy shadow.

## Registration semantics

`install_audit_plugin(event_bus, consumer=None, *, enabled=False, wrap=True, **plugin_kwargs)`

| Argument | Meaning |
| --- | --- |
| `enabled=False` (default) | The consumer is attached but its plugin counts `disabled` and never builds a request. Opt-in is explicit, not a side effect of importing. |
| `wrap=True` (default) | Only used with `consumer=None`: builds a fresh `AuditPlugin` behind an `AuditEventBridge`, which projects the *full* envelope at ingress and drops anything malformed. |
| `wrap=False` | Only when the bus already delivers projected events; requires an explicit consumer. |
| `consumer=` | An existing `AuditPlugin` / bridge / consumer to attach instead of building one. Attached as given: a bare `AuditPlugin` is already `EventPlugin`-shaped and applies its own `project_event` boundary, so it is registered directly and returned as-is. |

Idempotent per bus: installing the same object twice appends one consumer. `event_bus=None` is a no-op returning `None`. `start()` is **never** called by `install_audit_plugin`; the caller owns the lifespan, and an unstarted consumer still returns immediately from `emit()` while counting `disabled`.

`AuditEventConsumer` is the alternative for a producer that already holds a projected mapping (`{"event_type" | "event_kind", "severity"}`); it re-derives the projection rather than trusting the caller, so a producer that accidentally forwards `metadata`, `error` or a trace header has those keys dropped. `envelope_from_state(state)` builds the minimal `{"event": {"event_type", "severity"}}` envelope for such a producer and raises (without echoing the value) on a mapping that cannot project.

## Bounds

| Bound | Default | Position |
| --- | --- | --- |
| Queue maxsize | 64 | `put_nowait`; full ⇒ count `queue_full`, drop, never block the bus |
| Queue TTL | 2 s | checked by the worker before the provider call ⇒ `expired` |
| Request timeout | 1 s | `asyncio.wait_for` around the transport ⇒ `timeout` |
| Response cap | 16 KiB | read cap on the provider reply ⇒ `abstain`/`error` |
| Worker / thread | 1 in-process worker, 1 HTTP thread | a non-blocking semaphore refuses overlapping socket work |
| Retry | none | no automatic retry; at-most-once, in-memory |
| Circuit behaviour | failure ⇒ abstain | errors and timeouts stay advisory and never select a cheaper model |

Every failure mode collapses to a counted outcome bucket; the one exception is `AuditEventBridge`, which never raises into the bus even if an envelope attribute raises on access. Sustained failure drops observations rather than delaying OAuth. A timed-out socket thread may continue until its own socket timeout — bounded, but not cancellable.

## Rollback

**1. Remove the wiring.** Delete `oauth2_server/services/auth_audit_wiring.py` and the `attach`/`start`/`close` lines from the lifespan. On the next restart the bus is constructed exactly as before, with only its original plugins.

**2. Or detach at runtime, without a restart**, when you hold a reference:

```python
from auth_audit_jev.eventbus_adapter import remove_audit_plugin

remove_audit_plugin(app.state.event_bus, consumer)  # True when removed
await consumer.close()                              # drop queued work, stop the worker
```

`remove_audit_plugin` matches by identity, so no other plugin is touched, a double removal is a no-op returning `False`, and it accepts the bridge, the consumer or the bare `AuditPlugin` — whichever reference the operator kept. It is the same reference `install_audit_plugin` returned.

**3. Immediate cloud kill switch, no code change.** Stop exporting: unset `TYPESAFE_API_KEY` and restart, or detach as above. Either way the container makes no provider call. The pre-existing direct/OAuth routes are unaffected at every step, because nothing here ever replaced them.

**4. Uninstall (optional).** `.venv/bin/python -m pip uninstall auth-audit-jev`. Deleting the package cannot break an import that no longer exists.

After any rollback, confirm `await app.state.event_bus.health()` lists only the original plugins, `recent_events` still serves `GET /admin/api/events/recent`, and a normal login still returns its original response.

## Testing

`tests/test_eventbus_adapter.py` runs offline against serialized envelopes that mirror `EventEnvelope.model_dump(mode="json")` byte-shape and a local bus standing in for `EventBus.publish_best_effort`. It covers the four scenarios above, the `contract_state` × `project_event` agreement, privacy (no raw field in the request, queue, logs or metric labels), opt-in/disabled behaviour, a broken plugin that cannot break the bus, queue and timeout bounds, and rollback of the plugin list. No network and no live Jev call.

```sh
.venv/bin/python -m unittest discover -s tests -v
```

No live provider compatibility smoke has been run for this adapter, and no server integration has been performed in this repository. Wiring a specific deployment is a separate, reviewed change; see [integrations](integrations.md).
