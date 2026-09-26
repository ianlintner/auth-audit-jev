# Getting started

The library needs Python 3.11 or newer and has no runtime dependencies outside the standard library. Start offline: no API key or customer data is needed for the example below.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

## Run the local Docker example

From the repository root, with Docker Compose installed:

```sh
docker compose up --build -d
curl -fsS http://127.0.0.1:8765/health
curl -fsS -X POST http://127.0.0.1:8765/demo
curl -fsS http://127.0.0.1:8765/metrics
docker compose down
```

This **synthetic-only** container is not an OAuth server: it emits a fixed fake failure, uses a scripted fake Jev response, and shows safe alerts plus aggregate metrics. It has no provider key, accepts no customer event body, and cannot decide access. Compose binds to `127.0.0.1` only; the GitHub Pages site is static documentation and does not host this service.

## Try the shadow worker without cloud calls

Run this from the repository root after installing. The injected fake transport returns `other`, so no alert is emitted. This tests the shape and lifecycle, **not** provider behavior or detection quality.

```python
import asyncio
from auth_audit_jev import AuditPlugin

async def fake_transport(request):
    print(request["state"])
    return {
        "model": "jev-latest",
        "usage": {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0},
        "answers": {
            "assessment": {
                "type": "choice",
                "choice": "other",
                "confidence": 0.9,
                "probabilities": {"suspicious": 0.0, "routine": 0.0, "other": 1.0},
            }
        },
    }

async def main():
    plugin = AuditPlugin(transport=fake_transport, alert=print)
    await plugin.start()
    try:
        await plugin.emit({"event": {"event_type": "user_authentication_failed", "severity": "warning"}})
        await plugin.join()  # Only for tests or administration, never in a request handler.
        print(plugin.metrics.snapshot())
    finally:
        await plugin.close()

asyncio.run(main())
```

## Opt in to a real provider only after review

Set `TYPESAFE_API_KEY` in your process environment through a secret manager, not in source or Pages. Create `AuditPlugin(alert=your_safe_callback, enabled=True)` and start/close it with the application lifecycle. Without an injected transport or key, `start()` leaves the worker disabled. `health_check()` reports whether its worker is active. The callback receives only `event_kind`, `outcome`, and `assessment`; make it fast and nonblocking. Use a separate, controlled service if alerts need durable delivery.

The plugin implements the expected `name`, `emit(envelope)`, and `health_check()` interface for a Python `EventBus(plugins=[...])`, but this repository does **not** wire a specific server or deploy a provider integration. [Follow the integration roadmap](integrations.md) before enabling it in an OAuth service. Never call `join()` in an authorization handler or make cloud availability a condition for an access decision.

!!! note "Build these docs locally"
    In a separate docs environment, install `mkdocs>=1.6,<2` and `mkdocs-material>=9,<10`, then run `mkdocs serve` or `mkdocs build --strict`. Publishing is handled by the [Pages workflow](https://github.com/ianlintner/auth-audit-jev/blob/main/.github/workflows/docs.yml), not by a local push.
