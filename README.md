# Shadow-mode auth audit with TypeSafe Jev

An experimental **observation-only** Python `EventPlugin` for OAuth event envelopes and explicitly mapped IAM authn/authz outcome events. It evaluates allowlisted event kinds asynchronously and optionally emits a small advisory alert. It never blocks, denies, grants, or changes an OAuth flow. Do not put a provider request on the authorization path. A high-confidence alert is a review hint, **not proof of malicious activity**.

Human-readable guide: [Rat Intelligence documentation](https://ianlintner.github.io/auth-audit-jev/).

## Install and run tests

Python 3.11+; runtime uses only the standard library.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

### Local Docker example (synthetic only)

```sh
docker compose up --build -d
curl -fsS http://127.0.0.1:8765/health
curl -fsS -X POST http://127.0.0.1:8765/demo
curl -fsS http://127.0.0.1:8765/metrics
docker compose down
```

The container is a **scripted event-source demonstration, not an OAuth server**. It sends a fixed fake login-failure event through the plugin and a fake Jev transport, then exposes advisory output at `/alerts` and aggregate `/metrics`. It never contacts Jev, does not accept arbitrary event payloads, and cannot enforce access. Compose publishes only on local loopback, with a read-only unprivileged container and no API key. GitHub Pages hosts documentation only; no service runs there.

For local opt-in cloud use, set `TYPESAFE_API_KEY` in the process environment via your secret manager; never commit it. **Tests use fake transport and do not call the provider.** Start/stop on application lifespan; add the plugin to the Python server's `EventBus(plugins=[...])` only in a separate integration change, not by modifying that server here:

```python
from auth_audit_jev import AuditPlugin

# alert receives ONLY {event_kind, outcome, assessment}, no raw envelope.
plugin = AuditPlugin(alert=lambda safe: safe_alert_sink(safe), enabled=True)
await plugin.start()
# Register plugin with the existing EventBus on startup; EventBus calls await plugin.emit(envelope).
# ... on shutdown: await plugin.close()
```

`start()` stays disabled when no key is configured (unless a test transport is explicitly injected). `health_check()` reflects an active worker. `close()` cancels work, drops pending jobs, and never waits on the cloud. `join()` drains accepted jobs for tests/graceful administration; do not call it in an OAuth request handler. A callback must be fast and nonblocking; it is invoked in the worker and exceptions are counted, not logged. If an alert needs persistent delivery, pass the safe alert to a separate controlled observability service; no raw payload is retained here.

## Privacy and decision boundary

`project_event` recognizes the Rust/Python OAuth event enum literals plus six **canonical, opt-in IAM outcome literals** (`authentication_failed`, `authentication_succeeded`, `authorization_denied`, `authorization_allowed`, `permission_denied`, `access_denied`) and severity `info`, `warning`, `error`. IAM producers must map into these names explicitly; the OAuth servers do not yet emit them. The cloud-bound `state` contains exactly `event_kind`, `severity`, and an outcome enum derived from the event kind (`failure`, `success`, `observed`). It does **not** inspect, hash, copy, or serialize `id`, `user_id`, `client_id`, IP, token, header, timestamp, `metadata`, `error`, correlation, idempotency or trace context; unknown event types and severities are skipped. The outcome enum is only an event-type heuristic, not an independent verdict on access. Consequently, an individual event cannot establish attack patterns, velocity, account takeover, or authorization correctness. For more useful detection, upstream should compute rigorously privacy-reviewed, bounded numeric/bool aggregates and explicitly extend the allowlist with tests; never forward raw metadata.

One `choice` question with explicit `suspicious`, `routine`, `other` criteria goes to `POST https://api.typesafe.ai/v1/systemone` (`model: jev-latest`, bearer auth). The response must match the Jev model family (`jev-latest` or a resolved numeric Jev version), sole answer name, valid choice/probabilities, provider-reported usage and confidence >= 0.8; `other`, invalid/low-confidence responses, timeouts and transport errors abstain. No live provider compatibility smoke was run. Alerts include only fixed enum values. No raw envelopes, provider response bodies, exceptions, or credentials are logged or persisted by this library. Be aware the **existing OAuth event bus may itself have independent logging plugins**; assess those separately.

Queue maxsize defaults to 64, one worker, 2-second queue TTL, 1-second request timeout, 16 KiB response cap, no retry, redirects disabled, proxy bypassed. HTTP work uses one dedicated thread; a timed-out synchronous socket operation may continue until its socket timeout, and shutdown cannot kill an already-running thread. Sustained failures can drop events; at-most-once in-memory delivery is intentional. `Metrics.snapshot()` exposes fixed-label aggregates and `Metrics.prometheus()` returns Prometheus text (serve it only through a protected scrape endpoint; it does not itself open a port). Counters include queue drops, abstention, timeouts, provider-reported token/cost totals and a provider-call duration histogram. These are **not production request-path p99 measurements** or a claim that intervention is ready. There is no built-in alert deduplication, cross-process aggregation, calibration, circuit breaker, or durable storage; keep cloud disabled by default in unreviewed deployments (`enabled=False`).

## Rust and SAML boundary

Rust `oauth2-events::EventEnvelope` has equivalent event type/severity plus private IDs, metadata and tracing. A future Rust adapter should reconstruct the same explicit enum-only projection, add its own bounded asynchronous worker and contract tests against this payload, then attach at the event fan-out rather than authorization middleware. Do not serialize the full Rust envelope to this Python plugin or copy trace context to Jev. SAML assertions/attributes/NameID/session identifiers must never be forwarded. A future SAML event producer should first define a finite, reviewed allowlist of coarse authentication outcome enums and non-identifying aggregate signals; it is not supported by this OAuth-only MVP.

## Validation limits

Offline fake-transport tests cover projection, privacy, provider response validation, queue pressure, timeout/error abstention, alert threshold, lifecycle and bounded HTTP worker concurrency. No production latency benchmark, live provider call, detection accuracy study, or Rust/Python server integration was performed. Alerts require human review; enabling automated access intervention would require a separate policy and safety review.
