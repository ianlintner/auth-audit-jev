# Local shadow pilot (synthetic events only)

A contained, **advisory, shadow-only** deployment on the owner's homelab. It exists to
measure the real Jev round trip and prove rollback. It is not production monitoring and
it never changes an access decision.

| Item | Value |
| --- | --- |
| Approved by | Owner decision 2026-11-20 ("use best rec"): local homelab only, synthetic events only, free `api.typesafe.ai`, no production or real-user data |
| Process | `systemd --user` unit `auth-audit-jev-pilot`, bound to `127.0.0.1:4021` |
| Producer | the real `oauth2_server.services.events_bus.EventBus` and `emit_event` from `python-oauth2-server`, publishing four **synthetic** scenarios |
| Path | decision stub → `publish_best_effort` → `AuditEventBridge` → bounded queue (16, 5 s TTL) → one worker → Jev (3 s timeout, no retry) → alert file |
| Metrics | Prometheus job `auth_audit_jev_pilot` (15 s), dashboard UID `auth-audit-jev-pilot`, six alert rules |

## Controls

* **Secrets** live in `~/.config/auth-audit-jev/` (mode 0600): `typesafe.key`, `admin.token` (control endpoints), `metrics.token` (read-only scrape). Nothing is in the repo or unit file. The metrics token is also copied world-readable into `~/observability/prometheus/rules/` so the Prometheus container can read it; it only grants `GET /metrics` on a loopback port.
* **Protected metrics**: `/metrics` needs a bearer token (401 otherwise). Control endpoints need the admin token; the metrics token is rejected there. `/healthz` and `/readyz` are unauthenticated and expose only state.
* **No event input**: there is no endpoint that accepts an event body. `POST /pilot/synthetic?scenario=` picks from `authn_failure`, `authz_denial`, `authn_success`, `authz_allow`.
* **Hard call budget**: `AUDIT_PILOT_MAX_LIVE_CALLS` (default 200 per process). Excess calls count as `error`.
* **No enforcement**: the decision is computed and returned *before* the event is published. Nothing reads an audit result.
* **Lifecycle**: the plugin starts and stops with the service (`audit plugin started` / `audit plugin stopped` in the journal; SIGTERM drains and detaches it).

## Kill switch and rollback (fastest first)

```sh
touch ~/.config/auth-audit-jev/KILL                 # no token or HTTP needed; effective within ~1 s, blocks resume
curl -XPOST -H "Authorization: Bearer $(cat ~/.config/auth-audit-jev/admin.token)" localhost:4021/pilot/kill
systemctl --user disable --now auth-audit-jev-pilot # full stop; the producer app is untouched
rm ~/.config/auth-audit-jev/KILL                     # then POST /pilot/resume, or restart the unit, to re-enable
```

Kill removes the consumer from `EventBus.plugins`, drops queued work and stops the worker, so zero provider calls follow. Full removal: disable the unit, delete the `auth_audit_jev_pilot` job and rule file from `~/observability`, remove `~/.config/auth-audit-jev`. Backups of the edited Prometheus files are `*.bak-pilot-20261120`.

## Measured results (live, 2026-11-20, `evaluation/pilot-run.json`)

Driver: `python3 scripts/pilot_drive.py`. Synthetic events only; 59 live Jev calls.

| Measure | Result |
| --- | --- |
| Jev call duration, 42 sequential calls | p50 0.118 s, p95 0.154 s, p99 0.241 s, max 0.241 s (the first cold call before the run took 1.15 s) |
| Event to result (publish to terminal verdict), same 42 | p50 0.119 s, p95 0.154 s, p99 0.242 s |
| Event to **alert** against live Jev | **No data: 0 alerts.** Live Jev answered `other` below the 0.8 threshold for all 40 failure/denial events and `routine` for the 2 success events |
| Burst of 60 events (no waiting) | caller response p50 1.2 ms, p99 51 ms; 17 reached Jev (all abstain), **43 dropped as `queue_full`**, 0 expired |
| Access decisions | identical in every phase, including while audit was killed and while Jev abstained |
| Privacy leak test | canaries in user, client, IP, token, error and trace fields: 0 hits in the outbound request, `/metrics`, `/pilot/state`, alert file and journal; 0 transport-level blocks |
| Kill switch | 2.5 ms to detach; 0 provider calls afterwards; file-based kill also verified live |

**Alert path, separate run with a fake Jev** (`evaluation/pilot-run-fake-jev-alert-path.json`): a loopback stand-in that always answers `suspicious` at 0.95 (`AUDIT_PILOT_FAKE_JEV=suspicious`, port 4022, torn down afterwards, never used by the deployed unit). 42/42 failure and denial events produced an advisory alert; event-to-alert p50 0.1005 s, p95 0.1010 s, p99 0.1011 s. This latency is dominated by the fake's fixed 0.1 s sleep, so it validates plumbing and the dashboard, not Jev.

### What this does and does not show

* It shows the producer → bounded queue → live Jev → validation path works, is nonblocking, leaks no canary, and rolls back instantly.
* It does **not** show Jev is useful here. With only `{event_kind, severity, outcome}`, the live model abstained on 100% of failure/denial events. That is expected for three coarse fields and is the correct safe behavior, but the pilot currently yields no alerts. Richer, privacy-reviewed signals (see the `authn-signal/v1` layer) are the next experiment, not this one.
* Event-to-alert and event-to-result are measured with `?sync=1` probes where the queue is otherwise empty; under load they include queueing. They exclude real OAuth request-path latency.
* Natural login-failure and authorization-denial emission from `python-oauth2-server` is not shown: those events are injected synthetically on the real bus.
* Jev responses include no `cost_usd`. Token counts are exported; "free" is the owner's statement about the endpoint, not something this data proves.
* Grafana dashboard provisioning: the file is in the provider directory and Grafana logged no provisioning error, but the Grafana admin credentials in the compose file no longer authenticate, so `meta.provisioned` was **not** verified through the API. All nine dashboard queries execute successfully against Prometheus (empty panels are shown as no data, never zero).

## Live compatibility finding fixed here

`api.typesafe.ai` returns `usage` with `input_tokens` and `output_tokens` only. The validator required `cost_usd`, so it would have treated every live answer as invalid and masked any suspicious verdict as an abstain. `cost_usd` is now optional (still validated if present); tokens stay mandatory. The v1 `signal` layer's validator has the same requirement and was not changed here.

## Operate

```sh
sh scripts/pilot_install.sh                          # refresh release copy + restart unit
curl localhost:4021/readyz                           # {"ready": true, "audit": "enabled"|"killed"|"no_key"}
python3 scripts/pilot_drive.py --n 20 --burst 60     # measurement run (uses ~60 live calls)
python3 scripts/gen_pilot_dashboard.py               # regenerate deploy/observability/*.json
```

Deploy files live in `deploy/` (unit, dashboard, rules, promtool tests). Run the rule tests with `promtool test rules deploy/observability/auth-audit-jev-pilot.test.yml`.
