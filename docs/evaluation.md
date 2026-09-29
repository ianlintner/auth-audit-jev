# Offline synthetic evaluation

Reproducible, offline evaluation of the shadow auth-audit layer **with the dedup
change from PR #5 applied**. PR #5 is *not* merged: this evaluation is
stacked on its exact revision, so the numbers describe that draft's behavior
and nothing on the main line.

## What this is

- **Offline and deterministic.** No socket, no provider key, no paid request. The
  transport is a pure function of the request, so a stored report can be
  regenerated and compared field-by-field.
- **Synthetic and labeled.** 21 hand-written scenarios, each carrying a ground-truth
  category (or "abstain"), a declared provider answer, and a deliberate
  mis-answer pair (`fp_trap_*`, `fn_trap_*`) so the harness can observe a wrong
  provider answer instead of assuming the provider is always right.
- **A simulation, not a service measurement.** Every unavailable metric is listed
  below as *not measured*, with the reason. Nothing here is a claim about live Jev.

## Run it

```sh
python3 scripts/run_synthetic_eval.py                      # human-readable
python3 scripts/run_synthetic_eval.py --json evaluation/report.json
```

Exit code: `0` when the measured gates pass, `1` when a gate fails, `2` on setup
error. The committed run is `evaluation/run-output.txt` (stdout) and
`evaluation/report.json` (machine-readable).

Tests: `python3 -m unittest tests.test_evaluation -v` (determinism, privacy
negative tests, gates, rollback gate).

## Measured — this run

Source of truth: `evaluation/report.json` (`synthetic-eval/v1`), 21 scenarios,
1 tenant plus a no-tenant group.

| Metric | Value |
| --- | --- |
| Provider calls, dedup disabled (baseline) | 21 |
| Provider calls, dedup enabled | 19 |
| Provider calls saved | 2 |
| Suppression rate | 0.0952 |
| False positives (abuse alert on a benign event) | 1 |
| False negatives (missed abuse escalation) | 1 |
| Provider abstentions (`abstain` result counter) | 2 |
| Dedup counter `abstain_from_dedup` | 15 |
| No-alert outcomes (includes two suppressed repeats) | 4 |
| Escalations evaluated / required | 2 / 2 |
| Offline label agreement | 0.8824 |
| Queue drops, oversized burst probe (queue size 2, 10 emits) | 7, caller never blocked (max emit duration recorded) |
| Dedup registry final size vs capacity (8, 100 distinct keys) | 8, 92 evicted, bounded |

Per-category (offline, synthetic labels only):

| Category | support | predicted | precision | recall |
| --- | --- | --- | --- | --- |
| `user_error` | 8 | 9 | 0.8889 | 1.0000 |
| `client_misconfiguration` | 5 | 3 | 1.0000 | 0.6000 |
| `suspected_abuse` | 5 | 5 | 0.8000 | 0.8000 |
| `ambiguous` | 0 | 0 | n/a | n/a |
| `other` | 0 | 0 | n/a | n/a |

The one false positive and one false negative are not harness bugs: they are the
two scenarios where the *simulated provider is deliberately wrong*
(`fp_trap_provider_says_abuse_on_stale_secret`,
`fn_trap_provider_says_user_error_on_spray`). They exist to prove the harness can
detect a wrong answer at all; a zero count with no trap would be meaningless.

The `client_misconfiguration` recall of 0.6 is the honest consequence of two
scenarios where the provider declines to name a category
(`abstain_provider_malformed`) or names the residual (`abstain_provider_returns_residual`).
The layer abstains rather than guessing, which is the intended conservative
behavior; it is reported as abstain, not as an error.

### Latency and cost

- **Worker-side offline durations** are recorded (`offline_latency`: samples, mean,
  max) and are explicitly labeled in both the JSON (`note`) and the text report as
  *not* production request p99. They measure local plumbing only.
- **Cost is zero by construction.** The fake provider reports zero usage; no paid
  request is made.

## Not measured — stated as unavailable, never as zero

These are in `not_measured` in the report and are excluded from the gates. Reading
any of them out of this report would be a category error.

| Metric | Why it is not measured |
| --- | --- |
| `live_jev_confidence` | No live provider call is made; the fake returns fixed labels. |
| `event_to_alert_latency` | No event source, bus, or wall clock is attached offline. |
| `production_p99_latency` | Worker-side offline durations are a plumbing proxy. |
| `provider_cost_usd` | Offline fake usage is zero; no paid request occurs. |
| `live_provider_accuracy` | Synthetic labels are not ground truth about real traffic. |
| `real_traffic_precision_recall` | The corpus is invented and small; not a population estimate. |
| `inline_request_path_effect` | Shadow-only; nothing here touches an authorization decision. |

## Offline harness gates (not pilot approval)

Thresholds below validate the offline harness using fields it actually measures.
They **do not establish pilot readiness**: the deliberately wrong fake-provider
answers yield one false positive and one false negative, and no live Jev
calibration exists. The pilot remains blocked until separately approved data,
measured live metrics, privacy review and an owner decision.

| Gate | Threshold | Rationale |
| --- | --- | --- |
| `escalations_never_hidden` | hidden escalations == 0 | A repeat that crossed a threshold must never be suppressed. |
| `dedup_saves_calls` | saved calls >= 2 | The dedup change must actually save provider calls, not just relabel them. |
| `abstains_present` | actual provider abstentions >= 2 | Residual and malformed fake responses must abstain. |
| `false_positive_trap_detected` | declared false-positive trap recorded | The harness must detect an intentionally wrong fake-provider answer. |
| `false_negative_trap_detected` | declared false-negative trap recorded | A downgraded spray must be reported as a missed abuse alert. |
| `unavailable_metrics_marked` | >= 5 entries incl. `event_to_alert_latency` | The evaluator must refuse to imply it measured the live service. |
| `queue_drops_are_counted_not_blocking` | drops > 0 and caller never blocked | A full queue must drop and be visible, not stall the caller. |
| `dedup_state_is_bounded` | registry bounded | Dedup memory must not grow with distinct principals. |
| `no_cross_principal_collapse` | stranger evaluated | One principal's repeat must not suppress a stranger's identical coarse signal. |

**No threshold is defined for any unavailable metric.** There is no alert rule here
for live Jev confidence or event-to-alert latency, because there is no measurement
to attach one to. Adding such a rule requires a live, instrumented deployment.

## Privacy negative tests

`tests/test_evaluation.py::PrivacyNegativeTests` asserts the report carries no raw
identifier or payload:

- No `SECRET_*` scrub token and no bare `SECRET` substring appears in the report.
- No corpus scope/principal literal leaks into the report.
- No `Authorization` / `Bearer` / `api_key` / `answers` / `probabilities` /
  `jev-evil` marker appears in the report.
- The fake provider is a pure function: an unknown signal raises instead of
  falling through to a network call, and `response_for` records no call.

Identifiers are used only to key the local dedup fingerprint and are not emitted.

## Rollback gate

Dedup ships behind a kill switch. The rollback test asserts that with it engaged:

- provider calls equal the baseline exactly, saved calls are 0;
- every scenario is evaluated and nothing is suppressed;
- `DedupLayer.engage_kill_switch()` turns a subsequent repeat from `suppress`
  back into `evaluate`.

So rollback is provable offline: it restores the pre-dedup path with no
suppression.

## Limitations

1. **Synthetic, small, invented.** 21 scenarios is enough to exercise every branch
   and both mis-answer traps; it is not a population estimate and must not be read
   as one.
2. **The provider is a stub.** Precision/recall here measure the *classifier and
   dedup* against declared labels, not Jev's real accuracy.
3. **No live latency, no cost.** Both are marked unavailable above.
4. **Pinned to a draft.** These numbers describe PR #5's revision in an isolated
   worktree. Re-run after any change; do not carry them over.
5. **Timing fields are non-deterministic** by nature and are excluded from the
   determinism comparison.
