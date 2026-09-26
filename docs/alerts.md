# What an alert means

The provider is asked to choose **`suspicious`**, **`routine`**, or **`other`** from a very small event description. This is a coarse advisory classification, not a determination about a person, a session, an exploit, or authorization correctness.

| Result | What the plugin does | What an operator should infer |
| --- | --- | --- |
| Valid `suspicious` at or above the confidence threshold | Counts `recommendation`; calls your callback with fixed `event_kind`, `outcome`, `assessment` fields if one is supplied. Counts `alerted` only after that callback succeeds. | Investigate with independently governed internal evidence. Do not assume an attack occurred. |
| Valid `routine` at or above threshold | Counts `routine`; no callback. | No advisory flag from this one limited event; not proof of safety. |
| `other`, low confidence, invalid/mismatched response | Counts `abstain`; no callback. | The plugin cannot draw a usable conclusion. |
| Timeout, transport error, queue full/expired, disabled or unknown event | Records the appropriate aggregate result; no callback. | Monitoring may have a blind spot. Do not reinterpret it as benign traffic. |

The default threshold is 0.8 and requires a well-formed response: Jev-family model name, provider-reported usage, sole `assessment` choice answer, allowed choice and probability fields, finite confidence and consistent probabilities. This checks response *shape*, not model accuracy. There is no proven precision, recall, or false-positive rate for this project, and no live provider compatibility test has been performed.

## Operating guidance

- Decide where your controlled callback sends safe alerts and who reviews them. It must be fast and nonblocking; callback errors are counted, not logged. This library has no durable delivery or built-in deduplication.
- Monitor `Metrics.snapshot()` for fixed-label `results`, `queue_depth`, `inflight`, `provider_calls`, and provider-call duration sum/max; `Metrics.prometheus()` returns an exposition string for a protected scrape endpoint. Sudden drops, abstentions, timeouts, or queue pressure matter as much as alerts. Do not add identities as metric labels.
- Investigate using existing security processes. Use the event kind as a lead, not as an identity or root-cause report. Correlation with richer private logs stays inside your own approved systems.
- Keep the plugin observational. It does not revoke tokens, change policies, block a login, or notify an end user by itself.

[See the architecture](architecture.md) for the nonblocking path, or [measure latency](measurement.md) before making any operational claims.
