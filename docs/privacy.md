# Privacy and threat model

**What are we protecting?** Authentication events may contain user/client identifiers, IPs, tokens, headers, errors, metadata, timestamps, and trace context. Sending these to an external assessment service, a log sink, or a static Pages site would create unnecessary exposure. The provider is a separate trust boundary; even coarse events may reveal operational information, so obtain approval and understand its terms before enabling cloud calls.

## Controls in this MVP

| Boundary | Control | Remaining risk |
| --- | --- | --- |
| OAuth envelope → projection | A fresh object containing only known `event_kind`, `severity`, and derived `outcome`; unknown kinds/severities skipped. No arbitrary metadata forwarding. | Those coarse values still disclose event types to the provider. Event kind alone cannot establish intent. |
| Queue → worker | Bounded in-memory queue, one worker, short TTL; drop on overload. | At-most-once observations can be lost; not an audit ledger. |
| Worker → provider | HTTPS request with bearer key, finite timeout and response-size cap; no redirects or proxy use; no retry. | A timed-out socket call may continue briefly in its dedicated thread. Provider availability and handling remain external. |
| Provider → alert | Validate model and choice response; threshold and abstention; callback receives only fixed `event_kind`, `outcome`, `assessment`. | An alert can be wrong or incomplete. Your callback controls onward storage and routing. |
| Library → operations | Fixed-label aggregate counters and timing; no raw envelope, exception text, provider body, or credentials logged or persisted by this library. | Other bus plugins, app logs, APM, or your callback may behave differently. Review them separately. |

The projection does **not** inspect, hash, copy, or serialize `id`, `user_id`, `client_id`, IP address, token, header, timestamp, `metadata`, `error`, correlation/idempotency data, or tracing context. The outbound choice question and three-field state are the only application payload. Keep the API key in a secret manager and out of the repository, logs, browser, and GitHub Pages.

## What the lookout cannot know

A single coarse event cannot show account takeover, a sequence of attempts, rate or velocity, a specific identity, or whether an access decision was correct. Even an apparently routine assessment is **not** a certificate of safety. A high-confidence “suspicious” assessment is not verified attack detection. Review an alert against trusted internal evidence under existing access controls; do not attach raw event fields to the outbound provider request.

Future signals, if needed, should be bounded non-identifying booleans or numeric aggregates computed upstream and separately privacy-reviewed, then explicitly allowlisted and tested. Avoid turning the projection into a generic serializer. SAML assertions, attributes, NameID, and session identifiers must not enter a future adapter.

!!! danger "Never make shadow findings an authorization policy"
    A cloud outage, queue drop, model change, false positive, or false negative must not change who can access the service. Automated intervention would require a separate policy, safety, privacy, and measurement review.
