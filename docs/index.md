# A lookout, not a gatekeeper

**Rat Intelligence** is a small, experimental shadow-mode audit for OAuth events. It lets [TypeSafe Jev](https://typesafe.ai/) assess a deliberately narrow description of an event *after* the event is emitted. It can send a coarse advisory signal to your own alert callback. It **does not** grant, deny, delay, or repair access.

<div class="hero-line">Observe the tunnel. Keep the gate where it is.</div>

<div class="card-grid" markdown>
<div class="feature-card" markdown>
### 🐀 Small footprint
A bounded queue and one worker sit off the request path. Under pressure, events are dropped rather than slowing an OAuth decision.
</div>
<div class="feature-card" markdown>
### 🔒 Narrow view
Only fixed event-kind and severity enums, plus a derived outcome, go to Jev. No names, IDs, IPs, tokens, metadata, or trace context.
</div>
<div class="feature-card" markdown>
### 👁️ Human review
A “suspicious” result may generate an alert. It is a prompt to investigate, not proof of an attack or a policy verdict.
</div>
</div>

!!! warning "Experimental, not a security control"
    This MVP has offline fake-transport tests, but no live provider compatibility check, production request-latency study, or detection-accuracy validation. OAuth events and a small canonical IAM outcome vocabulary are recognized; no IAM or SAML producer is integrated. Keep existing authorization, logging, incident response, and human review in place.

## Pick a path

- [Run an offline local example](getting-started.md) without sending anything to a provider.
- [See the architecture](architecture.md) and exactly where the decision boundary sits.
- [Understand alerts](alerts.md), abstentions, and what this signal cannot establish.
- [Review the threat model](privacy.md) before opting into cloud processing.
- [Plan integration](integrations.md) with a Python event bus, a Rust producer, or future IAM/SAML sources.
- [Measure decision latency](measurement.md) without confusing worker timing for request-path safety.

*The Ikit Claw aesthetic is a wink; the safeguards are not. No warpstone-powered enforcement is hiding in this library.*
