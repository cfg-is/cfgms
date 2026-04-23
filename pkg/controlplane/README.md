# pkg/controlplane

Central provider for controller-steward communication over the control plane.

Implements the lightweight message channel used for heartbeats, commands, events, and DNA deltas. The data plane (bulk transfers) is handled separately by `pkg/dataplane`.

## Security Model

All control plane communication uses mutual TLS over QUIC. The controller enforces CN-binding: the Common Name in each steward's certificate must match the steward ID it claims in messages. A steward cannot impersonate another steward.

Per-message signing and replay protection (nonce / monotonic sequence) are explicitly out of scope for the current release. See [docs/architecture/controlplane-threat-model.md](../../docs/architecture/controlplane-threat-model.md) for the full threat model, attack scenarios, and the rationale for these scope decisions.

## Packages

- `interfaces/` — Provider contracts (import these in business logic)
- `providers/` — Concrete implementations (do not import directly)
- `types/` — Shared message types (Command, Event, Heartbeat, Response)
