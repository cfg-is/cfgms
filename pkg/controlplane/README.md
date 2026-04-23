# pkg/controlplane

Pluggable control plane provider for controller-steward communication.

The control plane carries lightweight messages (heartbeats, commands, events, DNA
deltas) over gRPC-over-QUIC with mandatory mutual TLS.

## Security Model

All control plane communication requires mTLS. Each steward must present a certificate
signed by the CFGMS certificate authority, and the controller enforces that the
certificate Common Name (CN) matches the steward ID asserted at registration and on
every subsequent message (CN-binding, epic #747).

The threat model — including attack scenarios, deliberate out-of-scope decisions on
per-message signing and replay protection, and PO-ratified rationale — is documented
in [docs/architecture/controlplane-threat-model.md](../../docs/architecture/controlplane-threat-model.md).

## Packages

| Package | Purpose |
|---------|---------|
| `interfaces/` | Provider contract (`Provider` interface) and contract tests |
| `providers/grpc/` | gRPC-over-QUIC implementation |
| `types/` | Shared message types (Command, Event, Heartbeat, Response) |
