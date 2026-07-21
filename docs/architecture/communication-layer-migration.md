# Communication Layer Migration Guide

## Status: Migration Complete (Phase 10.11)

As of Phase 10.11 (Stories #519–#522), the previous hybrid transport has been fully replaced
by **gRPC-over-QUIC**. All controller-steward communication now uses a single unified transport:

- **Control Plane** (commands, events, heartbeats): `pkg/controlplane/interfaces` with gRPC provider
- **Data Plane** (config sync, DNA sync, bulk transfers): `pkg/dataplane/interfaces` with gRPC provider
- **Transport layer**: `pkg/transport/quic` — QUIC connection management with mTLS

### What Was Removed

- `pkg/[legacy-broker]` packages — previous broker infrastructure (removed, see git history pre-#519)
- Previous client wrapper packages — replaced by `pkg/controlplane/interfaces` and `pkg/controlplane/types`
- `pkg/quic/client`, `pkg/quic/session` — standalone QUIC client (replaced by transport layer)
- Previous broker go.mod dependency — removed in Issue #522

### What Replaced It

| Before | After |
|--------|-------|
| Previous control plane (port 1883) | gRPC control service over QUIC (port 4433) |
| Standalone QUIC data plane (port 4433) | gRPC data service over QUIC (port 4433) |
| Two separate protocols, two ports | Single unified transport, one port |
| Separate broker process in controller | Lightweight gRPC server on transport listener |

---

## Current Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Feature Code                          │
│  (features/controller, features/steward, etc.)          │
├─────────────────────────────────────────────────────────┤
│  pkg/controlplane/interfaces  │  pkg/dataplane/interfaces│
│  (ControlPlaneProvider)       │  (DataPlaneProvider)     │
├───────────────────────────────┼──────────────────────────┤
│  providers/grpc (gRPC impl)   │  providers/grpc (gRPC)   │
├───────────────────────────────┴──────────────────────────┤
│  pkg/transport/quic (QUIC connection management)         │
│  [mTLS, multiplexed streams, reconnection]               │
└──────────────────────────────────────────────────────────┘
```

## Transport Configuration

The unified transport is configured via the `transport` block in `controller.cfg`:

```yaml
transport:
  listen_addr: "0.0.0.0:4433"   # Single port for the control + data plane (heartbeats, commands, cfg/DNA sync)
  use_cert_manager: true          # Use controller's cert manager for TLS (recommended)
  max_connections: 50000          # Maximum concurrent steward connections
  keepalive_period: 30s           # How often keepalive probes are sent
  idle_timeout: 5m                # Connection idle timeout
```

> **Scope of "one port".** The unification above consolidates the **control and data planes** onto a single QUIC port (4433) — it replaced the previous two-protocol/two-port control+data split. It does **not** cover **installer / steward-binary distribution**, which is served over the controller's **HTTPS REST listener** (port 9080), the same channel operators, browsers, and package managers use. Both the controller push and the steward self-fetch (Issue #2833) pull binaries over HTTPS, not QUIC — large-file transfer stays off the control/data-plane streams. A managed steward therefore reaches the controller on both 4433 (QUIC) and 9080 (HTTPS). Moving binary transfer onto the QUIC data plane was considered and deliberately not pursued (it would add a chunked bulk-transfer contract spanning both push and pull directions for little gain, since HTTPS egress is universally available); see the steward-binary distribution notes in `controller-operating-model.md`.

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `CFGMS_TRANSPORT_LISTEN_ADDR` | Transport listen address | `0.0.0.0:4433` |
| `CFGMS_TRANSPORT_USE_CERT_MANAGER` | Use cert manager for TLS | `true` |
| `CFGMS_TRANSPORT_MAX_CONNECTIONS` | Maximum concurrent connections | `50000` |
| `CFGMS_TRANSPORT_KEEPALIVE_PERIOD` | Keepalive probe interval | `30s` |
| `CFGMS_TRANSPORT_IDLE_TIMEOUT` | Connection idle timeout | `5m` |

## Architecture Check Enforcement

`make check-architecture` blocks the following imports in `features/`:

| Blocked Import             | Replacement                        |
|----------------------------|------------------------------------|
| `pkg/[legacy-broker]/client` (removed) | `pkg/controlplane/interfaces` |
| `pkg/[legacy-broker]/types` (removed)  | `pkg/controlplane/types` |
| `pkg/quic/client`          | (removed — use `pkg/dataplane/interfaces`) |
| `pkg/quic/session`         | (removed — use `pkg/dataplane/interfaces`) |

## Provider Construction Pattern

Both control plane and data plane use direct construction — the provider registry was removed in Story #832:

```go
import (
    cpgrpc "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
    dpgrpc "github.com/cfgis/cfgms/pkg/dataplane/providers/grpc"
)

// Controller side (server mode):
cp := cpgrpc.New(cpgrpc.ModeServer)
dp := dpgrpc.New(dpgrpc.ModeServer)

// Steward side (client mode):
cp := cpgrpc.New(cpgrpc.ModeClient)
dp := dpgrpc.New(dpgrpc.ModeClient)
```

## Related Documentation

- [Provider Architecture](provider-architecture.md) - Provider pattern foundation
- [Central Provider Compliance](decisions/001-central-provider-compliance-enforcement.md) - Enforcement ADR
- Archived: Previous transport protocol design (removed in Phase 10.11)
