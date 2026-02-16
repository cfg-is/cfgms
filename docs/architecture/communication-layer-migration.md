# Communication Layer Migration Guide

## Overview

As of Epic #267 (Communication Layer Abstraction), CFGMS uses pluggable provider
interfaces for all controller-steward communication. Direct imports of `pkg/mqtt`
and `pkg/quic` in feature code are deprecated and blocked by `make check-architecture`.

**Control Plane** (commands, events, heartbeats): `pkg/controlplane/interfaces`
**Data Plane** (config sync, DNA sync, bulk transfers): `pkg/dataplane/interfaces`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Feature Code                          │
│  (features/controller, features/steward, etc.)          │
├─────────────────────────────────────────────────────────┤
│  pkg/controlplane/interfaces  │  pkg/dataplane/interfaces│
│  (ControlPlaneProvider)       │  (DataPlaneProvider)     │
├───────────────────────────────┼──────────────────────────┤
│  providers/mqtt (MQTT impl)   │  providers/quic (QUIC)   │
│  (future: gRPC, WebSocket)    │  (future: gRPC, WS)     │
├───────────────────────────────┼──────────────────────────┤
│  pkg/mqtt (broker infra)      │  pkg/quic (transport)    │
│  [internal - do not import]   │  [internal - do not import]│
└───────────────────────────────┴──────────────────────────┘
```

## Migration Guide

### Control Plane: pkg/mqtt → pkg/controlplane

#### Before (deprecated)

```go
import (
    mqttClient "github.com/cfgis/cfgms/pkg/mqtt/client"
    mqttTypes "github.com/cfgis/cfgms/pkg/mqtt/types"
)

// Create MQTT client directly
client := mqttClient.New(broker, tlsConfig, stewardID)
client.Connect(ctx)

// Publish heartbeat via raw MQTT
heartbeat := mqttTypes.Heartbeat{
    StewardID: stewardID,
    Status:    mqttTypes.StatusHealthy,
}
client.Publish(ctx, "cfgms/heartbeat/"+stewardID, heartbeatJSON, 1)

// Subscribe to commands via raw MQTT
client.Subscribe(ctx, "cfgms/steward/"+stewardID+"/commands", handler)
```

#### After (required)

```go
import (
    cpInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
    _ "github.com/cfgis/cfgms/pkg/controlplane/providers/mqtt" // Register provider
    cpTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
)

// Get provider via registry
provider := cpInterfaces.GetProvider("mqtt")
provider.Initialize(ctx, config)

// Send heartbeat via provider (transport-agnostic)
heartbeat := &cpTypes.Heartbeat{
    StewardID: stewardID,
    Status:    cpTypes.StatusHealthy,
    Timestamp: time.Now(),
}
provider.SendHeartbeat(ctx, heartbeat)

// Subscribe to commands via provider
provider.SubscribeCommands(ctx, stewardID, func(cmd *cpTypes.Command) error {
    // Handle command
    return nil
})
```

### Data Plane: pkg/quic → pkg/dataplane

#### Before (deprecated)

```go
import (
    quicClient "github.com/cfgis/cfgms/pkg/quic/client"
)

// Create QUIC client directly
client := quicClient.New(controllerAddr, tlsConfig)
conn, err := client.Connect(ctx)

// Send/receive data via raw QUIC streams
stream, _ := conn.OpenStream()
stream.Write(configData)
```

#### After (required)

```go
import (
    dpInterfaces "github.com/cfgis/cfgms/pkg/dataplane/interfaces"
    _ "github.com/cfgis/cfgms/pkg/dataplane/providers/quic" // Register provider
    dpTypes "github.com/cfgis/cfgms/pkg/dataplane/types"
)

// Get provider via registry
provider := dpInterfaces.GetProvider("quic")
provider.Initialize(ctx, config)

// Connect via provider (transport-agnostic)
session, err := provider.Connect(ctx, controllerAddr, tlsConfig)

// Transfer data via semantic methods
err = session.SendConfig(ctx, configData, metadata)
config, err := session.ReceiveConfig(ctx)
```

### Message Types: pkg/mqtt/types → pkg/controlplane/types

| Old Type (pkg/mqtt/types)       | New Type (pkg/controlplane/types) |
|---------------------------------|-----------------------------------|
| `types.Command`                 | `cpTypes.Command`                 |
| `types.CommandType`             | `cpTypes.CommandType`             |
| `types.StatusUpdate`            | `cpTypes.Event`                   |
| `types.StatusEvent`             | `cpTypes.EventType`               |
| `types.Heartbeat`               | `cpTypes.Heartbeat`               |
| `types.HeartbeatStatus`         | `cpTypes.HeartbeatStatus`         |
| `types.ConfigStatusReport`      | `cpTypes.ConfigStatusReport`      |
| `types.ModuleStatus`            | `cpTypes.ModuleStatus`            |
| `types.CommandSyncConfig`       | `cpTypes.CommandSyncConfig`       |
| `types.CommandConnectQUIC`      | `cpTypes.CommandConnectDataPlane` |

### Key Differences

1. **Transport-agnostic naming**: `CommandConnectQUIC` → `CommandConnectDataPlane`
2. **Richer types**: Control plane types include `TenantID`, `Priority`, `Severity`
3. **Separate Response type**: Synchronous acknowledgments via `cpTypes.Response`
4. **Event filtering**: `cpTypes.EventFilter` for subscription filtering
5. **Provider registry**: Auto-registration pattern for multiple implementations

## Architecture Check Enforcement

`make check-architecture` blocks the following imports in `features/`:

| Blocked Import             | Replacement                        |
|----------------------------|------------------------------------|
| `pkg/mqtt/client`          | `pkg/controlplane/interfaces`      |
| `pkg/mqtt/types`           | `pkg/controlplane/types`           |
| `pkg/quic/client`          | `pkg/dataplane/interfaces`         |
| `pkg/quic/session`         | `pkg/dataplane/interfaces`         |

### Known Infrastructure Exceptions

The controller server (`features/controller/server/`) retains direct imports for
infrastructure bootstrap:

- `pkg/mqtt/interfaces` - MQTT broker lifecycle management (start/stop)
- `pkg/mqtt/providers/mochi` - Broker provider registration
- `pkg/quic/server` - QUIC listener management

These are server-side infrastructure that the providers wrap internally. Feature
code should never import these; they are used only by the controller's server
initialization.

## Provider Registration Pattern

Both control plane and data plane use auto-registration via blank imports:

```go
// In your main or init code, register providers:
import (
    _ "github.com/cfgis/cfgms/pkg/controlplane/providers/mqtt" // Register MQTT
    _ "github.com/cfgis/cfgms/pkg/dataplane/providers/quic"    // Register QUIC
)

// Then retrieve via registry:
cp := cpInterfaces.GetProvider("mqtt")
dp := dpInterfaces.GetProvider("quic")
```

This pattern enables future transport alternatives (gRPC, WebSocket) without
changing feature code.

## Related Documentation

- [MQTT+QUIC Protocol Design](mqtt-quic-protocol.md) - Original protocol specification
- [Plugin Architecture](plugin-architecture.md) - Provider pattern foundation
- [Central Provider Compliance](decisions/001-central-provider-compliance-enforcement.md) - Enforcement ADR
