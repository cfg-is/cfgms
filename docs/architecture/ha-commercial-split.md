# HA Commercial/OSS Split Architecture

**Story**: #222 - Move HA Code to Commercial Tier
**Date**: 2025-10-15
**Status**: Implementation Complete

## Overview

This document describes the architectural separation of High Availability (HA) functionality between OSS and Commercial tiers, implemented as part of v0.7.0 Open Source Preparation.

## Guiding Principles

Per `docs/product/feature-boundaries.md`:

- **OSS**: Single controller deployments
- **Commercial**: HA clustering (Blue-Green, Multi-node clusters)

## Architecture Design

### Interface Boundaries

All HA code is located in `commercial/ha/` with Go build tags controlling which implementation is used:

**Available in Both OSS and Commercial**:

- `interfaces.go` - All interface definitions and types (no build tag)
  - `ClusterManager` interface
  - `DeploymentMode` enum (SingleServerMode, BlueGreenMode, ClusterMode)
  - `NodeState`, `NodeRole`, `NodeInfo` types
  - `HealthStatus`, `HealthCheckFunc` types
  - All other HA interfaces (SessionSynchronizer, LoadBalancer, etc.)

**OSS Only** (`//go:build !commercial`):

- `manager_oss.go` - OSS stub implementation
  - Implements `ClusterManager` for SingleServerMode only
  - Basic health checking
  - No clustering functionality
  - Compiles by default (without build tags)

**Commercial Only** (`//go:build commercial`):

- `manager.go` - Full ClusterManager implementation
- `config.go` - HA configuration
- `health.go` - Health checking implementation
- `raft_consensus.go` - Raft-based consensus
- `raft_transport.go` - Raft HTTP transport
- `discovery.go` - Node discovery
- `failover.go` - Automatic failover
- `load_balancer.go` - Load balancing
- `session_sync.go` - Session synchronization
- `split_brain.go` - Split-brain detection
- `manager_test.go` - HA manager tests
- All implementation files requiring clustering

**Commercial HA Integration Tests** (`//go:build commercial`):

- `test/integration/ha/*.go` - All HA integration tests
  - `cluster_formation_test.go`
  - `geographic_test.go`
  - All other HA cluster tests

### Factory Pattern

The controller uses a factory pattern to create the appropriate HA manager:

```go
// OSS Build (default)
func NewManager(cfg *Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*Manager, error) {
    // Returns OSS stub - SingleServerMode only
}

// Commercial Build
func NewManager(cfg *Config, logger logging.Logger, storageManager *interfaces.StorageManager) (*Manager, error) {
    // Returns full commercial implementation with clustering
}
```

### OSS Stub Behavior

The OSS implementation (`manager_oss.go`):

| Method | OSS Behavior |
|--------|--------------|
| `Start()` | Succeeds - minimal startup |
| `Stop()` | Succeeds - clean shutdown |
| `GetDeploymentMode()` | Always returns `SingleServerMode` |
| `GetLocalNode()` | Returns single node info |
| `GetClusterNodes()` | Returns array with only local node |
| `IsLeader()` | Always returns `true` (single node is always leader) |
| `GetLeader()` | Returns local node |
| `RegisterHealthCheck()` | Supports basic health checks |
| `GetHealth()` | Returns health status |

Configuration: OSS mode is enforced by always setting `Mode: SingleServerMode` regardless of environment variables.

### API Handler Changes

HA API handlers (`features/controller/api/handlers_ha.go`) gracefully handle OSS deployments:

- `/api/v1/ha/status` - Returns single-node status
- `/api/v1/ha/cluster` - Returns single-node cluster
- `/api/v1/ha/leader` - Returns local node as leader
- `/api/v1/ha/nodes` - Returns array with single node

No breaking changes to API contracts.

### Build Process

**OSS Builds** (default - no build tags):

```bash
# Build OSS version (SingleServerMode only)
go build ./cmd/controller
make build-controller

# Runs OSS tests only (HA cluster tests excluded)
go test ./...
make test
```

**Commercial Builds** (requires `-tags commercial`):

```bash
# Build Commercial version (Full HA clustering)
go build -tags commercial ./cmd/controller
make build-controller TAGS=commercial

# Runs all tests including HA cluster tests
go test -tags commercial ./...
make test TAGS=commercial
```

**Build Tag Behavior**:

- Without tags: Uses `manager_oss.go` (OSS stub)
- With `-tags commercial`: Uses `manager.go` and full HA implementation
- Integration tests automatically excluded from OSS builds

## Migration Impact

### For OSS Users

- No functionality change - single controller was already the default
- HA APIs still work, returning single-node information
- No configuration changes required

### For Commercial Users

- No changes - full HA functionality preserved
- All existing HA configurations continue to work
- Raft consensus, failover, load balancing all intact

## Security Considerations

- OSS stub enforces SingleServerMode to prevent misconfiguration
- Commercial HA code is source-available (Elastic License v2)
- No security features removed from OSS
- Tenant isolation maintained in both tiers

## Testing Strategy

### OSS Tests

- Verify single-node mode works correctly
- Verify HA APIs return appropriate single-node responses
- Verify controller starts and stops cleanly
- All existing controller tests pass

### Commercial Tests

- All HA integration tests moved to commercial test suite
- Cluster formation, failover, geographic distribution tests
- Raft consensus testing
- Load balancing and session sync testing

## Documentation Updates

Updated documentation:

- `docs/product/feature-boundaries.md` - Confirmed HA as commercial
- `docs/product/roadmap.md` - Marked Story #222 complete
- `docs/architecture/ha-commercial-split.md` - This document
- `CLAUDE.md` - Updated to reflect HA as commercial feature

## Future Enhancements

### Extension Points

The interface-based design allows for future enhancements:

- Plugin-based HA implementations
- Third-party clustering solutions
- Alternative consensus algorithms
- Custom load balancing strategies

### Commercial Features

Potential future commercial HA features:

- Geographic load balancing
- Advanced failover policies
- Multi-region clusters
- Disaster recovery automation

## References

- Story #222: <https://github.com/cfg-is/cfgms/issues/222>
- Feature Boundaries: `docs/product/feature-boundaries.md`
- Epic: v0.7.0 Open Source Preparation
- Related Stories: #220 (gRPC Removal), #221 (CLI Rename)

---

*This architecture maintains clean separation between OSS and Commercial tiers while preserving API compatibility and providing clear extension points for future enhancements.*
