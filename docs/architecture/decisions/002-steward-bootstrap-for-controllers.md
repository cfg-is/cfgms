# ADR-002: Steward Bootstrap for Controller Nodes

**Status**: Accepted
**Date**: 2026-03-30
**Context**: Controller deployment, node management separation

## Decision

Production CFGMS controller nodes run a steward alongside the controller process. The steward manages node-level infrastructure (directories, packages, firewall, OS services). The controller manages fleet-level operations (CA, certificates, RBAC, config distribution, workflows).

The controller remains self-sufficient for quick-start deployments — it creates its own directories, certificates, and storage on first run without a steward.

## Context

### Two deployment stories

1. **Quick start**: Download binary, run it, manage endpoints. The controller handles everything needed to start — directory creation, CA generation, storage initialization. Fewer steps than Ansible.

2. **Production fleet**: Controller nodes managed at scale. A steward provides convergence-based node management — drift detection, automated recovery, consistent configuration across a fleet of controller nodes.

### Current overlap

The controller performs some operations that are both application-level (needed for quick start) and infrastructure-level (managed by steward in production):

| Operation | Location | Quick start | Production |
|-----------|----------|-------------|------------|
| Create CA directory | `initialization.go:81` | Controller creates it during `--init` | Steward pre-creates it; controller's `MkdirAll` is a no-op |
| Write cert PEM files to disk | `server.go:1159-1204` | Not needed — certs used in-memory | Not needed — exists only for integration test infrastructure |
| Create data/log directories | Manual (`mkdir -p`) | Controller could create these | Steward creates and maintains them |
| Install systemd service | Manual (create unit file) | Could use `controller install` | Steward manages the unit file |

### What stays in the controller

These are application-level operations needed for the "just works" experience:

- **Directory creation during `--init`**: `os.MkdirAll(caPath)` — same as `git init` creating `.git/`
- **CA and certificate generation**: Fleet-level security, not node management
- **RBAC initialization**: Application data, not infrastructure
- **Storage backend initialization**: Application data layer
- **Init marker (`.cfgms-initialized`)**: Application state

### What the steward adds for production

- **Convergence**: Node drifts are automatically corrected (package removed, firewall rule dropped, service stopped)
- **Consistency**: All controller nodes in a fleet share the same configuration
- **Independence**: Steward keeps the node healthy even if the controller process is down
- **Scalability**: New controller nodes bootstrapped via steward standalone mode

## Code Changes Required

The following changes support the production deployment model. Each has a corresponding GitHub issue in the v0.9.5 roadmap milestone.

### Remove `writeTransportCertsToDir` (Issue #576)

**File**: `features/controller/server/server.go:1179-1204`

The function writes `server.crt`, `server.key`, and `ca.crt` to disk. The comment at line 1159 states this exists so "integration test infrastructure can find them." The certs are already used in-memory at line 1167 for the TLS config — the file write serves no production purpose.

**Change**: Update integration test infrastructure (Makefile `generate-test-certificates`, Docker test configs) to obtain certs via the controller API or test helpers, then remove the function.

### Implement `service` module for steward (Issue #577)

The controller-node.cfg example uses the `script` module as a workaround for systemd service management. A dedicated `service` module provides idempotent Get/Set for OS service management (systemd, Windows Service, launchd).

**Change**: Implement `service` module in `features/modules/` using the existing platform implementations in `cmd/steward/service/manager_*.go` as reference.

### Add `controller install` subcommand (Issue #578)

The steward has `install`/`uninstall`/`status` subcommands for OS service registration. The controller has no equivalent — service installation is manual.

**Change**: Add the same pattern to `cmd/controller/`, reusing the service manager interfaces.

## Consequences

### Positive

- Production controller nodes get convergence-based management — same as every other managed endpoint
- CFGMS manages its own infrastructure (dog-fooding)
- Quick-start experience unchanged — controller still "just works"
- Clean separation: steward manages nodes, controller manages fleets

### Negative

- Two processes on controller nodes (steward + controller) — minor operational complexity
- Bootstrap requires two steps (steward convergence + controller init) in production — but quick start remains one step

### Neutral

- Log rotation stays in `pkg/logging/providers/file/` as shared library code — both components use it internally, this is not node management
- The `os.MkdirAll` in initialization stays — it's application-level and becomes a harmless no-op when steward pre-creates the directory

## Related

- [Single Controller Deployment](../../deployment/single-controller/walkthrough.md) — deployment guide
- [Controller Operating Model](../controller-operating-model.md) — startup sequence and node management boundary
- [Steward Operating Model](../steward-operating-model.md) — convergence loop
- [Example: controller-steward.cfg](../../deployment/single-controller/controller-steward.cfg) — steward config for controller nodes
