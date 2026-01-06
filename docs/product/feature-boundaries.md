# Feature Boundaries: OSS vs Commercial

**Last Updated**: 2025-10-15
**Status**: Finalized for v0.7.0

## Guiding Principle

**"All code that touches client environments/APIs are OSS"**

This maximizes trust, community velocity for integrations, and follows proven models (Terraform providers, Kubernetes operators). Our competitive moat is the platform and user experience, not the integrations.

## Licensing Structure

- **Open Source**: Apache 2.0
- **Commercial**: Elastic License v2 (source-available, prevents SaaS competition)
- **Split**: CLI/API (OSS) vs Web UI (Commercial)

## Feature Matrix

### Core Infrastructure

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Architecture** | ✅ Single controller | ✅ HA clustering | Move existing HA code to commercial |
| **Storage** | ✅ Git, SQLite | ✅ PostgreSQL HA | All providers support encryption |
| **Communication** | ✅ MQTT+QUIC | ✅ Same | No difference |
| **CLI/API** | ✅ All | ❌ None | Complete CLI access in OSS |
| **Web UI** | ❌ None | ✅ All | Primary commercial differentiator |

### Modules & Integrations

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **All Modules** | ✅ All | ❌ None | Endpoint, M365, Active Directory, etc. |
| **Module Contributions** | ✅ Default | ⚠️ Commercial possible | Reserve right to build commercial or reject |
| **PSA/RMM Integrations** | ✅ All | ❌ None | HaloPSA, SyncroMSP when built |
| **Directory Integration** | ✅ All | ❌ None | LDAP, AD, Entra ID |

### DNA System

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Drift Detection** | ✅ All | ❌ None | Core DNA functionality |
| **System Blueprints** | ✅ All | ❌ None | DNA snapshot capabilities |
| **Templates** | ✅ All | ❌ None | Go templates (not Jinja) |

### Multi-Tenancy

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Single MSP** | ✅ Unlimited depth | ❌ None | Full hierarchy: MSP→Client→Group→Device |
| **Multiple MSPs** | ❌ None | ✅ Unlimited | SaaS/Multi-MSP deployments |
| **Tenant Isolation** | ✅ All | ✅ Same | Security enforced everywhere |

### Workflow System

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Engine Core** | ✅ All | ❌ None | YAML execution, loops, conditions, error handling |
| **CLI Execution** | ✅ All | ❌ None | Full workflow capabilities via CLI |
| **Debugging** | ✅ All | ❌ None | Step-through, breakpoints, variable inspection |
| **Orchestration** | ❌ None | ✅ All | Approval workflows, multi-stage, complex dependencies |
| **Visual Editor** | ❌ None | ✅ All | Web UI drag-and-drop workflow builder |
| **DAG Visualization** | ❌ None | ✅ All | Workflow execution graphs (orchestration feature) |

### Data Processing

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Basic Processing** | ✅ All | ❌ None | Go templates, simple JSONPath, basic filters |
| **Advanced Processing** | ❌ None | ✅ All | Complex filters, XPath, advanced transformations |

### RBAC & Security

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Basic RBAC** | ✅ All | ❌ None | Users, groups, policies (via CLI) |
| **Advanced RBAC** | ❌ None | ✅ All | Conditional access, session management (Web UI) |
| **Audit Logging** | ✅ All | ❌ None | Complete audit trail |
| **Compliance** | ✅ All | ❌ None | SIEM integration, compliance reporting |

### Monitoring & Alerting

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Metrics Collection** | ✅ All | ❌ None | Performance, health, system metrics |
| **Threshold Alerts** | ✅ All | ❌ None | Alert generation and tracking |
| **SIEM Integration** | ✅ All | ❌ None | Security event correlation |
| **ML/Predictive** | ❌ None | ✅ All | Anomaly detection, forecasting |

### Reporting

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Data/CLI Reports** | ✅ All | ❌ None | Generate all reports via CLI |
| **Visual Reports** | ❌ None | ✅ All | Web UI charts, dashboards |
| **Scheduled Reports** | ✅ CLI scheduling | ✅ UI scheduling | Both can schedule |

### Discovery & Marketplace

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **Module Discovery** | ✅ Basic | ❌ None | CLI search/install from public repos |
| **Curated Marketplace** | ❌ None | ✅ All | Vetted, rated, commercial modules |

### Terminal Access

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **All Terminal Features** | ✅ All | ❌ None | Remote terminal via CLI |

### Compliance Templates

| Feature | OSS | Commercial | Notes |
|---------|-----|------------|-------|
| **All Templates** | ✅ All (near term) | ⚠️ Possible future | May add commercial templates later |

## Revenue Model (Phase 1)

**SaaS Pricing**: $250/month for 250 "managed units"

- 1 endpoint = 1 unit
- 1 M365 user = 0.1 unit
- Includes: Web UI, HA, Multi-MSP, ML monitoring, orchestration

**Self-Hosted**: OSS version free forever, commercial license for HA/UI

## Competitive Positioning

- **vs Rewst**: Web UI/UX is commercial differentiator (engine OSS)
- **vs N8N/Zapier**: Not competing - different market (MSP automation vs general iPaaS)
- **vs RMMs**: "Fill RMM gaps" initially → eventual replacement
- **vs Terraform**: Similar model - CLI/providers OSS, Cloud UI commercial

## Building OSS vs Commercial

### OSS Build (Default)

```bash
# Build OSS version (SingleServerMode only)
go build ./cmd/controller
make build-controller

# Run OSS tests (HA cluster tests excluded automatically)
go test ./...
make test
```

**OSS Includes**:

- Single controller deployment
- All modules and integrations
- Full CLI/API functionality
- Basic health monitoring

**OSS Excludes**:

- HA clustering (BlueGreenMode, ClusterMode)
- Raft consensus
- Automatic failover
- Load balancing
- Split-brain detection
- Session synchronization

### Commercial Build

```bash
# Build Commercial version (Full HA clustering)
go build -tags commercial ./cmd/controller
make build-controller TAGS=commercial

# Run all tests including HA cluster tests
go test -tags commercial ./...
make test TAGS=commercial
```

**Commercial Adds**:

- Full HA clustering capabilities
- Raft-based consensus
- Automatic failover
- Geographic load balancing
- Split-brain detection and resolution
- Cross-node session synchronization
- Blue-green deployments

### Technical Implementation

The codebase uses Go build tags to separate OSS and commercial functionality:

- **No build tag**: OSS stub in `commercial/ha/manager_oss.go`
- **`-tags commercial`**: Full implementation in `commercial/ha/manager.go` and related files

All code remains in the same repository with clean interface boundaries defined in `commercial/ha/interfaces.go`.

## Migration Tasks

1. ✅ **Move HA code** - Completed (Story #222) - Uses build tags for separation
2. **License headers**: Apache 2.0 for all current code
3. **Create LICENSE files**: LICENSE-APACHE-2.0 and LICENSE-ELASTIC-2.0
4. **Web UI development**: Early beta feature, commercial tier

---

*This document reflects finalized decisions from v0.7.0 planning discussions. All boundaries are subject to refinement based on market feedback and competitive dynamics.*
