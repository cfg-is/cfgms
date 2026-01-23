# Feature Boundaries: OSS vs Commercial

**Last Updated**: 2025-10-15
**Status**: Finalized for v0.7.0

## Guiding Principle

**"All code that touches client environments/APIs are OSS"**

This maximizes trust, community velocity for integrations, and follows proven models (Terraform providers, Kubernetes operators). Our competitive moat is the platform and user experience, not the integrations.

## Licensing Structure

- **Open Source**: Apache 2.0
- **Commercial**: Elastic License v2 (source-available, prevents SaaS competition)
- **Split**: CLI/API (OSS) vs Web UI/HA (Commercial)

## Feature Matrix

**Note**: Commercial tier includes ALL Open Source features. The tables below show what's available in each tier.

### Core Infrastructure

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Architecture** | ✅ Single controller | ✅ Single controller + HA clustering | HA: Raft consensus, auto-failover |
| **Storage** | ✅ Git, SQLite, PostgreSQL | ✅ Same + HA-optimized PostgreSQL | All providers support encryption |
| **Communication** | ✅ MQTT+QUIC | ✅ Same | No difference |
| **CLI/API** | ✅ All | ✅ Same | Complete CLI access in both |
| **Web UI** | ❌ None | ✅ Full UI | Graphical workflow builder, dashboards |

### Modules & Integrations

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **All Modules** | ✅ All | ✅ Same | Endpoint, M365, Active Directory, etc. |
| **Module Contributions** | ✅ Default | ✅ Same | Reserve right to build commercial or reject |
| **PSA/RMM Integrations** | ✅ All | ✅ Same | HaloPSA, SyncroMSP when built |
| **Directory Integration** | ✅ All | ✅ Same | LDAP, AD, Entra ID |

### DNA System

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Drift Detection** | ✅ All | ✅ Same | Core DNA functionality |
| **System Blueprints** | ✅ All | ✅ Same | DNA snapshot capabilities |
| **Templates** | ✅ All | ✅ Same | Go templates (not Jinja) |

### Multi-Tenancy

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Single MSP** | ✅ Unlimited depth | ✅ Same | Full hierarchy: MSP→Client→Group→Device |
| **Multiple MSPs** | ❌ None | ✅ Unlimited | SaaS/Multi-MSP deployments |
| **Tenant Isolation** | ✅ All | ✅ Same | Security enforced everywhere |

### Workflow System

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Engine Core** | ✅ All | ✅ Same | YAML execution, loops, conditions, error handling |
| **CLI Execution** | ✅ All | ✅ Same | Full workflow capabilities via CLI |
| **Debugging** | ✅ All | ✅ Same | Step-through, breakpoints, variable inspection |
| **Orchestration** | ❌ None | ✅ All | Approval workflows, multi-stage, complex dependencies |
| **Visual Editor** | ❌ None | ✅ Full | Web UI drag-and-drop workflow builder |
| **DAG Visualization** | ❌ None | ✅ Full | Workflow execution graphs (orchestration feature) |

### Data Processing

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Basic Processing** | ✅ All | ✅ Same | Go templates, simple JSONPath, basic filters |
| **Advanced Processing** | ❌ None | ✅ Full | Complex filters, XPath, advanced transformations |

### RBAC & Security

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Basic RBAC** | ✅ All | ✅ Same | Users, groups, policies (via CLI) |
| **Advanced RBAC** | ❌ None | ✅ Full | Conditional access, session management (Web UI) |
| **Audit Logging** | ✅ All | ✅ Same | Complete audit trail |
| **Compliance** | ✅ All | ✅ Same | SIEM integration, compliance reporting |

### Monitoring & Alerting

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Metrics Collection** | ✅ All | ✅ Same | Performance, health, system metrics |
| **Threshold Alerts** | ✅ All | ✅ Same | Alert generation and tracking |
| **SIEM Integration** | ✅ All | ✅ Same | Security event correlation |
| **ML/Predictive** | ❌ None | ✅ Full | Anomaly detection, forecasting |

### Reporting

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Data/CLI Reports** | ✅ All | ✅ Same | Generate all reports via CLI |
| **Visual Reports** | ❌ None | ✅ Full | Web UI charts, dashboards |
| **Scheduled Reports** | ✅ CLI scheduling | ✅ CLI + UI scheduling | Both can schedule |

### Discovery & Marketplace

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **Module Discovery** | ✅ Basic | ✅ Same | CLI search/install from public repos |
| **Curated Marketplace** | ❌ None | ✅ Full | Vetted, rated, commercial modules |

### Terminal Access

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **All Terminal Features** | ✅ All | ✅ Same | Remote terminal via CLI |

### Compliance Templates

| Feature | OSS | Commercial (includes all OSS) | Notes |
|---------|-----|-------------------------------|-------|
| **All Templates** | ✅ All (near term) | ✅ Same | May add commercial templates later |

## Technical Implementation

For details on how OSS and Commercial code is separated using Go build tags, see [HA Commercial/OSS Split Architecture](../architecture/ha-commercial-split.md).

---

*All boundaries are subject to refinement based on market feedback and competitive dynamics.*
