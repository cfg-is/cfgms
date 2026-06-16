# CFGMS Feature Boundaries

This document lists what functionality is part of CFGMS OSS (AGPL-3.0) and what is
available only under a commercial embedding license. All deployment shapes run the same
AGPL-3.0 code; the distinction is between features shipped in the OSS repository and
features delivered under a separate commercial agreement.

## Fleet Management

All fleet management features in this section are part of CFGMS OSS.

| Feature | Status | Notes |
|---------|--------|-------|
| Steward registration and approval | OSS | Includes token-based and IP-trust bulk approval |
| Fleet selector (name:, os:, platform:, arch:, tag:, dna.*, id:) | OSS | id: resolves a single steward by device ID |
| Config push fan-out | OSS | POST /api/v1/config/push — selector-based fan-out via CommandSyncConfig |
| Steward DNA collection | OSS | Convergence loop reports DNA attributes to controller |
| Steward module inventory | OSS | GET /api/v1/stewards/{id}/modules |
| **Steward binary distribution** | **OSS** | POST /api/v1/installer/steward-binaries — publish, approve, dispatch (Epic #1930) |
| Steward upgrade dispatch | OSS | POST /api/v1/stewards/upgrade — selector-based fan-out via CommandPushStewardBinary with approval gate and durable UpgradeStore (Issue #1945) |
| Per-steward upgrade status | OSS | GET /api/v1/stewards/upgrade/{upgrade_id} — lifecycle tracking from dispatched → downloaded → swapped → committed/rolled_back |
| Rollback dispatch | OSS | POST /api/v1/stewards/upgrade/{upgrade_id}/rollback — named-version target only |

## Configuration Management

| Feature | Status | Notes |
|---------|--------|-------|
| Cfg push and sync | OSS | Pull and push paths both supported |
| Config rollback | OSS | Snapshot-based rollback with compliance reporting |
| Module trust enforcement | OSS | Publisher signing, strict/controller/bypass trust modes |

## Installer Distribution

| Feature | Status | Notes |
|---------|--------|-------|
| Installer artifact storage | OSS | BlobStore-backed; PUT/GET/DELETE /api/v1/installer/artifacts |
| Steward binary publish | OSS | POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch} with Ed25519 signature verification |
| Binary approval gate | OSS | approved_by label required before dispatch; separate from publish identity |
| Installer package download | OSS | Public GET /api/v1/installer/download/{platform}/{arch} — assembles per-platform tar.gz on the fly |

## Multi-Tenancy

| Feature | Status | Notes |
|---------|--------|-------|
| Recursive parent-child tenant model | OSS | Arbitrary depth; path-based identification |
| Config inheritance | OSS | Root-to-leaf resolution |
| Tenant-scoped API keys and permissions | OSS | RBAC with per-tenant key scoping |
