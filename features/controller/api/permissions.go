// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// knownPermissions is the allow-list of valid permission IDs for handleCreateAPIKey.
// Each entry corresponds to a permission checked by requirePermission in server.go.
// C1: "*" (wildcard) is intentionally absent — it is never a valid permission ID.
var knownPermissions = map[string]bool{
	// Steward management
	"steward:list":            true,
	"steward:read":            true,
	"steward:telemetry":       true, // Issue #2765: live telemetry WebSocket fan-out
	"steward:read-dna":        true,
	"steward:read-logs":       true,
	"steward:auth-refresh":    true,
	"steward:read-config":     true,
	"steward:write-config":    true,
	"steward:validate-config": true,
	"steward:read-scripts":    true,
	"steward:execute-scripts": true,
	"steward:read-compliance": true,
	"steward:read-modules":    true,
	"steward:delete-config":   true,
	"steward:move":            true,
	"steward:decommission":    true,
	"steward:visibility":      true, // Issue #2918: hide/unhide steward from default fleet view
	// Config management
	"config:list":             true,
	"config:list-deployments": true,
	// Config push
	"config:push": true,
	// Certificate management
	"certificate:list":      true,
	"certificate:get":       true, // Issue #3129: get single certificate by serial
	"certificate:revoke":    true, // Issue #3129: revoke certificate by serial
	"certificate:provision": true,
	"certificate:rotate":    true,
	// RBAC
	"rbac:list-permissions":   true,
	"rbac:read-permission":    true,
	"rbac:list-roles":         true,
	"rbac:create-role":        true,
	"rbac:read-role":          true,
	"rbac:update-role":        true,
	"rbac:delete-role":        true,
	"rbac:list-subject-roles": true,
	"rbac:assign-role":        true,
	"rbac:revoke-role":        true,
	// API key management
	"api-key:list":   true,
	"api-key:create": true,
	"api-key:read":   true,
	"api-key:delete": true,
	// Registration token management
	"registration:list-tokens":  true,
	"registration:create-token": true,
	"registration:read-token":   true,
	"registration:delete-token": true,
	"registration:revoke-token": true,
	"registration:rotate-token": true,
	// Registration approval management (Issue #1568)
	"registration:list-pending": true,
	"registration:approve":      true,
	"registration:deny":         true,
	// Bulk CIDR approval (Issue #2969) — separate from registration:approve because it
	// additionally carries RequireUserPresence in permissionAssurance. Web accounts must be
	// able to hold it, so it belongs in this allow-list even though a Machine-assurance API
	// key can never satisfy its assurance requirement.
	"registration:approve-by-cidr": true,
	// IP-trust management (Issue #1698, #2932)
	"registration:list-ip-trust":   true,
	"registration:manage-ip-trust": true,
	// Monitoring
	"monitoring:read-health":            true,
	"monitoring:read-metrics":           true,
	"monitoring:read-config":            true,
	"monitoring:read-anomalies":         true,
	"monitoring:read-component-health":  true,
	"monitoring:read-component-metrics": true,
	// HA management
	"ha:read-status":  true,
	"ha:read-cluster": true,
	"ha:read-leader":  true,
	"ha:read-nodes":   true,
	// Compliance
	"compliance:read-summary": true,
	// Tenant management
	"tenant:create": true, // Issue #3195: was in permissionAssurance but missing here
	"tenant:list":   true,
	"tenant:read":   true,
	"tenant:update": true,
	"tenant:manage": true,
	// Tenant deletion pipeline (ADR-027 Decisions 3-4, Issue #3182)
	"tenant:delete":         true,
	"tenant:approve-delete": true,
	// Tenant-crossing grant and break-glass (ADR-025 Decision 2, Issue #3125)
	"tenant:crossing-grant":       true,
	"tenant:crossing-list":        true,
	"tenant:crossing-break-glass": true,
	// Script library administration (Issue #1670)
	"script:admin": true,
	// Installer artifact management (Issue #1702)
	"installer:upload": true,
	"installer:read":   true,
	"installer:delete": true,
	// Steward binary publishing (Issue #1944)
	"installer:publish:steward": true,
	// Steward upgrade dispatch and approval (Issue #1945)
	"installer:dispatch:steward": true,
	"installer:approve:steward":  true,
	// Registration-refresh management (Issue #2096)
	"registration:list-refresh":          true,
	"registration:approve-refresh":       true,
	"registration:deny-refresh":          true,
	"registration:manage-refresh-policy": true,
	// Batch job management (Issue #2296)
	"jobs:write": true,
	// Cluster registry (Issue #2424, #3303)
	"cluster:list": true,
	"cluster:read": true,
	// Issue #3303: cluster:drain-node gates POST /cluster/nodes/{id}/drain and
	// cluster:decommission-node gates POST /cluster/nodes/{id}/decommission. Both were
	// already in permissionAssurance (Min: AssuranceStrong) and are now grantable.
	// Controller HA-cluster nodes are fleet-wide infrastructure with no tenant column, so
	// neither requirePermission's tenant-isolation block nor its ADR-025 Decision 1 block
	// can bound them; clusterLifecycleScopeAllowed in handlers_cluster.go confines both
	// handlers to principals with no tenant confinement (TenantID == "").
	"cluster:drain-node":        true,
	"cluster:decommission-node": true,
	// Registration-refresh approval and policy (Issue #3303). These gate AssuranceStrong-level
	// routes (see permissionAssurance): refresh:approve for POST /stewards/refresh/{id}/approve,
	// refresh:set-policy for PUT /tenants/{tenant_path}/refresh-policy. Both were in
	// permissionAssurance but absent from knownPermissions (same drift pattern as tenant:create,
	// Issue #3195). refresh:approve adds a root-scoped crossing guard in handleApproveRefresh
	// (ADR-025 Decision 1); refresh:set-policy is covered by extractBoundaryTenantFromRequest
	// via tenant_path.
	"refresh:approve":    true,
	"refresh:set-policy": true,
	// Terminal relay (Issue #3303): gates GET /terminal/ws/{steward_id} at AssuranceStrong.
	// tenantScopedTerminalWrapper covers tenant-scoped callers; the root-scoped ADR-025 gap
	// ({steward_id} not in extractBoundaryTenantFromRequest) is closed inline there.
	"terminal:create": true,
	// Account management (Issue #2733, #2974, #3126, #3574)
	"account:list":                   true,
	"account:create":                 true,
	"account:get":                    true, // Issue #3126: get-one by username
	"account:update":                 true, // Issue #3126: update permissions and/or disabled state
	"account:delete":                 true,
	"account:revoke-enrollment-link": true, // Issue #2974: revoke an outstanding enrollment magic link
	// WebAuthn passkey / FIDO2 registration and credential management (Issue #2782, #2783)
	"webauthn:register": true,
	"webauthn:list":     true,
	"webauthn:revoke":   true,
	// Workflow management (Issue #2725)
	"workflow:list":    true,
	"workflow:read":    true,
	"workflow:write":   true,
	"workflow:execute": true,
	"workflow:cancel":  true,
	// Trigger management (Issue #2725)
	"trigger:manage": true,
	// Module bundle approval management (Issue #2728)
	"module:list-approvals": true,
	"module:approve":        true,
	"module:reject":         true,
	// Per-tenant assurance-policy management (Issue #2839)
	"assurance-policy:get": true,
	"assurance-policy:set": true,
	// Entity graph read API (Issue #2880)
	"entity:list": true,
	"entity:read": true,
	// Entity graph operator edge assertion (Issue #3374): gates POST /entities/edges,
	// the only mutating entity-graph route. It must be listed here so a least-privilege
	// API key or web account can actually hold it — otherwise handleCreateAPIKey and the
	// web-account handlers reject it with 400 INVALID_PERMISSION and the only principal
	// able to reach the route is an unscoped one (Permissions == nil, which hasPermission
	// blanket-allows). That is the same cross-registry drift fixed for tenant:create
	// (Issue #3195) and cluster:drain-node et al. (Issue #3303).
	"entity:write": true,
	// Reboot-window authoring (Issue #2979). Enforced on the tenant and steward
	// reboot-window routes and registered in the RBAC catalog as reboot_window.read /
	// reboot_window.override. Both must be listed here so a least-privilege API key or
	// web account can actually hold them — otherwise the only principal able to reach
	// the endpoints is an unscoped one (Permissions == nil), which is the privilege
	// inflation ADR-026 decision 3 exists to avoid.
	"reboot_window:read":     true,
	"reboot_window:override": true,
	// Alert state management (Issue #3266): acknowledge and silence endpoints.
	// Both must be listed here so a least-privilege principal can hold them.
	// alert:silence carries AssuranceStrong (see permissionAssurance); alert:acknowledge
	// does not and is intentionally absent from that map.
	"alert:acknowledge": true,
	"alert:silence":     true,
	// Report access (Issue #3282): read gates all GET endpoints under /api/v1/reports;
	// generate gates POST /reports/generate (write-shaped — may produce and persist a report).
	// Kept separate so a read-only principal can list templates without being able to trigger
	// generation.
	"report:read":     true,
	"report:generate": true,
}

// isKnownPermission reports whether p is a recognized permission ID.
// "*" and all other unlisted strings return false.
func isKnownPermission(p string) bool {
	return knownPermissions[p]
}
