// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

// knownPermissions is the allow-list of valid permission IDs for handleCreateAPIKey.
// Each entry corresponds to a permission checked by requirePermission in server.go.
// C1: "*" (wildcard) is intentionally absent — it is never a valid permission ID.
var knownPermissions = map[string]bool{
	// Steward management
	"steward:list":            true,
	"steward:read":            true,
	"steward:read-dna":        true,
	"steward:auth-refresh":    true,
	"steward:read-config":     true,
	"steward:write-config":    true,
	"steward:validate-config": true,
	"steward:read-scripts":    true,
	"steward:execute-scripts": true,
	"steward:read-compliance": true,
	"steward:delete-config":   true,
	// Config management
	"config:list":             true,
	"config:list-deployments": true,
	// Config push
	"config:push": true,
	// Certificate management
	"certificate:list":      true,
	"certificate:provision": true,
	// RBAC
	"rbac:list-permissions": true,
	"rbac:read-permission":  true,
	"rbac:list-roles":       true,
	"rbac:create-role":      true,
	"rbac:read-role":        true,
	"rbac:update-role":      true,
	"rbac:delete-role":      true,
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
	// Registration approval management (Issue #1568)
	"registration:list-pending": true,
	"registration:approve":      true,
	"registration:deny":         true,
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
	"tenant:manage": true,
	// Script library administration (Issue #1670)
	"script:admin": true,
}

// isKnownPermission reports whether p is a recognized permission ID.
// "*" and all other unlisted strings return false.
func isKnownPermission(p string) bool {
	return knownPermissions[p]
}
