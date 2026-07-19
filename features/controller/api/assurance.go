// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// Note: auth_tiers.go was replaced by this file (Issue #2780). The filename
// assurance.go was chosen for clarity; the PR description documents this choice.

import "github.com/cfgis/cfgms/pkg/session"

// Requirement declares the minimum assurance level a permission needs and
// whether a fresh user-presence proof is required for catastrophic operations.
// RequireUserPresence is forward-declared here for future WebAuthn enforcement;
// this story only writes the flag — enforcement is a separate, later story.
type Requirement struct {
	Min                 session.AssuranceLevel
	RequireUserPresence bool
}

// permissionAssurance is the authoritative registry of permission IDs that require
// elevated assurance (ADR-021). Permissions absent from this map can be held by any
// credential type (AssuranceMachine included). Permissions with Min > AssuranceMachine
// cannot be satisfied by API-key principals; the startup scan enforces this at boot.
//
// Authoring rule: new permission IDs that require elevated assurance belong here, not
// in a separate Tier-3 list. The registry is the single source of truth consumed by
// both requirePermission (enforcement) and scanAPIKeysForPrivilegedAccess (startup check).
var permissionAssurance = map[string]Requirement{
	// Former tier3Permissions set — 20 entries, all migrated to Min: AssuranceStrong.
	"certificate:provision":        {Min: session.AssuranceStrong}, // POST /certificates/provision
	"certificate:rotate":           {Min: session.AssuranceStrong}, // POST /certificates/signing/rotate
	"rbac:create-role":             {Min: session.AssuranceStrong}, // POST /rbac/roles
	"rbac:update-role":             {Min: session.AssuranceStrong}, // PUT  /rbac/roles/{id}
	"rbac:delete-role":             {Min: session.AssuranceStrong}, // DELETE /rbac/roles/{id}
	"api-key:create":               {Min: session.AssuranceStrong}, // POST /api-keys
	"api-key:delete":               {Min: session.AssuranceStrong}, // DELETE /api-keys/{id}
	"registration:create-token":    {Min: session.AssuranceStrong}, // POST /registration/tokens
	"registration:delete-token":    {Min: session.AssuranceStrong}, // DELETE /registration/tokens/{token}
	"registration:revoke-token":    {Min: session.AssuranceStrong}, // POST /registration/tokens/{token}/revoke
	"registration:rotate-token":    {Min: session.AssuranceStrong}, // POST /registration/tokens/{tenant_id}/rotate
	"registration:approve":         {Min: session.AssuranceStrong}, // POST /registration/{id}/approve + approve-all + approve-by-cidr
	"registration:manage-ip-trust": {Min: session.AssuranceStrong}, // POST + DELETE /registration/ip-trust
	"tenant:create":                {Min: session.AssuranceStrong}, // POST /tenants
	"refresh:approve":              {Min: session.AssuranceStrong}, // POST /stewards/refresh/{pending_id}/approve
	"refresh:set-policy":           {Min: session.AssuranceStrong}, // PUT /tenants/{tenant_path}/refresh-policy
	"steward:move":                 {Min: session.AssuranceStrong}, // POST /stewards/{id}/move
	"steward:decommission":         {Min: session.AssuranceStrong}, // DELETE /stewards/{id}
	"web-account:create":           {Min: session.AssuranceStrong}, // POST /web/accounts
	"web-account:delete":           {Min: session.AssuranceStrong}, // DELETE /web/accounts/{username}

	// Cluster node lifecycle permissions — new in Issue #2780.
	"cluster:drain-node":        {Min: session.AssuranceStrong}, // POST /cluster/nodes/{id}/drain
	"cluster:decommission-node": {Min: session.AssuranceStrong}, // POST /cluster/nodes/{id}/decommission

	// Session credential-minting — new in Issue #2780.
	// session:list and session:revoke are intentionally absent: revoking a session
	// is a de-escalation/safety action that must not be gated on AssuranceStrong
	// (a lost/stolen device needs revocation to succeed, not fail for assurance).
	"session:create": {Min: session.AssuranceStrong}, // POST /sessions — mints long-lived Bearer token

	// Forward-declared catastrophic permissions (no live REST routes yet).
	// RequireUserPresence: true marks these for a future fresh WebAuthn assertion;
	// enforcement of that flag is a separate story. Only Min is enforced today.
	"module:approve":      {Min: session.AssuranceStrong, RequireUserPresence: true},
	"module:reject":       {Min: session.AssuranceStrong, RequireUserPresence: true},
	"publisher-trust:add": {Min: session.AssuranceStrong, RequireUserPresence: true},
}
