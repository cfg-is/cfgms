// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// Note: auth_tiers.go was replaced by this file (Issue #2780). The filename
// assurance.go was chosen for clarity; the PR description documents this choice.

import "github.com/cfgis/cfgms/pkg/session"

// Requirement declares the minimum assurance level a permission needs and
// whether a fresh user-presence proof is required for catastrophic operations.
// RequireUserPresence: true is ENFORCED as of Issue #2784: requirePermission
// validates the X-Presence-Token header and rejects requests without a valid,
// fresh, single-use token with 401 WWW-Authenticate: CFGMS-StepUp.
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
	"certificate:provision":          {Min: session.AssuranceStrong},                            // POST /certificates/provision
	"certificate:rotate":             {Min: session.AssuranceStrong},                            // POST /certificates/signing/rotate
	"certificate:revoke":             {Min: session.AssuranceStrong},                            // POST /certificates/{serial}/revoke (Issue #3129)
	"rbac:create-role":               {Min: session.AssuranceStrong},                            // POST /rbac/roles
	"rbac:update-role":               {Min: session.AssuranceStrong},                            // PUT  /rbac/roles/{id}
	"rbac:delete-role":               {Min: session.AssuranceStrong},                            // DELETE /rbac/roles/{id}
	"rbac:assign-role":               {Min: session.AssuranceStrong},                            // POST /rbac/subjects/{id}/roles
	"rbac:revoke-role":               {Min: session.AssuranceStrong},                            // DELETE /rbac/subjects/{id}/roles/{role_id}
	"api-key:create":                 {Min: session.AssuranceStrong},                            // POST /api-keys
	"api-key:delete":                 {Min: session.AssuranceStrong},                            // DELETE /api-keys/{id}
	"registration:create-token":      {Min: session.AssuranceStrong},                            // POST /registration/tokens
	"registration:delete-token":      {Min: session.AssuranceStrong},                            // DELETE /registration/tokens/{token}
	"registration:revoke-token":      {Min: session.AssuranceStrong},                            // POST /registration/tokens/{token}/revoke
	"registration:rotate-token":      {Min: session.AssuranceStrong},                            // POST /registration/tokens/{tenant_id}/rotate
	"registration:approve":           {Min: session.AssuranceStrong},                            // POST /registration/{id}/approve + approve-all
	"registration:manage-ip-trust":   {Min: session.AssuranceStrong},                            // POST + DELETE /registration/ip-trust
	"tenant:create":                  {Min: session.AssuranceStrong},                            // POST /tenants
	"tenant:delete":                  {Min: session.AssuranceStrong},                            // POST /tenants/{id}/delete, DELETE /tenants/{id}/delete (Issue #3182)
	"tenant:approve-delete":          {Min: session.AssuranceStrong, RequireUserPresence: true}, // POST /tenants/{id}/delete/approve (Issue #3182)
	"tenant:update":                  {Min: session.AssuranceStrong},                            // PUT  /tenants/{id}
	"tenant:manage":                  {Min: session.AssuranceStrong},                            // POST /tenants/{id}/suspend, POST /tenants/{id}/config-source/test
	"tenant:crossing-grant":          {Min: session.AssuranceStrong},                            // POST /tenants/{id}/access-grants
	"tenant:crossing-break-glass":    {Min: session.AssuranceStrong},                            // POST /tenants/{id}/break-glass
	"refresh:approve":                {Min: session.AssuranceStrong},                            // POST /stewards/refresh/{pending_id}/approve
	"refresh:set-policy":             {Min: session.AssuranceStrong},                            // PUT /tenants/{tenant_path}/refresh-policy
	"steward:move":                   {Min: session.AssuranceStrong},                            // POST /stewards/{id}/move
	"steward:decommission":           {Min: session.AssuranceStrong},                            // DELETE /stewards/{id}
	"account:create":                 {Min: session.AssuranceStrong},                            // POST /accounts (Issue #3574)
	"account:update":                 {Min: session.AssuranceStrong},                            // PUT  /accounts/{username} (Issue #3126: can reset password or disable; Issue #3574)
	"account:delete":                 {Min: session.AssuranceStrong},                            // DELETE /accounts/{username} (Issue #3574)
	"account:revoke-enrollment-link": {Min: session.AssuranceStrong},                            // POST /accounts/{username}/enrollment-link/revoke (Issue #3574)

	// Cluster node lifecycle permissions — new in Issue #2780.
	"cluster:drain-node":        {Min: session.AssuranceStrong}, // POST /cluster/nodes/{id}/drain
	"cluster:decommission-node": {Min: session.AssuranceStrong}, // POST /cluster/nodes/{id}/decommission

	// Session credential-minting — new in Issue #2780.
	// session:list and session:revoke are intentionally absent: revoking a session
	// is a de-escalation/safety action that must not be gated on AssuranceStrong
	// (a lost/stolen device needs revocation to succeed, not fail for assurance).
	"session:create": {Min: session.AssuranceStrong}, // POST /sessions — mints long-lived Bearer token

	// WebAuthn passkey / FIDO2 registration and revocation (Issue #2782, #2783).
	// Credential-minting and credential-removal surfaces — both gated at AssuranceStrong,
	// consistent with session:create and account:create. List (webauthn:list) is read-only
	// and is intentionally absent from this map (reads are outside the elevated surface).
	"webauthn:register": {Min: session.AssuranceStrong}, // POST /accounts/{username}/webauthn/register/begin|finish (Issue #3574)
	"webauthn:revoke":   {Min: session.AssuranceStrong}, // POST /accounts/{username}/webauthn/revoke/{credential_id} (Issue #3574)

	// mTLS admin certificate binding management (Issue #3578).
	// bind and revoke are credential-mutation surfaces gated at AssuranceStrong, mirroring
	// webauthn:register and webauthn:revoke. list is read-only and is intentionally absent
	// from this map (reads are outside the elevated surface, matching webauthn:list).
	"cert-binding:bind":   {Min: session.AssuranceStrong}, // POST /accounts/{username}/certs/bind
	"cert-binding:revoke": {Min: session.AssuranceStrong}, // POST /accounts/{username}/certs/revoke/{serial}

	// WebAuthn presence-assertion endpoint (Issue #2784).
	// Mints a short-lived, single-use presence token consumed by RequireUserPresence-gated
	// routes. AssuranceStrong is required: the principal must already hold strong assurance
	// before they can perform a fresh presence ceremony.
	"webauthn:assert-presence": {Min: session.AssuranceStrong}, // POST /webauthn/presence/begin|finish

	// Steward visibility toggle (Issue #2918): AssuranceBasic (not Machine) so bare/compromised
	// API keys cannot hide an active steward. Reachable from web-session cookies and cfg Bearer
	// sessions. scanAPIKeysForPrivilegedAccess warns at boot on any key granted this permission.
	"steward:visibility": {Min: session.AssuranceBasic}, // PATCH /stewards/{id}/visibility

	// WebAuthn step-up elevation endpoint (ADR-021 Amendment 2, Issue #2965).
	// Callable at AssuranceBasic: this IS the step-up path (the caller cannot already be
	// at AssuranceStrong via a different path to reach here). AssuranceMachine principals
	// (API keys) cannot call this endpoint — they hold no web session to elevate.
	"webauthn:elevate": {Min: session.AssuranceBasic}, // POST /webauthn/elevate/begin|finish

	// Terminal relay (Issue #2761). Browser WebSocket clients must hold a WebAuthn-strength
	// session (AssuranceStrong) before an interactive terminal to a steward is opened.
	// The steward leg authenticates via mTLS independently of this check.
	"terminal:create": {Min: session.AssuranceStrong}, // GET /terminal/ws/{steward_id}

	// Catastrophic permissions (no live REST routes yet — issue #2728/#2732 adds the routes).
	// RequireUserPresence: true is ENFORCED as of Issue #2784: requirePermission now validates
	// the X-Presence-Token header (minted by POST /api/v1/webauthn/presence/finish) and rejects
	// requests without a valid, fresh, single-use token with:
	//   401 WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="strong", presence="required"
	// The presence mechanism: POST /webauthn/presence/begin → finish → attach X-Presence-Token.

	// Module bundle approval (Issue #2728/#2732) — code that runs on every managed endpoint.
	"module:approve":      {Min: session.AssuranceStrong, RequireUserPresence: true},
	"module:reject":       {Min: session.AssuranceStrong, RequireUserPresence: true},
	"publisher-trust:add": {Min: session.AssuranceStrong, RequireUserPresence: true},

	// Per-tenant assurance-policy admin (Issue #2839).
	// Requires AssuranceStrong so only a strongly-authenticated admin can raise a tenant's
	// own assurance posture — consistent with refresh:set-policy's existing bar.
	// assurance-policy:get is intentionally absent (reads stay unrestricted at the assurance
	// layer, matching refresh:get-policy's absence from this map).
	"assurance-policy:set": {Min: session.AssuranceStrong}, // PUT /tenants/{tenant_path}/assurance-policy

	// Bulk CIDR registration approval (Issue #2969): RFC1918 ranges collide across tenants,
	// making this a trust-boundary decision that must not be a convenience gate.
	// Approve-by-CIDR requires AssuranceStrong + a fresh user-presence proof.
	// (Single-entry approve and approve-all use registration:approve — AssuranceStrong only.)
	"registration:approve-by-cidr": {Min: session.AssuranceStrong, RequireUserPresence: true},

	// Alert silence (Issue #3266): silencing hides a real alert until it expires —
	// treat it like other consequential write actions already in this map.
	// alert:acknowledge is intentionally absent: low-risk read-adjacent action.
	"alert:silence": {Min: session.AssuranceStrong},

	// OSquery ad-hoc fleet query dispatch (Issue #3569): gates POST /api/v1/osquery/query.
	// RequireUserPresence: true mirrors module:approve/module:reject — catalog templates
	// may reach sensitive host state, so a fresh hardware-backed assertion is required.
	"osquery:execute": {Min: session.AssuranceStrong, RequireUserPresence: true},
}

// legacyPermissionIDs maps a current permission ID to the historical IDs that named the
// same operation before Issue #3574 renamed the web-account surface to account:*.
//
// Why this exists: per-tenant assurance-policy overrides are persisted keyed by the literal
// permission ID an admin wrote at the time (AssurancePolicyOverrideDTO.PermissionID) and are
// matched by string compare during resolution. Renaming the permission ID would therefore
// drop every stored override an admin had deliberately set on the old ID — a tenant that
// required a fresh WebAuthn presence assertion for web-account:delete would silently resolve
// to the global floor for account:delete, with no error, no log and no 4xx. That is the
// fail-OPEN direction relative to admin intent.
//
// Overrides can only raise Min (max) and can only set RequireUserPresence (OR), never clear
// either, so honouring a pre-rename override can never lower the effective bar.
//
// This mapping is read-side only and deliberately does not apply to grants: knownPermissions /
// isKnownPermission still reject the old IDs outright, which is the fail-CLOSED direction and
// is the hard-break behaviour Issue #3574 intends. scanAccountsForStalePermissions makes
// those dead grants observable at startup.
var legacyPermissionIDs = map[string][]string{
	"account:list":                   {"web-account:list"},
	"account:create":                 {"web-account:create"},
	"account:get":                    {"web-account:get"},
	"account:update":                 {"web-account:update"},
	"account:delete":                 {"web-account:delete"},
	"account:revoke-enrollment-link": {"web-account:revoke-enrollment-link"},
}

// overrideAppliesTo reports whether a stored assurance-policy override keyed by storedID
// governs permissionID: either an exact match, or a pre-rename ID for the same operation
// (see legacyPermissionIDs).
func overrideAppliesTo(storedID, permissionID string) bool {
	if storedID == permissionID {
		return true
	}
	for _, legacy := range legacyPermissionIDs[permissionID] {
		if storedID == legacy {
			return true
		}
	}
	return false
}
