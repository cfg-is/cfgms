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

	// WebAuthn passkey / FIDO2 registration and revocation (Issue #2782, #2783).
	// Credential-minting and credential-removal surfaces — both gated at AssuranceStrong,
	// consistent with session:create and web-account:create. List (webauthn:list) is read-only
	// and is intentionally absent from this map (reads are outside the elevated surface).
	"webauthn:register": {Min: session.AssuranceStrong}, // POST /web/accounts/{username}/webauthn/register/begin|finish
	"webauthn:revoke":   {Min: session.AssuranceStrong}, // POST /web/accounts/{username}/webauthn/revoke/{credential_id}

	// WebAuthn presence-assertion endpoint (Issue #2784).
	// Mints a short-lived, single-use presence token consumed by RequireUserPresence-gated
	// routes. AssuranceStrong is required: the principal must already hold strong assurance
	// before they can perform a fresh presence ceremony.
	"webauthn:assert-presence": {Min: session.AssuranceStrong}, // POST /webauthn/presence/begin|finish

	// WebAuthn step-up elevation endpoint (ADR-021 Amendment 2, Issue #2965).
	// Callable at AssuranceBasic: this IS the step-up path (the caller cannot already be
	// at AssuranceStrong via a different path to reach here). AssuranceMachine principals
	// (API keys) cannot call this endpoint — they hold no web session to elevate.
	"webauthn:elevate": {Min: session.AssuranceBasic}, // POST /webauthn/elevate/begin|finish

	// Catastrophic permissions (no live REST routes yet — issue #2728/#2732 adds the routes).
	// RequireUserPresence: true is ENFORCED as of Issue #2784: requirePermission now validates
	// the X-Presence-Token header (minted by POST /api/v1/webauthn/presence/finish) and rejects
	// requests without a valid, fresh, single-use token with:
	//   401 WWW-Authenticate: CFGMS-StepUp realm="cfgms", required="strong", presence="required"
	// Implementers of #2728 (module:approve/reject routes) and any future publisher-trust:add
	// routes must document to their clients that a presence ceremony is required before each call.
	// The presence mechanism: POST /webauthn/presence/begin → finish → attach X-Presence-Token.
	"module:approve":      {Min: session.AssuranceStrong, RequireUserPresence: true},
	"module:reject":       {Min: session.AssuranceStrong, RequireUserPresence: true},
	"publisher-trust:add": {Min: session.AssuranceStrong, RequireUserPresence: true},
}
