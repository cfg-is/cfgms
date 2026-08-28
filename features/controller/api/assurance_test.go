// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// TestPermissionAssurance_SourceOfTruth validates that the canonical permissionAssurance
// registry is non-empty and that every entry uses the resource:action format.
func TestPermissionAssurance_SourceOfTruth(t *testing.T) {
	require.NotEmpty(t, permissionAssurance, "permissionAssurance must declare at least one entry")
	for perm, req := range permissionAssurance {
		assert.NotEmpty(t, perm, "permissionAssurance must not contain empty permission IDs")
		assert.Contains(t, perm, ":", "permission ID %q must use resource:action format", perm)
		assert.GreaterOrEqual(t, int(req.Min), int(session.AssuranceMachine),
			"permission %q Min must be >= AssuranceMachine", perm)
		assert.LessOrEqual(t, int(req.Min), int(session.AssuranceStrong),
			"permission %q Min must be a known AssuranceLevel", perm)
	}
}

// TestPermissionAssurance_FormerTier3SetPresent verifies that every permission that was
// in the former tier3Permissions map is present in permissionAssurance with at least
// Min: AssuranceStrong. This acts as a migration completeness guard.
func TestPermissionAssurance_FormerTier3SetPresent(t *testing.T) {
	formerTier3 := []string{
		"certificate:provision",
		"certificate:rotate",
		"rbac:create-role",
		"rbac:update-role",
		"rbac:delete-role",
		"api-key:create",
		"api-key:delete",
		"registration:create-token",
		"registration:delete-token",
		"registration:revoke-token",
		"registration:rotate-token",
		"registration:approve",
		"registration:manage-ip-trust",
		"tenant:create",
		"refresh:approve",
		"refresh:set-policy",
		"steward:move",
		"steward:decommission",
		"account:create",
		"account:delete",
	}
	for _, perm := range formerTier3 {
		req, found := permissionAssurance[perm]
		require.True(t, found, "former Tier-3 permission %q must be in permissionAssurance", perm)
		assert.Equal(t, session.AssuranceStrong, req.Min,
			"former Tier-3 permission %q must require AssuranceStrong", perm)
	}
}

// TestPermissionAssurance_NewPermissionsPresent verifies that the new permissions
// introduced in Issue #2780 and #2784 are present in the registry with the correct requirements.
func TestPermissionAssurance_NewPermissionsPresent(t *testing.T) {
	newPerms := map[string]session.AssuranceLevel{
		"cluster:drain-node":        session.AssuranceStrong,
		"cluster:decommission-node": session.AssuranceStrong,
		"session:create":            session.AssuranceStrong,
		"webauthn:assert-presence":  session.AssuranceStrong, // Issue #2784: presence-ceremony endpoint
	}
	for perm, wantMin := range newPerms {
		req, found := permissionAssurance[perm]
		require.True(t, found, "new permission %q must be in permissionAssurance", perm)
		assert.Equal(t, wantMin, req.Min, "permission %q must have Min: %v", perm, wantMin)
	}
}

// TestPermissionAssurance_SessionListRevoke_Absent verifies that session:list and
// session:revoke are deliberately absent from permissionAssurance. These are ordinary
// grant permissions (de-escalation/safety actions must not require AssuranceStrong).
func TestPermissionAssurance_SessionListRevoke_Absent(t *testing.T) {
	for _, perm := range []string{"session:list", "session:revoke"} {
		_, found := permissionAssurance[perm]
		assert.False(t, found,
			"permission %q must be absent from permissionAssurance — "+
				"revoking/listing sessions is a safety action, not a credential-minting operation", perm)
	}
}

// TestPermissionAssurance_CatastrophicForwardDeclarations verifies that all
// catastrophic permissions carry RequireUserPresence: true (Issue #2784, #2969).
func TestPermissionAssurance_CatastrophicForwardDeclarations(t *testing.T) {
	catastrophic := []string{
		"module:approve",
		"module:reject",
		"publisher-trust:add",
		"registration:approve-by-cidr", // Issue #2969: bulk CIDR approval
		"tenant:approve-delete",        // Issue #3182: ADR-027 dual-control deletion approval
		"osquery:execute",              // Issue #3569: catalog queries may reach sensitive host state
		"signing-credential:request",   // Issue #3687: mints a CSR-signing credential
	}
	for _, perm := range catastrophic {
		req, found := permissionAssurance[perm]
		require.True(t, found, "catastrophic permission %q must be in permissionAssurance", perm)
		assert.Equal(t, session.AssuranceStrong, req.Min, "catastrophic permission %q must require AssuranceStrong", perm)
		assert.True(t, req.RequireUserPresence, "catastrophic permission %q must have RequireUserPresence: true", perm)
	}
}

// TestPermissionAssurance_ApproveByCIDRIsGrantable verifies that
// registration:approve-by-cidr is in the knownPermissions allow-list (Issue #2969).
// Splitting approve-by-cidr out of registration:approve is only usable if the new
// permission can actually be granted: handleCreateAccount and handleCreateAPIKey
// reject any permission ID absent from that list with 400 INVALID_PERMISSION, which
// would make the web console's CIDR approval flow ungrantable.
func TestPermissionAssurance_ApproveByCIDRIsGrantable(t *testing.T) {
	assert.True(t, isKnownPermission("registration:approve-by-cidr"),
		"registration:approve-by-cidr must be grantable to web accounts")
	// The permission it was split out of remains grantable and unchanged.
	assert.True(t, isKnownPermission("registration:approve"),
		"registration:approve must remain grantable for single approve + approve-all")
	// Sanity: the allow-list still rejects the wildcard.
	assert.False(t, isKnownPermission("*"), "wildcard must never be a valid permission ID")
}

// TestPermissionAssurance_TenantUpdateStrong is a REQUIRED test (Issue #3125 AC:
// "tenant:update is registered in permissionAssurance at Min: session.AssuranceStrong").
// tenant:update covers config-source-type/git-mount-point transitions — supply-chain-
// adjacent, blast-radius-relevant changes that sit at the same bar as tenant:create.
func TestPermissionAssurance_TenantUpdateStrong(t *testing.T) {
	req, found := permissionAssurance["tenant:update"]
	require.True(t, found, "tenant:update must be in permissionAssurance")
	assert.Equal(t, session.AssuranceStrong, req.Min,
		"tenant:update must require AssuranceStrong (same bar as tenant:create)")
	assert.False(t, req.RequireUserPresence,
		"tenant:update must not require user presence (not a catastrophic operation)")
}

// TestPermissionAssurance_SubjectRoleBindingStrong is a REQUIRED test (Issue #3128 AC:
// "rbac:assign-role and rbac:revoke-role are registered in permissionAssurance at
// Min: session.AssuranceStrong"). Assigning an existing (possibly powerful) role to a
// subject is at least as sensitive as editing the role definition itself.
func TestPermissionAssurance_SubjectRoleBindingStrong(t *testing.T) {
	for _, perm := range []string{"rbac:assign-role", "rbac:revoke-role"} {
		req, found := permissionAssurance[perm]
		require.True(t, found, "permission %q must be in permissionAssurance", perm)
		assert.Equal(t, session.AssuranceStrong, req.Min,
			"permission %q must require AssuranceStrong", perm)
		assert.False(t, req.RequireUserPresence,
			"permission %q must not require user presence (not a catastrophic operation)", perm)
	}
}

// TestPermissionAssurance_TenantManageStrong is a REQUIRED test (Issue #3181 AC:
// "tenant:manage is registered in permissionAssurance at Min: session.AssuranceStrong").
// Suspending a tenant is a denial of service against everything inside it, so it sits
// at the same assurance bar as tenant:create and tenant:update.
func TestPermissionAssurance_TenantManageStrong(t *testing.T) {
	req, found := permissionAssurance["tenant:manage"]
	require.True(t, found, "tenant:manage must be in permissionAssurance (Issue #3181)")
	assert.Equal(t, session.AssuranceStrong, req.Min,
		"tenant:manage must require AssuranceStrong (same bar as tenant:create and tenant:update)")
	assert.False(t, req.RequireUserPresence,
		"tenant:manage must not require user presence (not a catastrophic operation)")
}

// TestPermissionAssurance_TenantManage_FloorEnforced is a REQUIRED test (Issue #3181 AC:
// "A principal at AssuranceBasic is rejected by requirePermission for tenant:manage, while
// a principal at AssuranceStrong is admitted"). Proves the floor is enforced at runtime by
// requirePermission, not merely declared in the map.
func TestPermissionAssurance_TenantManage_FloorEnforced(t *testing.T) {
	server := setupTestServer(t)

	reached := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("tenant", "manage")(probe)

	newReq := func(principal *Principal) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/some-tenant/suspend", nil)
		ctx := context.WithValue(req.Context(), principalContextKey, principal)
		return req.WithContext(ctx)
	}

	t.Run("AssuranceBasic is rejected with step-up challenge", func(t *testing.T) {
		reached = false
		p := &Principal{
			ID:          "basic-user",
			Assurance:   session.AssuranceBasic,
			Permissions: []string{"tenant:manage"},
			TenantID:    "some-tenant",
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newReq(p))
		assert.Equal(t, http.StatusUnauthorized, rec.Code,
			"AssuranceBasic must be rejected for tenant:manage (step-up required)")
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp",
			"rejected caller must receive a step-up challenge, not a flat denial")
		assert.False(t, reached, "probe must not be reached when assurance is insufficient")
	})

	t.Run("AssuranceStrong is admitted", func(t *testing.T) {
		reached = false
		p := &Principal{
			ID:          "strong-user",
			Assurance:   session.AssuranceStrong,
			Permissions: []string{"tenant:manage"},
			TenantID:    "some-tenant",
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, newReq(p))
		assert.Equal(t, http.StatusOK, rec.Code,
			"AssuranceStrong must be admitted for tenant:manage")
		assert.True(t, reached, "probe must be reached when assurance is sufficient")
	})
}

// TestPermissionAssurance_AccountUpdateStrong is a REQUIRED test (Issue #3126 AC:
// "account:update is registered in permissionAssurance at Min: session.AssuranceStrong").
// An update endpoint that can reset a password or disable an account is at least as
// sensitive as account:create or account:delete, both already at AssuranceStrong.
func TestPermissionAssurance_AccountUpdateStrong(t *testing.T) {
	req, found := permissionAssurance["account:update"]
	require.True(t, found, "account:update must be in permissionAssurance (Issue #3126, #3574)")
	assert.Equal(t, session.AssuranceStrong, req.Min,
		"account:update must require AssuranceStrong (same bar as create and delete)")
	assert.False(t, req.RequireUserPresence,
		"account:update must not require user presence (not a catastrophic operation)")
}

// TestPermissionAssurance_CrossRegistryInvariant is a REQUIRED test (Issue #3195).
// It asserts that every permission ID registered in permissionAssurance is also
// present in knownPermissions — or is a documented, deliberate exception — so that
// cross-registry drift is caught mechanically rather than by review.
//
// Deliberate exceptions (not grantable by design):
//   - session:create: the session-creation endpoint enforces this; no principal holds it as an explicit grant
//   - webauthn:assert-presence: presence ceremony endpoint; implicit capability of any strongly-authenticated principal
//   - webauthn:elevate: step-up elevation path; it IS the auth upgrade mechanism, not a grantable grant
//   - publisher-trust:add: forward-declared in knownFuturePermissions; no active REST route yet
//
// The former pending-audit set (cluster:drain-node, cluster:decommission-node, refresh:approve,
// refresh:set-policy, terminal:create) has been fully resolved in Issue #3303: all five are now
// in knownPermissions with scope guards where required — ADR-025 Decision 1 root-scoped guards
// for refresh:approve and terminal:create, and clusterLifecycleScopeAllowed for the two
// cluster:* permissions, whose routes target fleet-wide, non-tenant infrastructure.
func TestPermissionAssurance_CrossRegistryInvariant(t *testing.T) {
	// Deliberate exceptions: permissions in permissionAssurance that are intentionally
	// absent from knownPermissions because they are not grantable principal grants.
	deliberate := map[string]bool{
		"session:create":           true, // session endpoint; no principal holds this as an explicit grant
		"webauthn:assert-presence": true, // presence ceremony; implicit capability, not a grantable grant
		"webauthn:elevate":         true, // step-up elevation mechanism; not a grantable permission
		"publisher-trust:add":      true, // forward-declared (no active route); knownFuturePermissions
	}

	for permID := range permissionAssurance {
		if deliberate[permID] {
			continue
		}
		assert.True(t, isKnownPermission(permID),
			"permission %q is in permissionAssurance but missing from knownPermissions — "+
				"add it to knownPermissions (if it should be grantable) or to the deliberate "+
				"exception set in this test with a documented reason (Issue #3195)", permID)
	}

	// Verify that tenant:create specifically is in knownPermissions — the direct fix for Issue #3195.
	assert.True(t, isKnownPermission("tenant:create"),
		"tenant:create must be in knownPermissions: it gates POST /tenants and must be grantable "+
			"to API keys and web accounts (Issue #3195)")
}

// TestPermissionAssurance_TenantDeletionPipelineStrong is a REQUIRED test (Issue #3182 AC:
// "tenant:delete and tenant:approve-delete are registered in permissionAssurance at
// Min: session.AssuranceStrong; tenant:approve-delete additionally carries RequireUserPresence: true").
// Requesting a deletion is a denial-of-service risk against the subtree; approving it is
// irreversible — both must be gated at the strongest assurance level available.
func TestPermissionAssurance_TenantDeletionPipelineStrong(t *testing.T) {
	req, found := permissionAssurance["tenant:delete"]
	require.True(t, found, "tenant:delete must be in permissionAssurance (Issue #3182)")
	assert.Equal(t, session.AssuranceStrong, req.Min,
		"tenant:delete must require AssuranceStrong (requesting deletion is a DoS risk)")
	assert.False(t, req.RequireUserPresence,
		"tenant:delete must not require user presence (non-catastrophic: cancellable during hold)")

	req, found = permissionAssurance["tenant:approve-delete"]
	require.True(t, found, "tenant:approve-delete must be in permissionAssurance (Issue #3182)")
	assert.Equal(t, session.AssuranceStrong, req.Min,
		"tenant:approve-delete must require AssuranceStrong (approval is irreversible)")
	assert.True(t, req.RequireUserPresence,
		"tenant:approve-delete must require user presence (irreversible cascade delete)")

	// Both must be grantable to web accounts and API keys.
	assert.True(t, isKnownPermission("tenant:delete"),
		"tenant:delete must be in knownPermissions so it can be granted to a principal")
	assert.True(t, isKnownPermission("tenant:approve-delete"),
		"tenant:approve-delete must be in knownPermissions so it can be granted to a principal")
}

// TestPermissionAssurance_Issue3687_StrongCredentialFloor is a REQUIRED test (Issue
// #3687 AC: "permissionAssurance gains all four permission IDs listed above, exact
// strings, exact Requirement values" and "a request gated by any of the four
// permissions using an API key at AssuranceMachine is rejected (401/403)").
//
// steward:execute-scripts and script:admin have live routes; the assurance gate on
// them is additionally exercised end-to-end through the real router by
// TestF2_AssuranceGate_ParityWithPermissionRegistry (tier_enforcement_test.go).
// operator-payload:sign and signing-credential:request have no route yet (consumed
// by stories S6 and S10 respectively), so this test drives requirePermission
// directly, exactly as TestPermissionAssurance_TenantManage_FloorEnforced does for
// tenant:manage.
func TestPermissionAssurance_Issue3687_StrongCredentialFloor(t *testing.T) {
	want := map[string]Requirement{
		"steward:execute-scripts":    {Min: session.AssuranceStrong},
		"script:admin":               {Min: session.AssuranceStrong},
		"operator-payload:sign":      {Min: session.AssuranceStrong},
		"signing-credential:request": {Min: session.AssuranceStrong, RequireUserPresence: true},
	}

	server := setupTestServer(t)

	for permID, wantReq := range want {
		req, found := permissionAssurance[permID]
		require.True(t, found, "permission %q must be in permissionAssurance", permID)
		assert.Equal(t, wantReq, req, "permission %q must have Requirement %+v", permID, wantReq)
		assert.True(t, isKnownPermission(permID), "permission %q must be grantable via knownPermissions", permID)

		parts := strings.SplitN(permID, ":", 2)
		require.Len(t, parts, 2, "permission %q must be resource:action", permID)

		reached := false
		probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
		handler := server.requirePermission(parts[0], parts[1])(probe)

		machinePrincipal := &Principal{
			ID:          "machine-caller",
			Assurance:   session.AssuranceMachine,
			Permissions: []string{permID},
		}
		httpReq := httptest.NewRequest(http.MethodPost, "/", nil)
		httpReq = httpReq.WithContext(context.WithValue(httpReq.Context(), principalContextKey, machinePrincipal))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httpReq)

		assert.False(t, reached, "Machine-assurance principal must not reach the handler for %q", permID)
		assert.True(t, rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden,
			"Machine-assurance principal must be rejected (401/403) for %q, got %d", permID, rec.Code)
	}
}

// TestPermissionAssurance_NonCatastrophicNoUserPresence verifies that non-catastrophic
// permissions do not accidentally have RequireUserPresence set.
func TestPermissionAssurance_NonCatastrophicNoUserPresence(t *testing.T) {
	catastrophic := map[string]bool{
		"module:approve":               true,
		"module:reject":                true,
		"publisher-trust:add":          true,
		"registration:approve-by-cidr": true, // Issue #2969
		"tenant:approve-delete":        true, // Issue #3182: ADR-027 dual-control deletion approval
		"osquery:execute":              true, // Issue #3569
		"signing-credential:request":   true, // Issue #3687: mints a CSR-signing credential
	}
	for perm, req := range permissionAssurance {
		if catastrophic[perm] {
			continue
		}
		assert.False(t, req.RequireUserPresence,
			"permission %q should not have RequireUserPresence (only catastrophic permissions carry this flag)", perm)
	}
}
