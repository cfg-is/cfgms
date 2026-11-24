// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
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
		"trigger:manage",               // Issue #6488: a trigger runs a workflow later, so it takes the same tap as running one
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
		// Issue #6408 (ADR-021 Amendment 13): assigning a role widens permissions, so it
		// takes a per-action tap; revoking one reduces access and stays tap-free.
		assert.Equal(t, perm == "rbac:assign-role", req.RequireUserPresence,
			"permission %q presence requirement", perm)
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
	assert.True(t, req.RequireUserPresence,
		"account:update must require a presence tap for every update (Issue #6408, ADR-021 Amendment 13)")
	assert.Empty(t, req.PresenceExemptRoutes,
		"account:update is all-or-nothing: presence requirements match method and route, not body, so disable is gated too")
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
		"steward:execute-scripts": {
			Min:                  session.AssuranceStrong,
			RequireUserPresence:  true,
			PresenceExemptRoutes: []string{"DELETE /api/v1/runs/{run_id}", "POST /api/v1/runs/command"},
		},
		"script:admin": {
			Min:                  session.AssuranceStrong,
			RequireUserPresence:  true,
			PresenceExemptRoutes: []string{"GET /api/v1/scripts", "GET /api/v1/scripts/{id}"},
		},
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
		"module:approve":                      true,
		"module:reject":                       true,
		"publisher-trust:add":                 true,
		"registration:approve-by-cidr":        true, // Issue #2969
		"tenant:approve-delete":               true, // Issue #3182: ADR-027 dual-control deletion approval
		"tenant:crossing-approve-break-glass": true, // Issue #4707: mirrors tenant:approve-delete
		"osquery:execute":                     true, // Issue #3569
		"signing-credential:request":          true, // Issue #3687: mints a CSR-signing credential
		"credential-request:approve":          true, // Issue #3718: decides the marker set/account binding for a credential
		"hyperv-profile:create":               true, // Issue #3785: rendered and executed as root at guest first boot
		"hyperv-profile:delete":               true, // Issue #3785: mirrors module:approve/module:reject
		"directory:credential-reveal":         true, // Issue #5559: returns a password once, per-action tap
		"steward:execute-scripts":             true, // Issue #5416: per-action tap, cancel and inline command exempt
		"script:admin":                        true, // Issue #5416: per-action tap, reads exempt
		"refresh:set-policy":                  true, // Issue #5419: can switch a tenant to auto_accept
		"installer:upload":                    true, // Issue #5298: per-action tap for human sessions
		"installer:delete":                    true, // Issue #5298
		"installer:publish:steward":           true, // Issue #5298
		"installer:approve:steward":           true, // Issue #6053: a tap to approve a steward binary
		"installer:dispatch:steward":          true, // Issue #5298: start and dispatch gated, halt and rollback exempt
		"automation-grant:create":             true, // Issue #5831: grants standing automation authority
		"content-approval:approve":            true, // Issue #5831: approves content for automated use
		"content-library:set-mode":            true, // Issue #5831: switches the content library mode
		"rollout-automation:set":              true, // Issue #6065: a tap to turn unattended rollouts on or off
		"rollout-credential:create":           true, // Issue #6066: a tap to mint the scoped rollout credential
		"account:set-software-authenticator":  true, // Issue #6141: a tap to allow a software authenticator for an account
		"workflow:write":                      true, // Issue #5899: a tap to save a workflow
		"workflow:execute":                    true, // Issue #5899: a tap to start a workflow
		"trigger:manage":                      true, // Issue #6488: a trigger runs a workflow later, so create, change, enable and manual run take the tap; delete, disable and reads are exempt
		// Issue #6408 (ADR-021 Amendment 13): credential creation, authenticator and
		// certificate binding, permission widening, account changes and break-glass.
		"account:create":              true,
		"account:update":              true,
		"webauthn:register":           true,
		"cert-binding:bind":           true,
		"cert-binding:rotate":         true,
		"api-key:create":              true,
		"rbac:create-role":            true,
		"rbac:update-role":            true,
		"rbac:assign-role":            true,
		"role:write":                  true,
		"tenant:crossing-break-glass": true,
	}
	for perm, req := range permissionAssurance {
		if catastrophic[perm] {
			continue
		}
		assert.False(t, req.RequireUserPresence,
			"permission %q should not have RequireUserPresence (only catastrophic permissions carry this flag)", perm)
	}
}

// TestPermissionAssurance_ConfigPushAndRefreshPolicy is a REQUIRED test (Issue #5419):
// config:push carries a Strong floor and refresh:set-policy requires user presence.
func TestPermissionAssurance_ConfigPushAndRefreshPolicy(t *testing.T) {
	push, found := permissionAssurance["config:push"]
	require.True(t, found, "config:push must be in permissionAssurance (Issue #5419)")
	assert.Equal(t, session.AssuranceStrong, push.Min)
	assert.True(t, push.AllowMachine, "scoped API keys keep working for config push")
	assert.False(t, push.RequireUserPresence)

	refresh, found := permissionAssurance["refresh:set-policy"]
	require.True(t, found, "refresh:set-policy must be in permissionAssurance")
	assert.Equal(t, session.AssuranceStrong, refresh.Min)
	assert.True(t, refresh.RequireUserPresence, "refresh:set-policy can switch a tenant to auto_accept")
}

// TestPermissionAssurance_ConfigPush_FloorEnforced drives the real requirePermission
// middleware on POST /api/v1/config/push (Issue #5419).
func TestPermissionAssurance_ConfigPush_FloorEnforced(t *testing.T) {
	server := setupTestServer(t)

	reached := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("config", "push")(probe)

	serve := func(p *Principal) *httptest.ResponseRecorder {
		reached = false
		req := httptest.NewRequest(http.MethodPost, "/api/v1/config/push", nil)
		req = req.WithContext(context.WithValue(req.Context(), principalContextKey, p))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	t.Run("Basic human session is challenged", func(t *testing.T) {
		rec := serve(&Principal{ID: "basic-user", Assurance: session.AssuranceBasic, Permissions: []string{"config:push"}})
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
		assert.False(t, reached)
	})

	t.Run("Strong human session is admitted", func(t *testing.T) {
		rec := serve(&Principal{ID: "strong-user", Assurance: session.AssuranceStrong, Permissions: []string{"config:push"}})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached)
	})

	t.Run("API key principal is admitted", func(t *testing.T) {
		rec := serve(&Principal{ID: "api-key", Assurance: session.AssuranceMachine, Permissions: []string{"config:push"}})
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, reached)
	})
}

// TestPermissionAssurance_WorkflowWriteExecute_FloorEnforced is a REQUIRED test (Issues #5498,
// #5899): workflow:write and workflow:execute carry a Strong floor and a presence tap for human
// sessions, and keep working with no tap for scoped API keys. It drives the real
// requirePermission middleware on the real workflow routes: saving a workflow (POST, PUT,
// DELETE) and starting one each get a presence step-up challenge without a fresh tap and
// succeed with one.
func TestPermissionAssurance_WorkflowWriteExecute_FloorEnforced(t *testing.T) {
	server := setupTestServer(t)

	routes := []struct {
		method, template, path, perm string
	}{
		{http.MethodPost, "/api/v1/workflows", "/api/v1/workflows", "workflow:write"},
		{http.MethodPut, "/api/v1/workflows/{id}", "/api/v1/workflows/wf-1", "workflow:write"},
		{http.MethodDelete, "/api/v1/workflows/{id}", "/api/v1/workflows/wf-1", "workflow:write"},
		{http.MethodPost, "/api/v1/workflows/{id}/execute", "/api/v1/workflows/wf-1/execute", "workflow:execute"},
	}

	for _, perm := range []string{"workflow:write", "workflow:execute"} {
		req, found := permissionAssurance[perm]
		require.True(t, found, "%s must be in permissionAssurance", perm)
		assert.Equal(t, session.AssuranceStrong, req.Min)
		assert.True(t, req.AllowMachine, "scoped API keys keep working")
		assert.True(t, req.RequireUserPresence, "a human takes a passkey tap")
	}

	for _, rt := range routes {
		resource, action, _ := strings.Cut(rt.perm, ":")
		t.Run(rt.method+" "+rt.template, func(t *testing.T) {
			newReq := func(p *Principal) *http.Request {
				r := httptest.NewRequest(rt.method, rt.path, strings.NewReader(`{"name":"wf-1"}`))
				return withPrincipal(r, p)
			}
			serve := func(r *http.Request) *httptest.ResponseRecorder {
				return serveOnRoute(server, rt.method, rt.template, resource, action, presenceOK, r)
			}

			rec := serve(newReq(&Principal{ID: "basic-user", Assurance: session.AssuranceBasic, Permissions: []string{rt.perm}, TenantID: "test-tenant"}))
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")

			human := &Principal{ID: "strong-user", Assurance: session.AssuranceStrong, Permissions: []string{rt.perm}, TenantID: "test-tenant"}
			assertPresenceChallenge(t, serve(newReq(human)), rt.perm)

			tapped := newReq(human)
			tapped.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, "strong-user", tapped, rt.perm))
			rec = serve(tapped)
			assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

			rec = serve(newReq(&Principal{ID: "api-key", Assurance: session.AssuranceMachine, Permissions: []string{rt.perm}, TenantID: "test-tenant"}))
			assert.Equal(t, http.StatusOK, rec.Code, "a scoped API key needs no tap")
		})
	}

	assert.NotContains(t, permissionAssurance, "workflow:read", "workflow:read stays ungated")
}

// triggerManageTappedRoutes are the trigger routes that take a presence tap, and
// triggerManageExemptRoutes the ones that do not (Issue #6488). The route-classification test
// requires every registered /api/v1/triggers route to appear in exactly one of them.
var triggerManageTappedRoutes = []string{
	"POST /api/v1/triggers",
	"PUT /api/v1/triggers/{id}",
	"POST /api/v1/triggers/{id}/enable",
	"POST /api/v1/triggers/{id}/execute",
}

var triggerManageExemptRoutes = []string{
	"GET /api/v1/triggers/health",
	"GET /api/v1/triggers",
	"GET /api/v1/triggers/{id}",
	"DELETE /api/v1/triggers/{id}",
	"POST /api/v1/triggers/{id}/disable",
	"GET /api/v1/triggers/{id}/executions",
}

// TestPermissionAssurance_TriggerManage_FloorEnforced is a REQUIRED test (Issue #6488): creating,
// re-targeting, enabling or manually running a trigger takes the same Strong floor and presence
// tap as running the workflow it starts, and a machine principal is never asked for a tap. It
// drives the real requirePermission gate on the real trigger routes.
func TestPermissionAssurance_TriggerManage_FloorEnforced(t *testing.T) {
	req, found := permissionAssurance["trigger:manage"]
	require.True(t, found, "trigger:manage must be in permissionAssurance")
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.True(t, req.RequireUserPresence, "a human takes a passkey tap")
	assert.True(t, req.AllowMachine, "scoped API keys are treated as for workflow:execute")
	assert.ElementsMatch(t, triggerManageExemptRoutes, req.PresenceExemptRoutes)

	server, router, mgr := triggerGateFixture(t)

	// Holding workflow:execute too keeps the workflow:execute check out of the way: this test
	// is about the assurance gate.
	perms := []string{"trigger:manage", "workflow:execute"}
	machine := triggerGatePrincipal("seed-key", session.AssuranceMachine, perms...)
	seed := httptest.NewRecorder()
	router.ServeHTTP(seed, triggerGateRequest(http.MethodPost, "/api/v1/triggers", string(scheduleTriggerBody(t, "t1")), machine))
	require.Equal(t, http.StatusCreated, seed.Code, seed.Body.String())

	routes := []struct {
		method, template, path, body string
		wantOK                       int
	}{
		{http.MethodPost, "/api/v1/triggers", "/api/v1/triggers", string(scheduleTriggerBody(t, "t2")), http.StatusCreated},
		{http.MethodPut, "/api/v1/triggers/{id}", "/api/v1/triggers/t1", string(scheduleTriggerBody(t, "t1")), http.StatusOK},
		{http.MethodPost, "/api/v1/triggers/{id}/enable", "/api/v1/triggers/t1/enable", "", http.StatusOK},
		{http.MethodPost, "/api/v1/triggers/{id}/execute", "/api/v1/triggers/t1/execute", "{}", http.StatusOK},
	}
	for _, rt := range routes {
		t.Run(rt.method+" "+rt.template, func(t *testing.T) {
			serve := func(r *http.Request) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				router.ServeHTTP(rec, r)
				return rec
			}

			basic := triggerGatePrincipal("basic-user", session.AssuranceBasic, perms...)
			rec := serve(triggerGateRequest(rt.method, rt.path, rt.body, basic))
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
			assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")

			human := triggerGatePrincipal("strong-user", session.AssuranceStrong, perms...)
			assertPresenceChallenge(t, serve(triggerGateRequest(rt.method, rt.path, rt.body, human)), "trigger:manage")

			tapped := triggerGateRequest(rt.method, rt.path, rt.body, human)
			tapTriggerRequest(t, server, tapped, human)
			rec = serve(tapped)
			assert.Equal(t, rt.wantOK, rec.Code, "a tapped Strong session reaches the handler: %s", rec.Body.String())
		})
	}

	// The machine principal needs no tap on any of them. Run last: the create above stored t2.
	for _, rt := range routes {
		rec := httptest.NewRecorder()
		body := rt.body
		path := rt.path
		if rt.method == http.MethodPost && rt.template == "/api/v1/triggers" {
			body = string(scheduleTriggerBody(t, "t3"))
		}
		router.ServeHTTP(rec, triggerGateRequest(rt.method, path, body, machine))
		assert.Equal(t, rt.wantOK, rec.Code, "machine principal on %s %s needs no tap: %s", rt.method, rt.template, rec.Body.String())
	}
	assert.ElementsMatch(t, []string{"t1", "t2", "t3"}, storedTriggerIDs(t, mgr))
}

// TestPermissionAssurance_TriggerManage_ExemptRoutesNeedNoTap is a REQUIRED test (Issue #6488):
// delete, disable and the reads succeed for a Strong human session with no presence token (stopping
// or removing automation is a de-escalation), still need a Strong session, and a create that is
// answered with a step-up challenge stores nothing.
func TestPermissionAssurance_TriggerManage_ExemptRoutesNeedNoTap(t *testing.T) {
	server, router, mgr := triggerGateFixture(t)
	perms := []string{"trigger:manage", "workflow:execute"}
	human := triggerGatePrincipal("strong-user", session.AssuranceStrong, perms...)

	serve := func(method, path, body string, p *Principal) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, triggerGateRequest(method, path, body, p))
		return rec
	}

	// A create without a tap is challenged and stores nothing.
	rec := serve(http.MethodPost, "/api/v1/triggers", string(scheduleTriggerBody(t, "untapped")), human)
	assertPresenceChallenge(t, rec, "trigger:manage")
	assert.Empty(t, storedTriggerIDs(t, mgr), "a create answered with a step-up challenge must store nothing")

	for _, id := range []string{"a", "b"} {
		req := triggerGateRequest(http.MethodPost, "/api/v1/triggers", string(scheduleTriggerBody(t, id)), human)
		tapTriggerRequest(t, server, req, human)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	}

	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/triggers/health"},
		{http.MethodGet, "/api/v1/triggers"},
		{http.MethodGet, "/api/v1/triggers/a"},
		{http.MethodGet, "/api/v1/triggers/a/executions"},
		{http.MethodPost, "/api/v1/triggers/a/disable"},
		{http.MethodDelete, "/api/v1/triggers/a"},
	} {
		rec := serve(c.method, c.path, "", human)
		assert.Contains(t, []int{http.StatusOK, http.StatusNoContent}, rec.Code, "%s %s needs no tap: %s", c.method, c.path, rec.Body.String())
	}
	assert.Equal(t, []string{"b"}, storedTriggerIDs(t, mgr))

	// No tap is not no assurance: a Basic session is still stepped up on a read.
	basic := triggerGatePrincipal("basic-user", session.AssuranceBasic, perms...)
	rec = serve(http.MethodGet, "/api/v1/triggers", "", basic)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
}

// TestPermissionAssurance_TriggerManage_RouteClassification is a REQUIRED test (Issue #6488): every
// registered /api/v1/triggers route is deliberately classified as tap-required or tap-exempt, and
// every PresenceExemptRoutes entry for trigger:manage matches a registered route. A trigger route
// added later without a classification decision fails here instead of silently inheriting the
// default.
func TestPermissionAssurance_TriggerManage_RouteClassification(t *testing.T) {
	server := newServerWithTriggerRoutes(t)

	registered := map[string]bool{}
	require.NoError(t, server.router.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, err := r.GetPathTemplate()
		if err != nil || !strings.HasPrefix(tpl, "/api/v1/triggers") {
			return nil
		}
		methods, err := r.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			registered[m+" "+tpl] = true
		}
		return nil
	}))
	require.NotEmpty(t, registered, "the walk must see the trigger routes")

	exempt := map[string]bool{}
	for _, e := range permissionAssurance["trigger:manage"].PresenceExemptRoutes {
		exempt[e] = true
	}
	decided := map[string]bool{}
	for _, e := range triggerManageExemptRoutes {
		decided[e] = true
		assert.True(t, exempt[e], "%s must be presence-exempt", e)
	}
	for _, e := range triggerManageTappedRoutes {
		decided[e] = true
		assert.False(t, exempt[e], "%s must take a presence tap", e)
	}

	for route := range registered {
		assert.True(t, decided[route], "trigger route %q has no presence classification: add it to the tap-required or the exempt list deliberately", route)
	}
	for e := range exempt {
		assert.True(t, registered[e], "presence-exempt entry %q matches no registered trigger route", e)
	}
	for e := range decided {
		assert.True(t, registered[e], "classified route %q is not registered", e)
	}
}

// TestStartupScan_NoWarnForWorkflowWriteExecuteKey is a REQUIRED test (Issue #5498): an API key
// holding only workflow:write and workflow:execute is not flagged by the startup scan.
func TestStartupScan_NoWarnForWorkflowWriteExecuteKey(t *testing.T) {
	capLog := &auditCapturingLogger{}
	server := setupTestServerWithLogger(t, capLog)

	capLog.mu.Lock()
	capLog.entries = nil
	capLog.mu.Unlock()

	err := server.secretStore.StoreSecret(context.Background(), &secretsif.SecretRequest{
		Key:       "hash-workflow-key",
		Value:     "hash-workflow-key",
		TenantID:  "default",
		CreatedBy: "test",
		Metadata: map[string]string{
			secretsif.MetadataKeySecretType: string(secretsif.SecretTypeAPIKey),
			"id":                            "test-workflow-key-id",
			"permissions":                   "workflow:write,workflow:execute",
		},
	})
	require.NoError(t, err)

	require.NoError(t, server.scanAPIKeysForPrivilegedAccess(context.Background()))
	assert.Nil(t, capLog.kvValue("overlapping_permissions"),
		"a key holding only workflow:write/execute must not be flagged")
}

// TestPermissionAssurance_ReportManage_FloorEnforced drives the real requirePermission
// middleware on POST /api/v1/reports/custom-templates (Issue #5686).
func TestPermissionAssurance_ReportManage_FloorEnforced(t *testing.T) {
	req, found := permissionAssurance["report:manage"]
	require.True(t, found, "report:manage must be in permissionAssurance")
	assert.Equal(t, session.AssuranceStrong, req.Min)
	assert.True(t, knownPermissions["report:manage"], "report:manage must be a known permission")

	server := setupTestServer(t)
	reached := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("report", "manage")(probe)

	serve := func(p *Principal) *httptest.ResponseRecorder {
		reached = false
		r := httptest.NewRequest(http.MethodPost, "/api/v1/reports/custom-templates", nil)
		r = r.WithContext(context.WithValue(r.Context(), principalContextKey, p))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)
		return rec
	}

	rec := serve(&Principal{ID: "api-key", Assurance: session.AssuranceMachine, Permissions: []string{"report:manage"}})
	assert.NotEqual(t, http.StatusOK, rec.Code, "a machine-assurance principal must be refused")
	assert.False(t, reached)

	rec = serve(&Principal{ID: "strong-user", Assurance: session.AssuranceStrong, Permissions: []string{"report:manage"}})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, reached)
}

// automationStrongPermissions is the set registered for the automation epic (Issue #5831).
var automationStrongPermissions = map[string]Requirement{
	"automation-grant:create":  {Min: session.AssuranceStrong, RequireUserPresence: true},
	"automation-grant:revoke":  {Min: session.AssuranceStrong},
	"content-approval:approve": {Min: session.AssuranceStrong, RequireUserPresence: true},
	"content-library:set-mode": {Min: session.AssuranceStrong, RequireUserPresence: true},
	"workflow:publish":         {Min: session.AssuranceStrong},
	"content-approval:revoke":  {Min: session.AssuranceStrong},
}

var automationReadPermissions = []string{
	"automation-grant:read", "automation-approval:read", "content-library:read",
}

// TestAutomationPermissions_Registered is a REQUIRED test (Issue #5831): the nine automation
// permissions exist with the stated requirements, none sets AllowMachine, the presence-required
// ones carry Strong and RequireUserPresence, and reads stay out of permissionAssurance.
func TestAutomationPermissions_Registered(t *testing.T) {
	for perm, want := range automationStrongPermissions {
		got, found := permissionAssurance[perm]
		require.True(t, found, "%s must be in permissionAssurance", perm)
		assert.Equal(t, want.Min, got.Min, perm)
		assert.Equal(t, want.RequireUserPresence, got.RequireUserPresence, perm)
		assert.False(t, got.AllowMachine, "%s must not set AllowMachine", perm)
		assert.Empty(t, got.PresenceExemptRoutes, perm)
		assert.True(t, isKnownPermission(perm), "%s must be a known permission", perm)
	}
	for _, perm := range []string{"automation-grant:create", "content-approval:approve", "content-library:set-mode"} {
		got := permissionAssurance[perm]
		assert.True(t, got.RequireUserPresence, perm)
		assert.Equal(t, session.AssuranceStrong, got.Min, perm)
	}
	for _, perm := range automationReadPermissions {
		_, inAssurance := permissionAssurance[perm]
		assert.False(t, inAssurance, "%s is a read and must stay out of permissionAssurance", perm)
		assert.True(t, isKnownPermission(perm), "%s must be a known permission", perm)
	}
}

// TestAutomationPermissions_APIKeyRefused drives the real requirePermission middleware: an
// API-key principal that holds the permission string is still refused for every Strong one.
func TestAutomationPermissions_APIKeyRefused(t *testing.T) {
	server := setupTestServer(t)
	for perm := range automationStrongPermissions {
		t.Run(perm, func(t *testing.T) {
			parts := strings.SplitN(perm, ":", 2)
			reached := false
			probe := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})
			handler := server.requirePermission(parts[0], parts[1])(probe)
			req := httptest.NewRequest(http.MethodPost, "/probe", nil)
			p := &Principal{ID: "api-key", Assurance: session.AssuranceMachine, Permissions: []string{perm}}
			req = req.WithContext(context.WithValue(req.Context(), principalContextKey, p))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.False(t, reached)
		})
	}
}
