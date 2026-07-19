// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// Assurance-gate enforcement tests (Issue #2780, ADR-021).
// Replaces the former requireTier(TierMTLSOnly) tests with assurance-level equivalents.
//
// Testing strategy:
//   - F2 parity Part (c): real API-key credentials → Machine-assurance gets 403, not step-up.
//   - F2 parity Part (d): Basic-assurance step-up on every strong-assurance route via
//     requirePermission directly (mTLS/web-session creds not available in unit tests).
//   - F2 parity Part (e): Strong-assurance principal passes through assurance gate on every
//     strong-assurance route via requirePermission directly.
//   - Machine-assurance gets 403 (not step-up): requirePermission direct call.
//   - Relay principal: requirePermission direct call.
//   - Non-strong routes reachable: real API-key through router.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// strongAssuranceRouteEntry is a single route entry for F2 parity testing.
type strongAssuranceRouteEntry struct {
	method     string
	path       string
	permission string
}

// strongAssuranceRouteTable is the authoritative list of routes that enforce
// AssuranceStrong via requirePermission (ADR-021, Issue #2780). The F2 parity
// test verifies this matches the permissionAssurance registry (minus known-future entries).
//
// Three routes share the "registration:approve" permission, and two share
// "registration:manage-ip-trust" — all must appear here so the parity check
// can verify the full set.
var strongAssuranceRouteTable = []strongAssuranceRouteEntry{
	// Former TierMTLSOnly set — all migrated to permissionAssurance with Min: AssuranceStrong.
	{"POST", "/api/v1/certificates/provision", "certificate:provision"},
	{"POST", "/api/v1/certificates/signing/rotate", "certificate:rotate"},
	{"POST", "/api/v1/rbac/roles", "rbac:create-role"},
	{"PUT", "/api/v1/rbac/roles/test-id", "rbac:update-role"},
	{"DELETE", "/api/v1/rbac/roles/test-id", "rbac:delete-role"},
	{"POST", "/api/v1/api-keys", "api-key:create"},
	{"DELETE", "/api/v1/api-keys/test-id", "api-key:delete"},
	{"POST", "/api/v1/registration/tokens", "registration:create-token"},
	{"DELETE", "/api/v1/registration/tokens/test-token", "registration:delete-token"},
	{"POST", "/api/v1/registration/tokens/test-token/revoke", "registration:revoke-token"},
	{"POST", "/api/v1/registration/tokens/test-tenant/rotate", "registration:rotate-token"},
	{"POST", "/api/v1/registration/reg-123/approve", "registration:approve"},
	{"POST", "/api/v1/registration/approve-all", "registration:approve"},
	{"POST", "/api/v1/registration/approve-by-cidr", "registration:approve"},
	{"POST", "/api/v1/registration/ip-trust", "registration:manage-ip-trust"},
	{"DELETE", "/api/v1/registration/ip-trust/test-tenant/192.168.1.0/24", "registration:manage-ip-trust"},
	{"POST", "/api/v1/tenants", "tenant:create"},
	{"POST", "/api/v1/stewards/refresh/pending-123/approve", "refresh:approve"},
	{"PUT", "/api/v1/tenants/test-tenant/refresh-policy", "refresh:set-policy"},
	{"POST", "/api/v1/stewards/test-steward-id/move", "steward:move"},
	{"DELETE", "/api/v1/stewards/test-steward-id", "steward:decommission"},
	{"POST", "/api/v1/web/accounts", "web-account:create"},
	{"DELETE", "/api/v1/web/accounts/test-user", "web-account:delete"},
	// Cluster node lifecycle (Issue #2780) — new entries in permissionAssurance.
	{"POST", "/api/v1/cluster/nodes/test-id/drain", "cluster:drain-node"},
	{"POST", "/api/v1/cluster/nodes/test-id/decommission", "cluster:decommission-node"},
	// Session credential-minting (Issue #2780) — requires step-up before issuing Bearer token.
	{"POST", "/api/v1/sessions", "session:create"},
}

// knownFuturePermissions lists permissionAssurance entries with Min > Machine
// that have no REST routes yet — forward-declared for future stories.
var knownFuturePermissions = map[string]bool{
	"module:approve":      true,
	"module:reject":       true,
	"publisher-trust:add": true,
}

// allStrongAssurancePermissions collects the unique permission IDs from
// strongAssuranceRouteTable, used to build a comprehensive API key for parity testing.
func allStrongAssurancePermissions() []string {
	seen := make(map[string]bool)
	var perms []string
	for _, entry := range strongAssuranceRouteTable {
		if !seen[entry.permission] {
			seen[entry.permission] = true
			perms = append(perms, entry.permission)
		}
	}
	return perms
}

// TestF2_AssuranceGate_ParityWithPermissionRegistry is the F2 required test
// (Issue #2780). It verifies five invariants:
//
//	(a) Every route in strongAssuranceRouteTable has its permission registered in
//	    permissionAssurance with Min > AssuranceMachine.
//
//	(b) Every permissionAssurance entry with Min > AssuranceMachine is covered
//	    by strongAssuranceRouteTable OR listed in knownFuturePermissions.
//
//	(c) Each route returns HTTP 403 (not 401 step-up) to a Machine-assurance API key
//	    that holds the matching permission — proving the assurance gate fires and
//	    correctly distinguishes Machine from Basic/Strong principals.
//
//	(d) Each route returns HTTP 401 + WWW-Authenticate: CFGMS-StepUp to a
//	    Basic-assurance caller (web-session / cfg-Bearer) — verifying that the
//	    step-up challenge fires for every migrated route, not just a sample.
//
//	(e) Each route accepts a Strong-assurance caller and reaches the handler —
//	    verifying the assurance gate does not over-block legitimate mTLS admins.
func TestF2_AssuranceGate_ParityWithPermissionRegistry(t *testing.T) {
	server := setupTestServer(t)

	// Part (a): verify each table entry has a permissionAssurance entry with Min > Machine.
	for _, entry := range strongAssuranceRouteTable {
		req, found := permissionAssurance[entry.permission]
		assert.True(t, found,
			"permission %q in strongAssuranceRouteTable must be in permissionAssurance — add it or remove the table entry",
			entry.permission)
		if found {
			assert.Greater(t, int(req.Min), int(session.AssuranceMachine),
				"permission %q must have Min > AssuranceMachine", entry.permission)
		}
	}

	// Part (b): every strong-assurance permission is in the table or known-future.
	tablePerms := make(map[string]bool)
	for _, entry := range strongAssuranceRouteTable {
		tablePerms[entry.permission] = true
	}
	for permID, req := range permissionAssurance {
		if req.Min <= session.AssuranceMachine {
			continue
		}
		if knownFuturePermissions[permID] {
			continue
		}
		assert.True(t, tablePerms[permID],
			"permission %q has Min > AssuranceMachine but is absent from strongAssuranceRouteTable and not in knownFuturePermissions — add a route entry or mark as known-future",
			permID)
	}

	// Part (c): Machine-assurance API key with matching permissions must get 403.
	// An API key always gets AssuranceMachine (see middleware.go: authenticationMiddleware).
	// requirePermission fires AFTER authentication, sees Machine < Strong, and returns 403
	// (not 401 step-up, because Machine principals cannot interactively prove user presence).
	apiKey := NewTestKey(t, server, allStrongAssurancePermissions())

	for _, entry := range strongAssuranceRouteTable {
		entry := entry
		t.Run("c_machine_403/"+entry.method+" "+entry.path, func(t *testing.T) {
			req := httptest.NewRequest(entry.method, entry.path, nil)
			req.Header.Set("X-API-Key", apiKey)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code,
				"Machine-assurance API key must get 403 on strong-assurance route")
			assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
				"Machine-assurance 403 must not include a step-up challenge")
		})
	}

	// Part (d): Basic-assurance caller must get 401 + CFGMS-StepUp on every
	// strong-assurance route. Uses requirePermission directly since mTLS/web-session
	// credentials are not available in unit tests; the gate is in requirePermission,
	// not in the authentication middleware (ADR-021 Decision 6).
	for _, entry := range strongAssuranceRouteTable {
		entry := entry
		t.Run("d_basic_gets_stepup/"+entry.method+" "+entry.path, func(t *testing.T) {
			parts := strings.SplitN(entry.permission, ":", 2)
			require.Len(t, parts, 2, "permission %q must be resource:action", entry.permission)
			assertStepUpFromRequirePermission(t, server, parts[0], parts[1])
		})
	}

	// Part (e): Strong-assurance caller must reach the inner handler (assurance gate
	// must not block a legitimate mTLS admin). Uses requirePermission directly with a
	// Strong-assurance + IsAdmin:true principal; IsAdmin short-circuits hasPermission
	// so no explicit permission grant is needed.
	strongPrincipal := &Principal{
		ID:         "cert-admin",
		Name:       "mtls-cert:cert-admin",
		IsAdmin:    true,
		Assurance:  session.AssuranceStrong,
		CertSerial: "abc123",
	}
	for _, entry := range strongAssuranceRouteTable {
		entry := entry
		t.Run("e_strong_passes/"+entry.method+" "+entry.path, func(t *testing.T) {
			parts := strings.SplitN(entry.permission, ":", 2)
			require.Len(t, parts, 2, "permission %q must be resource:action", entry.permission)

			handlerReached := false
			probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerReached = true
				w.WriteHeader(http.StatusOK)
			})
			handler := server.requirePermission(parts[0], parts[1])(probe)

			req := httptest.NewRequest(entry.method, entry.path, nil)
			req = req.WithContext(context.WithValue(req.Context(), principalContextKey, strongPrincipal))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.True(t, handlerReached,
				"Strong-assurance admin must reach handler for %s", entry.permission)
			assert.NotEqual(t, http.StatusUnauthorized, rec.Code,
				"Strong-assurance admin must not get 401 step-up on %s", entry.permission)
			assert.NotEqual(t, http.StatusForbidden, rec.Code,
				"Strong-assurance admin must not be blocked by assurance gate on %s", entry.permission)
			assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
				"Strong-assurance pass-through must not set WWW-Authenticate on %s", entry.permission)
		})
	}
}

// TestAssuranceGate_RouterWalk_StrongRoutesRegistered uses gorilla/mux Router.Match
// to verify that every entry in strongAssuranceRouteTable resolves to a real handler
// in the router. If a route is removed from server.go without updating the table,
// this test catches it before the F2 parity subtests run.
func TestAssuranceGate_RouterWalk_StrongRoutesRegistered(t *testing.T) {
	server := setupTestServer(t)

	for _, entry := range strongAssuranceRouteTable {
		entry := entry
		t.Run(entry.method+" "+entry.path, func(t *testing.T) {
			req := httptest.NewRequest(entry.method, entry.path, nil)
			var match mux.RouteMatch
			assert.True(t, server.router.Match(req, &match),
				"route %s %s must be registered in the router — update strongAssuranceRouteTable if the route was removed",
				entry.method, entry.path)
		})
	}
}

// TestAssuranceGate_BasicAssurance_GetsStepUp verifies that a Basic-assurance principal
// (web-session or cfg-CLI Bearer session) receives HTTP 401 + CFGMS-StepUp challenge from
// requirePermission on a strong-assurance route.
//
// Testing approach: call requirePermission directly rather than through the router, because
// mTLS admin cert and web-session credentials are not available in the unit-test environment
// (the assurance gate lives in requirePermission, not in the auth middleware).
func TestAssuranceGate_BasicAssurance_GetsStepUp(t *testing.T) {
	server := setupTestServer(t)

	basicPrincipal := &Principal{
		ID:        "web-admin",
		Name:      "web-session:web-admin",
		IsAdmin:   true,
		Assurance: session.AssuranceBasic,
	}

	// Use a representative strong-assurance route (api-key:create) to test the gate.
	// The F2 parity test (Part c) validates all routes; this test validates the step-up response shape.
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("api-key", "create")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"Basic-assurance admin must receive 401 step-up on strong-assurance route")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp",
		"401 must carry CFGMS-StepUp challenge")

	var body struct {
		Error             string `json:"error"`
		RequiredAssurance string `json:"required_assurance"`
	}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	assert.Equal(t, "step_up_required", body.Error)
	assert.Equal(t, "strong", body.RequiredAssurance)
}

// TestAssuranceGate_MachineAssurance_Gets403NotStepUp verifies that a Machine-assurance
// principal (API key / relay) with admin rights receives HTTP 403 — not 401 step-up —
// when the assurance gate fires. Machine principals must never be prompted to step up;
// they cannot interactively prove user presence (ADR-021).
//
// Uses requirePermission directly (same reasoning as TestAssuranceGate_BasicAssurance_GetsStepUp).
func TestAssuranceGate_MachineAssurance_Gets403NotStepUp(t *testing.T) {
	server := setupTestServer(t)

	machinePrincipal := &Principal{
		ID:        "machine-agent",
		Name:      "api-key:machine-agent",
		IsAdmin:   true,
		Assurance: session.AssuranceMachine,
	}

	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("api-key", "create")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, machinePrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"Machine-assurance principal must get 403, not 401 step-up")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Machine-assurance 403 must not include WWW-Authenticate step-up header")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code)
}

// TestAssuranceGate_StrongAssurance_ReachesHandler verifies that a Strong-assurance
// mTLS admin principal is NOT rejected by the assurance gate and passes through to
// the handler. Uses requirePermission directly since mTLS is unavailable in unit tests.
func TestAssuranceGate_StrongAssurance_ReachesHandler(t *testing.T) {
	server := setupTestServer(t)

	strongPrincipal := &Principal{
		ID:         "cert-admin",
		Name:       "mtls-cert:cert-admin",
		IsAdmin:    true,
		Assurance:  session.AssuranceStrong,
		CertSerial: "abc123",
	}

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("api-key", "create")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, strongPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"Strong-assurance admin must not receive 401 step-up")
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"Strong-assurance admin must not be rejected by the assurance gate")
	assert.True(t, handlerCalled, "inner handler must be called for Strong-assurance admin")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Strong-assurance pass-through must not set WWW-Authenticate")
}

// TestAssuranceGate_RelayPrincipal_Gets403 verifies that a relay-style Machine-assurance
// principal (IsAdmin: false, Permissions carry the matching grant) is rejected 403 on
// a strong-assurance route. This closes the relay-bypass vector documented in Issue #1675.
// Uses requirePermission directly since relay principals are only injected in-process.
func TestAssuranceGate_RelayPrincipal_Gets403(t *testing.T) {
	server := setupTestServer(t)

	relayPrincipal := &Principal{
		ID:          "relay-1",
		Name:        "relay:relay-1",
		IsAdmin:     false,
		Assurance:   session.AssuranceMachine,
		Permissions: []string{"api-key:create"},
		TenantID:    "relay-tenant",
	}

	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := server.requirePermission("api-key", "create")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, relayPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"relay (Machine-assurance) principal must be rejected 403 on strong-assurance route")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "INSUFFICIENT_PERMISSIONS", errResp.Error.Code)
}

// TestNonStrongRoute_RemainsReachableByAPIKey verifies that adding assurance gates
// to strong-assurance routes did not accidentally elevate routes that should remain
// accessible to Machine-assurance API-key principals (e.g. GET /api/v1/stewards).
func TestNonStrongRoute_RemainsReachableByAPIKey(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"non-strong-assurance route must remain reachable by API-key principal")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"valid API-key must be authenticated on non-strong-assurance route")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"non-strong-assurance route must not issue step-up challenge to API-key principal")
}

// assertStepUpFromRequirePermission is a shared helper for testing that the assurance gate
// returns 401 step-up for a specific resource:action pair with a Basic-assurance principal.
func assertStepUpFromRequirePermission(t *testing.T, server *Server, resource, action string) {
	t.Helper()
	basicPrincipal := &Principal{
		ID: "web-admin", Name: "web-session:web-admin",
		IsAdmin: true, Assurance: session.AssuranceBasic,
	}
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := server.requirePermission(resource, action)(probe)
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
}

// TestAssuranceGate_StepUp_SampleOfStrongRoutes verifies Basic-assurance step-up
// for a representative sample of strong-assurance routes via requirePermission directly.
// The full gate behavior across all routes is covered by the F2 parity test (Part c)
// using Machine-assurance; this test validates the step-up response is also correct.
func TestAssuranceGate_StepUp_SampleOfStrongRoutes(t *testing.T) {
	server := setupTestServer(t)

	sample := []struct{ resource, action string }{
		{"api-key", "create"},
		{"certificate", "provision"},
		{"registration", "approve"},
		{"cluster", "drain-node"},
		{"session", "create"},
	}

	for _, tc := range sample {
		tc := tc
		t.Run(tc.resource+":"+tc.action, func(t *testing.T) {
			assertStepUpFromRequirePermission(t, server, tc.resource, tc.action)
		})
	}
}

// TestAssuranceGate_StepUp_ResponseContainsRequiredAssuranceField verifies that the step-up
// response body always contains the required_assurance field so clients know which level
// to prove.
func TestAssuranceGate_StepUp_ResponseContainsRequiredAssuranceField(t *testing.T) {
	server := setupTestServer(t)

	basicPrincipal := &Principal{
		ID: "web-admin", Name: "web-session:web-admin",
		IsAdmin: true, Assurance: session.AssuranceBasic,
	}
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	handler := server.requirePermission("api-key", "create")(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, basicPrincipal))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&body))
	ra, _ := body["required_assurance"].(string)
	assert.False(t, strings.TrimSpace(ra) == "", "required_assurance must not be empty in step-up body")
}
