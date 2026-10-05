// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/registration"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// prepareSelectedTenantServer wires a crossing store and a client tenant
// ("msp-sel", beneath the root) onto server for Issue #4571's tests.
func prepareSelectedTenantServer(t *testing.T, server *Server) {
	t.Helper()
	wireCrossingStore(t, server)
	require.NoError(t, ensureTestRootTenant(context.Background(), server.tenantManager))
	_, err := server.tenantManager.CreateTenant(context.Background(), &tenant.TenantRequest{ID: "msp-sel", ParentID: testRootTenantID})
	require.NoError(t, err)
}

func grantSelectedTenantCrossing(t *testing.T, server *Server, principalID string) {
	t.Helper()
	now := time.Now()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID: "grant-sel-" + principalID, TenantID: "msp-sel", PrincipalID: principalID,
		Kind: business.TenantCrossingKindGrant, GrantedBy: "msp-admin",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
}

func rolePayloadJSON(t *testing.T) []byte {
	t.Helper()
	return validRolePayload("sel-role", "tag:sel")
}

// TestRoleConfig_RootScopedClientTenant_RequiresCrossing guards Issue #4571: a
// root-scoped caller selecting a client tenant with ?tenant= is challenged
// without a crossing, nothing is stored, and the same request succeeds with one.
// The root tenant itself needs no crossing.
func TestRoleConfig_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server := setupRoleConfigServer(t)
	prepareSelectedTenantServer(t, server)
	caller := rootScopedPrincipal("root-operator-sel")

	create := func(tenantID string) *httptest.ResponseRecorder {
		req := requestAsPrincipal(t, http.MethodPost, "/api/v1/roles?tenant="+tenantID, "", caller, rolePayloadJSON(t))
		rec := httptest.NewRecorder()
		server.handleCreateRoleConfig(rec, req)
		return rec
	}

	rec := create("msp-sel")
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)

	list := requestAsPrincipal(t, http.MethodGet, "/api/v1/roles?tenant=msp-sel", "", caller, nil)
	listRec := httptest.NewRecorder()
	server.handleListRoleConfigs(listRec, list)
	assert.Equal(t, http.StatusUnauthorized, listRec.Code, "reading a client tenant's roles needs a crossing too")

	assert.Equal(t, http.StatusCreated, create(testRootTenantID).Code, "the root tenant itself needs no crossing")

	grantSelectedTenantCrossing(t, server, caller.ID)
	assert.Equal(t, http.StatusCreated, create("msp-sel").Code, "with an active crossing the role is created")
}

// TestRegistrationToken_RootScopedClientTenant_RequiresCrossing guards Issue #4571:
// minting an enrollment token for a client tenant needs a crossing.
func TestRegistrationToken_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server, _ := setupTestServerWithTokenStore(t)
	prepareSelectedTenantServer(t, server)
	caller := rootScopedPrincipal("root-operator-sel")

	create := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(registration.TokenCreateRequest{
			TenantID: "msp-sel", ControllerURL: "grpc://controller.example.com:7443", ExpiresIn: "1d",
		})
		require.NoError(t, err)
		req := requestAsPrincipal(t, http.MethodPost, "/api/v1/registration/tokens", "", caller, body)
		rec := httptest.NewRecorder()
		server.handleCreateRegistrationToken(rec, req)
		return rec
	}

	rec := create()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

	grantSelectedTenantCrossing(t, server, caller.ID)
	assert.Equal(t, http.StatusCreated, create().Code)
}

// TestIPTrust_RootScopedClientTenant_RequiresCrossing guards Issue #4571: adding a
// registration IP-trust range for a client tenant needs a crossing.
func TestIPTrust_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server, store := newIPTrustServer(t)
	prepareSelectedTenantServer(t, server)
	caller := rootScopedPrincipal("root-operator-sel")

	add := func() *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]interface{}{"tenant_id": "msp-sel", "cidr": "198.51.100.0/24"})
		require.NoError(t, err)
		req := requestAsPrincipal(t, http.MethodPost, "/api/v1/registration/ip-trust", "", caller, body)
		rec := httptest.NewRecorder()
		server.handleAddIPTrust(rec, req)
		return rec
	}

	rec := add()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	ranges, err := store.ListTrustedRanges(context.Background(), "msp-sel")
	require.NoError(t, err)
	assert.Empty(t, ranges, "a refused add stores nothing")

	grantSelectedTenantCrossing(t, server, caller.ID)
	assert.Less(t, add().Code, 300, "with an active crossing the range is added")
}

// TestHypervProfile_RootScopedClientTenant_RequiresCrossing guards Issue #4571:
// profiles drive VM provisioning in a tenant, so a root-scoped caller selecting a
// client tenant with ?tenant= needs a crossing.
func TestHypervProfile_RootScopedClientTenant_RequiresCrossing(t *testing.T) {
	server := setupHypervProfileServer(t)
	prepareSelectedTenantServer(t, server)
	caller := rootScopedPrincipal("root-operator-sel")

	create := func() *httptest.ResponseRecorder {
		req := requestAsPrincipal(t, http.MethodPost, "/api/v1/hyperv/profiles?tenant=msp-sel", "", caller, validHypervProfilePayload("sel-profile"))
		rec := httptest.NewRecorder()
		server.handleCreateHypervProfile(rec, req)
		return rec
	}

	rec := create()
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())

	grantSelectedTenantCrossing(t, server, caller.ID)
	assert.Equal(t, http.StatusCreated, create().Code)
}

func saveSelectedTenantToken(t *testing.T, store registration.Store, tenantID string) *registration.Token {
	t.Helper()
	token, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID: tenantID, ControllerURL: "grpc://controller.example.com:7443", ExpiresIn: "1d",
	})
	require.NoError(t, err)
	require.NoError(t, store.SaveToken(context.Background(), token))
	return token
}

func listTokenTenants(t *testing.T, server *Server, caller *Principal) []string {
	t.Helper()
	req := requestAsPrincipal(t, http.MethodGet, "/api/v1/registration/tokens", "", caller, nil)
	rec := httptest.NewRecorder()
	server.handleListRegistrationTokens(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp TokenListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	tenants := make([]string, 0, len(resp.Tokens))
	for _, tok := range resp.Tokens {
		tenants = append(tenants, tok.TenantID)
	}
	return tenants
}

// TestRegistrationToken_RootScopedListAll_HidesUncrossedTenants guards the #4575
// review: a root-scoped list with no tenant_id shows the root tenant's tokens and
// crossed tenants' only — never an uncrossed client tenant's.
func TestRegistrationToken_RootScopedListAll_HidesUncrossedTenants(t *testing.T) {
	server, store := setupTestServerWithTokenStore(t)
	prepareSelectedTenantServer(t, server)
	saveSelectedTenantToken(t, store, testRootTenantID)
	saveSelectedTenantToken(t, store, "msp-sel")
	caller := rootScopedPrincipal("root-operator-sel")

	assert.Equal(t, []string{testRootTenantID}, listTokenTenants(t, server, caller), "uncrossed tenants' tokens are hidden")

	grantSelectedTenantCrossing(t, server, caller.ID)
	assert.ElementsMatch(t, []string{testRootTenantID, "msp-sel"}, listTokenTenants(t, server, caller))
}

// TestRegistrationToken_RootScopedTokenRoutes_RequireCrossing locks in the gate on
// the token-addressed routes: without a crossing, get/delete/revoke on a client
// tenant's token and rotate of a client tenant are refused and the token remains.
func TestRegistrationToken_RootScopedTokenRoutes_RequireCrossing(t *testing.T) {
	server, store := setupTestServerWithTokenStore(t)
	prepareSelectedTenantServer(t, server)
	token := saveSelectedTenantToken(t, store, "msp-sel")
	caller := rootScopedPrincipal("root-operator-sel")

	routes := []struct {
		name    string
		method  string
		path    string
		vars    map[string]string
		handler func(http.ResponseWriter, *http.Request)
	}{
		{"get", http.MethodGet, "/api/v1/registration/tokens/x", map[string]string{"token": token.Token}, server.handleGetRegistrationToken},
		{"revoke", http.MethodPost, "/api/v1/registration/tokens/x/revoke", map[string]string{"token": token.Token}, server.handleRevokeRegistrationToken},
		{"rotate", http.MethodPost, "/api/v1/registration/tokens/msp-sel/rotate", map[string]string{"tenant_id": "msp-sel"}, server.handleRotateRegistrationToken},
		{"delete", http.MethodDelete, "/api/v1/registration/tokens/x", map[string]string{"token": token.Token}, server.handleDeleteRegistrationToken},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			req := mux.SetURLVars(requestAsPrincipal(t, rt.method, rt.path, "", caller, []byte("{}")), rt.vars)
			rec := httptest.NewRecorder()
			rt.handler(rec, req)
			assert.Contains(t, []int{http.StatusUnauthorized, http.StatusNotFound}, rec.Code,
				"%s on an uncrossed client tenant must be refused: %s", rt.name, rec.Body.String())
		})
	}

	stored, err := store.GetToken(context.Background(), token.Token)
	require.NoError(t, err, "the token survives every refused request")
	assert.False(t, stored.Revoked, "the token was not revoked")
}
