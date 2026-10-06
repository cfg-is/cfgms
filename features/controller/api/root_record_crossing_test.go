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
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// boundRootOperator is the principal the authentication middleware builds for a
// root-scope account after Issue #4665: bound to the deployment's root tenant,
// with root authority from GlobalScope.
func boundRootOperator(id string) *Principal {
	return &Principal{
		ID:            id,
		Name:          "session:" + id,
		Assurance:     session.AssuranceStrong,
		TenantID:      testRootTenantID,
		GlobalScope:   true,
		RootScoped:    true,
		AccountBound:  true,
		ImplicitAdmin: true,
	}
}

// asRootOperator gives req the context the authentication middleware sets for a
// root principal: its root tenant ID and an explicit root scope.
func asRootOperator(req *http.Request, principal *Principal, vars map[string]string) *http.Request {
	req = mux.SetURLVars(req, vars)
	ctx := context.WithValue(req.Context(), ctxkeys.TenantID, principal.TenantID)
	ctx = context.WithValue(ctx, principalContextKey, principal)
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewRootScope())
	return req.WithContext(ctx)
}

func grantCrossing(t *testing.T, server *Server, principalID, tenantID string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, server.tenantCrossingStore.CreateTenantCrossing(context.Background(), &business.TenantCrossing{
		ID:          "grant-" + principalID + "-" + tenantID,
		TenantID:    tenantID,
		PrincipalID: principalID,
		Kind:        business.TenantCrossingKindGrant,
		GrantedBy:   tenantID + "-admin",
		CreatedAt:   now,
		ExpiresAt:   now.Add(time.Hour),
	}))
}

func assertCrossingChallenge(t *testing.T, rec *httptest.ResponseRecorder, tenantID string) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, rec.Code,
		"a root caller without a crossing must get the tenant-crossing challenge: %s", rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `required="tenant-crossing"`)
	var challenge map[string]interface{}
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&challenge))
	assert.Equal(t, "tenant_crossing_required", challenge["error"])
	assert.Equal(t, "/api/v1/tenants/"+tenantID+"/break-glass", challenge["break_glass_endpoint"])
}

// TestTenantAccessForScope_RootCrossingBoundary guards Issue #4665: a root scope is
// not unconditional. A principal subject to the ADR-025 crossing boundary reaches
// the root tenant's own records, and a client tenant's only through a crossing.
func TestTenantAccessForScope_RootCrossingBoundary(t *testing.T) {
	server := seedRootTenant(t, setupCrossingTestServer(t))
	ctx := context.Background()
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-scope", ParentID: testRootTenantID})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: "msp-scope-client", ParentID: "msp-scope"})
	require.NoError(t, err)

	const route = "TEST /records/{id}"
	root := ctxkeys.NewRootScope()
	operator := boundRootOperator("scope-operator")
	withPrincipal := func(p *Principal) context.Context {
		return context.WithValue(ctx, principalContextKey, p)
	}

	cases := []struct {
		name     string
		ctx      context.Context
		scope    ctxkeys.TenantScope
		resource string
		want     tenantAuthDecision
	}{
		{"boundary subject, root tenant record", withPrincipal(operator), root, testRootTenantID, tenantAuthAllowed},
		{"boundary subject, record with no tenant", withPrincipal(operator), root, "", tenantAuthAllowed},
		{"boundary subject, MSP record", withPrincipal(operator), root, "msp-scope", tenantAuthNeedsCrossing},
		{"boundary subject, client record below an MSP", withPrincipal(operator), root, "msp-scope-client", tenantAuthNeedsCrossing},
		{"boundary subject, unknown tenant", withPrincipal(operator), root, "no-such-tenant", tenantAuthDenied},
		{"root without the boundary (unbound bootstrap cert)", withPrincipal(&Principal{ID: "bootstrap", GlobalScope: true, CertSerial: "01"}), root, "msp-scope", tenantAuthAllowed},
		{"root scope with no principal (system-internal)", ctx, root, "msp-scope", tenantAuthAllowed},
		{"tenant scope, own tenant", ctx, ctxkeys.NewTenantScope("msp-scope"), "msp-scope", tenantAuthAllowed},
		{"tenant scope, other tenant", ctx, ctxkeys.NewTenantScope("msp-scope"), "msp-other", tenantAuthDenied},
		{"unset scope", withPrincipal(operator), ctxkeys.TenantScope{}, testRootTenantID, tenantAuthDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, server.tenantAccessForScope(tc.ctx, tc.scope, tc.resource, route))
		})
	}

	t.Run("an active crossing on the MSP covers it and its clients", func(t *testing.T) {
		grantCrossing(t, server, operator.ID, "msp-scope")
		assert.Equal(t, tenantAuthAllowed, server.tenantAccessForScope(withPrincipal(operator), root, "msp-scope", route))
		assert.Equal(t, tenantAuthAllowed, server.tenantAccessForScope(withPrincipal(operator), root, "msp-scope-client", route))
	})
}

// TestRootRecordRoutes_CrossingBoundary guards Issue #4665 at the handler level:
// routes that name a stored record by ID carry no tenant in the request, so the
// permission middleware's boundary gate cannot see the record's tenant. A root
// caller must still be challenged for a client tenant's record, and let through
// once it holds a crossing.
func TestRootRecordRoutes_CrossingBoundary(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	server = seedRootTenant(t, wireCrossingStore(t, server))
	ctx := context.Background()
	const msp = "msp-records"
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: msp, ParentID: testRootTenantID})
	require.NoError(t, err)

	newToken := func(t *testing.T) string {
		t.Helper()
		tok, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      msp,
			ControllerURL: "grpc://controller.example.com:7443",
			Group:         "crossing-group",
		})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, tok))
		return tok.Token
	}
	newAccount := func(t *testing.T, username string) {
		t.Helper()
		rec := postAccount(t, server, testAdminPrincipal(), AccountRequest{
			Username:    username,
			TenantID:    msp,
			Permissions: []string{"steward:list"},
		})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	}

	routes := []struct {
		name string
		call func(t *testing.T, operator *Principal) *httptest.ResponseRecorder
		// ok is the status the route answers once the caller may act.
		ok int
	}{
		{"GET /api/v1/registration/tokens/{token}", func(t *testing.T, operator *Principal) *httptest.ResponseRecorder {
			token := newToken(t)
			rec := httptest.NewRecorder()
			server.handleGetRegistrationToken(rec, asRootOperator(
				httptest.NewRequest(http.MethodGet, "/api/v1/registration/tokens/"+token, nil), operator, map[string]string{"token": token}))
			return rec
		}, http.StatusOK},
		{"DELETE /api/v1/registration/tokens/{token}", func(t *testing.T, operator *Principal) *httptest.ResponseRecorder {
			token := newToken(t)
			rec := httptest.NewRecorder()
			server.handleDeleteRegistrationToken(rec, asRootOperator(
				httptest.NewRequest(http.MethodDelete, "/api/v1/registration/tokens/"+token, nil), operator, map[string]string{"token": token}))
			return rec
		}, http.StatusNoContent},
		{"DELETE /api/v1/accounts/{username}", func(t *testing.T, operator *Principal) *httptest.ResponseRecorder {
			username := "msp-user-" + operator.ID
			newAccount(t, username)
			rec := httptest.NewRecorder()
			server.handleDeleteAccount(rec, asRootOperator(
				httptest.NewRequest(http.MethodDelete, "/api/v1/accounts/"+username, nil), operator, map[string]string{"username": username}))
			return rec
		}, http.StatusOK},
	}

	for i, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			t.Run("no crossing", func(t *testing.T) {
				rec := rt.call(t, boundRootOperator("op-without-"+string(rune('a'+i))))
				assertCrossingChallenge(t, rec, msp)
			})
			t.Run("active crossing", func(t *testing.T) {
				operator := boundRootOperator("op-with-" + string(rune('a'+i)))
				grantCrossing(t, server, operator.ID, msp)
				rec := rt.call(t, operator)
				assert.Equal(t, rt.ok, rec.Code, rec.Body.String())
			})
		})
	}
}
