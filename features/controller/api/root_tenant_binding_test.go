// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// webSessionRequest returns a request carrying a web session cookie for an
// account cached on srv, issued (not elevated) for tenantID.
func webSessionRequest(t *testing.T, srv *Server, issue func(principalID, tenantID string) string, acct *account, method, path string) *http.Request {
	t.Helper()
	srv.cacheAccount(acct)
	token := issue(acct.ID, acct.TenantID)
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(&http.Cookie{Name: "cfgms_session", Value: token})
	return req
}

// TestRootTenantBinding_WebSessions guards Issue #4665: a root-scope account's web
// session is bound to the deployment's root tenant and carries root scope from the
// account's explicit root_scope flag — even before any step-up, since proof
// strength is enforced per permission, not by withholding scope — while a tenant
// account's session stays confined to its tenant.
func TestRootTenantBinding_WebSessions(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
	issue := func(principalID, tenantID string) string {
		_, token, err := mgr.Issue(context.Background(), principalID, "web-login", tenantID)
		require.NoError(t, err)
		return token
	}

	var principal *Principal
	var scope ctxkeys.TenantScope
	var ctxTenant string
	capture := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, _ = r.Context().Value(principalContextKey).(*Principal)
		scope, _ = r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
		ctxTenant, _ = r.Context().Value(ctxkeys.TenantID).(string)
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("root account", func(t *testing.T) {
		rec := httptest.NewRecorder()
		capture.ServeHTTP(rec, webSessionRequest(t, srv, issue,
			&account{ID: "bind-root-op", Username: "bind-root-op", RootScope: true}, http.MethodGet, "/api/v1/stewards"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotNil(t, principal)
		assert.True(t, scope.IsRoot(), "a root-scope account acts as root")
		assert.Equal(t, testRootTenantID, principal.TenantID, "bound to the root tenant, not an empty tenant")
		assert.Equal(t, testRootTenantID, ctxTenant)
	})

	t.Run("tenant account", func(t *testing.T) {
		require.NoError(t, ensureTestRootTenant(context.Background(), srv.tenantManager))
		rec := httptest.NewRecorder()
		capture.ServeHTTP(rec, webSessionRequest(t, srv, issue,
			&account{ID: "bind-tenant-op", Username: "bind-tenant-op", TenantID: "acme-corp", Permissions: []string{"steward:list"}},
			http.MethodGet, "/api/v1/stewards"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.False(t, scope.IsRoot())
		assert.True(t, scope.IsTenant())
		assert.Equal(t, "acme-corp", scope.Path())
	})
}

// TestRootTenantBinding_RootWebSessionReachesRootOnlyEndpoints guards Issue #4665
// end to end: through the authentication middleware, a root-scope account's web
// session is served by root-only endpoints — workflows and installer artifacts —
// that previously answered 404 / 403 because its session carried an empty
// tenant and no root scope.
func TestRootTenantBinding_RootWebSessionReachesRootOnlyEndpoints(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)
	srv.blobStore = newFSBlobStore(t)
	issue := func(principalID, tenantID string) string {
		_, token, err := mgr.Issue(context.Background(), principalID, "web-login", tenantID)
		require.NoError(t, err)
		return token
	}
	rootAcct := &account{ID: "bind-root-web", Username: "bind-root-web", RootScope: true}

	h, _ := newTestWorkflowHandler(t)
	h.SetTenantResolution(srv.rootTenantID, srv.selectAuthorizedTenant)
	h.SetRequirePermFn(allowAllPermFn)
	router := mux.NewRouter()
	require.NoError(t, h.RegisterWorkflowRoutes(router.PathPrefix("/workflows").Subrouter()))

	rec := httptest.NewRecorder()
	srv.authenticationMiddleware(router).ServeHTTP(rec, webSessionRequest(t, srv, issue, rootAcct, http.MethodGet, "/workflows"))
	assert.Equal(t, http.StatusOK, rec.Code, "root web session must list workflows: %s", rec.Body.String())

	rec = httptest.NewRecorder()
	srv.authenticationMiddleware(http.HandlerFunc(srv.handleListInstallerArtifacts)).
		ServeHTTP(rec, webSessionRequest(t, srv, issue, rootAcct, http.MethodGet, "/api/v1/installer/artifacts"))
	assert.Equal(t, http.StatusOK, rec.Code, "root web session must list installer artifacts: %s", rec.Body.String())
}
