// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

// handlers_web_accounts_test.go — regression coverage for the hasPermission change
// (ADR-025 Amendment 3, Issue #3585): ImplicitAdmin replaces the Permissions==nil sentinel.
//
// Two critical properties are pinned here:
//  1. A root-scope web account resolves every permission (ImplicitAdmin: true).
//  2. A tenant-scoped web account is confined to its explicit permission list verbatim.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// TestWebAccount_RootScope_ResolvesEveryPermission verifies the platform-administrator
// half of the web-account model (ADR-025 Amendment 3). A root-scope web account must:
//
//   - Carry ImplicitAdmin: true in the resolved Principal.
//   - Be admitted by hasPermission for any named permission, including permissions
//     that did not exist when the account was created (forward-compatibility).
//   - Still be challenged for an AssuranceStrong route (breadth ≠ proof strength).
func TestWebAccount_RootScope_ResolvesEveryPermission(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:        "root-admin-regression",
		Username:  "root-admin-regression",
		TenantID:  "",
		RootScope: true,
	})
	cookie := issueWebSession(t, mgr, "root-admin-regression", "")

	// Capture the resolved principal.
	var capturedPrincipal *Principal
	captureHandler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	captureHandler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)

	// ADR-025 Amendment 3: ImplicitAdmin is the explicit gate; nil Permissions is not.
	assert.True(t, capturedPrincipal.ImplicitAdmin,
		"root-scope web account must carry ImplicitAdmin: true")
	assert.NotNil(t, capturedPrincipal.Permissions,
		"Permissions must not be nil — the nil-sentinel is gone; ImplicitAdmin is the gate")
	assert.True(t, capturedPrincipal.GlobalScope,
		"root-scope account must have cross-tenant visibility")

	// hasPermission: any named permission is granted, including forward-compat ones.
	assert.True(t, srv.hasPermission(capturedPrincipal, "steward:read"),
		"root-scope account must be admitted for a known permission")
	assert.True(t, srv.hasPermission(capturedPrincipal, "some-future:permission"),
		"root-scope account must be admitted for permissions not yet registered")

	// requirePermission: Basic-minimum route is reachable without a challenge.
	stewardListHandler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "list")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	stewardListHandler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code,
		"root-scope account must reach a Basic-minimum route without a step-up challenge")

	// requirePermission: AssuranceStrong route triggers step-up (breadth ≠ proof).
	require.Equal(t, session.AssuranceStrong, permissionAssurance["certificate:provision"].Min,
		"precondition: certificate:provision requires AssuranceStrong")
	certProvHandler := srv.authenticationMiddleware(
		srv.requirePermission("certificate", "provision")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/certificates/provision", nil)
	req3.AddCookie(cookie)
	rec3 := httptest.NewRecorder()
	certProvHandler.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusUnauthorized, rec3.Code,
		"implicit admin must be challenged for AssuranceStrong route, not silently admitted")
	assert.Contains(t, rec3.Header().Get("WWW-Authenticate"), "CFGMS-StepUp",
		"challenge must be a step-up invitation")
}

// TestWebAccount_TenantScoped_ConfinedToExplicitGrants verifies the least-privilege half
// of the web-account model (ADR-025 Amendment 3). A tenant-scoped web account must:
//
//   - Carry ImplicitAdmin: false in the resolved Principal.
//   - Be admitted by hasPermission only for permissions in its Permissions slice.
//   - Be denied for every permission absent from that slice.
func TestWebAccount_TenantScoped_ConfinedToExplicitGrants(t *testing.T) {
	srv, mgr, _ := setupTestServerWithWebSession(t, time.Now)

	srv.cacheAccount(&account{
		ID:          "tenant-operator-regression",
		Username:    "tenant-operator-regression",
		TenantID:    "tenant-a",
		RootScope:   false,
		Permissions: []string{"steward:list", "steward:read"},
	})
	cookie := issueWebSession(t, mgr, "tenant-operator-regression", "tenant-a")

	var capturedPrincipal *Principal
	captureHandler := srv.authenticationMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPrincipal, _ = r.Context().Value(principalContextKey).(*Principal)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	captureHandler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedPrincipal)

	// Least-privilege: ImplicitAdmin must be false; Permissions is the authority.
	assert.False(t, capturedPrincipal.ImplicitAdmin,
		"tenant-scoped account must NOT carry ImplicitAdmin: true")
	require.NotNil(t, capturedPrincipal.Permissions,
		"tenant-scoped account must carry a non-nil Permissions slice")
	assert.False(t, capturedPrincipal.GlobalScope,
		"tenant-scoped account must not have cross-tenant visibility")

	// Granted permissions are accessible.
	assert.True(t, srv.hasPermission(capturedPrincipal, "steward:list"),
		"configured grant must be admitted")
	assert.True(t, srv.hasPermission(capturedPrincipal, "steward:read"),
		"configured grant must be admitted")

	// Absent permissions are denied — human assurance must not widen the grant set.
	assert.False(t, srv.hasPermission(capturedPrincipal, "steward:write-config"),
		"permission absent from account's grant set must be denied")
	assert.False(t, srv.hasPermission(capturedPrincipal, "rbac:create-role"),
		"permission absent from account's grant set must be denied")
	assert.False(t, srv.hasPermission(capturedPrincipal, "certificate:provision"),
		"permission absent from account's grant set must be denied")

	// requirePermission: a granted permission is reachable.
	stewardListHandler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "list")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req2.AddCookie(cookie)
	rec2 := httptest.NewRecorder()
	stewardListHandler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code,
		"tenant-scoped account must reach a route it holds the permission for")

	// requirePermission: a missing permission produces 403.
	writeConfigHandler := srv.authenticationMiddleware(
		srv.requirePermission("steward", "write-config")(
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })))
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/s1/config", nil)
	req3.AddCookie(cookie)
	rec3 := httptest.NewRecorder()
	writeConfigHandler.ServeHTTP(rec3, req3)
	assert.Equal(t, http.StatusForbidden, rec3.Code,
		"tenant-scoped account must be denied a permission it does not hold")
}
