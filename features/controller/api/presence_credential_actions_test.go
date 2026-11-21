// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
//
// Issue #6408, ADR-021 Amendment 13: every action that creates a credential, adds an
// authenticator, binds a certificate, grants or widens permissions, changes an account or
// opens a break-glass crossing needs a fresh per-action presence tap. Access reductions
// stay tap-free.

package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/testutil/webauthntest"
)

// presenceRouteCase is one route behind a permission, with a concrete request path for
// its mux template.
type presenceRouteCase struct {
	method, template, path, body, permission string
}

// splitPermission returns the requirePermission resource and action of a permission ID.
func splitPermission(id string) (resource, action string) {
	parts := strings.SplitN(id, ":", 2)
	return parts[0], parts[1]
}

// tappedRoutes are the routes of the eleven permissions Amendment 13 gates.
var tappedRoutes = []presenceRouteCase{
	{http.MethodPost, "/api/v1/accounts", "/api/v1/accounts", `{"username":"u1"}`, "account:create"},
	{http.MethodPut, "/api/v1/accounts/{username}", "/api/v1/accounts/u1", `{"disabled":true}`, "account:update"},
	{http.MethodPost, "/api/v1/accounts/{username}/webauthn/register/begin", "/api/v1/accounts/u1/webauthn/register/begin", ``, "webauthn:register"},
	{http.MethodPost, "/api/v1/accounts/{username}/webauthn/register/finish", "/api/v1/accounts/u1/webauthn/register/finish", `{"id":"x"}`, "webauthn:register"},
	{http.MethodPost, "/api/v1/accounts/{username}/certs/bind", "/api/v1/accounts/u1/certs/bind", `{"serial":"1"}`, "cert-binding:bind"},
	{http.MethodPost, "/api/v1/accounts/{username}/certs/rotate/{old_serial}", "/api/v1/accounts/u1/certs/rotate/7", `{"serial":"2"}`, "cert-binding:rotate"},
	{http.MethodPost, "/api/v1/api-keys", "/api/v1/api-keys", `{"name":"k"}`, "api-key:create"},
	{http.MethodPost, "/api/v1/rbac/roles", "/api/v1/rbac/roles", `{"name":"r"}`, "rbac:create-role"},
	{http.MethodPut, "/api/v1/rbac/roles/{id}", "/api/v1/rbac/roles/r1", `{"name":"r"}`, "rbac:update-role"},
	{http.MethodPost, "/api/v1/rbac/subjects/{id}/roles", "/api/v1/rbac/subjects/s1/roles", `{"role_id":"r1"}`, "rbac:assign-role"},
	{http.MethodPost, "/api/v1/roles", "/api/v1/roles", `{"name":"r"}`, "role:write"},
	{http.MethodPost, "/api/v1/tenants/{id}/break-glass", "/api/v1/tenants/test-tenant/break-glass", `{"reason_category":"account_recovery"}`, "tenant:crossing-break-glass"},
}

// tapFreeRoutes are the access reductions and the role delete: Strong assurance, no tap.
var tapFreeRoutes = []presenceRouteCase{
	{http.MethodDelete, "/api/v1/accounts/{username}", "/api/v1/accounts/u1", ``, "account:delete"},
	{http.MethodPost, "/api/v1/accounts/{username}/enrollment-link/revoke", "/api/v1/accounts/u1/enrollment-link/revoke", ``, "account:revoke-enrollment-link"},
	{http.MethodPost, "/api/v1/accounts/{username}/certs/revoke/{serial}", "/api/v1/accounts/u1/certs/revoke/7", ``, "cert-binding:revoke"},
	{http.MethodPost, "/api/v1/accounts/{username}/webauthn/revoke/{credential_id}", "/api/v1/accounts/u1/webauthn/revoke/Y3JlZA", ``, "webauthn:revoke"},
	{http.MethodDelete, "/api/v1/rbac/subjects/{id}/roles/{role_id}", "/api/v1/rbac/subjects/s1/roles/r1", ``, "rbac:revoke-role"},
	{http.MethodDelete, "/api/v1/rbac/roles/{id}", "/api/v1/rbac/roles/r1", ``, "rbac:delete-role"},
	{http.MethodDelete, "/api/v1/roles/{name}", "/api/v1/roles/r1", ``, "role:write"},
}

func (c presenceRouteCase) request(permission string) *http.Request {
	var body *bytes.Reader
	if c.body == "" {
		body = bytes.NewReader(nil)
	} else {
		body = bytes.NewReader([]byte(c.body))
	}
	req := httptest.NewRequest(c.method, c.path, body)
	return withPrincipal(req, &Principal{
		ID: "presence-admin", Assurance: session.AssuranceStrong, Permissions: []string{permission}, TenantID: "test-tenant",
	})
}

// [REQUIRED TEST] Each newly gated permission's routes: a Strong session with no presence
// token gets the presence challenge naming the permission; the same request with a token
// bound to its method, path, body hash and permission reaches the handler. Both
// register/begin and register/finish are gated, so a browser add-passkey takes two taps.
func TestPresenceCredentialActions_GatedRoutes(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range tappedRoutes {
		resource, action := splitPermission(c.permission)
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			t.Run("a Strong session without a tap is challenged", func(t *testing.T) {
				rec := serveOnRoute(server, c.method, c.template, resource, action, presenceOK, c.request(c.permission))
				assertPresenceChallenge(t, rec, c.permission)
			})
			t.Run("a bound tap is admitted", func(t *testing.T) {
				req := c.request(c.permission)
				req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, "presence-admin", req, c.permission))
				rec := serveOnRoute(server, c.method, c.template, resource, action, presenceOK, req)
				assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
			})
			t.Run("a tap is single use", func(t *testing.T) {
				req := c.request(c.permission)
				token := mintPresenceTokenFor(t, server, "presence-admin", req, c.permission)
				req.Header.Set(presenceTokenHeader, token)
				require.Equal(t, http.StatusOK, serveOnRoute(server, c.method, c.template, resource, action, presenceOK, req).Code)
				again := c.request(c.permission)
				again.Header.Set(presenceTokenHeader, token)
				assert.Equal(t, http.StatusUnauthorized, serveOnRoute(server, c.method, c.template, resource, action, presenceOK, again).Code)
			})
			t.Run("a tap bound to another permission is refused", func(t *testing.T) {
				req := c.request(c.permission)
				req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, "presence-admin", req, c.permission+"-other"))
				rec := serveOnRoute(server, c.method, c.template, resource, action, presenceOK, req)
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
			})
		})
	}
}

// The registered routes themselves carry the gate: through the real router, a Strong
// session without a tap is challenged for the permission before any handler runs.
func TestPresenceCredentialActions_RouterChallengesWithoutATap(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range tappedRoutes {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			auth := newStrongBearerHeader(t, server, []string{c.permission}, "test-tenant")
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte(c.body)))
			req.Header.Set("Authorization", auth)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assertPresenceChallenge(t, rec, c.permission)
		})
	}
}

// [REQUIRED TEST] A Strong session with no presence token succeeds on every tap-free
// action, and on DELETE /roles/{name}, which role:write exempts.
func TestPresenceCredentialActions_AccessReductionsStayTapFree(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range tapFreeRoutes {
		resource, action := splitPermission(c.permission)
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			rec := serveOnRoute(server, c.method, c.template, resource, action, presenceOK, c.request(c.permission))
			assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
		})
	}

	t.Run("the real router does not challenge them for presence", func(t *testing.T) {
		for _, c := range tapFreeRoutes {
			auth := newStrongBearerHeader(t, server, []string{c.permission}, "test-tenant")
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte(c.body)))
			req.Header.Set("Authorization", auth)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`, "%s %s: %s", c.method, c.path, rec.Body.String())
			assert.NotContains(t, rec.Body.String(), "step_up_required", "%s %s", c.method, c.path)
		}
	})
}

// The registry pins the split: the eleven gated entries keep the Strong floor and add the
// tap, the access reductions stay at Strong alone, and session:revoke stays absent.
func TestPresenceCredentialActions_RegistryEntries(t *testing.T) {
	for _, id := range []string{
		"account:create", "account:update", "webauthn:register", "cert-binding:bind", "cert-binding:rotate",
		"api-key:create", "rbac:create-role", "rbac:update-role", "rbac:assign-role", "role:write",
		"tenant:crossing-break-glass",
	} {
		req, ok := permissionAssurance[id]
		require.True(t, ok, id)
		assert.Equal(t, session.AssuranceStrong, req.Min, id)
		assert.True(t, req.RequireUserPresence, "%s needs a per-action tap", id)
		if id != "role:write" {
			assert.Empty(t, req.PresenceExemptRoutes, "%s exempts no route", id)
		}
	}
	assert.Equal(t, []string{"DELETE /api/v1/roles/{name}"}, permissionAssurance["role:write"].PresenceExemptRoutes)

	for _, id := range []string{
		"account:delete", "account:revoke-enrollment-link", "cert-binding:revoke",
		"rbac:revoke-role", "rbac:delete-role", "webauthn:revoke",
	} {
		req, ok := permissionAssurance[id]
		require.True(t, ok, id)
		assert.Equal(t, session.AssuranceStrong, req.Min, id)
		assert.False(t, req.RequireUserPresence, "%s reduces access and stays tap-free", id)
	}
	_, ok := permissionAssurance["session:revoke"]
	assert.False(t, ok, "session:revoke has no assurance entry")
}

// [REQUIRED TEST] Redeeming an enrollment token for a first passkey uses
// /api/v1/web/passkey/enroll/begin|finish, which has no permissionAssurance entry: it works
// through the real router with no presence token.
func TestPresenceCredentialActions_EnrollmentRedemptionNeedsNoTap(t *testing.T) {
	const username = "enroll-no-tap-user"
	server, _, rawToken := setupEnrollServer(t, tvRPID, []string{tvOrigin}, username)

	do := func(path string, body []byte) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		req.Header.Set(enrollmentTokenHeader, rawToken)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		return rec
	}

	begin := do("/api/v1/web/passkey/enroll/begin", nil)
	require.Equal(t, http.StatusOK, begin.Code, begin.Body.String())
	assert.NotContains(t, begin.Header().Get("WWW-Authenticate"), "presence")

	key, _ := webauthntest.NewKey(t)
	reg := webauthntest.Register(t, key, []byte("enroll-no-tap-cred"), tvRPID, tvOrigin, publicKeyChallenge(t, begin))
	finish := do("/api/v1/web/passkey/enroll/finish", reg.Body())
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, finish.Code, finish.Body.String())

	acct, err := server.getAccount(t.Context(), username)
	require.NoError(t, err)
	require.Len(t, acct.Credentials, 1, "the first passkey was enrolled")

	for _, id := range []string{"web-passkey:enroll", "passkey:enroll", "webauthn:enroll"} {
		_, gated := permissionAssurance[id]
		assert.False(t, gated, "%s must not appear in permissionAssurance", id)
	}
}

// [REQUIRED TEST] An account holding the software-authenticator flag completes the gated
// actions with presence tokens its software authenticator minted for the exact request,
// following the presenceFinish pattern of the enforcement tests.
func TestPresenceCredentialActions_SoftwareAuthenticatorTaps(t *testing.T) {
	f := newEnfFixture(t, true, false)
	f.edit(t, func(a *account) {
		a.Permissions = append(a.Permissions, "account:create", "account:update", "tenant:crossing-break-glass")
	})
	bearer := f.agentBearer(t)
	p := f.principal()

	t.Run("POST /api/v1/accounts", func(t *testing.T) {
		const body = `{"username":"sw-made","tenant_id":"` + enfTenant + `"}`
		untapped := f.agentRequest(t, bearer, http.MethodPost, "/api/v1/accounts", body)
		require.Equal(t, http.StatusUnauthorized, untapped.Code, untapped.Body.String())
		assert.Contains(t, untapped.Header().Get("WWW-Authenticate"), `presence="required"`)

		rec := f.tappedRequest(t, p, bearer, http.MethodPost, "/api/v1/accounts", body, "account:create")
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	})

	t.Run("PUT /api/v1/accounts/{username}", func(t *testing.T) {
		const path = "/api/v1/accounts/sw-made"
		const body = `{"disabled":true}`
		untapped := f.agentRequest(t, bearer, http.MethodPut, path, body)
		require.Equal(t, http.StatusUnauthorized, untapped.Code, untapped.Body.String())

		rec := f.tappedRequest(t, p, bearer, http.MethodPut, path, body, "account:update")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	})

	// Break-glass is a root-scope action and a flagged root account is a root agent whose
	// allowlist (ADR-021 Amendment 11) does not include it, so the handler refuses this
	// tenant account on its own rule. What the test pins is that the software
	// authenticator's tap satisfies the presence gate: no step-up challenge comes back.
	t.Run("POST /api/v1/tenants/{id}/break-glass", func(t *testing.T) {
		path := "/api/v1/tenants/" + enfTenant + "/break-glass"
		const body = `{"reason_category":"account_recovery","justification":"software authenticator presence test"}`
		untapped := f.agentRequest(t, bearer, http.MethodPost, path, body)
		require.Equal(t, http.StatusUnauthorized, untapped.Code, untapped.Body.String())
		assert.Contains(t, untapped.Header().Get("WWW-Authenticate"), `permission="tenant:crossing-break-glass"`)

		rec := f.tappedRequest(t, p, bearer, http.MethodPost, path, body, "tenant:crossing-break-glass")
		assert.NotContains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`, rec.Body.String())
		assert.NotContains(t, rec.Body.String(), "step_up_required")
		assert.NotContains(t, rec.Body.String(), "presence_token")
	})
}
