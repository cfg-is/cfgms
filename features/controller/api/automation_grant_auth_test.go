// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// grantFixture is a real server with a real grant store and two sentinel routes on
// the api subrouter: one the test admits into the automation route table, one it does
// not. A sentinel records whether its handler ran.
type grantFixture struct {
	srv         *Server
	store       *AutomationGrantStore
	logs        *captureAllLogger
	allowedHits int
	deniedHits  int
	principal   *Principal
	scope       ctxkeys.TenantScope
}

const (
	sentinelAllowedTemplate = "/api/v1/zz-automation-test/allowed/{run_id}"
	sentinelDeniedTemplate  = "/api/v1/zz-automation-test/denied/{run_id}"
)

func newGrantFixture(t *testing.T) *grantFixture {
	t.Helper()
	logs := &captureAllLogger{}
	srv := setupTestServerWithLogger(t, logs)
	sm := pkgtesting.SetupTestStorage(t)
	store, err := NewAutomationGrantStore(sm.GetConfigStore(), srv.secretStore)
	require.NoError(t, err)
	srv.SetAutomationGrantStore(store)

	f := &grantFixture{srv: srv, store: store, logs: logs}
	srv.apiRouter.HandleFunc("/zz-automation-test/allowed/{run_id}", func(w http.ResponseWriter, r *http.Request) {
		f.allowedHits++
		f.principal, _ = r.Context().Value(principalContextKey).(*Principal)
		f.scope, _ = r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)
	srv.apiRouter.HandleFunc("/zz-automation-test/denied/{run_id}", func(w http.ResponseWriter, _ *http.Request) {
		f.deniedHits++
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet, http.MethodPost)
	return f
}

// admitSentinel puts GET sentinelAllowedTemplate in the closed table for the test.
func admitSentinel(t *testing.T) {
	t.Helper()
	automationRoutesMu.Lock()
	automationRoutes = append(automationRoutes, automationRoute{http.MethodGet, sentinelAllowedTemplate})
	automationRoutesMu.Unlock()
	t.Cleanup(func() {
		automationRoutesMu.Lock()
		automationRoutes = nil
		automationRoutesMu.Unlock()
	})
}

func (f *grantFixture) newGrant(t *testing.T) (*AutomationGrant, string) {
	t.Helper()
	g, cred, err := f.store.Create(context.Background(), "msp-a/client-1", "deploy", "admin-1", time.Now().Add(time.Hour))
	require.NoError(t, err)
	return g, cred
}

func (f *grantFixture) do(method, path, remoteAddr string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	if mutate != nil {
		mutate(req)
	}
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func bearer(cred string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+cred) }
}

func grantErrorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == nil {
		return ""
	}
	return resp.Error.Code
}

func TestAutomationGrantAuth_ValidCredentialBuildsGrantPrincipal(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	grant, cred := f.newGrant(t)

	rec := f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/run-1", "", bearer(cred))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, f.allowedHits)

	p := f.principal
	require.NotNil(t, p)
	assert.Equal(t, AuthChannelAutomationGrant, p.Channel)
	assert.Equal(t, grant.ID, p.ID)
	assert.Equal(t, session.AssuranceMachine, p.Assurance)
	assert.False(t, p.GlobalScope)
	assert.False(t, p.RootScoped)
	assert.False(t, p.ImplicitAdmin)
	assert.False(t, p.AccountBound)
	assert.Nil(t, p.Permissions)
	assert.Equal(t, "msp-a/client-1", p.TenantID)
	assert.False(t, f.scope.IsRoot(), "a grant is never root scoped")
	assert.Equal(t, ctxkeys.NewTenantScope("msp-a/client-1"), f.scope)
}

func TestAutomationGrantAuth_ExpiredAndRevokedAre401WithoutAPIKeyFallthrough(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)

	_, expired := f.newGrant(t)
	f.store.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	rec := f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "", bearer(expired))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "INVALID_AUTOMATION_GRANT", grantErrorCode(t, rec), "grant error, not the API-key error")
	f.store.now = time.Now

	g, cred := f.newGrant(t)
	_, err := f.store.Revoke(context.Background(), g.TenantID, g.ID, "admin-1")
	require.NoError(t, err)
	rec = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "", bearer(cred))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "INVALID_AUTOMATION_GRANT", grantErrorCode(t, rec))

	// With no grant store wired a grant credential is still refused, not passed on.
	f.srv.SetAutomationGrantStore(nil)
	rec = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "", bearer(cred))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "INVALID_AUTOMATION_GRANT", grantErrorCode(t, rec))
	assert.Zero(t, f.allowedHits)
}

func TestAutomationGrantAuth_RevocationTakesEffectOnNextRequest(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	g, cred := f.newGrant(t)

	rec := f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "", bearer(cred))
	require.Equal(t, http.StatusOK, rec.Code)

	_, err := f.store.Revoke(context.Background(), g.TenantID, g.ID, "admin-1")
	require.NoError(t, err)

	rec = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "", bearer(cred))
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 1, f.allowedHits, "the revoked credential must not reach the handler again")
}

var templateVar = regexp.MustCompile(`\{[^}]+\}`)

// TestAutomationGrant_EmptyTableDeniesEveryRoute walks the real router and sends a
// grant request to every method+template under /api/v1 (the authenticated surface),
// including routes registered without requirePermission.
func TestAutomationGrant_EmptyTableDeniesEveryRoute(t *testing.T) {
	f := newGrantFixture(t)
	_, cred := f.newGrant(t)

	type target struct{ method, template string }
	var targets []target
	require.NoError(t, f.srv.router.Walk(func(r *mux.Route, _ *mux.Router, ancestors []*mux.Route) error {
		tpl, err := r.GetPathTemplate()
		if err != nil || !strings.HasPrefix(tpl, "/api/v1/") {
			return nil
		}
		// Routes registered directly on the base router (health, registration, web
		// login, ...) sit outside the authenticated api subrouter: no credential is
		// authenticated there, so no grant principal exists on them.
		if len(ancestors) == 0 {
			return nil
		}
		methods, err := r.GetMethods()
		if err != nil {
			return nil
		}
		for _, m := range methods {
			targets = append(targets, target{m, tpl})
		}
		return nil
	}))
	require.Greater(t, len(targets), 100, "the walk must see the real route table")

	denied := 0
	for i, tg := range targets {
		path := templateVar.ReplaceAllString(tg.template, "x1")
		// A distinct source per request keeps the router-wide per-source budget out of the way.
		rec := f.do(tg.method, path, fmt.Sprintf("10.1.%d.%d:5000", i/250, i%250+1), bearer(cred))
		probe := httptest.NewRequest(tg.method, path, nil)
		var match mux.RouteMatch
		if !f.srv.router.Match(probe, &match) || match.Route == nil {
			continue // a regex-constrained variable the filler does not satisfy
		}
		if got, _ := match.Route.GetPathTemplate(); got != tg.template {
			continue // an earlier route shadows this template for the filler path
		}
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", tg.method, tg.template)
		assert.Equal(t, "AUTOMATION_ROUTE_DENIED", grantErrorCode(t, rec), "%s %s", tg.method, tg.template)
		denied++
	}
	assert.Greater(t, denied, len(targets)/2, "most templates must have been exercised")
	assert.Zero(t, f.deniedHits)
}

func TestAutomationGrant_RefusedOnSensitiveRoutes(t *testing.T) {
	f := newGrantFixture(t)
	_, cred := f.newGrant(t)
	for _, tc := range []struct{ name, method, path string }{
		{"presence requirement", http.MethodPost, "/api/v1/stewards/s1/credentials/rotate"},
		{"config push", http.MethodPost, "/api/v1/config/push"},
		{"service control", http.MethodPost, "/api/v1/stewards/s1/services/svc/actions"},
		{"terminal", http.MethodGet, "/api/v1/terminal/ws/s1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(tc.method, tc.path, "", bearer(cred))
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "AUTOMATION_ROUTE_DENIED", grantErrorCode(t, rec))
		})
	}
}

func TestAutomationGrantAuth_FailedAttemptsThrottledAndCredentialNeverLeaks(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	_, valid := f.newGrant(t)
	canary := "cfgag_" + strings.Repeat("ab", 16) + "_CANARYSECRETVALUE0123456789"

	var bodies strings.Builder
	var last *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		last = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "203.0.113.9:4000", bearer(canary))
		require.Equal(t, http.StatusUnauthorized, last.Code)
		bodies.WriteString(last.Body.String())
	}
	last = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "203.0.113.9:4000", bearer(canary))
	assert.Equal(t, http.StatusTooManyRequests, last.Code, "the failed attempts must be throttled")
	assert.Equal(t, "THROTTLED", grantErrorCode(t, last))
	bodies.WriteString(last.Body.String())

	// The throttle is per IP and also holds a valid credential from the blocked address.
	last = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "203.0.113.9:4001", bearer(valid))
	assert.Equal(t, http.StatusTooManyRequests, last.Code)
	last = f.do(http.MethodGet, "/api/v1/zz-automation-test/allowed/r", "198.51.100.7:4000", bearer(valid))
	assert.Equal(t, http.StatusOK, last.Code)

	assert.NotContains(t, bodies.String(), "CANARYSECRETVALUE")
	assert.NotContains(t, f.logs.captured(), "CANARYSECRETVALUE")
	assert.NotContains(t, f.logs.captured(), strings.TrimPrefix(valid, "cfgag_"))
}

func TestAutomationGrantAuth_OnlyAuthorizationBearerCarriesCredential(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	_, cred := f.newGrant(t)
	path := "/api/v1/zz-automation-test/allowed/r"

	for name, mutate := range map[string]func(*http.Request){
		"x-api-key header": func(r *http.Request) { r.Header.Set("X-API-Key", cred) },
		"cookie":           func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "__Host-cfgms_session", Value: cred}) },
		"cookie bearer":    func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "Authorization", Value: "Bearer " + cred}) },
		"basic scheme":     func(r *http.Request) { r.Header.Set("Authorization", "Basic "+cred) },
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(http.MethodGet, path, "", mutate)
			assert.Equal(t, http.StatusUnauthorized, rec.Code)
		})
	}
	t.Run("query string", func(t *testing.T) {
		for _, q := range []string{"token", "api_key", "credential", "access_token"} {
			rec := f.do(http.MethodGet, path+"?"+q+"="+cred, "", nil)
			assert.Equal(t, http.StatusUnauthorized, rec.Code, q)
		}
	})
	t.Run("grant bearer plus api key header is refused", func(t *testing.T) {
		rec := f.do(http.MethodGet, path, "", func(r *http.Request) {
			r.Header.Set("Authorization", "Bearer "+cred)
			r.Header.Set("X-API-Key", "anything")
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
	assert.Zero(t, f.allowedHits)
}

func TestAutomationGrant_UnmatchedRequestsNeverReachAHandler(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	_, cred := f.newGrant(t)

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/zz-automation-test/unknown/r"},
		{http.MethodGet, "/api/v1/does-not-exist"},
		{http.MethodPost, "/api/v1/zz-automation-test/allowed/r"}, // method not allowed
		{http.MethodDelete, "/api/v1/zz-automation-test/denied/r"},
	} {
		rec := f.do(tc.method, tc.path, "", bearer(cred))
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusForbidden},
			rec.Code, "%s %s", tc.method, tc.path)
	}
	assert.Zero(t, f.allowedHits)
	assert.Zero(t, f.deniedHits)
}

func TestAutomationGrant_PathVariantsCannotReachHandlerOutsideTable(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	_, cred := f.newGrant(t)

	variants := []string{
		"/api/v1//zz-automation-test/denied/r",
		"/api//v1/zz-automation-test/denied/r",
		"/api/v1/zz-automation-test/denied/r/",
		"/api/v1/zz-automation-test/./denied/r",
		"/api/v1/zz-automation-test/allowed/../denied/r",
		"/api/v1/zz-automation-test/allowed/%2e%2e/denied/r",
		"/API/V1/ZZ-AUTOMATION-TEST/DENIED/r",
		"/api/v1/zz-automation-test%2Fdenied/r",
		"/api/v1/zz-automation-test/denied%2Fr",
		"/api/v1/zz-automation-test/denied/r%00",
	}
	for _, p := range variants {
		f.do(http.MethodGet, p, "", bearer(cred))
	}
	assert.Zero(t, f.deniedHits, "no variant may reach a handler outside the table")

	// Variants of the admitted route are only served when they resolve to the exact template.
	for _, p := range []string{
		"/api/v1//zz-automation-test/allowed/r",
		"/API/V1/zz-automation-test/allowed/r",
		"/api/v1/zz-automation-test/allowed/r/",
	} {
		// A non-/api/ path falls to the public SPA handler, which is not an API handler.
		f.do(http.MethodGet, p, "", bearer(cred))
	}
	assert.Zero(t, f.allowedHits)
}

func TestAutomationGrant_TableKeyedByMethodAndTemplate(t *testing.T) {
	f := newGrantFixture(t)
	admitSentinel(t)
	_, cred := f.newGrant(t)

	assert.True(t, automationRouteAllowed(http.MethodGet, sentinelAllowedTemplate))
	assert.False(t, automationRouteAllowed(http.MethodPost, sentinelAllowedTemplate))
	assert.False(t, automationRouteAllowed(http.MethodGet, sentinelDeniedTemplate))
	assert.False(t, automationRouteAllowed(http.MethodGet, ""))

	// The denied sentinel serves GET and POST; neither is admitted, and admitting the
	// allowed template for GET does not admit a sibling that shares a method.
	for _, m := range []string{http.MethodGet, http.MethodPost} {
		rec := f.do(m, "/api/v1/zz-automation-test/denied/r", "", bearer(cred))
		assert.Equal(t, http.StatusForbidden, rec.Code, m)
	}
	// Same template, another method that the route also serves: add it to the route
	// and confirm the guard still refuses it.
	f.srv.apiRouter.HandleFunc("/zz-automation-test/allowed/{run_id}", func(w http.ResponseWriter, _ *http.Request) {
		f.deniedHits++
	}).Methods(http.MethodPost)
	rec := f.do(http.MethodPost, "/api/v1/zz-automation-test/allowed/r", "", bearer(cred))
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, f.deniedHits)
}

func TestAutomationGrant_NonGrantPrincipalsAreNotGuarded(t *testing.T) {
	f := newGrantFixture(t)
	called := false
	h := f.srv.automationRouteGuard(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/anything", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{Channel: AuthChannelAPIKey}))
	h.ServeHTTP(httptest.NewRecorder(), req)
	assert.True(t, called)
}
