// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// doFrom sends one request with the grant credential from a distinct source, which
// keeps the router-wide per-source budget out of the way of a wide walk.
func (f *runFixture) doFrom(seq int, method, path, cred string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = fmt.Sprintf("10.7.%d.%d:5000", seq/250, seq%250+1)
	req.Header.Set("Authorization", "Bearer "+cred)
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

// matchedTemplate returns the template the real router matches for the request, and
// false when no route matches it.
func (f *runFixture) matchedTemplate(method, path string) (string, bool) {
	var match mux.RouteMatch
	if !f.srv.router.Match(httptest.NewRequest(method, path, nil), &match) || match.Route == nil {
		return "", false
	}
	tpl, err := match.Route.GetPathTemplate()
	return tpl, err == nil
}

// [REQUIRED TEST] The refusal matrix: every route template the real router has
// registered, under every method, is refused for a grant principal unless it is in
// the automation route table. The matrix is built by walking the router, so a route
// added later is covered without editing this test.
func TestAutomationAllowlist_RefusalMatrixOverEveryRegisteredTemplate(t *testing.T) {
	f := newRunFixture(t)

	type target struct{ method, template string }
	var targets []target
	require.NoError(t, f.srv.router.Walk(func(r *mux.Route, _ *mux.Router, ancestors []*mux.Route) error {
		tpl, err := r.GetPathTemplate()
		if err != nil || !strings.HasPrefix(tpl, "/api/v1/") || len(ancestors) == 0 {
			// Routes on the base router sit outside the authenticated api subrouter:
			// no credential is authenticated there, so no grant principal exists.
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

	var refused, admitted int
	for i, tg := range targets {
		if automationRouteAllowed(tg.method, tg.template) {
			admitted++
			continue
		}
		path := templateVar.ReplaceAllString(tg.template, "x1")
		if got, ok := f.matchedTemplate(tg.method, path); !ok || got != tg.template {
			continue // a regex-constrained variable the filler does not satisfy, or an earlier route shadows it
		}
		rec := f.doFrom(i, tg.method, path, f.cred)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", tg.method, tg.template)
		assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec), "%s %s", tg.method, tg.template)
		refused++
	}
	assert.Greater(t, refused, len(targets)/2, "most templates must have been exercised")
	assert.GreaterOrEqual(t, admitted, 7, "begin, end and the five read routes are the admitted templates")
	assert.Zero(t, f.hits, "no handler ran")
}

// [REQUIRED TEST] The routes the story names are refused by name, with a valid open
// run in hand, so the refusal is the route guard's and not a missing run.
func TestAutomationAllowlist_NamedRoutesAreRefused(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	for i, tc := range []struct{ name, method, path string }{
		{"config push by steward", http.MethodPut, "/api/v1/stewards/s1/config"},
		{"config push", http.MethodPost, "/api/v1/config/push"},
		{"service control", http.MethodPost, "/api/v1/stewards/s1/services/svc/actions"},
		{"process control", http.MethodPost, "/api/v1/stewards/s1/processes/42/actions"},
		{"terminal websocket", http.MethodGet, "/api/v1/terminal/ws/s1"},
		{"script run", http.MethodPost, "/api/v1/runs/script"},
		{"command run", http.MethodPost, "/api/v1/runs/command"},
		{"existing steward list", http.MethodGet, "/api/v1/stewards"},
		{"existing run read", http.MethodGet, "/api/v1/runs/" + runID},
	} {
		rec := f.doFrom(i, tc.method, tc.path, f.cred)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s: %s", tc.name, rec.Body.String())
		assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec), tc.name)
	}

	// A path under the run prefix that no route registers is never matched: the
	// router answers it itself and no handler runs.
	for i, tc := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/automation/runs/" + runID + "/stewards/s1/logs"},
		{http.MethodPut, "/api/v1/automation/runs/" + runID + "/stewards/s1/config"},
		{http.MethodPost, "/api/v1/automation/runs/" + runID + "/stewards"},
	} {
		rec := f.doFrom(100+i, tc.method, tc.path, f.cred)
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, rec.Code, "%s %s", tc.method, tc.path)
	}
	assert.Zero(t, f.hits)
}

// [REQUIRED TEST] Every permission in permissionAssurance with RequireUserPresence is
// refused for a grant principal. The set comes from the table at test time. Each
// permission is mounted on a real route of the api router and called with a grant
// credential: the route guard refuses it (it is not in the automation table), and the
// permission middleware refuses the grant principal on its own as well, since a grant
// holds no permission and carries no presence tap.
func TestAutomationAllowlist_EveryPresenceGatedPermissionIsRefused(t *testing.T) {
	f := newRunFixture(t)
	f.beginOK(t, f.cred, runClient1, "ticket-1")

	ids := presenceGatedIDs(t)
	require.NotEmpty(t, ids)
	var reached int
	reachedHandler := func(w http.ResponseWriter, _ *http.Request) {
		reached++
		w.WriteHeader(http.StatusOK)
	}
	grantPrincipal := &Principal{Channel: AuthChannelAutomationGrant, ID: f.grant.ID, TenantID: f.grant.TenantID}

	for i, id := range ids {
		parts := strings.SplitN(id, ":", 2)
		path := fmt.Sprintf("/zz-presence/%d", i)
		f.srv.apiRouter.Handle(path, f.srv.requirePermission(parts[0], parts[1])(http.HandlerFunc(reachedHandler))).
			Methods(http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch)

		for j, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			require.False(t, automationRouteAllowed(method, "/api/v1"+path), id)
			rec := f.doFrom(i*10+j, method, "/api/v1"+path, f.cred)
			assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s: %s", method, id, rec.Body.String())
			assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec), "%s %s", method, id)
		}

		// The permission middleware alone, given a grant principal with no tap.
		req := httptest.NewRequest(http.MethodPost, "/api/v1"+path, strings.NewReader("{}"))
		req = withPrincipal(req, grantPrincipal)
		rec := httptest.NewRecorder()
		f.srv.requirePermission(parts[0], parts[1])(http.HandlerFunc(reachedHandler)).ServeHTTP(rec, req)
		assert.NotEqual(t, http.StatusOK, rec.Code, "permission %s must refuse a grant principal", id)
	}
	assert.Zero(t, reached, "no presence-gated handler ran for a grant principal")
}
