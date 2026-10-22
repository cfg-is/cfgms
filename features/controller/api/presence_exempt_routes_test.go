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

	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// serveOnRoute registers handler behind requirePermission(resource, action) on a
// fresh router at the real path template, then serves req through it. mux.CurrentRoute
// is therefore set, so PresenceExemptRoutes matching works as it does in production,
// and path variables are populated from the request path.
func serveOnRoute(server *Server, method, template, resource, action string, handler http.Handler, req *http.Request) *httptest.ResponseRecorder {
	router := mux.NewRouter()
	router.Handle(template, server.requirePermission(resource, action)(handler)).Methods(method)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

var presenceOK = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

type exemptCase struct {
	method, template, path, permission string
	resource, action                   string
	gated                              bool
}

var exemptCases = []exemptCase{
	{http.MethodPost, "/api/v1/runs/script", "/api/v1/runs/script", "steward:execute-scripts", "steward", "execute-scripts", true},
	{http.MethodPut, "/api/v1/scripts/{id}/privilege", "/api/v1/scripts/s1/privilege", "script:admin", "script", "admin", true},
	{http.MethodDelete, "/api/v1/runs/{run_id}", "/api/v1/runs/r1", "steward:execute-scripts", "steward", "execute-scripts", false},
	{http.MethodPost, "/api/v1/runs/command", "/api/v1/runs/command", "steward:execute-scripts", "steward", "execute-scripts", false},
	{http.MethodGet, "/api/v1/scripts", "/api/v1/scripts", "script:admin", "script", "admin", false},
	{http.MethodGet, "/api/v1/scripts/{id}", "/api/v1/scripts/s1", "script:admin", "script", "admin", false},
}

func presenceStrongPrincipal(perm string) *Principal {
	return &Principal{ID: "presence-admin", Assurance: session.AssuranceStrong, Permissions: []string{perm}, TenantID: "test-tenant"}
}

func newExemptRequest(c exemptCase) *http.Request {
	var body *strings.Reader
	if c.method == http.MethodGet || c.method == http.MethodDelete {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(`{"x":1}`)
	}
	req := httptest.NewRequest(c.method, c.path, body)
	return withPrincipal(req, presenceStrongPrincipal(c.permission))
}

func assertPresenceChallenge(t *testing.T, rec *httptest.ResponseRecorder, permission string) {
	t.Helper()
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	challenge := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, challenge, "CFGMS-StepUp")
	assert.Contains(t, challenge, `presence="required"`)
	assert.Contains(t, challenge, `permission="`+permission+`"`)
}

func TestPresenceExemptRoutes_GatedAndExempt(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range exemptCases {
		t.Run(c.method+" "+c.template, func(t *testing.T) {
			rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, newExemptRequest(c))
			if c.gated {
				assertPresenceChallenge(t, rec, c.permission)
			} else {
				assert.Equal(t, http.StatusOK, rec.Code, "exempt route must reach its handler without a presence token")
			}
		})
	}
}

// A browser-minted token and a relay-minted token share one shape: bound to the
// exact request. Both pass on the gated routes.
func TestPresenceExemptRoutes_BoundTokensPass(t *testing.T) {
	server := setupTestServer(t)
	for _, c := range exemptCases {
		if !c.gated {
			continue
		}
		for _, source := range []string{"browser", "relay"} {
			t.Run(source+" "+c.method+" "+c.template, func(t *testing.T) {
				req := newExemptRequest(c)
				req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(t, server, "presence-admin", req, c.permission))
				rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, req)
				assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
			})
		}
	}
}

func TestPresenceExemptRoutes_BoundTokenForOtherRouteRefused(t *testing.T) {
	server := setupTestServer(t)
	other := newExemptRequest(exemptCases[0])
	token := mintPresenceTokenFor(t, server, "presence-admin", other, "steward:execute-scripts")

	req := newExemptRequest(exemptCases[1])
	req.Header.Set(presenceTokenHeader, token)
	rec := serveOnRoute(server, exemptCases[1].method, exemptCases[1].template, "script", "admin", presenceOK, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func serverWithOverride(t *testing.T, ov business.AssurancePolicyOverride) *Server {
	t.Helper()
	server := setupTestServer(t)
	apStore := newTestAssurancePolicyStore()
	require.NoError(t, apStore.SetPolicy(context.Background(), &business.AssurancePolicy{
		TenantID:  "test-tenant",
		Overrides: []business.AssurancePolicyOverride{ov},
	}))
	server.assurancePolicyStore = apStore
	server.tenantStore = newTestTenantStoreWithPath(map[string][]string{"test-tenant": {"test-tenant"}})
	return server
}

// An override that sets RequireUserPresence withdraws the exemptions: cancel is challenged.
func TestPresenceExemptRoutes_OverrideClearsExemptions(t *testing.T) {
	server := serverWithOverride(t, business.AssurancePolicyOverride{
		PermissionID: "steward:execute-scripts", RequireUserPresence: true,
	})
	c := exemptCases[2] // DELETE /api/v1/runs/{run_id}
	rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, newExemptRequest(c))
	assertPresenceChallenge(t, rec, "steward:execute-scripts")
}

// An override that only raises Min leaves the exemptions in place.
func TestPresenceExemptRoutes_MinOnlyOverrideKeepsExemptions(t *testing.T) {
	strong := int(session.AssuranceStrong)
	server := serverWithOverride(t, business.AssurancePolicyOverride{
		PermissionID: "steward:execute-scripts", MinOverride: &strong,
	})
	c := exemptCases[2]
	rec := serveOnRoute(server, c.method, c.template, c.resource, c.action, presenceOK, newExemptRequest(c))
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestPresenceExemptRoutes_NoCurrentRouteIsChallenged(t *testing.T) {
	server := setupTestServer(t)
	c := exemptCases[2] // would be exempt on its route
	req := newExemptRequest(c)
	rec := httptest.NewRecorder()
	server.requirePermission(c.resource, c.action)(presenceOK).ServeHTTP(rec, req)
	assertPresenceChallenge(t, rec, "steward:execute-scripts")
}

func TestValidatePresenceExemptRoutes_RealRouterValid(t *testing.T) {
	server := setupTestServer(t)
	require.NoError(t, server.validatePresenceExemptRoutes())
}

func TestValidatePresenceExemptRoutes_StaleEntryNamed(t *testing.T) {
	server := setupTestServer(t)
	orig := permissionAssurance["script:admin"]
	t.Cleanup(func() { permissionAssurance["script:admin"] = orig })

	stale := orig
	stale.PresenceExemptRoutes = append(append([]string{}, orig.PresenceExemptRoutes...), "GET /api/v1/scripts/{renamed}")
	permissionAssurance["script:admin"] = stale

	err := server.validatePresenceExemptRoutes()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GET /api/v1/scripts/{renamed}")
}
