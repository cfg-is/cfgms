// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
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

const unattendedTestTenant = "unattended-tenant"

type unattendedRolloutFixture struct {
	tb    *testing.T
	srv   *Server
	store *UnattendedRolloutStore
	mux   *mux.Router
}

// newUnattendedRolloutFixture wires the real routes behind the real
// requirePermission middleware on a server with a durable store and audit manager.
func newUnattendedRolloutFixture(t *testing.T) *unattendedRolloutFixture {
	t.Helper()
	srv := setupTestServer(t)
	st, _ := newUnattendedRolloutStore(t)
	srv.SetUnattendedRolloutStore(st)
	r := mux.NewRouter()
	registerUnattendedRolloutRoutes(srv, r.PathPrefix("/api/v1").Subrouter())
	return &unattendedRolloutFixture{tb: t, srv: srv, store: st, mux: r}
}

func unattendedAdmin() *Principal {
	return &Principal{
		ID: "rollout-admin", Assurance: session.AssuranceStrong, TenantID: unattendedTestTenant,
		Permissions: []string{"rollout-automation:set", "rollout-automation:read"},
	}
}

func (f *unattendedRolloutFixture) do(method, body string, p *Principal, presence bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/api/v1/rollout-settings/unattended", strings.NewReader(body))
	req = withPrincipal(req, p)
	if presence {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.tb, f.srv, p.ID, req, "rollout-automation:set"))
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *unattendedRolloutFixture) enabled(t *testing.T) bool {
	t.Helper()
	got, err := f.store.Get(t.Context())
	require.NoError(t, err)
	return got.Enabled
}

type unattendedResponse struct {
	Data struct {
		Enabled   bool    `json:"enabled"`
		ChangedBy string  `json:"changed_by"`
		ChangedAt *string `json:"changed_at"`
	} `json:"data"`
}

func TestPutUnattendedRolloutRequiresTapAndAudits(t *testing.T) {
	f := newUnattendedRolloutFixture(t)
	p := unattendedAdmin()

	rec := f.do(http.MethodPut, `{"enabled":true}`, p, false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	assert.False(t, f.enabled(t), "a challenged request changes nothing")
	assert.Empty(t, auditEntriesByAction(t, f.srv, "unattended_rollouts_changed"))

	rec = f.do(http.MethodPut, `{"enabled":true}`, p, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp unattendedResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Data.Enabled)
	assert.Equal(t, "rollout-admin", resp.Data.ChangedBy)
	assert.NotNil(t, resp.Data.ChangedAt)
	assert.True(t, f.enabled(t))

	entries := auditEntriesByAction(t, f.srv, "unattended_rollouts_changed")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, "rollout-admin", e.UserID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, "rollout-admin", e.Details["principal"])
	assert.Equal(t, false, e.Details["previous"])
	assert.Equal(t, true, e.Details["new"])

	// Turning it off, and setting the value it already has, are audited too.
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, `{"enabled":false}`, p, true).Code)
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, `{"enabled":false}`, p, true).Code)
	entries = auditEntriesByAction(t, f.srv, "unattended_rollouts_changed")
	require.Len(t, entries, 3)
	assert.False(t, f.enabled(t))
	var sawOff bool
	for _, e := range entries {
		if e.Details["previous"] == true && e.Details["new"] == false {
			sawOff = true
		}
	}
	assert.True(t, sawOff, "the change back records true -> false")
}

func TestPutUnattendedRolloutRejectsBadBodyAndMissingAudit(t *testing.T) {
	f := newUnattendedRolloutFixture(t)
	p := unattendedAdmin()

	for name, body := range map[string]string{
		"missing enabled": `{}`,
		"not a bool":      `{"enabled":"yes"}`,
		"null":            `{"enabled":null}`,
		"not json":        `enabled=true`,
		"unknown field":   `{"enabled":true,"tenant":"other"}`,
		"trailing value":  `{"enabled":true}{"enabled":false}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := f.do(http.MethodPut, body, p, true)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.False(t, f.enabled(t))
		})
	}
	assert.Empty(t, auditEntriesByAction(t, f.srv, "unattended_rollouts_changed"), "no audit for a rejected request")

	// No audit manager, no change.
	f.srv.auditManager = nil
	rec := f.do(http.MethodPut, `{"enabled":true}`, p, true)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.False(t, f.enabled(t))
}

func TestPutUnattendedRolloutRefusesMachinePrincipal(t *testing.T) {
	f := newUnattendedRolloutFixture(t)

	apiKey := &Principal{
		ID: "key-1", Channel: AuthChannelAPIKey, Assurance: session.AssuranceMachine, TenantID: unattendedTestTenant,
		Permissions: []string{"rollout-automation:set", "rollout-automation:read"},
	}
	rec := f.do(http.MethodPut, `{"enabled":true}`, apiKey, true)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	// A human principal without the permission is refused too.
	noPerm := &Principal{ID: "viewer", Assurance: session.AssuranceStrong, TenantID: unattendedTestTenant, Permissions: []string{"rollout-automation:read"}}
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodPut, `{"enabled":true}`, noPerm, true).Code)

	assert.False(t, f.enabled(t))
	assert.Empty(t, auditEntriesByAction(t, f.srv, "unattended_rollouts_changed"))
}

func TestGetUnattendedRolloutRoute(t *testing.T) {
	f := newUnattendedRolloutFixture(t)

	reader := &Principal{ID: "reader", Assurance: session.AssuranceBasic, TenantID: unattendedTestTenant, Permissions: []string{"rollout-automation:read"}}
	rec := f.do(http.MethodGet, "", reader, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp unattendedResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Data.Enabled, "off by default")
	assert.Empty(t, resp.Data.ChangedBy)
	assert.Contains(t, rec.Body.String(), `"changed_at":null`)

	require.Equal(t, http.StatusOK, f.do(http.MethodPut, `{"enabled":true}`, unattendedAdmin(), true).Code)
	rec = f.do(http.MethodGet, "", reader, false)
	require.Equal(t, http.StatusOK, rec.Code)
	resp = unattendedResponse{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Data.Enabled)
	assert.Equal(t, "rollout-admin", resp.Data.ChangedBy)
	assert.NotNil(t, resp.Data.ChangedAt)

	// The set permission does not read.
	setOnly := &Principal{ID: "setter", Assurance: session.AssuranceStrong, TenantID: unattendedTestTenant, Permissions: []string{"rollout-automation:set"}}
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodGet, "", setOnly, false).Code)

	// The route is on the server's public router at runtime, for both methods.
	var methods []string
	require.NoError(t, f.srv.router.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		if tpl, _ := r.GetPathTemplate(); tpl == "/api/v1/rollout-settings/unattended" {
			m, _ := r.GetMethods()
			methods = append(methods, m...)
		}
		return nil
	}))
	assert.ElementsMatch(t, []string{"GET", "PUT"}, methods)

	// An unwired store answers 503.
	f.srv.unattendedRolloutStore = nil
	assert.Equal(t, http.StatusServiceUnavailable, f.do(http.MethodGet, "", reader, false).Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.do(http.MethodPut, `{"enabled":true}`, unattendedAdmin(), true).Code)
}

// TestUnattendedRolloutStoreWiredAtStartup: the controller startup path builds the
// store and sets it on the API server. The real-start check (a started server
// answers the setting) lives in features/controller/server, which this package
// cannot import; this one pins the wiring call in the startup source.
func TestUnattendedRolloutStoreWiredAtStartup(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "../server/server.go", nil, 0)
	require.NoError(t, err)
	called := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				called[sel.Sel.Name] = true
			}
		}
		return true
	})
	assert.True(t, called["NewUnattendedRolloutStore"], "startup must construct the store")
	assert.True(t, called["SetUnattendedRolloutStore"], "startup must set the store on the API server")

	// A server with no store wired answers 503 rather than a default.
	srv := setupTestServer(t)
	assert.Nil(t, srv.UnattendedRolloutStore())
}
