// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const libraryModeTestTenant = "lib-tenant"

type libraryModeFixture struct {
	tb    *testing.T
	srv   *Server
	store *ContentApprovalStore
	mux   *mux.Router
}

// newLibraryModeFixture wires the real routes behind the real requirePermission
// middleware on a server with a durable approval store and audit manager.
func newLibraryModeFixture(t *testing.T) *libraryModeFixture {
	t.Helper()
	srv := setupTestServer(t)
	st, _ := newApprovalStore(t)
	srv.SetContentApprovalStore(st)
	r := mux.NewRouter()
	registerContentLibraryModeRoutes(srv, r.PathPrefix("/api/v1").Subrouter())
	return &libraryModeFixture{tb: t, srv: srv, store: st, mux: r}
}

func libraryModeAdmin() *Principal {
	return &Principal{
		ID: "mode-admin", Assurance: session.AssuranceStrong, TenantID: libraryModeTestTenant,
		Permissions: []string{"content-library:set-mode", "content-library:read"},
	}
}

func (f *libraryModeFixture) do(method, kind, body string, p *Principal, presence bool) *httptest.ResponseRecorder {
	path := "/api/v1/automation/libraries/" + kind + "/mode"
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = withPrincipal(req, p)
	if presence {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.tb, f.srv, p.ID, req, "content-library:set-mode"))
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *libraryModeFixture) mode(t *testing.T, kind LibraryKind) ApprovalMode {
	t.Helper()
	m, err := f.store.GetMode(context.Background(), libraryModeTestTenant, kind)
	require.NoError(t, err)
	return m
}

func TestLibraryMode_PutWithoutPresenceIsChallenged_WithPresenceChangesModeAndEvaluatorSeesIt(t *testing.T) {
	f := newLibraryModeFixture(t)
	p := libraryModeAdmin()

	rec := f.do(http.MethodPut, "script", `{"mode":"approve"}`, p, false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	assert.Equal(t, ApprovalModeSigned, f.mode(t, LibraryKindScript), "a challenged request changes nothing")

	rec = f.do(http.MethodPut, "script", `{"mode":"approve"}`, p, true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// The evaluator reads through the same store on its next call.
	assert.Equal(t, ApprovalModeApprove, f.mode(t, LibraryKindScript))
	assert.Equal(t, ApprovalModeSigned, f.mode(t, LibraryKindWorkflow), "the other kind is untouched")

	get := f.do(http.MethodGet, "script", "", p, false)
	require.Equal(t, http.StatusOK, get.Code, get.Body.String())
	var resp struct {
		Data libraryModeResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(get.Body.Bytes(), &resp))
	assert.Equal(t, "script", resp.Data.Kind)
	assert.Equal(t, ApprovalModeApprove, resp.Data.Mode)
}

func TestLibraryMode_ModeChangeWritesAuditWithPreviousAndNew(t *testing.T) {
	f := newLibraryModeFixture(t)
	p := libraryModeAdmin()

	require.Equal(t, http.StatusOK, f.do(http.MethodPut, "workflow", `{"mode":"comment"}`, p, true).Code)

	entries := auditEntriesByAction(t, f.srv, "content_library.mode_change")
	require.Len(t, entries, 1)
	e := entries[0]
	assert.Equal(t, libraryModeTestTenant, e.TenantID)
	assert.Equal(t, "mode-admin", e.UserID)
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, "workflow", e.Details["kind"])
	assert.Equal(t, libraryModeTestTenant, e.Details["tenant"])
	assert.Equal(t, "signed", e.Details["previous"])
	assert.Equal(t, "comment", e.Details["new"])
	assert.Equal(t, "mode-admin", e.Details["actor"])

	require.Equal(t, http.StatusOK, f.do(http.MethodPut, "workflow", `{"mode":"signed"}`, p, true).Code)
	entries = auditEntriesByAction(t, f.srv, "content_library.mode_change")
	require.Len(t, entries, 2)
	var sawBack bool
	for _, e := range entries {
		if e.Details["previous"] == "comment" && e.Details["new"] == "signed" {
			sawBack = true
		}
	}
	assert.True(t, sawBack, "the second change records comment -> signed")
}

func TestLibraryMode_SameModeStillRequiresTapAndIsAudited(t *testing.T) {
	f := newLibraryModeFixture(t)
	p := libraryModeAdmin()

	// The current mode is signed; setting signed is challenged exactly like a change.
	rec := f.do(http.MethodPut, "script", `{"mode":"signed"}`, p, false)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)

	require.Equal(t, http.StatusOK, f.do(http.MethodPut, "script", `{"mode":"signed"}`, p, true).Code)
	entries := auditEntriesByAction(t, f.srv, "content_library.mode_change")
	require.Len(t, entries, 1)
	assert.Equal(t, "signed", entries[0].Details["previous"])
	assert.Equal(t, "signed", entries[0].Details["new"])
	assert.Equal(t, ApprovalModeSigned, f.mode(t, LibraryKindScript))
}

func TestLibraryMode_InvalidModeOrKindIs400AndChangesNothing(t *testing.T) {
	f := newLibraryModeFixture(t)
	p := libraryModeAdmin()
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, "script", `{"mode":"approve"}`, p, true).Code)

	for name, c := range map[string]struct{ kind, body string }{
		"unknown mode":   {"script", `{"mode":"yolo"}`},
		"empty mode":     {"script", `{"mode":""}`},
		"missing mode":   {"script", `{}`},
		"wrong case":     {"script", `{"mode":"Comment"}`},
		"not json":       {"script", `mode=comment`},
		"unknown field":  {"script", `{"mode":"comment","tenant":"other"}`},
		"unknown kind":   {"playbook", `{"mode":"comment"}`},
		"trailing value": {"script", `{"mode":"comment"}{"mode":"signed"}`},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(auditEntriesByAction(t, f.srv, "content_library.mode_change"))
			rec := f.do(http.MethodPut, c.kind, c.body, p, true)
			assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
			assert.Equal(t, ApprovalModeApprove, f.mode(t, LibraryKindScript))
			assert.Len(t, auditEntriesByAction(t, f.srv, "content_library.mode_change"), before, "no audit for a rejected request")
		})
	}
}

func TestLibraryMode_APIKeyAndGrantPrincipalsRefused(t *testing.T) {
	f := newLibraryModeFixture(t)

	apiKey := &Principal{
		ID: "key-1", Channel: AuthChannelAPIKey, Assurance: session.AssuranceMachine, TenantID: libraryModeTestTenant,
		Permissions: []string{"content-library:set-mode", "content-library:read"},
	}
	rec := f.do(http.MethodPut, "script", `{"mode":"comment"}`, apiKey, true)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	// A grant-derived principal (the relay path) holding the permission verbatim.
	grant := &Principal{
		ID: "grant-1", Channel: AuthChannelRelay, Assurance: session.AssuranceMachine, TenantID: libraryModeTestTenant,
		Permissions: []string{"content-library:set-mode"},
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/automation/libraries/script/mode", strings.NewReader(`{"mode":"comment"}`))
	req = withPrincipal(req, grant)
	req = req.WithContext(context.WithValue(req.Context(), relayPrincipalKey, grant))
	rec = httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())

	// A human principal without the permission is refused too.
	noPerm := &Principal{ID: "viewer", Assurance: session.AssuranceStrong, TenantID: libraryModeTestTenant, Permissions: []string{"content-library:read"}}
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodPut, "script", `{"mode":"comment"}`, noPerm, true).Code)

	assert.Equal(t, ApprovalModeSigned, f.mode(t, LibraryKindScript))
	assert.Empty(t, auditEntriesByAction(t, f.srv, "content_library.mode_change"))
}

func TestLibraryMode_AuditFailureLeavesModeUnchanged(t *testing.T) {
	f := newLibraryModeFixture(t)
	p := libraryModeAdmin()
	require.Equal(t, http.StatusOK, f.do(http.MethodPut, "script", `{"mode":"approve"}`, p, true).Code)

	// A stopped audit manager refuses every event.
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, f.srv.auditManager.Stop(stopCtx))

	rec := f.do(http.MethodPut, "script", `{"mode":"comment"}`, p, true)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, ApprovalModeApprove, f.mode(t, LibraryKindScript), "no audit, no change")

	// With no audit manager at all the change is refused as well.
	f.srv.auditManager = nil
	rec = f.do(http.MethodPut, "script", `{"mode":"comment"}`, p, true)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, ApprovalModeApprove, f.mode(t, LibraryKindScript))
}

func TestLibraryMode_GetRequiresReadPermissionAndNoTap(t *testing.T) {
	f := newLibraryModeFixture(t)

	reader := &Principal{ID: "reader", Assurance: session.AssuranceBasic, TenantID: libraryModeTestTenant, Permissions: []string{"content-library:read"}}
	rec := f.do(http.MethodGet, "workflow", "", reader, false)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"mode":"signed"`)

	setOnly := &Principal{ID: "setter", Assurance: session.AssuranceStrong, TenantID: libraryModeTestTenant, Permissions: []string{"content-library:set-mode"}}
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodGet, "workflow", "", setOnly, false).Code)
	assert.Equal(t, http.StatusBadRequest, f.do(http.MethodGet, "playbook", "", reader, false).Code)
}

func TestLibraryMode_UnwiredStoreIs503(t *testing.T) {
	f := newLibraryModeFixture(t)
	f.srv.contentApprovalStore = nil
	p := libraryModeAdmin()
	assert.Equal(t, http.StatusServiceUnavailable, f.do(http.MethodPut, "script", `{"mode":"approve"}`, p, true).Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.do(http.MethodGet, "script", "", p, false).Code)
}

// TestLibraryMode_OnlyStoreWritesMode: no other registered route or sync path can
// change the mode. The exhaustive namespace-writer check is
// TestContentApprovalNamespaces_OnlyStoreWrites (Story #5835); this asserts that
// this file reaches the mode only through ContentApprovalStore.SetMode and never
// names the namespace.
func TestLibraryMode_OnlyStoreWritesMode(t *testing.T) {
	for _, c := range []string{"PUT", "POST", "PATCH", "DELETE"} {
		t.Run(c, func(t *testing.T) {
			f := newLibraryModeFixture(t)
			var modeRoutes []string
			require.NoError(t, f.srv.router.Walk(func(r *mux.Route, _ *mux.Router, _ []*mux.Route) error {
				tpl, _ := r.GetPathTemplate()
				methods, _ := r.GetMethods()
				if strings.Contains(tpl, "/automation/libraries/") {
					for _, m := range methods {
						if m == c {
							modeRoutes = append(modeRoutes, tpl)
						}
					}
				}
				return nil
			}))
			if c == "PUT" {
				assert.Equal(t, []string{"/api/v1/automation/libraries/{kind}/mode"}, modeRoutes)
			} else {
				assert.Empty(t, modeRoutes)
			}
		})
	}
}

func TestLibraryMode_AssuranceOverrideCannotLowerPermission(t *testing.T) {
	// A tenant override can only tighten: one asking for Basic and no presence
	// still resolves to Strong with the tap.
	basic := int(session.AssuranceBasic)
	srv := serverWithOverride(t, business.AssurancePolicyOverride{
		PermissionID: "content-library:set-mode", MinOverride: &basic,
	})
	req, found, err := srv.resolveAssuranceRequirement(context.Background(), "test-tenant", "content-library:set-mode")
	require.NoError(t, err)
	require.True(t, found)
	assert.True(t, req.RequireUserPresence)
	assert.False(t, req.AllowMachine)
	assert.Equal(t, session.AssuranceStrong, req.Min)
}
