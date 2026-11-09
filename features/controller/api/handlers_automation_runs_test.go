// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
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

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// Tenant hierarchy used by every test here:
//
//	root
//	 |- msp-a        <- grant tenant
//	 |   |- client-1 <- run tenant
//	 |   |   `- site-a
//	 |   `- client-2
//	`- msp-b
const (
	runMSP     = "msp-a"
	runClient1 = "client-1"
	runClient2 = "client-2"
	runSiteA   = "site-a"
	runOther   = "msp-b"

	probeTemplate  = "/api/v1/zz-automation-run/{run_id}/probe"
	probePath      = "/api/v1/zz-automation-run/%s/probe"
	runsBeginPath  = "/api/v1/automation/runs"
	runsEndPathFmt = "/api/v1/automation/runs/%s/end"
)

type runFixture struct {
	srv   *Server
	store *AutomationGrantStore
	grant *AutomationGrant
	cred  string

	hits      int
	principal *Principal
	tenantCtx string
	scope     ctxkeys.TenantScope
	runCtx    *RunBinding
}

// newRunFixture builds a real server with a real tenant tree, a real grant on
// msp-a, and a probe route registered through registerAutomationRoute.
func newRunFixture(t *testing.T) *runFixture {
	t.Helper()
	logs := &captureAllLogger{}
	srv := setupTestServerWithLogger(t, logs)
	for _, tr := range []tenant.TenantRequest{
		{ID: runMSP, ParentID: testRootTenantID},
		{ID: runOther, ParentID: testRootTenantID},
		{ID: runClient1, ParentID: runMSP},
		{ID: runClient2, ParentID: runMSP},
		{ID: runSiteA, ParentID: runClient1},
	} {
		tr := tr
		_, err := srv.tenantManager.CreateTenant(context.Background(), &tr)
		require.NoError(t, err)
	}
	sm := pkgtesting.SetupTestStorage(t)
	store, err := NewAutomationGrantStore(sm.GetConfigStore(), srv.secretStore)
	require.NoError(t, err)
	srv.SetAutomationGrantStore(store)

	f := &runFixture{srv: srv, store: store}
	f.grant, f.cred = f.newGrant(t, runMSP)

	snapshot := automationRouteTable()
	t.Cleanup(func() {
		automationRoutesMu.Lock()
		automationRoutes = snapshot
		automationRoutesMu.Unlock()
	})
	srv.registerAutomationRoute(srv.apiRouter, http.MethodGet, "/zz-automation-run/{run_id}/probe", f.probe)
	srv.registerAutomationRoute(srv.apiRouter, http.MethodPost, "/zz-automation-run/{run_id}/probe", f.probe)
	return f
}

func (f *runFixture) probe(w http.ResponseWriter, r *http.Request) {
	f.hits++
	f.principal, _ = r.Context().Value(principalContextKey).(*Principal)
	f.tenantCtx, _ = r.Context().Value(ctxkeys.TenantID).(string)
	f.scope, _ = r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	f.runCtx = automationRunFromContext(r.Context())
	w.WriteHeader(http.StatusOK)
}

func (f *runFixture) newGrant(t *testing.T, tenantID string) (*AutomationGrant, string) {
	t.Helper()
	g, cred, err := f.store.Create(context.Background(), tenantID, "deploy", "admin-1", time.Now().Add(24*time.Hour))
	require.NoError(t, err)
	return g, cred
}

func (f *runFixture) do(method, path, cred string, body any) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func (f *runFixture) begin(cred, tenantID, ref string) *httptest.ResponseRecorder {
	return f.do(http.MethodPost, runsBeginPath, cred, AutomationRunBeginRequest{
		TenantID: tenantID, EventRef: ref, EventSource: "psa-a",
	})
}

// beginOK begins a run and returns its id.
func (f *runFixture) beginOK(t *testing.T, cred, tenantID, ref string) string {
	t.Helper()
	rec := f.begin(cred, tenantID, ref)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp struct {
		Data AutomationRunResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Data.RunID)
	assert.Equal(t, tenantID, resp.Data.TenantID)
	return resp.Data.RunID
}

func (f *runFixture) probeRun(cred, runID string) *httptest.ResponseRecorder {
	return f.do(http.MethodGet, strings.Replace(probePath, "%s", runID, 1), cred, nil)
}

func (f *runFixture) auditEntries(t *testing.T, tenantID, action string) []*business.AuditEntry {
	t.Helper()
	require.NoError(t, f.srv.auditManager.Flush(context.Background()))
	entries, err := f.srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: tenantID})
	require.NoError(t, err)
	var out []*business.AuditEntry
	for _, e := range entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func codeOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var resp ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil || resp.Error == nil {
		return ""
	}
	return resp.Error.Code
}

func TestAutomationRunBegin_RefusesTenantOutsideGrantSubtree(t *testing.T) {
	f := newRunFixture(t)
	for _, outside := range []string{runOther, testRootTenantID, "no-such-tenant"} {
		rec := f.begin(f.cred, outside, "ticket-1")
		assert.Equal(t, http.StatusForbidden, rec.Code, outside)
		assert.Equal(t, "TENANT_OUT_OF_SCOPE", codeOf(t, rec), outside)
	}
	// The grant tenant itself and any descendant are inside the subtree.
	for _, inside := range []string{runMSP, runClient1, runClient2, runSiteA} {
		f.beginOK(t, f.cred, inside, "inside-"+inside)
	}
}

func TestAutomationRunBegin_ValidatesBody(t *testing.T) {
	f := newRunFixture(t)
	long := strings.Repeat("a", automationEventFieldMaxLen+1)
	cases := []struct {
		name string
		body any
	}{
		{"missing tenant", AutomationRunBeginRequest{EventRef: "t-1", EventSource: "psa-a"}},
		{"missing ref", AutomationRunBeginRequest{TenantID: runClient1, EventSource: "psa-a"}},
		{"missing source", AutomationRunBeginRequest{TenantID: runClient1, EventRef: "t-1"}},
		{"long ref", AutomationRunBeginRequest{TenantID: runClient1, EventRef: long, EventSource: "psa-a"}},
		{"unsafe ref", AutomationRunBeginRequest{TenantID: runClient1, EventRef: "t 1;rm", EventSource: "psa-a"}},
		{"newline ref", AutomationRunBeginRequest{TenantID: runClient1, EventRef: "t-1\nforged", EventSource: "psa-a"}},
		{"unsafe source", AutomationRunBeginRequest{TenantID: runClient1, EventRef: "t-1", EventSource: "psa<a>"}},
		{"unknown field", map[string]string{"tenant_id": runClient1, "event_ref": "t-1", "event_source": "p", "extra": "x"}},
	}
	for _, tc := range cases {
		rec := f.do(http.MethodPost, runsBeginPath, f.cred, tc.body)
		assert.Equal(t, http.StatusBadRequest, rec.Code, tc.name)
	}
}

func TestAutomationRunBegin_RequiresGrantPrincipal(t *testing.T) {
	f := newRunFixture(t)
	rec := f.begin("", runClient1, "t-1")
	assert.GreaterOrEqual(t, rec.Code, 400)
	assert.Less(t, rec.Code, 500)
}

// [REQUIRED TEST] A run is bound to that tenant only: a call for a descendant of
// the run tenant is refused.
func TestAutomationRun_BoundToRunTenantOnly(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	rec := f.probeRun(f.cred, runID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Equal(t, 1, f.hits)

	path := strings.Replace(probePath, "%s", runID, 1)
	for _, named := range []string{runSiteA, runMSP, runClient2, runOther} {
		// Query naming another tenant.
		for _, key := range []string{"tenant_id", "tenant"} {
			rec := f.do(http.MethodGet, path+"?"+key+"="+named, f.cred, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code, "query %s=%s", key, named)
			assert.Equal(t, "AUTOMATION_RUN_DENIED", codeOf(t, rec))
		}
		// Body naming another tenant.
		rec := f.do(http.MethodPost, path, f.cred, map[string]any{"tenant_id": named, "x": 1})
		assert.Equal(t, http.StatusForbidden, rec.Code, "body tenant_id=%s", named)
		rec = f.do(http.MethodPost, path, f.cred, map[string]any{"Tenant": named})
		assert.Equal(t, http.StatusForbidden, rec.Code, "body Tenant=%s", named)
	}
	require.Equal(t, 1, f.hits, "no refused call reached the handler")

	// Naming the run tenant itself, or no tenant, is fine, and the body is intact.
	rec = f.do(http.MethodGet, path+"?tenant_id="+runClient1, f.cred, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = f.do(http.MethodPost, path, f.cred, map[string]any{"tenant_id": runClient1})
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 3, f.hits)

	// A run begun on the descendant is locked to the descendant, not to client-1.
	siteRun := f.beginOK(t, f.cred, runSiteA, "ticket-2")
	require.Equal(t, http.StatusOK, f.probeRun(f.cred, siteRun).Code)
	assert.Equal(t, runSiteA, f.tenantCtx)
}

// [REQUIRED TEST] A grant with grant tenant MSP and run tenant client-1 is seen as
// client-1 by a handler through the context scope, the context tenant id and the
// Principal object in context.
func TestAutomationRun_HandlerSeesRunTenantThroughEveryView(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	require.Equal(t, http.StatusOK, f.probeRun(f.cred, runID).Code)

	require.NotNil(t, f.principal)
	assert.Equal(t, runClient1, f.principal.TenantID, "principal object")
	assert.Equal(t, runClient1, f.tenantCtx, "context tenant id")
	assert.Equal(t, ctxkeys.NewTenantScope(runClient1), f.scope, "context tenant scope")
	assert.False(t, f.scope.IsRoot())

	// Still the grant's identity and nothing more.
	assert.Equal(t, f.grant.ID, f.principal.ID)
	assert.Equal(t, AuthChannelAutomationGrant, f.principal.Channel)
	assert.False(t, f.principal.GlobalScope)
	assert.False(t, f.principal.ImplicitAdmin)
	assert.Nil(t, f.principal.Permissions)

	require.NotNil(t, f.runCtx)
	assert.Equal(t, runID, f.runCtx.ID)
	assert.Equal(t, runMSP, f.runCtx.GrantTenantID)
}

// [REQUIRED TEST] For every entry in the route table except begin: a request with
// no run id, an ended or expired run, or another grant's run is refused.
func TestAutomationRun_EveryRouteRefusesWithoutAValidRun(t *testing.T) {
	f := newRunFixture(t)

	// A route registered through the helper with no run id in its template.
	f.srv.registerAutomationRoute(f.srv.apiRouter, http.MethodGet, "/zz-automation-run/norunid", f.probe)

	otherGrant, otherCred := f.newGrant(t, runMSP)
	require.NotEqual(t, f.grant.ID, otherGrant.ID)
	otherRun := f.beginOK(t, otherCred, runClient1, "ticket-other")

	ended := f.beginOK(t, f.cred, runClient1, "ticket-ended")
	require.Equal(t, http.StatusOK, f.do(http.MethodPost, strings.Replace(runsEndPathFmt, "%s", ended, 1), f.cred, nil).Code)

	expiring := f.beginOK(t, f.cred, runClient1, "ticket-expiring")

	table := automationRouteTable()
	var checked int
	for _, rt := range table {
		if rt.template == automationBeginTemplate {
			continue
		}
		checked++
		pathFor := func(runID string) string {
			return automationTemplatePath(rt.template, runID)
		}
		hitsBefore := f.hits

		if !strings.Contains(rt.template, "{run_id}") {
			rec := f.do(rt.method, rt.template, f.cred, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code, "no run id: %s %s", rt.method, rt.template)
			continue
		}
		// Unknown and malformed run ids (the "no run id" the URL can carry).
		for _, bad := range []string{strings.Repeat("0", 32), "x", strings.Repeat("a", 31)} {
			rec := f.do(rt.method, pathFor(bad), f.cred, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code, "bad id %q: %s %s", bad, rt.method, rt.template)
		}
		// Another grant's run.
		rec := f.do(rt.method, pathFor(otherRun), f.cred, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, "other grant: %s %s", rt.method, rt.template)
		// An ended run.
		rec = f.do(rt.method, pathFor(ended), f.cred, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, "ended: %s %s", rt.method, rt.template)
		assert.Equal(t, hitsBefore, f.hits, "handler never ran: %s %s", rt.method, rt.template)
	}
	assert.GreaterOrEqual(t, checked, 4, "end, two probes and the no-run-id route are in the table")

	// An expired run: move the clock past the 1h cap (the grant itself lasts 24h).
	f.store.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	t.Cleanup(func() { f.store.now = time.Now })
	for _, rt := range table {
		if !strings.Contains(rt.template, "{run_id}") {
			continue
		}
		rec := f.do(rt.method, automationTemplatePath(rt.template, expiring), f.cred, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, "expired: %s %s", rt.method, rt.template)
	}
	assert.Equal(t, 0, f.hits)
}

func TestAutomationRun_RunIdComesFromThePathOnly(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	bogus := strings.Repeat("0", 32)
	path := strings.Replace(probePath, "%s", bogus, 1)

	// A valid run id in a header, the query or the body does not rescue a bad path id.
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Set("X-Run-Id", runID) },
		func(r *http.Request) { r.Header.Set("X-Automation-Run", runID) },
		func(r *http.Request) { r.URL.RawQuery = "run_id=" + runID },
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+f.cred)
		mutate(req)
		rec := httptest.NewRecorder()
		f.srv.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}
	rec := f.do(http.MethodPost, path, f.cred, map[string]string{"run_id": runID})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Zero(t, f.hits)
}

// [REQUIRED TEST] A second begin for the same event reference with a different
// tenant is refused; the open-run cap and the begin rate limit refuse the excess.
func TestAutomationRunBegin_EventBindingCapAndRate(t *testing.T) {
	t.Run("event bound to its first tenant", func(t *testing.T) {
		f := newRunFixture(t)
		f.beginOK(t, f.cred, runClient1, "ticket-1")

		rec := f.begin(f.cred, runClient2, "ticket-1")
		assert.Equal(t, http.StatusConflict, rec.Code)
		assert.Equal(t, "EVENT_BOUND_TO_OTHER_TENANT", codeOf(t, rec))
		rec = f.begin(f.cred, runSiteA, "ticket-1")
		assert.Equal(t, http.StatusConflict, rec.Code, "a descendant is another tenant")

		// The same event on the same tenant is allowed, another event is free, and
		// another grant's binding of the same reference is its own.
		f.beginOK(t, f.cred, runClient1, "ticket-1")
		f.beginOK(t, f.cred, runClient2, "ticket-2")
		_, otherCred := f.newGrant(t, runMSP)
		f.beginOK(t, otherCred, runClient2, "ticket-1")
	})

	t.Run("open run cap", func(t *testing.T) {
		f := newRunFixture(t)
		var first string
		for i := 0; i < maxOpenAutomationRunsPerGrant; i++ {
			id := f.beginOK(t, f.cred, runClient1, "cap-"+string(rune('a'+i)))
			if i == 0 {
				first = id
			}
		}
		rec := f.begin(f.cred, runClient1, "cap-excess")
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "OPEN_RUN_CAP", codeOf(t, rec))

		// The refused begin bound nothing: the event is still free for another tenant.
		require.Equal(t, http.StatusOK, f.do(http.MethodPost, strings.Replace(runsEndPathFmt, "%s", first, 1), f.cred, nil).Code)
		f.beginOK(t, f.cred, runClient2, "cap-excess")

		// Another grant has its own budget.
		_, otherCred := f.newGrant(t, runMSP)
		f.beginOK(t, otherCred, runClient1, "cap-a")
	})

	t.Run("begin rate limit, node-local counter", func(t *testing.T) {
		f := newRunFixture(t)
		for i := 0; i < automationBeginRateBound; i++ {
			// Refused begins (bad tenant) still count toward the bound.
			rec := f.begin(f.cred, runOther, "rate-1")
			require.Equal(t, http.StatusForbidden, rec.Code)
		}
		rec := f.begin(f.cred, runClient1, "rate-1")
		assert.Equal(t, http.StatusTooManyRequests, rec.Code)
		assert.Equal(t, "RATE_LIMITED", codeOf(t, rec))
	})

	t.Run("begin rate limit, shared counter store", func(t *testing.T) {
		f := newRunFixture(t)
		f.srv.rateCounterStore = pkgtesting.SetupTestRateCounterStore()
		for i := 0; i < automationBeginRateBound; i++ {
			require.Equal(t, http.StatusForbidden, f.begin(f.cred, runOther, "rate-2").Code)
		}
		assert.Equal(t, http.StatusTooManyRequests, f.begin(f.cred, runClient1, "rate-2").Code)
	})
}

// [REQUIRED TEST] Revoking the grant makes its open run refuse on the next call,
// and EndRunsForGrant ends all open runs of a grant.
func TestAutomationRun_RevokeAndEndRunsForGrant(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	require.Equal(t, http.StatusOK, f.probeRun(f.cred, runID).Code)

	_, err := f.store.Revoke(context.Background(), f.grant.TenantID, f.grant.ID, "admin-1")
	require.NoError(t, err)
	rec := f.probeRun(f.cred, runID)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, 1, f.hits)

	// The wrapper itself re-reads the grant: a grant principal whose record is revoked
	// is refused even when authentication did not stop it first (the run is valid).
	g2, cred2 := f.newGrant(t, runMSP)
	run2 := f.beginOK(t, cred2, runClient1, "ticket-2")
	revoked := *g2
	now := time.Now()
	revoked.RevokedAt = &now
	require.NoError(t, f.store.writeGrant(context.Background(), &revoked))
	req := httptest.NewRequest(http.MethodGet, strings.Replace(probePath, "%s", run2, 1), nil)
	req = mux.SetURLVars(req, map[string]string{"run_id": run2})
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, automationGrantPrincipal(g2)))
	w := httptest.NewRecorder()
	f.srv.requireAutomationRun(http.HandlerFunc(f.probe)).ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, 1, f.hits)
	refused := f.auditEntries(t, runMSP, "automation.call")
	require.NotEmpty(t, refused)
	reasons := map[any]bool{}
	for _, e := range refused {
		reasons[e.Details["reason"]] = true
	}
	assert.True(t, reasons["grant_revoked"], "the wrapper refused on its own grant re-read")

	t.Run("EndRunsForGrant", func(t *testing.T) {
		f := newRunFixture(t)
		other, otherCred := f.newGrant(t, runMSP)
		ids := []string{
			f.beginOK(t, f.cred, runClient1, "e-1"),
			f.beginOK(t, f.cred, runClient2, "e-2"),
			f.beginOK(t, f.cred, runSiteA, "e-3"),
		}
		otherRun := f.beginOK(t, otherCred, runClient1, "e-4")
		_ = other

		runs := f.srv.automationRunStore()
		n, err := runs.EndRunsForGrant(context.Background(), f.grant.ID)
		require.NoError(t, err)
		assert.Equal(t, 3, n)
		for _, id := range ids {
			assert.Equal(t, http.StatusForbidden, f.probeRun(f.cred, id).Code)
			b, err := runs.Get(context.Background(), runMSP, id)
			require.NoError(t, err)
			assert.True(t, b.Ended)
			require.NotNil(t, b.EndedAt)
		}
		assert.Equal(t, http.StatusOK, f.probeRun(otherCred, otherRun).Code, "another grant's run is untouched")

		n, err = runs.EndRunsForGrant(context.Background(), f.grant.ID)
		require.NoError(t, err)
		assert.Zero(t, n, "nothing left to end")
	})
}

func TestAutomationRunEnd_EndsOnceAndAudits(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	endPath := strings.Replace(runsEndPathFmt, "%s", runID, 1)

	rec := f.do(http.MethodPost, endPath, f.cred, nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusForbidden, f.do(http.MethodPost, endPath, f.cred, nil).Code, "an ended run admits nothing")
	assert.Equal(t, http.StatusForbidden, f.probeRun(f.cred, runID).Code)
	assert.Len(t, f.auditEntries(t, runClient1, "automation.run.end"), 1)
}

// [REQUIRED TEST] A refused request is audited with the presented run id and never
// with the credential; every accepted call writes an audit event with grant, run,
// tenant and event ref.
func TestAutomationRun_Audit(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-audit")
	require.Equal(t, http.StatusOK, f.probeRun(f.cred, runID).Code)

	calls := f.auditEntries(t, runClient1, "automation.call")
	require.Len(t, calls, 1)
	e := calls[0]
	assert.Equal(t, business.AuditResultSuccess, e.Result)
	assert.Equal(t, f.grant.ID, e.UserID)
	assert.Equal(t, runID, e.ResourceID)
	assert.Equal(t, f.grant.ID, e.Details["grant_id"])
	assert.Equal(t, runID, e.Details["run_id"])
	assert.Equal(t, runClient1, e.Details["tenant_id"])
	assert.Equal(t, runMSP, e.Details["owner_tenant_id"])
	assert.Equal(t, "ticket-audit", e.Details["event_ref"])
	assert.Equal(t, probeTemplate, e.Details["route"])

	begins := f.auditEntries(t, runClient1, "automation.run.begin")
	require.Len(t, begins, 1)
	assert.Equal(t, "ticket-audit", begins[0].Details["event_ref"])

	// A refused call: bad run id, and another grant's run.
	bogus := strings.Repeat("0", 32)
	require.Equal(t, http.StatusForbidden, f.probeRun(f.cred, bogus).Code)
	_, otherCred := f.newGrant(t, runMSP)
	require.Equal(t, http.StatusForbidden, f.probeRun(otherCred, runID).Code)

	denied := f.auditEntries(t, runMSP, "automation.call")
	require.Len(t, denied, 2)
	byRun := map[string]*business.AuditEntry{}
	for _, d := range denied {
		assert.Equal(t, business.AuditResultDenied, d.Result)
		byRun[d.Details["reason"].(string)] = d
	}
	require.Contains(t, byRun, "run_not_found")
	assert.Equal(t, bogus, byRun["run_not_found"].Details["run_id"], "the presented run id is recorded")
	assert.Equal(t, f.grant.ID, byRun["run_not_found"].UserID)
	// Another grant's run id is not found under this grant's tenant key space, so it
	// is indistinguishable from an unknown one.

	// No audit record anywhere carries a credential.
	require.NoError(t, f.srv.auditManager.Flush(context.Background()))
	for _, tenantID := range []string{runMSP, runClient1} {
		entries, err := f.srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{TenantID: tenantID})
		require.NoError(t, err)
		for _, en := range entries {
			raw, err := json.Marshal(en)
			require.NoError(t, err)
			assert.NotContains(t, string(raw), f.cred)
			assert.NotContains(t, string(raw), otherCred)
			assert.NotContains(t, string(raw), automationGrantCredentialPrefix)
		}
	}
}

func TestAutomationRun_AuditSanitizesCallerText(t *testing.T) {
	f := newRunFixture(t)
	f.srv.emitAutomationAudit(context.Background(), f.grant.ID, "run\nforged", runClient1, runMSP,
		"ref\r\nforged", "automation.call", business.AuditResultDenied,
		auditDetail{Key: "reason", Value: "why\nforged"})
	entries := f.auditEntries(t, runClient1, "automation.call")
	require.Len(t, entries, 1)
	raw, err := json.Marshal(entries[0].Details)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "\\n")
	assert.NotContains(t, string(raw), "\\r")
}

// [REQUIRED TEST] A route registered under the /api/v1/automation/runs/{run_id}/
// prefix without the registration helper is refused for a grant principal.
func TestAutomationRun_UnregisteredRouteUnderRunPrefixIsRefused(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	var ran bool
	f.srv.apiRouter.HandleFunc("/automation/runs/{run_id}/sneaky", func(w http.ResponseWriter, _ *http.Request) {
		ran = true
		w.WriteHeader(http.StatusOK)
	}).Methods(http.MethodGet)

	rec := f.do(http.MethodGet, "/api/v1/automation/runs/"+runID+"/sneaky", f.cred, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "AUTOMATION_ROUTE_DENIED", codeOf(t, rec))
	assert.False(t, ran)
}

// [REQUIRED TEST] Every route registered through registerAutomationRoute is behind
// requireAutomationRun and is in the route table.
func TestAutomationRun_RegisteredRoutesAreWrappedAndInTheTable(t *testing.T) {
	f := newRunFixture(t)

	table := automationRouteTable()
	has := func(method, template string) bool {
		for _, rt := range table {
			if rt.method == method && rt.template == template {
				return true
			}
		}
		return false
	}
	assert.True(t, has(http.MethodPost, automationBeginTemplate))
	assert.True(t, has(http.MethodPost, automationEndTemplate))
	assert.True(t, has(http.MethodGet, probeTemplate))
	assert.True(t, has(http.MethodPost, probeTemplate))
	assert.False(t, has(http.MethodGet, automationBeginTemplate), "membership is by method")

	// A helper-registered route is behind the wrapper: with no run it never runs, and
	// the same handler registered as a plain route (no wrapper) is not in the table.
	var plainRan bool
	f.srv.apiRouter.HandleFunc("/zz-automation-run/plain/{run_id}", func(http.ResponseWriter, *http.Request) {
		plainRan = true
	}).Methods(http.MethodGet)
	assert.False(t, has(http.MethodGet, "/api/v1/zz-automation-run/plain/{run_id}"))
	rec := f.do(http.MethodGet, "/api/v1/zz-automation-run/plain/"+strings.Repeat("a", 32), f.cred, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, plainRan)

	// Every table entry, called with a grant credential and no valid run, is refused.
	for _, rt := range table {
		if rt.template == automationBeginTemplate {
			continue
		}
		rec := f.do(rt.method, automationTemplatePath(rt.template, strings.Repeat("0", 32)), f.cred, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", rt.method, rt.template)
		assert.Equal(t, "AUTOMATION_RUN_DENIED", codeOf(t, rec), "%s %s", rt.method, rt.template)
	}
	assert.Zero(t, f.hits)
}

func TestAutomationRun_NonGrantPrincipalIsRefusedByTheWrapper(t *testing.T) {
	f := newRunFixture(t)
	for _, p := range []*Principal{nil, {Channel: AuthChannelAPIKey, ID: "key-1", TenantID: runMSP}} {
		req := httptest.NewRequest(http.MethodGet, strings.Replace(probePath, "%s", strings.Repeat("a", 32), 1), nil)
		if p != nil {
			req = req.WithContext(context.WithValue(req.Context(), principalContextKey, p))
		}
		w := httptest.NewRecorder()
		f.srv.requireAutomationRun(http.HandlerFunc(f.probe)).ServeHTTP(w, req)
		assert.Equal(t, http.StatusForbidden, w.Code)
	}
	assert.Zero(t, f.hits)
}

func TestAutomationRun_NoGrantStoreIs503(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	f.srv.SetAutomationGrantStore(nil)
	// Authentication refuses first when no grant store is wired.
	assert.Equal(t, http.StatusUnauthorized, f.probeRun(f.cred, runID).Code)
	assert.Nil(t, f.srv.automationRunStore())

	req := httptest.NewRequest(http.MethodGet, strings.Replace(probePath, "%s", runID, 1), nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, automationGrantPrincipal(f.grant)))
	w := httptest.NewRecorder()
	f.srv.requireAutomationRun(http.HandlerFunc(f.probe)).ServeHTTP(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAutomationRunStore_ArtifactsAreScopedToTheirRun(t *testing.T) {
	f := newRunFixture(t)
	runA := f.beginOK(t, f.cred, runClient1, "art-1")
	runB := f.beginOK(t, f.cred, runClient1, "art-2")
	runs := f.srv.automationRunStore()
	ctx := context.Background()

	has, err := runs.HasArtifact(ctx, runA, "workflow_execution", "exec-1")
	require.NoError(t, err)
	assert.False(t, has)

	require.NoError(t, runs.RecordArtifact(ctx, runA, "workflow_execution", "exec-1"))
	has, err = runs.HasArtifact(ctx, runA, "workflow_execution", "exec-1")
	require.NoError(t, err)
	assert.True(t, has)

	for _, c := range []struct{ run, kind, id string }{
		{runB, "workflow_execution", "exec-1"},
		{runA, "script_run", "exec-1"},
		{runA, "workflow_execution", "exec-2"},
		{strings.Repeat("0", 32), "workflow_execution", "exec-1"},
		{"bad", "workflow_execution", "exec-1"},
		{runA, "", "exec-1"},
	} {
		has, err := runs.HasArtifact(ctx, c.run, c.kind, c.id)
		require.NoError(t, err)
		assert.False(t, has, "%+v", c)
	}

	assert.ErrorIs(t, runs.RecordArtifact(ctx, strings.Repeat("0", 32), "k", "i"), ErrAutomationRunNotFound)
	assert.Error(t, runs.RecordArtifact(ctx, runA, "", "i"))
	assert.Error(t, runs.RecordArtifact(ctx, runA, "k", strings.Repeat("x", automationArtifactMaxLen+1)))
}

func TestAutomationRunStore_Construction(t *testing.T) {
	_, err := NewAutomationRunStore(nil, nil)
	assert.Error(t, err)
	s, err := NewAutomationRunStore(pkgtesting.SetupTestStorage(t).GetConfigStore(), nil)
	require.NoError(t, err)
	_, err = s.Get(context.Background(), runMSP, "not-a-run-id")
	assert.ErrorIs(t, err, ErrAutomationRunNotFound)
	_, err = s.End(context.Background(), runMSP, strings.Repeat("a", 32))
	assert.ErrorIs(t, err, ErrAutomationRunNotFound)
}

func TestAutomationRunBinding_Expiry(t *testing.T) {
	f := newRunFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	b, err := f.srv.automationRunStore().Get(context.Background(), runMSP, runID)
	require.NoError(t, err)
	assert.WithinDuration(t, b.CreatedAt.Add(MaxAutomationRunLifetime), b.ExpiresAt, time.Second)
	assert.True(t, b.Open(b.CreatedAt))
	assert.False(t, b.Open(b.ExpiresAt))
}

// [REQUIRED TEST] runTenantOnly accepts a device whose own tenant equals the run
// tenant and refuses a device in a descendant, an ancestor and a sibling; the filter
// builder returns only exact-tenant devices.
func TestRunTenantOnly(t *testing.T) {
	assert.True(t, runTenantOnly(runClient1, runClient1))
	assert.False(t, runTenantOnly(runClient1, runSiteA), "descendant")
	assert.False(t, runTenantOnly(runClient1, runMSP), "ancestor")
	assert.False(t, runTenantOnly(runClient1, runClient2), "sibling")
	assert.False(t, runTenantOnly(runClient1, ""), "no tenant")
	assert.False(t, runTenantOnly("", ""), "no run tenant")
	assert.False(t, runTenantOnly("", runClient1))
}

func TestRunTenantOnlyFilter(t *testing.T) {
	devices := []fleet.StewardData{
		{ID: "d-msp", TenantID: runMSP, Status: "online"},
		{ID: "d-c1-a", TenantID: runClient1, Status: "online"},
		{ID: "d-c1-b", TenantID: runClient1, Status: "online"},
		{ID: "d-site", TenantID: runSiteA, Status: "online"},
		{ID: "d-c2", TenantID: runClient2, Status: "online"},
		{ID: "d-none", TenantID: "", Status: "online"},
	}
	q := fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: devices})
	ctx := context.Background()

	got, err := q.Search(ctx, runTenantOnlyFilter(runClient1))
	require.NoError(t, err)
	var ids []string
	for _, d := range got {
		ids = append(ids, d.ID)
		assert.True(t, runTenantOnly(runClient1, d.TenantID))
	}
	assert.ElementsMatch(t, []string{"d-c1-a", "d-c1-b"}, ids)

	f := runTenantOnlyFilter(runClient1)
	assert.Empty(t, f.TenantSubtree)
	assert.Empty(t, f.TenantSubtreeIDs)

	// An empty run tenant fails closed: it matches no device, never all of them.
	got, err = q.Search(ctx, runTenantOnlyFilter(""))
	require.NoError(t, err)
	assert.Empty(t, got)
}
