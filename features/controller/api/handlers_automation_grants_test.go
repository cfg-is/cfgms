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

const grantsPath = "/api/v1/automation/grants"

// grantRoutesFixture runs the real grant routes behind the real requirePermission
// middleware (with presence tokens) on the run fixture's server, tenant tree and
// durable stores. Requests from a grant credential go through the full router.
type grantRoutesFixture struct {
	*runFixture
	t   *testing.T
	mux *mux.Router
}

func newGrantRoutesFixture(t *testing.T) *grantRoutesFixture {
	t.Helper()
	rf := newRunFixture(t)
	r := mux.NewRouter()
	registerAutomationGrantRoutes(rf.srv, r.PathPrefix("/api/v1").Subrouter())
	return &grantRoutesFixture{runFixture: rf, t: t, mux: r}
}

func grantAdmin(id, tenantID string) *Principal {
	return &Principal{
		ID: id, Assurance: session.AssuranceStrong, TenantID: tenantID,
		Permissions: []string{"automation-grant:create", "automation-grant:revoke", "automation-grant:read"},
	}
}

func rootGrantAdmin() *Principal {
	p := grantAdmin("root-admin", "")
	p.GlobalScope, p.RootScoped = true, true
	return p
}

// call sends one request as principal p. presence mints a presence token bound to the
// request for the given permission.
func (f *grantRoutesFixture) call(method, path string, body any, p *Principal, presencePerm string) *httptest.ResponseRecorder {
	f.t.Helper()
	var rdr *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(f.t, err)
		rdr = strings.NewReader(string(raw))
	} else {
		rdr = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	req = withPrincipal(req, p)
	if presencePerm != "" {
		req.Header.Set(presenceTokenHeader, mintPresenceTokenFor(f.t, f.srv, p.ID, req, presencePerm))
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

type createBody = automationGrantCreateRequest

func inOneDay() time.Time { return time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second) }

func (f *grantRoutesFixture) create(p *Principal, body createBody) *httptest.ResponseRecorder {
	return f.call(http.MethodPost, grantsPath, body, p, "automation-grant:create")
}

func (f *grantRoutesFixture) createOK(t *testing.T, p *Principal, tenantID string) automationGrantCreateResponse {
	t.Helper()
	rec := f.create(p, createBody{Name: "deploy", TenantID: tenantID, ExpiresAt: inOneDay()})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var resp struct {
		Data automationGrantCreateResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Data.Grant)
	require.NotEmpty(t, resp.Data.Credential)
	return resp.Data
}

func (f *grantRoutesFixture) list(p *Principal, query string) (*httptest.ResponseRecorder, []AutomationGrant) {
	rec := f.call(http.MethodGet, grantsPath+query, nil, p, "")
	var resp struct {
		Data struct {
			Grants []AutomationGrant `json:"grants"`
		} `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	return rec, resp.Data.Grants
}

func (f *grantRoutesFixture) revoke(p *Principal, id string) *httptest.ResponseRecorder {
	return f.call(http.MethodDelete, grantsPath+"/"+id, nil, p, "")
}

func grantIDs(gs []AutomationGrant) []string {
	ids := []string{}
	for _, g := range gs {
		ids = append(ids, g.ID)
	}
	return ids
}

func TestAutomationGrants_CreateNeedsPresence_CredentialReturnedOnce(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	body := createBody{Name: "deploy", ExpiresAt: inOneDay()}

	rec := f.call(http.MethodPost, grantsPath, body, admin, "")
	require.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "CFGMS-StepUp")
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `presence="required"`)
	_, listed := f.list(admin, "")
	assert.Equal(t, []string{f.grant.ID}, grantIDs(listed), "a challenged request creates nothing")

	created := f.createOK(t, admin, "")
	assert.Equal(t, runMSP, created.Grant.TenantID, "the tenant defaults to the caller's")
	assert.Equal(t, "admin-1", created.Grant.CreatedBy)
	assert.True(t, strings.HasPrefix(created.Credential, automationGrantCredentialPrefix+created.Grant.ID+"_"))

	// The credential authenticates, end to end.
	runID := f.beginOK(t, created.Credential, runClient1, "ticket-1")
	assert.Equal(t, http.StatusOK, f.probeRun(created.Credential, runID).Code)

	// No later read returns it.
	rec, listed = f.list(admin, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.ElementsMatch(t, []string{f.grant.ID, created.Grant.ID}, grantIDs(listed))
	secret := strings.TrimPrefix(created.Credential, automationGrantCredentialPrefix+created.Grant.ID+"_")
	assert.NotContains(t, rec.Body.String(), secret)
	assert.NotContains(t, rec.Body.String(), created.Credential)
	assert.NotContains(t, strings.ToLower(rec.Body.String()), "credential")
}

func TestAutomationGrants_CreateValidatesBody(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	cases := map[string]any{
		"missing name":    createBody{ExpiresAt: inOneDay()},
		"missing expiry":  createBody{Name: "deploy"},
		"expired":         createBody{Name: "deploy", ExpiresAt: time.Now().Add(-time.Hour)},
		"beyond the cap":  createBody{Name: "deploy", ExpiresAt: time.Now().Add(MaxGrantLifetime + 24*time.Hour)},
		"unknown field":   map[string]any{"name": "deploy", "expires_at": inOneDay(), "permissions": []string{"*"}},
		"bad expiry type": map[string]any{"name": "deploy", "expires_at": "tomorrow"},
	}
	for name, body := range cases {
		rec := f.call(http.MethodPost, grantsPath, body, admin, "automation-grant:create")
		assert.Equal(t, http.StatusBadRequest, rec.Code, name+": "+rec.Body.String())
	}
	rec := f.call(http.MethodPost, grantsPath, "not an object", admin, "automation-grant:create")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	_, listed := f.list(admin, "")
	assert.Len(t, listed, 1, "only the fixture grant exists")
}

func TestAutomationGrants_RevokeNeedsNoTapButStrongAssurance_RefusesRevokedCredentialNext(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	created := f.createOK(t, admin, "")
	runID := f.beginOK(t, created.Credential, runClient1, "ticket-1")
	require.Equal(t, http.StatusOK, f.probeRun(created.Credential, runID).Code)

	// A Basic session may not revoke: it is challenged for a stronger factor.
	basic := grantAdmin("basic-admin", runMSP)
	basic.Assurance = session.AssuranceBasic
	assert.Equal(t, http.StatusUnauthorized, f.revoke(basic, created.Grant.ID).Code)
	require.Equal(t, http.StatusOK, f.probeRun(created.Credential, runID).Code, "still valid")

	rec := f.revoke(admin, created.Grant.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), created.Credential)

	// The very next request with the credential is refused.
	assert.Equal(t, http.StatusUnauthorized, f.probeRun(created.Credential, runID).Code)
	assert.Equal(t, http.StatusUnauthorized, f.begin(created.Credential, runClient1, "ticket-2").Code)

	_, listed := f.list(admin, "")
	var seen *AutomationGrant
	for i := range listed {
		if listed[i].ID == created.Grant.ID {
			seen = &listed[i]
		}
	}
	require.NotNil(t, seen)
	require.NotNil(t, seen.RevokedAt)
	assert.Equal(t, "admin-1", seen.RevokedBy)

	// Revoking again is not an error and keeps the original record.
	assert.Equal(t, http.StatusOK, f.revoke(admin, created.Grant.ID).Code)
	assert.Equal(t, http.StatusNotFound, f.revoke(admin, strings.Repeat("0", 32)).Code)
}

// [REQUIRED TEST] Revoking a grant ends its open runs.
func TestAutomationGrants_RevokeEndsOpenRuns(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	created := f.createOK(t, admin, "")
	run1 := f.beginOK(t, created.Credential, runClient1, "ticket-1")
	run2 := f.beginOK(t, created.Credential, runSiteA, "ticket-2")
	// A run of another grant stays open.
	_, otherCred := f.newGrant(t, runMSP)
	otherRun := f.beginOK(t, otherCred, runClient1, "ticket-other")

	rec := f.revoke(admin, created.Grant.ID)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp struct {
		Data automationGrantRevokeResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Data.RunsEnded)

	runs := f.srv.automationRunStore()
	for _, id := range []string{run1, run2} {
		run, err := runs.findByID(context.Background(), id)
		require.NoError(t, err)
		assert.True(t, run.Ended, "run %s is ended", id)
	}
	open, err := runs.findByID(context.Background(), otherRun)
	require.NoError(t, err)
	assert.False(t, open.Ended, "another grant's run is untouched")
	assert.Equal(t, http.StatusOK, f.probeRun(otherCred, otherRun).Code)
}

// [REQUIRED TEST] A caller cannot list, revoke or create a grant outside its subtree.
func TestAutomationGrants_OutsideSubtreeIs404(t *testing.T) {
	f := newGrantRoutesFixture(t)
	mspGrant := f.grant
	otherGrant, otherCred := f.newGrant(t, runOther)
	clientGrant, _ := f.newGrant(t, runClient1)
	childAdmin := grantAdmin("client-admin", runClient1)

	rec, listed := f.list(childAdmin, "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{clientGrant.ID}, grantIDs(listed), "only its own subtree is listed")

	mspAdmin := grantAdmin("msp-admin", runMSP)
	_, listed = f.list(mspAdmin, "")
	assert.ElementsMatch(t, []string{mspGrant.ID, clientGrant.ID}, grantIDs(listed))

	// Revoke: a parent's grant, another MSP's grant.
	for _, g := range []*AutomationGrant{mspGrant, otherGrant} {
		rec := f.revoke(childAdmin, g.ID)
		assert.Equal(t, http.StatusNotFound, rec.Code, g.TenantID)
	}
	assert.Equal(t, http.StatusNotFound, f.revoke(mspAdmin, otherGrant.ID).Code)
	// Neither grant was revoked.
	for _, g := range []*AutomationGrant{mspGrant, otherGrant} {
		got, err := f.store.Get(context.Background(), g.TenantID, g.ID)
		require.NoError(t, err)
		assert.False(t, got.Revoked(), g.TenantID)
	}
	f.beginOK(t, otherCred, runOther, "still-valid")
}

// [REQUIRED TEST] A child-tenant admin cannot create a grant at its parent, the MSP
// tenant or the root.
func TestAutomationGrants_CreateOutsideSubtreeIs404(t *testing.T) {
	f := newGrantRoutesFixture(t)
	childAdmin := grantAdmin("client-admin", runClient1)

	for _, target := range []string{runMSP, testRootTenantID, runOther, runClient2, "no-such-tenant"} {
		rec := f.create(childAdmin, createBody{Name: "deploy", TenantID: target, ExpiresAt: inOneDay()})
		assert.Equal(t, http.StatusNotFound, rec.Code, target+": "+rec.Body.String())
	}
	// Its own subtree is fine, including a descendant.
	for _, target := range []string{runClient1, runSiteA} {
		rec := f.create(childAdmin, createBody{Name: "deploy", TenantID: target, ExpiresAt: inOneDay()})
		assert.Equal(t, http.StatusCreated, rec.Code, target+": "+rec.Body.String())
	}
	all, err := f.store.List(context.Background(), []string{runMSP, testRootTenantID, runOther, runClient2})
	require.NoError(t, err)
	assert.Equal(t, []string{f.grant.ID}, grantIDsOf(all), "nothing was created outside the subtree")
}

func grantIDsOf(gs []*AutomationGrant) []string {
	ids := []string{}
	for _, g := range gs {
		ids = append(ids, g.ID)
	}
	return ids
}

func TestAutomationGrants_RootScopedCallerMustNameTenant(t *testing.T) {
	f := newGrantRoutesFixture(t)
	root := rootGrantAdmin()

	rec := f.create(root, createBody{Name: "deploy", ExpiresAt: inOneDay()})
	assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())

	// An MSP tenant is below the root-to-MSP boundary: a crossing is required.
	rec = f.create(root, createBody{Name: "deploy", TenantID: runMSP, ExpiresAt: inOneDay()})
	assert.Equal(t, http.StatusUnauthorized, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), "tenant-crossing")

	// The root tenant itself is allowed.
	created := f.createOK(t, root, testRootTenantID)
	assert.Equal(t, testRootTenantID, created.Grant.TenantID)

	// Listing is for one tenant: the root tenant by default, never every tenant.
	_, listed := f.list(root, "")
	assert.Equal(t, []string{created.Grant.ID}, grantIDs(listed))
	rec, _ = f.list(root, "?tenant="+runMSP)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, http.StatusUnauthorized, f.revoke(root, f.grant.ID).Code, "msp grant needs a crossing")
}

// [REQUIRED TEST] Creation with an API-key principal is refused.
func TestAutomationGrants_APIKeyPrincipalRefused(t *testing.T) {
	f := newGrantRoutesFixture(t)
	apiKey := &Principal{
		ID: "key-1", Channel: AuthChannelAPIKey, Assurance: session.AssuranceMachine, TenantID: runMSP,
		Permissions: []string{"automation-grant:create", "automation-grant:revoke", "automation-grant:read"},
	}
	rec := f.create(apiKey, createBody{Name: "deploy", ExpiresAt: inOneDay()})
	assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusForbidden, f.revoke(apiKey, f.grant.ID).Code)

	all, err := f.store.List(context.Background(), []string{runMSP})
	require.NoError(t, err)
	assert.Equal(t, []string{f.grant.ID}, grantIDsOf(all))
	assert.Empty(t, auditEntriesByAction(t, f.srv, automationGrantAuditCreate))
	assert.Empty(t, auditEntriesByAction(t, f.srv, automationGrantAuditRevoke))
}

// A principal without the permission is refused, and so is a grant principal on every
// grant route, through the full router and real authentication.
func TestAutomationGrants_NoPermissionAndGrantPrincipalRefused(t *testing.T) {
	f := newGrantRoutesFixture(t)
	viewer := &Principal{ID: "viewer", Assurance: session.AssuranceStrong, TenantID: runMSP, Permissions: []string{"automation-grant:read"}}
	assert.Equal(t, http.StatusForbidden, f.create(viewer, createBody{Name: "d", ExpiresAt: inOneDay()}).Code)
	assert.Equal(t, http.StatusForbidden, f.revoke(viewer, f.grant.ID).Code)
	rec, _ := f.list(viewer, "")
	assert.Equal(t, http.StatusOK, rec.Code)

	_, otherCred := f.newGrant(t, runMSP)
	for _, cred := range []string{f.cred, otherCred} {
		for _, c := range []struct{ method, path string }{
			{http.MethodPost, grantsPath},
			{http.MethodGet, grantsPath},
			{http.MethodDelete, grantsPath + "/" + f.grant.ID},
		} {
			rec := f.do(c.method, c.path, cred, createBody{Name: "d", ExpiresAt: inOneDay()})
			assert.Equal(t, http.StatusForbidden, rec.Code, c.method+" "+c.path+": "+rec.Body.String())
		}
	}
	// The grant's own credential is still valid: the refused DELETE revoked nothing.
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	assert.Equal(t, http.StatusOK, f.probeRun(f.cred, runID).Code)
}

// [REQUIRED TEST]-adjacent: each action writes exactly one audit event with the
// grant id, tenant, expiry and actor, and no event holds the credential.
func TestAutomationGrants_AuditEventsCarryFieldsAndNoCredential(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	created := f.createOK(t, admin, runClient1)
	require.Equal(t, http.StatusOK, f.revoke(admin, created.Grant.ID).Code)

	for _, action := range []string{automationGrantAuditCreate, automationGrantAuditRevoke} {
		entries := auditEntriesByAction(t, f.srv, action)
		require.Len(t, entries, 1, action)
		e := entries[0]
		assert.Equal(t, runClient1, e.TenantID)
		assert.Equal(t, "admin-1", e.UserID)
		assert.Equal(t, business.AuditResultSuccess, e.Result)
		assert.Equal(t, created.Grant.ID, e.ResourceID)
		assert.Equal(t, created.Grant.ID, e.Details["grant_id"])
		assert.Equal(t, runClient1, e.Details["tenant"])
		assert.Equal(t, created.Grant.ExpiresAt.UTC().Format(time.RFC3339), e.Details["expires_at"])
		assert.Equal(t, "admin-1", e.Details["actor"])
	}

	require.NoError(t, f.srv.auditManager.Flush(context.Background()))
	all, err := f.srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{})
	require.NoError(t, err)
	secret := strings.TrimPrefix(created.Credential, automationGrantCredentialPrefix+created.Grant.ID+"_")
	for _, e := range all {
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), secret)
		assert.NotContains(t, string(raw), created.Credential)
	}
}

// [REQUIRED TEST] If the audit event cannot be written, create and revoke fail and
// change nothing.
func TestAutomationGrants_AuditFailureChangesNothing(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	live := f.createOK(t, admin, "")
	liveRun := f.beginOK(t, live.Credential, runClient1, "ticket-1")

	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, f.srv.auditManager.Stop(stopCtx))

	rec := f.create(admin, createBody{Name: "unaudited", ExpiresAt: inOneDay()})
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.NotContains(t, rec.Body.String(), automationGrantCredentialPrefix, "no credential is returned")
	all, err := f.store.List(context.Background(), []string{runMSP})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{f.grant.ID, live.Grant.ID}, grantIDsOf(all), "no unaudited grant is born")

	rec = f.revoke(admin, live.Grant.ID)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, http.StatusOK, f.probeRun(live.Credential, liveRun).Code, "not revoked, run still open")
	got, err := f.store.Get(context.Background(), runMSP, live.Grant.ID)
	require.NoError(t, err)
	assert.False(t, got.Revoked())

	// With no audit manager at all, both are refused as well.
	f.srv.auditManager = nil
	assert.Equal(t, http.StatusServiceUnavailable, f.create(admin, createBody{Name: "unaudited", ExpiresAt: inOneDay()}).Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.revoke(admin, live.Grant.ID).Code)
	all, err = f.store.List(context.Background(), []string{runMSP})
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestAutomationGrants_UnwiredStoreIs503(t *testing.T) {
	f := newGrantRoutesFixture(t)
	admin := grantAdmin("admin-1", runMSP)
	f.srv.automationGrantStore = nil
	assert.Equal(t, http.StatusServiceUnavailable, f.create(admin, createBody{Name: "d", ExpiresAt: inOneDay()}).Code)
	assert.Equal(t, http.StatusServiceUnavailable, f.revoke(admin, f.grant.ID).Code)
	rec, _ := f.list(admin, "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
