// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/api/proto/controller"
	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
)

// The hierarchy is the one of handlers_automation_runs_test.go. The fleet holds one
// steward in each of msp-a, client-1, client-1/site-a and client-2, so a client-1 run
// has a steward inside the run tenant, one below it, one beside it and one above it.
const (
	readsSecretValue = "enrol-secret-value-7f3a"
	readsPathPrefix  = "/api/v1/automation/runs/"
)

type readsFixture struct {
	*runFixture
	mspSteward, c1Steward, siteSteward, c2Steward string
	runStore                                      *controllerrun.RunStoreSQL
	addrSeq                                       int
}

func newReadsFixture(t *testing.T) *readsFixture {
	t.Helper()
	f := &readsFixture{runFixture: newRunFixture(t)}
	f.mspSteward = f.registerSteward(t, runMSP, "msp-host")
	f.c1Steward = f.registerSteward(t, runClient1, "c1-host")
	f.siteSteward = f.registerSteward(t, runSiteA, "site-host")
	f.c2Steward = f.registerSteward(t, runClient2, "c2-host")

	now := time.Now()
	var data []fleet.StewardData
	for id, tn := range map[string]string{
		f.mspSteward: runMSP, f.c1Steward: runClient1, f.siteSteward: runSiteA, f.c2Steward: runClient2,
	} {
		data = append(data, fleet.StewardData{
			ID: id, TenantID: tn, Status: "online", LastHeartbeat: now,
			DNAAttributes: map[string]string{"hostname": tn + "-host", "os": "linux", "steward.version": "v1.0"},
		})
	}
	f.srv.fleetQuery = fleet.NewMemoryQuery(&fleetTestStewardProvider{stewards: data})

	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "runs.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	f.runStore = controllerrun.NewRunStoreSQL(db)
	require.NoError(t, f.runStore.Init(context.Background()))
	f.srv.runManager = controllerrun.NewManager(f.runStore, nil)
	return f
}

// registerSteward registers a live steward under tenantID whose DNA carries a
// credential-shaped attribute the API must never return.
func (f *readsFixture) registerSteward(t *testing.T, tenantID, _ string) string {
	t.Helper()
	req := &controller.RegisterRequest{
		Version: "v1.0",
		InitialDna: testRegistrationDNA(t, map[string]string{
			"hostname": tenantID + "-host", "os": "linux", "enrollment_token": readsSecretValue,
		}),
	}
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
	resp, err := f.srv.controllerService.AcceptRegistration(ctx, req)
	require.NoError(t, err)
	return resp.StewardId
}

func (f *readsFixture) get(path, cred string) *httptest.ResponseRecorder {
	f.addrSeq++
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = fmt.Sprintf("10.9.%d.%d:5000", f.addrSeq/250, f.addrSeq%250+1)
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	rec := httptest.NewRecorder()
	f.srv.router.ServeHTTP(rec, req)
	return rec
}

func (f *readsFixture) runPath(runID, suffix string) string { return readsPathPrefix + runID + suffix }

// startedRun records a stored run (and one job per device) as started by runID.
func (f *readsFixture) startedRun(t *testing.T, startedBy, resultRunID, runTenant string, devices ...string) {
	t.Helper()
	f.storeRun(t, resultRunID, runTenant, devices...)
	require.NoError(t, f.runFixture.srv.automationRunStore().RecordArtifact(
		context.Background(), startedBy, automationArtifactKindRun, resultRunID))
}

func (f *readsFixture) storeRun(t *testing.T, resultRunID, runTenant string, devices ...string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, f.runStore.CreateRun(&controllerrun.RunRecord{
		RunID: resultRunID, TenantID: runTenant, CreatedAt: now,
		Status: controllerrun.RunStatusCompleted, JobCount: len(devices),
	}))
	for i, d := range devices {
		require.NoError(t, f.runStore.CreateJob(&controllerrun.JobRecord{
			JobID: fmt.Sprintf("%s-job-%d", resultRunID, i), RunID: resultRunID, DeviceID: d,
			Status: controllerrun.JobStatusCompleted, CreatedAt: now, Output: "output-of-" + d,
		}))
	}
}

func dataOf[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var env struct {
		Data T `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env), rec.Body.String())
	return env.Data
}

func stewardIDs(list []StewardInfo) []string {
	ids := make([]string, 0, len(list))
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	sort.Strings(ids)
	return ids
}

// automationTemplatePath turns a route template into a request path: {run_id} becomes
// runID and every other variable (the read routes carry {id} and {result_run_id})
// becomes a value that passes request validation.
func automationTemplatePath(template, runID string) string {
	return templateVar.ReplaceAllStringFunc(template, func(v string) string {
		if v == "{run_id}" {
			return runID
		}
		return "x1"
	})
}

var automationReadTemplates = []string{
	"/api/v1/automation/runs/{run_id}/stewards",
	"/api/v1/automation/runs/{run_id}/stewards/{id}",
	"/api/v1/automation/runs/{run_id}/stewards/{id}/dna",
	"/api/v1/automation/runs/{run_id}/results/{result_run_id}",
	"/api/v1/automation/runs/{run_id}/results/{result_run_id}/jobs",
}

// The route table lists the read templates plus begin and end, and nothing else.
func TestAutomationReads_RouteTableIsTheClosedSet(t *testing.T) {
	f := newReadsFixture(t)
	var got []string
	for _, rt := range automationRouteTable() {
		if strings.Contains(rt.template, "zz-automation-run") {
			continue // the fixture's own probe routes
		}
		got = append(got, rt.method+" "+rt.template)
	}
	want := []string{
		"POST " + automationBeginTemplate, "POST " + automationEndTemplate,
		"POST " + automationScriptsTemplate, "GET " + automationScriptsTemplate, // handlers_automation_script_run_test.go
		"POST " + automationWorkflowRunTemplate, "GET " + automationExecutionsTemplate, // handlers_automation_workflow_run_test.go
		"GET " + automationExecutionGetTemplate,
	}
	for _, tpl := range automationReadTemplates {
		want = append(want, "GET "+tpl)
	}
	sort.Strings(got)
	sort.Strings(want)
	assert.Equal(t, want, got)

	// Reads are GET only: the same templates under another method are refused.
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	rec := f.do(http.MethodPost, f.runPath(runID, "/stewards"), f.cred, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, "mux answers a method outside the template's set")
}

// Each read returns the data of the underlying handler, for the run tenant only.
func TestAutomationReads_ReturnRunTenantData(t *testing.T) {
	f := newReadsFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	list := f.get(f.runPath(runID, "/stewards"), f.cred)
	require.Equal(t, http.StatusOK, list.Code, list.Body.String())
	listed := dataOf[[]StewardInfo](t, list)
	assert.Equal(t, []string{f.c1Steward}, stewardIDs(listed))
	assert.Equal(t, runClient1, listed[0].TenantID)

	got := f.get(f.runPath(runID, "/stewards/"+f.c1Steward), f.cred)
	require.Equal(t, http.StatusOK, got.Code, got.Body.String())
	one := dataOf[StewardInfo](t, got)
	assert.Equal(t, f.c1Steward, one.ID)
	assert.Equal(t, runClient1, one.TenantID)
	assert.Equal(t, listed[0].Version, one.Version)

	dna := f.get(f.runPath(runID, "/stewards/"+f.c1Steward+"/dna"), f.cred)
	require.Equal(t, http.StatusOK, dna.Code, dna.Body.String())
	info := dataOf[DNAInfo](t, dna)
	assert.Equal(t, runClient1+"-host", info.Hostname)

	// A filter, an attribute lookup and pagination keep the underlying handler's behaviour.
	filtered := f.get(f.runPath(runID, "/stewards")+"?os=linux", f.cred)
	require.Equal(t, http.StatusOK, filtered.Code, filtered.Body.String())
	assert.Equal(t, []string{f.c1Steward}, stewardIDs(dataOf[[]StewardInfo](t, filtered)))

	page := f.get(f.runPath(runID, "/stewards")+"?limit=1&offset=0", f.cred)
	require.Equal(t, http.StatusOK, page.Code, page.Body.String())
	pg := dataOf[StewardListPage](t, page)
	assert.Equal(t, 1, pg.Total, "total counts run-tenant stewards only, never a descendant's")
	assert.Equal(t, []string{f.c1Steward}, stewardIDs(pg.Stewards))

	bad := f.get(f.runPath(runID, "/stewards")+"?limit=abc", f.cred)
	assert.Equal(t, http.StatusBadRequest, bad.Code)

	// A run result this run started.
	f.startedRun(t, runID, "result-run-1", runClient1, f.c1Steward)
	res := f.get(f.runPath(runID, "/results/result-run-1"), f.cred)
	require.Equal(t, http.StatusOK, res.Code, res.Body.String())
	assert.Equal(t, "result-run-1", dataOf[controllerrun.RunRecord](t, res).RunID)
	jobs := f.get(f.runPath(runID, "/results/result-run-1/jobs"), f.cred)
	require.Equal(t, http.StatusOK, jobs.Code, jobs.Body.String())
	rows := dataOf[[]map[string]any](t, jobs)
	require.Len(t, rows, 1)
	assert.Equal(t, f.c1Steward, rows[0]["device_id"])
	assert.Equal(t, "output-of-"+f.c1Steward, rows[0]["output"])
}

// [REQUIRED TEST] Each read returns only run-tenant data when the fleet holds data
// for two tenants: a client-1 run cannot see a client-2 steward, and cannot see a
// descendant (client-1/site-a) steward.
func TestAutomationReads_OnlyRunTenantData(t *testing.T) {
	f := newReadsFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")

	for _, outside := range []struct{ name, id string }{
		{"sibling client-2", f.c2Steward},
		{"descendant client-1/site-a", f.siteSteward},
		{"ancestor msp-a", f.mspSteward},
		{"unknown", "no-such-steward"},
	} {
		for _, suffix := range []string{"", "/dna"} {
			rec := f.get(f.runPath(runID, "/stewards/"+outside.id+suffix), f.cred)
			assert.Equal(t, http.StatusNotFound, rec.Code, "%s%s: %s", outside.name, suffix, rec.Body.String())
			assert.Equal(t, "STEWARD_NOT_FOUND", codeOf(t, rec), outside.name+suffix)
		}
	}
	// A refused read is indistinguishable from an unknown steward.
	known := f.get(f.runPath(runID, "/stewards/"+f.c2Steward), f.cred)
	unknown := f.get(f.runPath(runID, "/stewards/no-such-steward"), f.cred)
	assert.Equal(t, unknown.Code, known.Code)
	assert.Equal(t, codeOf(t, unknown), codeOf(t, known))

	// The list, unfiltered and filtered every way the handler offers, holds only
	// client-1's own steward and never leaks a count of the descendant.
	for _, query := range []string{
		"", "?os=linux", "?status=online", "?hostname=" + runSiteA + "-host", "?hostname=" + runClient2 + "-host",
		"?q=all", "?q=os:linux", "?include_hidden=true&include_deregistered=true&include_quarantined=true",
	} {
		rec := f.get(f.runPath(runID, "/stewards")+query, f.cred)
		require.Equal(t, http.StatusOK, rec.Code, "%q: %s", query, rec.Body.String())
		for _, s := range dataOf[[]StewardInfo](t, rec) {
			assert.Equal(t, runClient1, s.TenantID, "query %q returned %s", query, s.ID)
		}
		assert.NotContains(t, rec.Body.String(), f.siteSteward, query)
		assert.NotContains(t, rec.Body.String(), f.c2Steward, query)
	}

	// A run on the descendant tenant sees the descendant only.
	siteRun := f.beginOK(t, f.cred, runSiteA, "ticket-site")
	rec := f.get(f.runPath(siteRun, "/stewards"), f.cred)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, []string{f.siteSteward}, stewardIDs(dataOf[[]StewardInfo](t, rec)))
	assert.Equal(t, http.StatusNotFound, f.get(f.runPath(siteRun, "/stewards/"+f.c1Steward), f.cred).Code)

	// Result runs in a descendant or sibling tenant are refused even when recorded
	// as this run's, and a job on a device outside the run tenant is dropped.
	f.startedRun(t, runID, "result-in-site", runSiteA, f.siteSteward)
	f.startedRun(t, runID, "result-in-c2", runClient2, f.c2Steward)
	f.startedRun(t, runID, "result-mixed", runClient1, f.c1Steward, f.siteSteward, f.c2Steward, "no-such-device")
	for _, id := range []string{"result-in-site", "result-in-c2"} {
		for _, suffix := range []string{"", "/jobs"} {
			assert.Equal(t, http.StatusNotFound, f.get(f.runPath(runID, "/results/"+id+suffix), f.cred).Code, id+suffix)
		}
	}
	jobs := f.get(f.runPath(runID, "/results/result-mixed/jobs"), f.cred)
	require.Equal(t, http.StatusOK, jobs.Code, jobs.Body.String())
	rows := dataOf[[]map[string]any](t, jobs)
	require.Len(t, rows, 1)
	assert.Equal(t, f.c1Steward, rows[0]["device_id"])
	assert.NotContains(t, jobs.Body.String(), "output-of-"+f.siteSteward)
	assert.NotContains(t, jobs.Body.String(), "output-of-"+f.c2Steward)
}

// [REQUIRED TEST] A client-1 run cannot read, target or filter-select a
// client-1/site-a device through any route in the table.
func TestAutomationReads_CannotReachDescendantDevice(t *testing.T) {
	f := newReadsFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	f.startedRun(t, runID, "result-site", runSiteA, f.siteSteward)

	for _, rt := range automationRouteTable() {
		if rt.method != http.MethodGet || !strings.HasPrefix(rt.template, readsPathPrefix) {
			continue
		}
		path := strings.NewReplacer("{run_id}", runID, "{id}", f.siteSteward, "{result_run_id}", "result-site").Replace(rt.template)
		// Read by id, and select through every query field that names a tenant.
		for _, query := range []string{
			"", "?tenant_id=" + runSiteA, "?tenant=" + runSiteA, "?tenant_id=" + runClient1 + "/" + runSiteA,
			"?q=" + runClient1 + "/" + runSiteA + "/os:linux", "?q=hostname:" + runSiteA + "-host",
			"?hostname=" + runSiteA + "-host",
		} {
			rec := f.get(path+query, f.cred)
			assert.NotContains(t, rec.Body.String(), f.siteSteward, "%s%s -> %d", rt.template, query, rec.Code)
			assert.NotContains(t, rec.Body.String(), runSiteA+"-host", "%s%s -> %d", rt.template, query, rec.Code)
			if !strings.HasSuffix(rt.template, "/stewards") {
				// The list answers 200 with the run tenant's own devices; every
				// by-id route refuses the descendant outright.
				assert.NotEqual(t, http.StatusOK, rec.Code, "%s%s must not return the descendant device", rt.template, query)
			}
		}
	}

	// Targeting: a body that names the descendant tenant is refused before any handler.
	rec := f.do(http.MethodPost, fmt.Sprintf(runsEndPathFmt, runID), f.cred, map[string]string{"tenant_id": runSiteA})
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// [REQUIRED TEST] A grant cannot read a run, job or output started by a human, by
// another grant, or by another run of the same grant.
func TestAutomationReads_OnlyRunsThisRunStarted(t *testing.T) {
	f := newReadsFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	otherRunSameGrant := f.beginOK(t, f.cred, runClient1, "ticket-2")
	_, otherCred := f.newGrant(t, runMSP)
	otherGrantRun := f.beginOK(t, otherCred, runClient1, "ticket-3")

	f.startedRun(t, runID, "mine", runClient1, f.c1Steward)
	f.startedRun(t, otherRunSameGrant, "same-grant-other-run", runClient1, f.c1Steward)
	f.startedRun(t, otherGrantRun, "other-grant", runClient1, f.c1Steward)
	f.storeRun(t, "human", runClient1, f.c1Steward)

	for _, suffix := range []string{"", "/jobs"} {
		rec := f.get(f.runPath(runID, "/results/mine"+suffix), f.cred)
		assert.Equal(t, http.StatusOK, rec.Code, "mine"+suffix)
		for _, id := range []string{"human", "same-grant-other-run", "other-grant", "no-such-run"} {
			rec := f.get(f.runPath(runID, "/results/"+id+suffix), f.cred)
			assert.Equal(t, http.StatusNotFound, rec.Code, id+suffix)
			assert.Equal(t, "NOT_FOUND", codeOf(t, rec), id+suffix)
			assert.NotContains(t, rec.Body.String(), "output-of-", id+suffix)
		}
	}
	// The other grant reads its own run's result and not this grant's.
	assert.Equal(t, http.StatusOK, f.get(f.runPath(otherGrantRun, "/results/other-grant"), otherCred).Code)
	assert.Equal(t, http.StatusForbidden, f.get(f.runPath(runID, "/results/mine"), otherCred).Code)
	assert.Equal(t, http.StatusNotFound, f.get(f.runPath(otherGrantRun, "/results/mine"), otherCred).Code)

	// Ending the run closes the reads.
	require.Equal(t, http.StatusOK, f.do(http.MethodPost, fmt.Sprintf(runsEndPathFmt, runID), f.cred, nil).Code)
	assert.Equal(t, http.StatusForbidden, f.get(f.runPath(runID, "/results/mine"), f.cred).Code)
}

var secretFieldName = regexp.MustCompile(`(?i)token|secret|password|passwd|credential|api_?key|private|pem|certificate|passphrase`)

// jsonKeys returns every object key in a decoded JSON document.
func jsonKeys(v any, into *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			*into = append(*into, k)
			jsonKeys(child, into)
		}
	case []any:
		for _, child := range x {
			jsonKeys(child, into)
		}
	}
}

// [REQUIRED TEST] The response body of every route contains no credential or
// secret-bearing field.
func TestAutomationReads_NoSecretBearingFields(t *testing.T) {
	f := newReadsFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	f.startedRun(t, runID, "mine", runClient1, f.c1Steward)

	checked := 0
	for _, rt := range automationRouteTable() {
		if rt.method != http.MethodGet || !strings.HasPrefix(rt.template, readsPathPrefix) || rt.template == automationScriptsTemplate ||
			rt.template == automationExecutionsTemplate || rt.template == automationExecutionGetTemplate {
			continue // these need a library or a workflow engine; their own test files cover them
		}
		path := strings.NewReplacer("{run_id}", runID, "{id}", f.c1Steward, "{result_run_id}", "mine").Replace(rt.template)
		rec := f.get(path, f.cred)
		require.Equal(t, http.StatusOK, rec.Code, "%s: %s", rt.template, rec.Body.String())

		var doc any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
		var keys []string
		jsonKeys(doc, &keys)
		require.NotEmpty(t, keys)
		for _, k := range keys {
			assert.False(t, secretFieldName.MatchString(k), "%s returns secret-bearing field %q", rt.template, k)
		}
		body := rec.Body.String()
		assert.NotContains(t, body, readsSecretValue, rt.template)
		assert.NotContains(t, body, f.cred, rt.template)
		checked++
	}
	assert.Equal(t, len(automationReadTemplates), checked, "every read route was exercised")

	// The attribute lookup path of the DNA route refuses the credential-shaped key too.
	rec := f.get(f.runPath(runID, "/stewards/"+f.c1Steward+"/dna")+"?attribute=enrollment_token", f.cred)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), readsSecretValue)
}

// The wrapper's own failures: no run manager and no run store answer without a
// panic and without leaking.
func TestAutomationReads_UnavailableBackends(t *testing.T) {
	f := newReadsFixture(t)
	runID := f.beginOK(t, f.cred, runClient1, "ticket-1")
	f.startedRun(t, runID, "mine", runClient1, f.c1Steward)

	f.srv.runManager = nil
	for _, suffix := range []string{"", "/jobs"} {
		rec := f.get(f.runPath(runID, "/results/mine"+suffix), f.cred)
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code, suffix)
	}
}

func TestAutomationReads_HandlersRefuseWithoutARunBinding(t *testing.T) {
	f := newReadsFixture(t)
	for name, h := range map[string]http.HandlerFunc{
		"list":   f.srv.handleAutomationListStewards,
		"get":    f.srv.handleAutomationGetSteward,
		"dna":    f.srv.handleAutomationGetStewardDNA,
		"result": f.srv.handleAutomationGetResultRun,
		"jobs":   f.srv.handleAutomationGetResultRunJobs,
	} {
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req = mux.SetURLVars(req, map[string]string{"id": f.c1Steward, "result_run_id": "mine"})
		rec := httptest.NewRecorder()
		h(rec, req)
		assert.NotEqual(t, http.StatusOK, rec.Code, name)
		assert.NotContains(t, rec.Body.String(), f.c1Steward, name)
	}
}

func TestBufferedResponse(t *testing.T) {
	b := newBufferedResponse()
	assert.True(t, b.ok())
	b.Header().Set("Content-Type", "application/json")
	b.WriteHeader(http.StatusTeapot)
	b.WriteHeader(http.StatusOK) // the first status wins, as on a real writer
	_, err := b.Write([]byte(`{"data":[1]}`))
	require.NoError(t, err)
	assert.False(t, b.ok())

	var out []int
	require.NoError(t, b.data(&out))
	assert.Equal(t, []int{1}, out)

	rec := httptest.NewRecorder()
	b.replay(rec)
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	assert.Equal(t, `{"data":[1]}`, rec.Body.String())

	implicit := newBufferedResponse()
	_, _ = implicit.Write([]byte("x"))
	assert.True(t, implicit.ok())
	bad := newBufferedResponse()
	_, _ = bad.Write(bytes.NewBufferString("not json").Bytes())
	assert.Error(t, bad.data(&out))
}
