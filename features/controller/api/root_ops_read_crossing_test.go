// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/batchjob"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// opsReadFixture is a server holding one operational record of every kind in the
// root tenant and in a client tenant below an MSP.
type opsReadFixture struct {
	server  *Server
	msp     string
	records map[string]string // kind -> ID of the client tenant's record
	rootIDs map[string]string // kind -> ID of the root tenant's record
}

const (
	opsMSP        = "msp-ops"
	opsClient     = "client-ops"
	opsRootDevice = "ops-root-steward"
	opsCliDevice  = "ops-client-steward"
)

func setupOpsReadFixture(t *testing.T) *opsReadFixture {
	t.Helper()
	ctx := context.Background()
	server := wireCrossingStore(t, setupTestServer(t))
	_, err := server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: opsMSP, ParentID: testRootTenantID})
	require.NoError(t, err)
	_, err = server.tenantManager.CreateTenant(ctx, &tenant.TenantRequest{ID: opsClient, ParentID: opsMSP})
	require.NoError(t, err)
	require.NoError(t, server.controllerService.RegisterSteward(opsRootDevice, testRootTenantID, "localhost:7100", "online"))
	require.NoError(t, server.controllerService.RegisterSteward(opsCliDevice, opsClient, "localhost:7101", "online"))

	sm := pkgtesting.SetupTestStorage(t)
	commandStore := sm.GetCommandStore()
	require.NotNil(t, commandStore)
	server.SetCommandStore(commandStore)
	pushStore := sm.GetPushStore()
	require.NotNil(t, pushStore)
	server.pushStore = pushStore
	server.batchJobStore = newTestAPIBatchJobStore()
	server.upgradeStore = newTestUpgradeStore()
	server.rolloutStore = newTestRolloutStore()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	runStore := controllerrun.NewRunStoreSQL(db)
	require.NoError(t, runStore.Init(ctx))
	server.runManager = controllerrun.NewManager(runStore, nil)

	f := &opsReadFixture{server: server, msp: opsMSP, records: map[string]string{}, rootIDs: map[string]string{}}
	now := time.Now().UTC()
	for _, c := range []struct {
		kind, tenant string
		ids          map[string]string
	}{{"root", testRootTenantID, f.rootIDs}, {"client", opsClient, f.records}} {
		suffix := "-" + c.kind
		tn := c.tenant
		require.NoError(t, commandStore.CreateCommandRecord(ctx, &business.CommandRecord{
			ID: "cmd" + suffix, Type: "sync_config", StewardID: "s" + suffix, TenantID: tn, IssuedBy: "test"}))
		c.ids["command"] = "cmd" + suffix
		createPushRecord(t, pushStore, "push"+suffix, tn, "cfg"+suffix)
		c.ids["push"] = "push" + suffix
		require.NoError(t, server.batchJobStore.CreateBatchJob(ctx, &batchjob.BatchJob{
			ID: "job" + suffix, TenantID: tn, Status: batchjob.BatchJobStatusPending, CreatedAt: now, UpdatedAt: now}))
		c.ids["job"] = "job" + suffix
		require.NoError(t, server.upgradeStore.CreateUpgrade(ctx, &business.UpgradeRecord{
			ID: "upg" + suffix, StewardID: "s" + suffix, TenantID: tn, Version: "v1.0.0", Platform: "linux", Arch: "amd64",
			Status: business.UpgradeStatusCommitted, CreatedAt: now, OperationNonce: make([]byte, 32), BundleSignature: make([]byte, 64)}))
		c.ids["upgrade"] = "upg" + suffix
		require.NoError(t, server.rolloutStore.CreateRollout(ctx, &business.RolloutRecord{
			ID: "roll" + suffix, TenantID: tn, TargetVersion: "v1.0.0", Status: business.RolloutStatusCompleted, StartedAt: now}))
		c.ids["rollout"] = "roll" + suffix
		require.NoError(t, runStore.CreateRun(&controllerrun.RunRecord{
			RunID: "run" + suffix, TenantID: tn, CreatedAt: now, Status: controllerrun.RunStatusCompleted, JobCount: 1}))
		c.ids["run"] = "run" + suffix
	}
	// A root-owned run that fanned out to a root and a client steward.
	require.NoError(t, runStore.CreateRun(&controllerrun.RunRecord{
		RunID: "run-span", TenantID: testRootTenantID, CreatedAt: now, Status: controllerrun.RunStatusCompleted, JobCount: 2}))
	for _, dev := range []string{opsRootDevice, opsCliDevice} {
		require.NoError(t, runStore.CreateJob(&controllerrun.JobRecord{
			JobID: "span-job-" + dev, RunID: "run-span", DeviceID: dev, Status: controllerrun.JobStatusCompleted, CreatedAt: now}))
	}
	return f
}

// opsCaller shapes the request context for a caller.
type opsCaller func(req *http.Request, vars map[string]string) *http.Request

func rootOperatorCaller(p *Principal) opsCaller {
	return func(req *http.Request, vars map[string]string) *http.Request { return asRootOperator(req, p, vars) }
}

func mspAdminCaller() opsCaller {
	p := &Principal{ID: "msp-admin", Assurance: 3, TenantID: opsMSP}
	return func(req *http.Request, vars map[string]string) *http.Request {
		req = mux.SetURLVars(req, vars)
		ctx := context.WithValue(req.Context(), ctxkeys.TenantID, opsMSP)
		ctx = context.WithValue(ctx, principalContextKey, p)
		ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, ctxkeys.NewTenantScope(opsMSP))
		return req.WithContext(ctx)
	}
}

func certAdminCaller() opsCaller {
	p := &Principal{ID: "cert-admin", Assurance: 1, GlobalScope: true, CertSerial: "01"}
	return rootOperatorCaller(p)
}

func (f *opsReadFixture) byIDCalls() []struct {
	name, kind string
	call       func(w http.ResponseWriter, r *http.Request)
	varName    string
} {
	s := f.server
	return []struct {
		name, kind string
		call       func(w http.ResponseWriter, r *http.Request)
		varName    string
	}{
		{"GET /commands/{id}", "command", s.handleGetCommandRecord, "id"},
		{"GET /config/push/{id}", "push", s.handleGetConfigPush, "id"},
		{"GET /jobs/{id}", "job", s.handleGetJob, "id"},
		{"GET /runs/{run_id}", "run", s.handleGetRun, "run_id"},
		{"GET /runs/{run_id}/jobs", "run", s.handleGetRunJobs, "run_id"},
		{"GET /rollout/{rollout_id}", "rollout", s.handleGetRollout, "rollout_id"},
		{"GET /stewards/upgrade/{upgrade_id}", "upgrade", s.handleUpgradeStatus, "upgrade_id"},
	}
}

func listIDs(t *testing.T, rec *httptest.ResponseRecorder, key string) []string {
	t.Helper()
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Data []map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	ids := make([]string, 0, len(body.Data))
	for _, row := range body.Data {
		id, _ := row[key].(string)
		ids = append(ids, id)
	}
	return ids
}

// TestRootOpsReads_ByIDCrossingBoundary: a boundary-subject root session is
// challenged for a client tenant's record, reads root's own, and succeeds under a
// crossing; MSP admins and certificate admins are unchanged; not-found stays 404.
func TestRootOpsReads_ByIDCrossingBoundary(t *testing.T) {
	f := setupOpsReadFixture(t)
	for _, rt := range f.byIDCalls() {
		t.Run(rt.name, func(t *testing.T) {
			do := func(caller opsCaller, id string) *httptest.ResponseRecorder {
				rec := httptest.NewRecorder()
				rt.call(rec, caller(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{rt.varName: id}))
				return rec
			}
			clientID, rootID := f.records[rt.kind], f.rootIDs[rt.kind]

			noCross := boundRootOperator("ops-no-" + rt.name)
			assertCrossingChallenge(t, do(rootOperatorCaller(noCross), clientID), opsClient)
			assert.Equal(t, http.StatusOK, do(rootOperatorCaller(noCross), rootID).Code, "root's own record stays readable")
			assert.Equal(t, http.StatusNotFound, do(rootOperatorCaller(noCross), "no-such-record").Code, "not-found stays 404")

			crossed := boundRootOperator("ops-yes-" + rt.name)
			grantCrossing(t, f.server, crossed.ID, opsMSP)
			assert.Equal(t, http.StatusOK, do(rootOperatorCaller(crossed), clientID).Code)

			assert.Equal(t, http.StatusOK, do(mspAdminCaller(), clientID).Code, "tenant-scoped MSP admin unchanged")
			assert.Equal(t, http.StatusNotFound, do(mspAdminCaller(), rootID).Code, "MSP admin still cannot read root's record")
			assert.Equal(t, http.StatusOK, do(certAdminCaller(), clientID).Code, "unrestricted certificate admin unchanged")
		})
	}
}

// TestRootOpsReads_ListsCrossingBoundary: GET /jobs and GET /runs return root's
// own records until a crossing covers the owning MSP.
func TestRootOpsReads_ListsCrossingBoundary(t *testing.T) {
	f := setupOpsReadFixture(t)
	lists := []struct {
		name    string
		call    func(w http.ResponseWriter, r *http.Request)
		key     string
		rootIDs []string
		client  string
	}{
		{"GET /jobs", f.server.handleListJobs, "ID", []string{"job-root"}, "job-client"},
		{"GET /runs", f.server.handleListRuns, "run_id", []string{"run-root", "run-span"}, "run-client"},
	}
	for _, l := range lists {
		t.Run(l.name, func(t *testing.T) {
			list := func(caller opsCaller, query string) []string {
				rec := httptest.NewRecorder()
				l.call(rec, caller(httptest.NewRequest(http.MethodGet, "/x"+query, nil), nil))
				return listIDs(t, rec, l.key)
			}
			op := boundRootOperator("ops-list-" + l.key)
			assert.ElementsMatch(t, l.rootIDs, list(rootOperatorCaller(op), ""))

			grantCrossing(t, f.server, op.ID, opsMSP)
			assert.ElementsMatch(t, append([]string{l.client}, l.rootIDs...), list(rootOperatorCaller(op), ""))

			// Pagination counts only readable rows.
			other := boundRootOperator("ops-page-" + l.key)
			assert.Len(t, list(rootOperatorCaller(other), "?limit=1"), 1)
			assert.Len(t, list(rootOperatorCaller(other), "?offset=100"), 0)

			assert.Contains(t, list(certAdminCaller(), ""), l.client, "certificate admin keeps root breadth")
			for _, id := range l.rootIDs {
				assert.NotContains(t, list(mspAdminCaller(), ""), id, "tenant-scoped MSP admin never sees root's records")
			}
		})
	}
}

// TestRootOpsReads_RunJobsOmitsOtherTenantRows: a run that fanned out to a client
// tenant lists that tenant's per-target rows only under a crossing.
func TestRootOpsReads_RunJobsOmitsOtherTenantRows(t *testing.T) {
	f := setupOpsReadFixture(t)
	devices := func(caller opsCaller) []string {
		rec := httptest.NewRecorder()
		f.server.handleGetRunJobs(rec, caller(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"run_id": "run-span"}))
		return listIDs(t, rec, "device_id")
	}
	op := boundRootOperator("ops-span")
	assert.Equal(t, []string{opsRootDevice}, devices(rootOperatorCaller(op)))

	grantCrossing(t, f.server, op.ID, opsMSP)
	assert.ElementsMatch(t, []string{opsRootDevice, opsCliDevice}, devices(rootOperatorCaller(op)))

	assert.ElementsMatch(t, []string{opsRootDevice, opsCliDevice}, devices(certAdminCaller()), "certificate admin sees every row")
}

// TestRootOpsReads_PendingDeliveriesCrossingBoundary: the pending-deliveries list
// of a client tenant's steward needs a crossing for a boundary-subject root caller.
func TestRootOpsReads_PendingDeliveriesCrossingBoundary(t *testing.T) {
	f := setupOpsReadFixture(t)
	require.NoError(t, f.server.commandStore.CreateCommandRecord(context.Background(), &business.CommandRecord{
		ID: "cmd-pending", Type: "sync_config", StewardID: opsCliDevice, TenantID: opsClient, IssuedBy: "test"}))
	do := func(caller opsCaller) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		f.server.handleListPendingDeliveries(rec, caller(httptest.NewRequest(http.MethodGet, "/x", nil), map[string]string{"id": opsCliDevice}))
		return rec
	}
	op := boundRootOperator("ops-pending")
	assertCrossingChallenge(t, do(rootOperatorCaller(op)), opsClient)
	grantCrossing(t, f.server, op.ID, opsMSP)
	assert.Equal(t, http.StatusOK, do(rootOperatorCaller(op)).Code)
	assert.Equal(t, http.StatusOK, do(certAdminCaller()).Code)
}
