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

	"github.com/cfgis/cfgms/features/controller/fleet"
	controllerrun "github.com/cfgis/cfgms/features/controller/run"
	scriptmodule "github.com/cfgis/cfgms/features/modules/script"
	_ "modernc.org/sqlite"
)

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
func newTestRunQueue() *scriptmodule.ExecutionQueue {
	monitor := scriptmodule.NewExecutionMonitor()
	keyManager := scriptmodule.NewEphemeralKeyManager()
	return scriptmodule.NewExecutionQueue(monitor, keyManager, 0, "", nil, nil, 0)
}

// setupRunServer creates a test server wired with a run manager, execution queue,
// and a fleet query returning the given stewards.
func setupRunServer(t *testing.T, stewards []fleet.StewardResult) (*Server, *controllerrun.Manager, *scriptmodule.ExecutionQueue) {
	t.Helper()
	server := setupTestServer(t)

	manager := newTestRunManager(t)
	queue := newTestRunQueue()

	server.SetRunManager(manager, queue)
	server.fleetQuery = &staticRunFleetQuery{results: stewards}

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
