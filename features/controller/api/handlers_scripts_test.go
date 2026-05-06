// SPDX-License-Identifier: Apache-2.0
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/script"
)

// newTestScriptTracker opens an in-memory SQLite database and returns a ready
// ExecutionTrackingStore. The database is closed automatically via t.Cleanup.
func newTestScriptTracker(t *testing.T) *script.ExecutionTrackingStore {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err, "open in-memory sqlite")
	t.Cleanup(func() { _ = db.Close() })

	store := script.NewExecutionTrackingStore(db)
	require.NoError(t, store.Init(context.Background()), "tracker Init must succeed")
	return store
}

// seedExecution writes a completed execution record to the tracker.
func seedExecution(t *testing.T, tracker *script.ExecutionTrackingStore, executionID, deviceID, scriptRef, state string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rec := &script.ExecutionRecord{
		ExecutionID:  executionID,
		DeviceID:     deviceID,
		ScriptRef:    scriptRef,
		Shell:        "bash",
		ExitCode:     0,
		State:        state,
		DurationMs:   1500,
		QueuedAt:     now.Add(-10 * time.Second),
		DispatchedAt: now.Add(-5 * time.Second),
		CompletedAt:  now,
	}
	require.NoError(t, tracker.Record(context.Background(), rec))
}

// setupScriptServer creates a test server with a real script tracker, audit logger,
// and execution monitor wired in.
func setupScriptServer(t *testing.T) (*Server, *script.ExecutionTrackingStore) {
	t.Helper()
	server := setupTestServer(t)
	tracker := newTestScriptTracker(t)
	auditLogger := script.NewAuditLogger(1000)
	monitor := script.NewExecutionMonitor()
	server.SetScriptModule(tracker, auditLogger, monitor)
	return server, tracker
}

// TestHandleListScriptExecutions_Real verifies that the list handler returns actual
// records from the tracker, not hardcoded stub data.
func TestHandleListScriptExecutions_Real(t *testing.T) {
	server, tracker := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	seedExecution(t, tracker, "exec-001", "steward-abc", "scripts/backup.sh", "completed")
	seedExecution(t, tracker, "exec-002", "steward-abc", "scripts/health.sh", "completed")
	seedExecution(t, tracker, "exec-003", "steward-xyz", "scripts/other.sh", "completed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-abc/scripts/executions", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	items, ok := resp.Data.([]interface{})
	require.True(t, ok, "expected array in response data")
	assert.Len(t, items, 2, "should return only the two records for steward-abc")

	// Verify the returned records are the real ones and not the old hardcoded stub.
	ids := make([]string, 0, len(items))
	for _, item := range items {
		m := item.(map[string]interface{})
		ids = append(ids, m["id"].(string))
		// Confirm steward_id matches the queried steward.
		assert.Equal(t, "steward-abc", m["steward_id"].(string))
		// The old stub always used "example-exec-1" as the ID.
		assert.NotEqual(t, "example-exec-1", m["id"].(string))
	}
	assert.Contains(t, ids, "exec-001")
	assert.Contains(t, ids, "exec-002")
}

// TestHandleListScriptExecutions_Pagination verifies limit and offset work correctly.
func TestHandleListScriptExecutions_Pagination(t *testing.T) {
	server, tracker := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	for i := 0; i < 5; i++ {
		seedExecution(t, tracker, "exec-pag-00"+string(rune('0'+i)), "steward-pag", "scripts/s.sh", "completed")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-pag/scripts/executions?limit=2&offset=1", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	items, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 2, "limit=2 should return exactly 2 records after skipping offset=1")
}

// TestHandleListScriptExecutions_StatusFilter verifies the status query parameter is applied.
func TestHandleListScriptExecutions_StatusFilter(t *testing.T) {
	server, tracker := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	seedExecution(t, tracker, "exec-done", "steward-flt", "scripts/s.sh", "completed")
	seedExecution(t, tracker, "exec-fail", "steward-flt", "scripts/f.sh", "failed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-flt/scripts/executions?status=failed", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	items, ok := resp.Data.([]interface{})
	require.True(t, ok)
	assert.Len(t, items, 1)
	assert.Equal(t, "exec-fail", items[0].(map[string]interface{})["id"])
}

// TestHandleListScriptExecutions_ServiceUnavailable verifies 503 when no tracker is wired.
func TestHandleListScriptExecutions_ServiceUnavailable(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-1/scripts/executions", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleGetScriptExecution_Found verifies the single-execution handler returns the
// correct record when the execution ID exists.
func TestHandleGetScriptExecution_Found(t *testing.T) {
	server, tracker := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	seedExecution(t, tracker, "exec-target", "steward-1", "scripts/deploy.sh", "completed")
	seedExecution(t, tracker, "exec-other", "steward-1", "scripts/other.sh", "failed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-1/scripts/executions/exec-target", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	item, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "exec-target", item["id"])
	assert.Equal(t, "steward-1", item["steward_id"])
	assert.Equal(t, "scripts/deploy.sh", item["resource_id"])
}

// TestHandleGetScriptExecution_NotFound verifies 404 for a non-existent execution ID.
func TestHandleGetScriptExecution_NotFound(t *testing.T) {
	server, tracker := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	seedExecution(t, tracker, "exec-exists", "steward-1", "scripts/s.sh", "completed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-1/scripts/executions/does-not-exist", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleGetScriptExecution_ServiceUnavailable verifies 503 when no tracker is wired.
func TestHandleGetScriptExecution_ServiceUnavailable(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-1/scripts/executions/exec-1", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleGetScriptMetrics_Real verifies the metrics handler returns aggregated data
// from the real AuditLogger, not hardcoded stubs.
func TestHandleGetScriptMetrics_Real(t *testing.T) {
	server, _ := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	// Seed audit logger with known records so we can assert non-stub output.
	cfg := &script.ScriptConfig{
		Shell:         script.ShellBash,
		Content:       "echo hello",
		Timeout:       30 * time.Second,
		SigningPolicy: script.SigningPolicyNone,
	}
	result := &script.ExecutionResult{
		ExitCode:  0,
		Stdout:    "hello",
		Duration:  500 * time.Millisecond,
		StartTime: time.Now().Add(-1 * time.Second),
		EndTime:   time.Now(),
	}
	rec := script.CreateAuditRecord("steward-metrics", "scripts/test.sh", cfg, result, nil)
	require.NoError(t, server.scriptAuditLogger.LogExecution(context.Background(), rec))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-metrics/scripts/metrics", nil)
	req.Header.Set("X-API-Key", apiKey)
	rw := httptest.NewRecorder()
	server.router.ServeHTTP(rw, req)

	require.Equal(t, http.StatusOK, rw.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &resp))

	m, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "steward-metrics", m["steward_id"])

	// Old stub always returned total_executions=42; a real result with 1 record returns 1.
	totalRaw, ok := m["total_executions"]
	require.True(t, ok)
	total := int(totalRaw.(float64))
	assert.Equal(t, 1, total, "should reflect the single seeded record, not the old stub value of 42")
}

// TestHandleGetScriptMetrics_ServiceUnavailable verifies 503 when no audit logger is wired.
func TestHandleGetScriptMetrics_ServiceUnavailable(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-1/scripts/metrics", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleGetScriptStatus_Real verifies the status handler uses real tracker data.
func TestHandleGetScriptStatus_Real(t *testing.T) {
	server, tracker := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	seedExecution(t, tracker, "exec-last", "steward-status", "scripts/health.sh", "completed")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-status/scripts/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	m, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "steward-status", m["steward_id"])
	assert.Equal(t, "enabled", m["script_capability"])

	// last_execution must reflect the real seeded record.
	lastRaw, ok := m["last_execution"]
	require.True(t, ok, "last_execution must be present")
	last, ok := lastRaw.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "exec-last", last["execution_id"])
	assert.Equal(t, "scripts/health.sh", last["resource_id"])
}

// TestHandleGetScriptStatus_NoRecords verifies the status handler returns nil last_execution
// when the tracker has no records for the steward.
func TestHandleGetScriptStatus_NoRecords(t *testing.T) {
	server, _ := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-empty/scripts/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	m, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Nil(t, m["last_execution"], "last_execution should be nil when no records exist")
}

// TestHandleGetScriptStatus_ServiceUnavailable verifies 503 when no tracker is wired.
func TestHandleGetScriptStatus_ServiceUnavailable(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:read-scripts"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards/steward-1/scripts/status", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandlePostScriptRetry_NotImplemented verifies that the retry handler returns 501.
func TestHandlePostScriptRetry_NotImplemented(t *testing.T) {
	server, _ := setupScriptServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:execute-scripts"})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/stewards/steward-1/scripts/executions/exec-1/retry", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotImplemented, rec.Code)

	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "NOT_IMPLEMENTED", errResp.Error.Code)
}
