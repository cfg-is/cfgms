// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/ctxkeys"
	stewardconfig "github.com/cfgis/cfgms/features/steward/config"
	"github.com/cfgis/cfgms/features/steward/discovery"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Auto-register git storage provider
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// newTestWorkflowHandler creates a WorkflowHandler backed by real git storage and a real engine.
func newTestWorkflowHandler(t *testing.T) (*WorkflowHandler, interfaces.ConfigStore) {
	t.Helper()

	storageConfig := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", storageConfig)
	require.NoError(t, err)
	configStore := storageManager.GetConfigStore()

	registry := make(discovery.ModuleRegistry)
	errorConfig := stewardconfig.ErrorHandlingConfig{
		ModuleLoadFailure: stewardconfig.ActionContinue,
	}
	moduleFactory := factory.New(registry, errorConfig)
	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(moduleFactory, logger)

	handler := NewWorkflowHandler(engine, configStore, nil, logger)
	return handler, configStore
}

// withTenantContext injects a tenant ID into the request context, as the auth middleware does.
func withTenantContext(r *http.Request, tenantID string) *http.Request {
	ctx := context.WithValue(r.Context(), ctxkeys.TenantID, tenantID)
	return r.WithContext(ctx)
}

// newWorkflowRouter wires a WorkflowHandler onto a fresh mux.Router.
func newWorkflowRouter(h *WorkflowHandler) *mux.Router {
	router := mux.NewRouter()
	sub := router.PathPrefix("/workflows").Subrouter()
	h.RegisterWorkflowRoutes(sub)
	return router
}

// minimalWorkflowBody returns a valid JSON create-workflow request body.
func minimalWorkflowBody(name string) []byte {
	return mustMarshal(CreateWorkflowRequest{
		Name: name,
		Steps: []workflow.Step{
			{Name: "step1", Type: workflow.StepTypeTask},
		},
	})
}

// mustMarshal marshals v to JSON and panics on error (test helper only).
func mustMarshal(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("mustMarshal: " + err.Error())
	}
	return b
}

// --- handler nil-check tests -------------------------------------------------

func TestWorkflowHandler_NilEngine_ReturnsServiceUnavailable(t *testing.T) {
	logger := logging.NewNoopLogger()
	// Handler with nil engine and nil configStore
	h := NewWorkflowHandler(nil, nil, nil, logger)
	router := newWorkflowRouter(h)

	tests := []struct {
		method string
		path   string
		body   []byte
	}{
		{"GET", "/workflows", nil},
		{"POST", "/workflows", minimalWorkflowBody("wf")},
		{"GET", "/workflows/wf", nil},
		{"PUT", "/workflows/wf", minimalWorkflowBody("wf")},
		{"DELETE", "/workflows/wf", nil},
		{"POST", "/workflows/wf/execute", nil},
	}
	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			var bodyReader *bytes.Reader
			if tc.body != nil {
				bodyReader = bytes.NewReader(tc.body)
			} else {
				bodyReader = bytes.NewReader(nil)
			}
			req := httptest.NewRequest(tc.method, tc.path, bodyReader)
			req = withTenantContext(req, "test-tenant")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusServiceUnavailable, rec.Code, "expected 503 for path %s", tc.path)
		})
	}
}

// --- list workflows ----------------------------------------------------------

func TestWorkflowHandler_ListWorkflows_EmptyReturnsEmpty(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("GET", "/workflows", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.EqualValues(t, 0, resp["count"])
}

// --- create workflow ---------------------------------------------------------

func TestWorkflowHandler_CreateWorkflow_InvalidJSON_Returns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("POST", "/workflows", bytes.NewBufferString("not-json"))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWorkflowHandler_CreateWorkflow_MissingName_Returns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	body := mustMarshal(CreateWorkflowRequest{
		Steps: []workflow.Step{{Name: "s1", Type: workflow.StepTypeTask}},
	})
	req := httptest.NewRequest("POST", "/workflows", bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWorkflowHandler_CreateWorkflow_NoSteps_Returns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	body := mustMarshal(CreateWorkflowRequest{Name: "wf"})
	req := httptest.NewRequest("POST", "/workflows", bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWorkflowHandler_CreateWorkflow_InvalidVersion_Returns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	body := mustMarshal(CreateWorkflowRequest{
		Name:    "wf",
		Version: "not-semver",
		Steps:   []workflow.Step{{Name: "s1", Type: workflow.StepTypeTask}},
	})
	req := httptest.NewRequest("POST", "/workflows", bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWorkflowHandler_CreateWorkflow_ValidRequest_Returns201(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("my-workflow")))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)
	var vw workflow.VersionedWorkflow
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &vw))
	assert.Equal(t, "my-workflow", vw.Name)
	assert.Equal(t, "1.0.0", vw.Version)
}

// --- get workflow ------------------------------------------------------------

func TestWorkflowHandler_GetWorkflow_NotFound_Returns404(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("GET", "/workflows/nonexistent", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWorkflowHandler_GetWorkflow_ExistingWorkflow_Returns200(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create first
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("get-test")))
	createReq = withTenantContext(createReq, "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Then get
	req := httptest.NewRequest("GET", "/workflows/get-test", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var vw workflow.VersionedWorkflow
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &vw))
	assert.Equal(t, "get-test", vw.Name)
}

// --- update workflow ---------------------------------------------------------

func TestWorkflowHandler_UpdateWorkflow_NoSteps_Returns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	body := mustMarshal(CreateWorkflowRequest{Name: "wf"})
	req := httptest.NewRequest("PUT", "/workflows/wf", bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestWorkflowHandler_UpdateWorkflow_ValidRequest_Returns200(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create first
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("upd-wf")))
	createReq = withTenantContext(createReq, "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Update with new version
	body := mustMarshal(CreateWorkflowRequest{
		Name:    "upd-wf",
		Version: "2.0.0",
		Steps:   []workflow.Step{{Name: "step2", Type: workflow.StepTypeTask}},
	})
	req := httptest.NewRequest("PUT", "/workflows/upd-wf", bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var vw workflow.VersionedWorkflow
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &vw))
	assert.Equal(t, "2.0.0", vw.Version)
}

// --- delete workflow ---------------------------------------------------------

func TestWorkflowHandler_DeleteWorkflow_NotFound_Returns404(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("DELETE", "/workflows/nosuchworkflow", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWorkflowHandler_DeleteWorkflow_ExistingWorkflow_Returns200(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create first
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("del-wf")))
	createReq = withTenantContext(createReq, "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Delete
	req := httptest.NewRequest("DELETE", "/workflows/del-wf", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "del-wf", resp["deleted"])

	// Subsequent GET should 404
	getReq := httptest.NewRequest("GET", "/workflows/del-wf", nil)
	getReq = withTenantContext(getReq, "test-tenant")
	getRec := httptest.NewRecorder()
	router.ServeHTTP(getRec, getReq)
	assert.Equal(t, http.StatusNotFound, getRec.Code)
}

// --- list after create -------------------------------------------------------

func TestWorkflowHandler_ListWorkflows_AfterCreate_ReturnsWorkflow(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create a workflow
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("list-wf")))
	createReq = withTenantContext(createReq, "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// List
	req := httptest.NewRequest("GET", "/workflows", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.EqualValues(t, 1, resp["count"])
}

// --- execute workflow --------------------------------------------------------

func TestWorkflowHandler_ExecuteWorkflow_WorkflowNotFound_Returns404(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("POST", "/workflows/nosuchworkflow/execute", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWorkflowHandler_ExecuteWorkflow_ExistingWorkflow_Returns202WithFields(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create the workflow first
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("exec-wf")))
	createReq = withTenantContext(createReq, "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Execute the workflow
	req := httptest.NewRequest("POST", "/workflows/exec-wf/execute", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp["execution_id"], "execution_id must be non-empty")
	assert.Equal(t, "exec-wf", resp["workflow_name"])
	assert.NotEmpty(t, resp["status"], "status must be non-empty")
	assert.Contains(t, resp, "start_time")
}

// --- executions --------------------------------------------------------------

func TestWorkflowHandler_GetWorkflowExecutions_NoEngine_Returns503(t *testing.T) {
	logger := logging.NewNoopLogger()
	h := NewWorkflowHandler(nil, nil, nil, logger)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("GET", "/workflows/wf/executions", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestWorkflowHandler_GetWorkflowExecutions_EmptyResult_Returns200(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("GET", "/workflows/nonexistent/executions", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.EqualValues(t, 0, resp["count"])
}

// --- trigger routes ----------------------------------------------------------

func TestWorkflowHandler_RegisterTriggerRoutes_NilManager_NoRegistration(t *testing.T) {
	logger := logging.NewNoopLogger()
	h := NewWorkflowHandler(nil, nil, nil, logger)

	router := mux.NewRouter()
	sub := router.PathPrefix("/triggers").Subrouter()
	// Should not panic when trigger manager is nil
	assert.NotPanics(t, func() {
		h.RegisterTriggerRoutes(sub)
	})
}

// --- log injection safety ----------------------------------------------------

// TestWorkflowHandler_SpecialCharsInName_HandledSafely verifies that workflow names
// containing characters that would be dangerous in log entries are handled safely.
// The code sanitizes user-provided values via logging.SanitizeLogValue before logging.
func TestWorkflowHandler_SpecialCharsInName_HandledSafely(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// URL-safe name that includes tab and other control characters
	// (newlines cannot appear in HTTP request-URIs; they are rejected by Go's HTTP library)
	req := httptest.NewRequest("GET", "/workflows/wf%09injected", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Handler must not return 5xx — the workflow simply won't be found
	assert.True(t, rec.Code < 500, "handler must not return 5xx for special-char workflow name, got %d", rec.Code)
}
