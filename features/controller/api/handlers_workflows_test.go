// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTestWorkflowHandler creates a WorkflowHandler backed by real git storage and a real engine.
func newTestWorkflowHandler(t *testing.T) (*WorkflowHandler, cfgconfig.ConfigStore) {
	t.Helper()

	storageManager := pkgtesting.SetupTestStorage(t)
	configStore := storageManager.GetConfigStore()

	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logger, nil, nil, nil, nil, nil)

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
		{"GET", "/workflows/wf/executions/exec_1_1", nil},
		{"POST", "/workflows/wf/executions/exec_1_1/cancel", nil},
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

// TestTriggerRouteRegistration verifies that all 10 documented trigger paths are
// registered (non-404 from mux) when the workflow handler is wired with a real trigger
// manager. This guards against the double-prefix bug where /triggers/triggers/... was
// registered instead of /triggers/...
//
// Route-registration is verified via router.Match rather than a live ServeHTTP call
// because several routes correctly return HTTP 404 for non-existent resource IDs — that
// is handler-level 404, not mux-level 404.  router.Match returns false only when no
// route matches, which is the exact condition the double-prefix bug would trigger.
func TestTriggerRouteRegistration(t *testing.T) {
	logger := logging.NewNoopLogger()
	mgr := trigger.NewControllerTriggerManager(nil, nil)
	h := NewWorkflowHandler(nil, nil, mgr, logger)

	router := mux.NewRouter()
	sub := router.PathPrefix("/triggers").Subrouter()
	h.RegisterTriggerRoutes(sub)

	paths := []struct {
		method string
		path   string
	}{
		{"GET", "/triggers/health"},
		{"POST", "/triggers"},
		{"GET", "/triggers"},
		{"GET", "/triggers/test-id"},
		{"PUT", "/triggers/test-id"},
		{"DELETE", "/triggers/test-id"},
		{"POST", "/triggers/test-id/enable"},
		{"POST", "/triggers/test-id/disable"},
		{"POST", "/triggers/test-id/execute"},
		{"GET", "/triggers/test-id/executions"},
	}

	for _, tc := range paths {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			var match mux.RouteMatch
			assert.True(t, router.Match(req, &match),
				"route %s %s must be registered (no match — likely double-prefix bug)", tc.method, tc.path)
		})
	}
}

// --- log injection safety ----------------------------------------------------

// capturingLogger records Error calls so tests can assert that user-supplied values
// are sanitised before they reach the logger (CWE-117 / go/log-injection).
type capturingLogger struct {
	logging.NoopLogger
	mu      sync.Mutex
	entries []struct {
		msg string
		kvs []interface{}
	}
}

func (l *capturingLogger) Error(msg string, kvs ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = append(l.entries, struct {
		msg string
		kvs []interface{}
	}{msg: msg, kvs: kvs})
}

// loggedNameValues returns all "name" key values captured across Error calls.
func (l *capturingLogger) loggedNameValues() []string {
	return l.loggedValuesForKey("name")
}

// loggedValuesForKey returns all string values for key across all captured Error calls.
func (l *capturingLogger) loggedValuesForKey(key string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var vals []string
	for _, e := range l.entries {
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == key {
				if v, ok := e.kvs[i+1].(string); ok {
					vals = append(vals, v)
				}
			}
		}
	}
	return vals
}

// --- fleet query wiring (Issue #609) -----------------------------------------

// staticStewardProvider is a minimal fleet.StewardProvider for wiring tests.
type staticStewardProvider struct{}

func (p *staticStewardProvider) GetAllStewards() []fleet.StewardData { return nil }

// TestWorkflowHandler_SetFleetQuery verifies that SetFleetQuery stores the fleet
// query implementation on WorkflowHandler so it is available for script dispatch targeting.
func TestWorkflowHandler_SetFleetQuery(t *testing.T) {
	logger := logging.NewNoopLogger()
	h := NewWorkflowHandler(nil, nil, nil, logger)
	assert.Nil(t, h.fleetQuery, "fleetQuery must be nil before SetFleetQuery")

	q := fleet.NewMemoryQuery(&staticStewardProvider{})
	h.SetFleetQuery(q)
	assert.Equal(t, q, h.fleetQuery, "SetFleetQuery must assign the query to the handler field")
}

// TestWorkflowHandler_SpecialCharsInName_HandledSafely verifies that workflow names
// containing CWE-117 log-injection characters (LF, CR) are stripped before they reach
// the logger. The test uses a GET for a nonexistent workflow, which always exercises the
// error path in handleGetWorkflow and guarantees logger.Error is called — making the
// sanitisation assertion unconditional, not vacuous.
//
// URL path parameters may carry encoded control characters: gorilla/mux decodes %0a → \n
// and %0d → \r when extracting path variables, so injecting them is realistic.
func TestWorkflowHandler_SpecialCharsInName_HandledSafely(t *testing.T) {
	_, configStore := newTestWorkflowHandler(t)
	capLogger := &capturingLogger{}

	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), capLogger, nil, nil, nil, nil, nil)
	h := NewWorkflowHandler(engine, configStore, nil, capLogger)
	router := newWorkflowRouter(h)

	// %0a = LF (\n), %0d = CR (\r) — gorilla/mux decodes these from the URL path.
	// The workflow does not exist, so handleGetWorkflow always calls logger.Error,
	// ensuring the sanitisation assertion below is never vacuous.
	req := httptest.NewRequest("GET", "/workflows/wf%0ainjected%0dfake-log-line", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	// Handler returns 404 (not 5xx) — the special-char name doesn't cause a crash.
	assert.Equal(t, http.StatusNotFound, rec.Code, "nonexistent workflow must return 404")

	// logger.Error must have been called with the sanitised name — exactly once because
	// the workflow is not found and GetLatestWorkflow returns an error.
	names := capLogger.loggedNameValues()
	require.NotEmpty(t, names, "logger.Error must have been called with a 'name' key")
	for _, name := range names {
		assert.NotContains(t, name, "\n", "logger must not receive raw LF in workflow name")
		assert.NotContains(t, name, "\r", "logger must not receive raw CR in workflow name")
	}
}

// newTestWorkflowHandlerAndEngine creates a WorkflowHandler and returns the engine separately
// so tests that need to inspect or wait on execution state can do so directly.
func newTestWorkflowHandlerAndEngine(t *testing.T) (*WorkflowHandler, cfgconfig.ConfigStore, *workflow.Engine) {
	t.Helper()
	storageManager := pkgtesting.SetupTestStorage(t)
	configStore := storageManager.GetConfigStore()
	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logger, nil, nil, nil, nil, nil)
	handler := NewWorkflowHandler(engine, configStore, nil, logger)
	return handler, configStore, engine
}

// createAndExecuteWorkflow is a test helper that creates a workflow then executes it,
// returning the execution ID. Uses the provided router and tenant ID.
//
// For long-running (delay-step) workflows the async execution goroutine would
// otherwise remain parked in the engine's delay step for the full delay duration
// after the test returns, because the httptest request context is never cancelled.
// A t.Cleanup cancels the execution so its goroutine unwinds promptly at test end
// instead of leaking (which previously showed up as goroutines stuck in
// executeDelayStep and added scheduler pressure to the rest of the package).
func createAndExecuteWorkflow(t *testing.T, router *mux.Router, eng *workflow.Engine, wfName, tenantID string, longRunning bool) string {
	t.Helper()

	// Create workflow
	var body []byte
	if longRunning {
		// Delay step keeps execution alive long enough for the cancel test.
		body = mustMarshal(CreateWorkflowRequest{
			Name: wfName,
			Steps: []workflow.Step{
				{
					Name:  "long-wait",
					Type:  workflow.StepTypeDelay,
					Delay: &workflow.DelayConfig{Duration: 30 * time.Second},
				},
			},
		})
	} else {
		// Task step with no module fails immediately → execution reaches terminal state.
		body = minimalWorkflowBody(wfName)
	}

	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(body))
	createReq = withTenantContext(createReq, tenantID)
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code, "workflow create must succeed")

	// Execute workflow
	execReq := httptest.NewRequest("POST", "/workflows/"+wfName+"/execute", bytes.NewReader([]byte("{}")))
	execReq = withTenantContext(execReq, tenantID)
	execRec := httptest.NewRecorder()
	router.ServeHTTP(execRec, execReq)
	require.Equal(t, http.StatusAccepted, execRec.Code, "workflow execute must succeed")

	var execResp map[string]interface{}
	require.NoError(t, json.Unmarshal(execRec.Body.Bytes(), &execResp))
	execID, ok := execResp["execution_id"].(string)
	require.True(t, ok && execID != "", "execution_id must be non-empty")

	// Ensure the async execution goroutine is torn down when the test ends so a
	// long delay step cannot outlive the test. Cancelling an already-terminal
	// execution is a no-op.
	if eng != nil {
		t.Cleanup(func() { _ = eng.CancelExecution(execID) })
	}
	return execID
}

// --- cancel execution ---------------------------------------------------------

func TestWorkflowHandler_CancelExecution_UnknownExecID_Returns404(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("POST", "/workflows/my-wf/executions/exec_9999_0/cancel", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "not found")
}

func TestWorkflowHandler_CancelExecution_RunningExecution_Returns200(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	// Use a long-running delay step so the execution stays non-terminal.
	execID := createAndExecuteWorkflow(t, router, engine, "long-wf", "test-tenant", true)

	req := httptest.NewRequest("POST", "/workflows/long-wf/executions/"+execID+"/cancel", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, execID, resp["cancelled"])
}

// waitForTerminalState blocks until the execution reaches a terminal state or fails the test
// after 5 seconds. Uses a ticker so the goroutine scheduler drives the check, not a sleep.
func waitForTerminalState(t *testing.T, eng *workflow.Engine, execID string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-ticker.C:
			ex, err := eng.GetExecution(execID)
			if err == nil && ex != nil {
				s := ex.GetStatus()
				if s == workflow.StatusCompleted || s == workflow.StatusFailed || s == workflow.StatusCancelled {
					return
				}
			}
		case <-timeout.C:
			t.Fatalf("execution %s did not reach a terminal state within 5 seconds", execID)
		}
	}
}

func TestWorkflowHandler_CancelExecution_TerminalExecution_Returns409(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	// Task step with no module name fails immediately → terminal state reached quickly.
	execID := createAndExecuteWorkflow(t, router, engine, "quick-wf", "test-tenant", false)
	waitForTerminalState(t, engine, execID)

	req := httptest.NewRequest("POST", "/workflows/quick-wf/executions/"+execID+"/cancel", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusConflict, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Contains(t, resp["error"], "terminal")
}

func TestWorkflowHandler_CancelExecution_CrossTenant_Returns403(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	// Create and execute the workflow in tenant A with a long delay so it stays non-terminal.
	execID := createAndExecuteWorkflow(t, router, engine, "xsec-cancel-wf", "tenant-a", true)

	// Tenant B tries to cancel tenant A's execution. tenant-b has no workflow
	// named "xsec-cancel-wf" in its config namespace → 403.
	req := httptest.NewRequest("POST", "/workflows/xsec-cancel-wf/executions/"+execID+"/cancel", nil)
	req = withTenantContext(req, "tenant-b")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// --- get execution ------------------------------------------------------------

func TestWorkflowHandler_GetExecution_CorrectRecord_Returns200(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	execID := createAndExecuteWorkflow(t, router, engine, "get-exec-wf", "test-tenant", true)

	req := httptest.NewRequest("GET", "/workflows/get-exec-wf/executions/"+execID, nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, execID, resp["id"])
	assert.Equal(t, "get-exec-wf", resp["workflow_name"])
	assert.NotEmpty(t, resp["status"])
}

func TestWorkflowHandler_GetExecution_CrossTenant_Returns403(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	// Create and execute the workflow in tenant A.
	execID := createAndExecuteWorkflow(t, router, engine, "xsec-wf", "tenant-a", true)

	// Tenant B tries to access tenant A's execution.
	// tenant-b has no workflow named "xsec-wf" → 403.
	req := httptest.NewRequest("GET", "/workflows/xsec-wf/executions/"+execID, nil)
	req = withTenantContext(req, "tenant-b")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestWorkflowHandler_GetExecution_NotFound_Returns404(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("GET", "/workflows/my-wf/executions/exec_9999_0", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestWorkflowHandler_GetExecution_SpecialCharsInVars_HandledSafely verifies that
// execution IDs containing CWE-117 log-injection characters are stripped before they
// reach the logger in both the exec_id field and the error field.
//
// engine.GetExecution embeds the raw execID in its error via fmt.Errorf with %s, so
// without sanitization the error field also carries the tainted value.
func TestWorkflowHandler_GetExecution_SpecialCharsInVars_HandledSafely(t *testing.T) {
	_, configStore := newTestWorkflowHandler(t)
	capLogger := &capturingLogger{}
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), capLogger, nil, nil, nil, nil, nil)
	h := NewWorkflowHandler(engine, configStore, nil, capLogger)
	router := newWorkflowRouter(h)

	// %0a = LF (\n), %0d = CR (\r). gorilla/mux decodes percent-encoding when extracting
	// path variables, so these characters arrive in mux.Vars(r)["exec_id"] unescaped.
	// The engine returns fmt.Errorf("execution not found: %s", execID), embedding them.
	req := httptest.NewRequest("GET", "/workflows/my-wf/executions/exec%0ainjected%0dfake", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	require.NotEmpty(t, capLogger.entries, "logger.Error must be called for unknown exec_id")

	for _, key := range []string{"exec_id", "error"} {
		for _, v := range capLogger.loggedValuesForKey(key) {
			assert.NotContains(t, v, "\n", "logger key %q must not contain raw LF", key)
			assert.NotContains(t, v, "\r", "logger key %q must not contain raw CR", key)
		}
	}
}

// --- permission gating (Issue #2725) -----------------------------------------

// testRequirePermFn is a minimal requirePermFn for WorkflowHandler unit tests.
// It mirrors the real s.requirePermission logic: admin principals always pass,
// non-admin principals need the exact "resourceType:action" permission string.
func testRequirePermFn(resourceType, action string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, _ := r.Context().Value(principalContextKey).(*Principal)
			if p == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"authentication required"}`))
				return
			}
			if p.Assurance >= session.AssuranceBasic {
				next.ServeHTTP(w, r)
				return
			}
			need := resourceType + ":" + action
			for _, have := range p.Permissions {
				if have == need {
					next.ServeHTTP(w, r)
					return
				}
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"insufficient permissions"}`))
		})
	}
}

// withPermissions injects a non-admin principal carrying the listed permissions.
func withPermissions(r *http.Request, perms ...string) *http.Request {
	p := &Principal{ID: "test-key", Assurance: session.AssuranceMachine, Permissions: perms}
	return r.WithContext(context.WithValue(r.Context(), principalContextKey, p))
}

// newPermGatedWorkflowRouter creates a mux.Router with workflow routes registered
// under /workflows using testRequirePermFn permission gating.
func newPermGatedWorkflowRouter(h *WorkflowHandler) *mux.Router {
	h.SetRequirePermFn(testRequirePermFn)
	router := mux.NewRouter()
	sub := router.PathPrefix("/workflows").Subrouter()
	h.RegisterWorkflowRoutes(sub)
	return router
}

// TestWorkflowPermission_Execute_ForbiddenWithoutPermission verifies that
// POST /workflows/{id}/execute returns 403 when the caller lacks workflow:execute.
func TestWorkflowPermission_Execute_ForbiddenWithoutPermission(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)

	// Create workflow as admin so the execute target exists.
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("perm-exec-wf")))
	createReq = withTenantContext(withAdminPrincipal(createReq), "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code, "setup: create workflow must succeed")

	// Caller has workflow:read but not workflow:execute → 403.
	req := httptest.NewRequest("POST", "/workflows/perm-exec-wf/execute", nil)
	req = withTenantContext(withPermissions(req, "workflow:read"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestWorkflowPermission_Execute_SucceedsWithPermission verifies that
// POST /workflows/{id}/execute returns 202 when the caller has workflow:execute.
func TestWorkflowPermission_Execute_SucceedsWithPermission(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)

	// Create workflow as admin.
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("perm-exec-ok-wf")))
	createReq = withTenantContext(withAdminPrincipal(createReq), "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Caller has workflow:execute → 202.
	req := httptest.NewRequest("POST", "/workflows/perm-exec-ok-wf/execute", nil)
	req = withTenantContext(withPermissions(req, "workflow:execute"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusAccepted, rec.Code)

	// Clean up the execution goroutine so it doesn't outlive the test.
	if engine != nil {
		var execResp map[string]interface{}
		if jsonErr := json.Unmarshal(rec.Body.Bytes(), &execResp); jsonErr == nil {
			if execID, ok := execResp["execution_id"].(string); ok && execID != "" {
				t.Cleanup(func() { _ = engine.CancelExecution(execID) })
			}
		}
	}
}

// TestWorkflowPermission_Delete_ForbiddenWithoutPermission verifies that
// DELETE /workflows/{id} returns 403 when the caller lacks workflow:write.
func TestWorkflowPermission_Delete_ForbiddenWithoutPermission(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)

	// Create workflow as admin.
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("perm-del-wf")))
	createReq = withTenantContext(withAdminPrincipal(createReq), "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Caller has workflow:read but not workflow:write → 403.
	req := httptest.NewRequest("DELETE", "/workflows/perm-del-wf", nil)
	req = withTenantContext(withPermissions(req, "workflow:read"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestWorkflowPermission_Delete_SucceedsWithPermission verifies that
// DELETE /workflows/{id} returns 200 when the caller has workflow:write.
func TestWorkflowPermission_Delete_SucceedsWithPermission(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)

	// Create workflow as admin.
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(minimalWorkflowBody("perm-del-ok-wf")))
	createReq = withTenantContext(withAdminPrincipal(createReq), "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// Caller has workflow:write → 200.
	req := httptest.NewRequest("DELETE", "/workflows/perm-del-ok-wf", nil)
	req = withTenantContext(withPermissions(req, "workflow:write"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

// TestWorkflowPermission_Cancel_ForbiddenWithoutPermission verifies that
// POST /workflows/{id}/executions/{exec_id}/cancel returns 403 without workflow:cancel.
func TestWorkflowPermission_Cancel_ForbiddenWithoutPermission(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)

	// Create and execute a long-running workflow as admin so the execution is non-terminal.
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(mustMarshal(CreateWorkflowRequest{
		Name: "perm-cancel-wf",
		Steps: []workflow.Step{
			{Name: "wait", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: 30 * time.Second}},
		},
	})))
	createReq = withTenantContext(withAdminPrincipal(createReq), "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	execReq := httptest.NewRequest("POST", "/workflows/perm-cancel-wf/execute", nil)
	execReq = withTenantContext(withAdminPrincipal(execReq), "test-tenant")
	execRec := httptest.NewRecorder()
	router.ServeHTTP(execRec, execReq)
	require.Equal(t, http.StatusAccepted, execRec.Code)

	var execResp map[string]interface{}
	require.NoError(t, json.Unmarshal(execRec.Body.Bytes(), &execResp))
	execID, ok := execResp["execution_id"].(string)
	require.True(t, ok && execID != "", "execution_id must be non-empty")
	t.Cleanup(func() { _ = engine.CancelExecution(execID) })

	// Caller has workflow:execute but not workflow:cancel → 403.
	req := httptest.NewRequest("POST", "/workflows/perm-cancel-wf/executions/"+execID+"/cancel", nil)
	req = withTenantContext(withPermissions(req, "workflow:execute"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

// TestWorkflowPermission_Cancel_SucceedsWithPermission verifies that
// POST /workflows/{id}/executions/{exec_id}/cancel returns 200 with workflow:cancel.
func TestWorkflowPermission_Cancel_SucceedsWithPermission(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)

	// Create and execute a long-running workflow as admin.
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(mustMarshal(CreateWorkflowRequest{
		Name: "perm-cancel-ok-wf",
		Steps: []workflow.Step{
			{Name: "wait", Type: workflow.StepTypeDelay, Delay: &workflow.DelayConfig{Duration: 30 * time.Second}},
		},
	})))
	createReq = withTenantContext(withAdminPrincipal(createReq), "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	execReq := httptest.NewRequest("POST", "/workflows/perm-cancel-ok-wf/execute", nil)
	execReq = withTenantContext(withAdminPrincipal(execReq), "test-tenant")
	execRec := httptest.NewRecorder()
	router.ServeHTTP(execRec, execReq)
	require.Equal(t, http.StatusAccepted, execRec.Code)

	var execResp map[string]interface{}
	require.NoError(t, json.Unmarshal(execRec.Body.Bytes(), &execResp))
	execID, ok := execResp["execution_id"].(string)
	require.True(t, ok && execID != "", "execution_id must be non-empty")

	// Caller has workflow:cancel → 200.
	req := httptest.NewRequest("POST", "/workflows/perm-cancel-ok-wf/executions/"+execID+"/cancel", nil)
	req = withTenantContext(withPermissions(req, "workflow:cancel"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	// Execution already cancelled; cleanup is a no-op but kept for consistency.
	t.Cleanup(func() { _ = engine.CancelExecution(execID) })
}

// TestWorkflowHandler_CancelExecution_SpecialCharsInVars_HandledSafely mirrors the get
// variant above for the cancel path, which exercises the same engine error-embedding
// pattern and the same CodeQL-recognised sanitization fix.
func TestWorkflowHandler_CancelExecution_SpecialCharsInVars_HandledSafely(t *testing.T) {
	_, configStore := newTestWorkflowHandler(t)
	capLogger := &capturingLogger{}
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), capLogger, nil, nil, nil, nil, nil)
	h := NewWorkflowHandler(engine, configStore, nil, capLogger)
	router := newWorkflowRouter(h)

	req := httptest.NewRequest("POST", "/workflows/my-wf/executions/exec%0ainjected%0dfake/cancel", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	require.NotEmpty(t, capLogger.entries, "logger.Error must be called for unknown exec_id on cancel")

	for _, key := range []string{"exec_id", "error"} {
		for _, v := range capLogger.loggedValuesForKey(key) {
			assert.NotContains(t, v, "\n", "logger key %q must not contain raw LF", key)
			assert.NotContains(t, v, "\r", "logger key %q must not contain raw CR", key)
		}
	}
}
