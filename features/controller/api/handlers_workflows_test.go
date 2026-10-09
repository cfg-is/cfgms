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
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
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

// withTenantContext injects a tenant ID into the request context, as the auth middleware
// does — and, since Issue #4335, the corresponding ctxkeys.TenantScope: an empty
// tenantID mirrors scopeForVerifiedAdminCert (middleware.go) and becomes root scope,
// a non-empty one becomes a tenant scope. Without this, workflowStoreForRequest sees
// an unset scope and fails closed, which is correct for a real unscoped context but
// wrong for these tests, which use "" to mean "unrestricted admin" like production does.
func withTenantContext(r *http.Request, tenantID string) *http.Request {
	ctx := context.WithValue(r.Context(), ctxkeys.TenantID, tenantID)
	scope := ctxkeys.NewRootScope()
	if tenantID != "" {
		scope = ctxkeys.NewTenantScope(tenantID)
	}
	ctx = context.WithValue(ctx, ctxkeys.TenantScopeKey, scope)
	return r.WithContext(ctx)
}

// allowAllPermFn is an always-allow permission gate for tests that exercise workflow
// CRUD behavior without caring about RBAC. RegisterWorkflowRoutes fails closed on a
// nil gate (Issue #4316), so tests that used to rely on that nil meaning "ungated"
// wire this in explicitly instead.
func allowAllPermFn(_, _ string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

// newWorkflowRouter wires a WorkflowHandler onto a fresh mux.Router.
func newWorkflowRouter(h *WorkflowHandler) *mux.Router {
	if h.requirePermFn == nil {
		h.SetRequirePermFn(allowAllPermFn)
	}
	router := mux.NewRouter()
	sub := router.PathPrefix("/workflows").Subrouter()
	if err := h.RegisterWorkflowRoutes(sub); err != nil {
		panic("newWorkflowRouter: " + err.Error())
	}
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

	// workflows must serialize as [] not null — a nil slice marshals as null and crashes
	// client-side .map() calls, so the storage layer must return a non-nil empty slice.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Equal(t, json.RawMessage("[]"), raw["workflows"], "empty workflows list must be [] not null")
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

// TestWorkflowHandler_GetWorkflowExecutions_CrossTenant_Returns403 proves the
// tenant-isolation gate added by Issue #4316: a tenant that can guess another
// tenant's workflow name must not be able to read its execution history. Mirrors
// TestWorkflowHandler_GetExecution_CrossTenant_Returns403 on the sibling route.
func TestWorkflowHandler_GetWorkflowExecutions_CrossTenant_Returns403(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	// Create and execute the workflow in tenant A so at least one execution exists.
	createAndExecuteWorkflow(t, router, engine, "xsec-list-wf", "tenant-a", false)

	// The engine lists only the caller's tenant, so tenant B's listing is empty and
	// never contains tenant A's execution history.
	req := httptest.NewRequest("GET", "/workflows/xsec-list-wf/executions", nil)
	req = withTenantContext(req, "tenant-b")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.EqualValues(t, 0, resp["count"], "tenant B must not see tenant A's executions")
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
func waitForTerminalState(t *testing.T, eng *workflow.Engine, tenantID, execID string) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case <-ticker.C:
			ex, err := eng.GetExecution(context.Background(), tenantID, execID)
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
	waitForTerminalState(t, engine, "test-tenant", execID)

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

	// Tenant B tries to cancel tenant A's execution. The lookup is scoped to the
	// caller's tenant, so A's execution is not found for B — not forbidden, not
	// cancelled.
	req := httptest.NewRequest("POST", "/workflows/xsec-cancel-wf/executions/"+execID+"/cancel", nil)
	req = withTenantContext(req, "tenant-b")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	ex, err := engine.GetExecution(context.Background(), "tenant-a", execID)
	require.NoError(t, err)
	assert.NotEqual(t, workflow.StatusCancelled, ex.GetStatus(), "tenant B must not cancel tenant A's run")
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

	// Tenant B tries to access tenant A's execution. The lookup is scoped to the
	// caller's tenant, so A's execution is not found for B (never forbidden, never
	// A's record).
	req := httptest.NewRequest("GET", "/workflows/xsec-wf/executions/"+execID, nil)
	req = withTenantContext(req, "tenant-b")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "xsec-wf\"", "tenant A's record must not be returned")
}

// TestWorkflowHandler_GetExecution_StoreOnlyRecord_ReturnsTerminalStatus proves the
// durable store answers for an execution the handler's own engine never ran (it ran
// on another node), and that another tenant's caller gets none of it (Issue #4675).
func TestWorkflowHandler_GetExecution_StoreOnlyRecord_ReturnsTerminalStatus(t *testing.T) {
	storageManager := pkgtesting.SetupTestStorage(t)
	execStore := storageManager.GetWorkflowExecutionStore()
	require.NotNil(t, execStore, "the test storage manager must provide a workflow execution store")
	logger := logging.NewNoopLogger()
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logger, nil, nil, nil, nil, nil,
		workflow.WithExecutionStore(execStore))
	t.Cleanup(engine.Shutdown)
	h := NewWorkflowHandler(engine, storageManager.GetConfigStore(), nil, logger)
	router := newWorkflowRouter(h)

	// The workflow definition is shared storage; the execution record is written by
	// another node's engine, so this engine holds nothing in memory for it.
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		rec := postWorkflowAsTenant(t, router, http.MethodPost, "/workflows", tenant, minimalWorkflowBody("remote-wf"))
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	}
	start := time.Now().UTC().Truncate(time.Millisecond)
	require.NoError(t, execStore.Save(context.Background(), &business.WorkflowExecutionRecord{
		TenantID: "tenant-a", ExecutionID: "exec-remote-1", WorkflowName: "remote-wf", Status: "completed",
		StartTime: start, EndTime: start.Add(time.Second),
		Payload: []byte(`{"step_results":{"s1":{"status":"completed","start_time":"` + start.Format(time.RFC3339Nano) + `","duration":1000}}}`),
	}))

	req := withTenantContext(httptest.NewRequest("GET", "/workflows/remote-wf/executions/exec-remote-1", nil), "tenant-a")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, "completed", resp["status"])
	assert.Equal(t, "exec-remote-1", resp["id"])
	assert.Contains(t, resp["step_results"], "s1")

	// The listing and the workflow summary read the same shared history.
	req = withTenantContext(httptest.NewRequest("GET", "/workflows/remote-wf/executions", nil), "tenant-a")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.EqualValues(t, 1, resp["count"])

	// Tenant B owns a workflow of the same name but must not see tenant A's record.
	req = withTenantContext(httptest.NewRequest("GET", "/workflows/remote-wf/executions/exec-remote-1", nil), "tenant-b")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "completed")
	req = withTenantContext(httptest.NewRequest("GET", "/workflows/remote-wf/executions", nil), "tenant-b")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.EqualValues(t, 0, resp["count"])

	// A run with no owner on this node cannot be cancelled here.
	require.NoError(t, execStore.Save(context.Background(), &business.WorkflowExecutionRecord{
		TenantID: "tenant-a", ExecutionID: "exec-remote-2", WorkflowName: "remote-wf", Status: "running",
		StartTime: start, Payload: []byte(`{}`),
	}))
	req = withTenantContext(httptest.NewRequest("POST", "/workflows/remote-wf/executions/exec-remote-2/cancel", nil), "tenant-a")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
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

// --- unset tenant scope (Issue #4335) -----------------------------------------

// withUnsetTenantScope injects the request context an auth-plumbing bug produces:
// ctxkeys.TenantID is present, exactly as authenticationMiddleware sets it, but
// ctxkeys.TenantScopeKey was never established (a dropped context, or a handler reached
// through a path that never ran the scope middleware). withTenantContext deliberately
// always sets a scope, so this is the only helper that reproduces the unset state
// workflowStoreForRequest must fail closed on.
func withUnsetTenantScope(r *http.Request) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), ctxkeys.TenantID, ""))
}

// TestWorkflowHandler_UnsetTenantScope_Refused is the [REQUIRED TEST] for Issue #4335:
// every workflow route that resolves a store through workflowStoreForRequest must refuse
// a request whose ctxkeys.TenantScope was never established, rather than silently
// resolving a store over the "" tenant bucket.
//
// The refusal is asserted on both the status and the body: it is a 404 whose error is
// exactly "not found", which is what distinguishes it from every answer the pre-fix
// "" bucket produced on these same routes — 200 with an empty list, a resource-specific
// `workflow "x" not found`, or the tenant-isolation 403 "access denied". A tenant-scoped
// control read proves the fixture's workflow and execution are reachable when a scope is
// present, and the post-loop assertions prove the refused writes (create, update, delete,
// execute, cancel) never reached the store or the engine.
func TestWorkflowHandler_UnsetTenantScope_Refused(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	const tenant = "tenant-a"
	// A long-running (delay-step) execution stays non-terminal so the cancel route reaches
	// its tenant gate instead of short-circuiting on terminal state.
	execID := createAndExecuteWorkflow(t, router, engine, "tenant-a-wf", tenant, true)

	scopedGet := func(t *testing.T) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, withTenantContext(httptest.NewRequest("GET", "/workflows/tenant-a-wf", nil), tenant))
		return rec
	}
	require.Equal(t, http.StatusOK, scopedGet(t).Code,
		"control: a scoped caller must be able to read the seeded workflow")

	routes := []struct {
		method string
		path   string
		body   []byte
	}{
		{"GET", "/workflows", nil},
		{"POST", "/workflows", minimalWorkflowBody("smuggled-wf")},
		{"GET", "/workflows/tenant-a-wf", nil},
		{"PUT", "/workflows/tenant-a-wf", minimalWorkflowBody("tenant-a-wf")},
		{"DELETE", "/workflows/tenant-a-wf", nil},
		{"POST", "/workflows/tenant-a-wf/execute", []byte("{}")},
		{"GET", "/workflows/tenant-a-wf/executions", nil},
		{"GET", "/workflows/tenant-a-wf/executions/" + execID, nil},
		{"POST", "/workflows/tenant-a-wf/executions/" + execID + "/cancel", nil},
	}

	for _, tc := range routes {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, bytes.NewReader(tc.body))
			req = withUnsetTenantScope(req)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusNotFound, rec.Code,
				"an unset tenant scope must be refused, not served from the \"\" bucket: %s", rec.Body.String())

			var resp map[string]interface{}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			assert.Equal(t, "not found", resp["error"],
				"the refusal must be the scope-unset 404, not a resource-specific not-found or a 403")
		})
	}

	// The refused writes must have left the tenant's workflows untouched: the seeded
	// workflow is still readable (update and delete were refused) and the refused create
	// added nothing the tenant can see.
	require.Equal(t, http.StatusOK, scopedGet(t).Code,
		"a refused update or delete must not have removed the tenant's workflow")

	listRec := httptest.NewRecorder()
	router.ServeHTTP(listRec, withTenantContext(httptest.NewRequest("GET", "/workflows", nil), tenant))
	require.Equal(t, http.StatusOK, listRec.Code, "body: %s", listRec.Body.String())
	var listResp struct {
		Workflows []workflow.VersionedWorkflow `json:"workflows"`
	}
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &listResp))
	require.Len(t, listResp.Workflows, 1, "a refused create must not write a workflow")
	assert.Equal(t, "tenant-a-wf", listResp.Workflows[0].Name)

	// The refused execute started no second execution, and the refused cancel left the
	// seeded one running.
	execRec := httptest.NewRecorder()
	router.ServeHTTP(execRec, withTenantContext(httptest.NewRequest("GET", "/workflows/tenant-a-wf/executions", nil), tenant))
	require.Equal(t, http.StatusOK, execRec.Code, "body: %s", execRec.Body.String())
	var execResp map[string]interface{}
	require.NoError(t, json.Unmarshal(execRec.Body.Bytes(), &execResp))
	assert.EqualValues(t, 1, execResp["count"], "a refused execute must not start a second execution")

	execution, err := engine.GetExecution(context.Background(), tenant, execID)
	require.NoError(t, err)
	require.NotNil(t, execution)
	assert.NotEqual(t, workflow.StatusCancelled, execution.GetStatus(),
		"a refused cancel must not cancel the tenant's execution")
}

// newPermGatedWorkflowRouter creates a mux.Router with workflow routes registered
// under /workflows using testRequirePermFn permission gating.
func newPermGatedWorkflowRouter(h *WorkflowHandler) *mux.Router {
	h.SetRequirePermFn(testRequirePermFn)
	router := mux.NewRouter()
	sub := router.PathPrefix("/workflows").Subrouter()
	if err := h.RegisterWorkflowRoutes(sub); err != nil {
		panic("newPermGatedWorkflowRouter: " + err.Error())
	}
	return router
}

// TestWorkflowHandler_RegisterWorkflowRoutes_NilGate_ReturnsError covers the
// fail-closed branch added in Issue #4316: a WorkflowHandler that never had
// SetRequirePermFn called must make RegisterWorkflowRoutes return an error and
// register no routes at all, instead of silently exposing every workflow route
// ungated.
func TestWorkflowHandler_RegisterWorkflowRoutes_NilGate_ReturnsError(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	require.Nil(t, h.requirePermFn, "precondition: no permission gate may be wired")

	router := mux.NewRouter()
	sub := router.PathPrefix("/workflows").Subrouter()

	err := h.RegisterWorkflowRoutes(sub)
	require.Error(t, err, "nil permission gate must fail closed")
	assert.Contains(t, err.Error(), "workflow routes: no permission gate wired")
	assert.Contains(t, err.Error(), "SetRequirePermFn")

	assert.Empty(t, walkRoutes(t, sub),
		"no workflow route may be registered when the permission gate is nil")

	// Nothing is served: every workflow method/path the success branch would have
	// registered 404s on the router the subrouter belongs to.
	for _, tc := range []struct{ method, path string }{
		{"GET", "/workflows"},
		{"POST", "/workflows"},
		{"GET", "/workflows/wf-1"},
		{"PUT", "/workflows/wf-1"},
		{"DELETE", "/workflows/wf-1"},
		{"POST", "/workflows/wf-1/execute"},
		{"GET", "/workflows/wf-1/executions"},
		{"GET", "/workflows/wf-1/executions/exec-1"},
		{"POST", "/workflows/wf-1/executions/exec-1/cancel"},
	} {
		req := withTenantContext(httptest.NewRequest(tc.method, tc.path, nil), "test-tenant")
		req = withAdminPrincipal(req)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusNotFound, rec.Code,
			"%s %s must not be served when registration failed closed", tc.method, tc.path)
	}

	// Positive control on the same handler: wiring a gate makes registration
	// succeed and register the full route set, proving the empty result above is
	// the nil-gate branch and not an unrelated registration failure.
	h.SetRequirePermFn(testRequirePermFn)
	gated := mux.NewRouter()
	gatedSub := gated.PathPrefix("/workflows").Subrouter()
	require.NoError(t, h.RegisterWorkflowRoutes(gatedSub))
	assert.Len(t, walkRoutes(t, gatedSub), 14,
		"a wired gate must register every workflow route")
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

// --- step ID assignment (Issue #3036) ----------------------------------------

// nestedWorkflowBody builds a workflow with a top-level sequential step that
// contains two task child steps, for testing nested ID assignment.
func nestedWorkflowBody(name string) []byte {
	return mustMarshal(CreateWorkflowRequest{
		Name: name,
		Steps: []workflow.Step{
			{
				Name: "outer",
				Type: workflow.StepTypeSequential,
				Steps: []workflow.Step{
					{Name: "inner-a", Type: workflow.StepTypeTask},
					{Name: "inner-b", Type: workflow.StepTypeTask},
				},
			},
			{Name: "sibling", Type: workflow.StepTypeTask},
		},
	})
}

// TestWorkflowHandler_GetWorkflow_StepIDsPresent verifies that GET /workflows/{id}
// returns computed structural IDs on every step including nested children.
func TestWorkflowHandler_GetWorkflow_StepIDsPresent(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create
	createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(nestedWorkflowBody("id-test")))
	createReq = withTenantContext(createReq, "test-tenant")
	createRec := httptest.NewRecorder()
	router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code)

	// GET
	req := httptest.NewRequest("GET", "/workflows/id-test", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))

	// Decode the steps array
	var steps []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw["steps"], &steps))
	require.Len(t, steps, 2, "expected 2 top-level steps")

	// Top-level: outer → s0, sibling → s1
	assertStepID(t, steps[0], "s0", "outer")
	assertStepID(t, steps[1], "s1", "sibling")

	// Nested: inner-a → s0.s0, inner-b → s0.s1
	var children []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(steps[0]["steps"], &children))
	require.Len(t, children, 2, "expected 2 nested steps")
	assertStepID(t, children[0], "s0.s0", "inner-a")
	assertStepID(t, children[1], "s0.s1", "inner-b")
}

// TestWorkflowHandler_ListWorkflows_StepIDsPresent verifies that GET /workflows
// returns computed IDs on every step in every workflow in the list response.
func TestWorkflowHandler_ListWorkflows_StepIDsPresent(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// Create two workflows
	for _, name := range []string{"list-id-wf1", "list-id-wf2"} {
		createReq := httptest.NewRequest("POST", "/workflows", bytes.NewReader(nestedWorkflowBody(name)))
		createReq = withTenantContext(createReq, "test-tenant")
		createRec := httptest.NewRecorder()
		router.ServeHTTP(createRec, createReq)
		require.Equal(t, http.StatusCreated, createRec.Code, "create %s", name)
	}

	// List
	req := httptest.NewRequest("GET", "/workflows", nil)
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	var workflows []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(body["workflows"], &workflows))
	require.GreaterOrEqual(t, len(workflows), 2)

	// Every workflow in the list must have IDs on its top-level steps
	for _, wf := range workflows {
		var steps []map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(wf["steps"], &steps))
		for i, step := range steps {
			var id string
			require.NoError(t, json.Unmarshal(step["id"], &id), "step %d id must be present", i)
			assert.NotEmpty(t, id, "step %d id must not be empty", i)
		}
	}
}

// assertStepID is a helper that checks a decoded step map has the expected id and name.
func assertStepID(t *testing.T, step map[string]json.RawMessage, wantID, wantName string) {
	t.Helper()
	var id, name string
	require.NoError(t, json.Unmarshal(step["id"], &id), "step.id must be present")
	require.NoError(t, json.Unmarshal(step["name"], &name), "step.name must be present")
	assert.Equal(t, wantID, id, "step %q: wrong id", wantName)
	assert.Equal(t, wantName, name, "step with id %q: wrong name", wantID)
}

// --- declared inputs ---------------------------------------------------------

func inputsWorkflowBody(name string) []byte {
	return mustMarshal(CreateWorkflowRequest{
		Name: name,
		Steps: []workflow.Step{
			{Name: "step1", Type: workflow.StepTypeTask},
		},
		Inputs: []workflow.InputSpec{
			{Name: "host", Type: workflow.InputTypeString, Required: true},
			{Name: "env", Type: workflow.InputTypeEnum, Options: []string{"dev", "prod"}, Default: "dev"},
		},
	})
}

func postWorkflow(t *testing.T, router *mux.Router, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestWorkflowHandler_Inputs_CreateGetRoundTrip(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	require.Equal(t, http.StatusCreated, postWorkflow(t, router, "/workflows", inputsWorkflowBody("in-wf")).Code)

	req := withTenantContext(httptest.NewRequest("GET", "/workflows/in-wf", nil), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	var resp workflow.VersionedWorkflow
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Inputs, 2)
	assert.Equal(t, "host", resp.Inputs[0].Name)
	assert.True(t, resp.Inputs[0].Required)
	assert.Equal(t, []string{"dev", "prod"}, resp.Inputs[1].Options)
}

func TestWorkflowHandler_Inputs_CreateRejectsInvalidDeclaration(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	body := mustMarshal(CreateWorkflowRequest{
		Name:   "bad-in",
		Steps:  []workflow.Step{{Name: "s", Type: workflow.StepTypeTask}},
		Inputs: []workflow.InputSpec{{Name: "tenant_id", Type: workflow.InputTypeString}},
	})
	assert.Equal(t, http.StatusBadRequest, postWorkflow(t, router, "/workflows", body).Code)
}

func TestWorkflowHandler_Inputs_ExecuteMissingRequiredReturns400(t *testing.T) {
	h, _, eng := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)
	require.Equal(t, http.StatusCreated, postWorkflow(t, router, "/workflows", inputsWorkflowBody("in-wf")).Code)

	rec := postWorkflow(t, router, "/workflows/in-wf/execute", []byte(`{"inputs":{}}`))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var resp struct {
		Fields []workflow.InputFieldError `json:"fields"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.Len(t, resp.Fields, 1)
	assert.Equal(t, "host", resp.Fields[0].Field)

	execs, err := eng.ListExecutions(context.Background(), "test-tenant")
	require.NoError(t, err)
	for _, ex := range execs {
		assert.Equal(t, workflow.StatusFailed, ex.GetStatus(), "no execution may have started")
	}
}

func TestWorkflowHandler_Inputs_ExecuteEnumOutsideOptionsReturns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	require.Equal(t, http.StatusCreated, postWorkflow(t, router, "/workflows", inputsWorkflowBody("in-wf")).Code)

	rec := postWorkflow(t, router, "/workflows/in-wf/execute", []byte(`{"inputs":{"host":"a","env":"qa"}}`))
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.NotContains(t, rec.Body.String(), "qa")
}

// --- validate workflow (Issue #4612) ----------------------------------------

func postValidate(t *testing.T, router *mux.Router, body []byte) (int, ValidateWorkflowResponse) {
	t.Helper()
	req := httptest.NewRequest("POST", "/workflows/validate", bytes.NewReader(body))
	req = withTenantContext(req, "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	var resp ValidateWorkflowResponse
	if rec.Code == http.StatusOK {
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	}
	return rec.Code, resp
}

func validTaskStep(name string) workflow.Step {
	return workflow.Step{Name: name, Type: workflow.StepTypeTask, Module: "file", Config: map[string]interface{}{"path": "/tmp/x"}}
}

func TestWorkflowHandler_Validate_ValidWorkflow(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	code, resp := postValidate(t, router, mustMarshal(CreateWorkflowRequest{
		Name: "ok", Steps: []workflow.Step{validTaskStep("a")},
	}))
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, resp.Valid)
	assert.NotNil(t, resp.Issues)
	assert.Empty(t, resp.Issues)
}

func TestWorkflowHandler_Validate_TwoDefectsReturnsBoth(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	code, resp := postValidate(t, router, mustMarshal(CreateWorkflowRequest{
		Name: "bad",
		Steps: []workflow.Step{
			validTaskStep("a"),
			{Name: "b", Type: workflow.StepTypeTask, Module: "file"},
			{Name: "c", Type: workflow.StepTypeTask, Config: map[string]interface{}{"k": "v"}},
		},
	}))
	assert.Equal(t, http.StatusOK, code)
	assert.False(t, resp.Valid)
	require.Len(t, resp.Issues, 2)
	assert.Equal(t, "steps[1].config", resp.Issues[0].Path)
	assert.Equal(t, "b", resp.Issues[0].StepName)
	assert.Equal(t, "steps[2].module", resp.Issues[1].Path)
	assert.Equal(t, "c", resp.Issues[1].StepName)
}

func TestWorkflowHandler_Validate_PersistsAndExecutesNothing(t *testing.T) {
	h, store := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	for _, wf := range []CreateWorkflowRequest{
		{Name: "persist-me", Steps: []workflow.Step{validTaskStep("a")}},
		{Name: "persist-bad", Steps: []workflow.Step{{Name: "x", Type: workflow.StepTypeTask}}},
	} {
		code, _ := postValidate(t, router, mustMarshal(wf))
		require.Equal(t, http.StatusOK, code)
	}

	listReq := withTenantContext(httptest.NewRequest("GET", "/workflows", nil), "test-tenant")
	listRec := httptest.NewRecorder()
	router.ServeHTTP(listRec, listReq)
	var list map[string]interface{}
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &list))
	assert.EqualValues(t, 0, list["count"], "validate must not store a workflow")
	assert.NotNil(t, store)

	execs, err := h.engine.ListExecutions(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Empty(t, execs, "validate must not start an execution")
}

func TestWorkflowHandler_Validate_NestedApprovalReportsStepPath(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	gate := workflow.Step{
		Name: "gate", Type: workflow.StepTypeApproval,
		Approval: &workflow.ApprovalConfig{Message: "ok?", Timeout: time.Hour},
	}
	code, resp := postValidate(t, router, mustMarshal(CreateWorkflowRequest{
		Name: "nested",
		Steps: []workflow.Step{
			validTaskStep("a"),
			{Name: "fan", Type: workflow.StepTypeParallel, Steps: []workflow.Step{validTaskStep("b"), gate}},
		},
	}))
	assert.Equal(t, http.StatusOK, code)
	assert.False(t, resp.Valid)
	require.Len(t, resp.Issues, 1)
	assert.Equal(t, "steps[1].steps[1]", resp.Issues[0].Path)
	assert.Equal(t, "gate", resp.Issues[0].StepName)
	assert.Contains(t, resp.Issues[0].Message, "approval steps must be top-level")
}

func TestWorkflowHandler_Validate_TruncatesLongValues(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	long := string(bytes.Repeat([]byte("z"), 5000))
	_, resp := postValidate(t, router, mustMarshal(CreateWorkflowRequest{
		Name:  "long",
		Steps: []workflow.Step{{Name: long, Type: workflow.StepType(long)}},
	}))
	require.False(t, resp.Valid)
	for _, is := range resp.Issues {
		assert.Less(t, len(is.Message), 300)
		assert.Less(t, len(is.StepName), 100)
	}
}

func TestWorkflowHandler_Validate_NotShadowedByID(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	// A workflow literally named "validate" must not capture POST /validate,
	// and GET /validate still resolves to the {id} route.
	code, _ := postValidate(t, router, mustMarshal(CreateWorkflowRequest{Name: "w", Steps: []workflow.Step{validTaskStep("a")}}))
	assert.Equal(t, http.StatusOK, code)

	req := withTenantContext(httptest.NewRequest("GET", "/workflows/validate", nil), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestWorkflowHandler_Validate_InvalidJSON_Returns400(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	code, _ := postValidate(t, router, []byte("not-json"))
	assert.Equal(t, http.StatusBadRequest, code)
}

func TestWorkflowPermission_Validate_GatedOnRead(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)
	body := mustMarshal(CreateWorkflowRequest{Name: "w", Steps: []workflow.Step{validTaskStep("a")}})

	req := withTenantContext(withPermissions(httptest.NewRequest("POST", "/workflows/validate", bytes.NewReader(body)), "workflow:execute"), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	req = withTenantContext(withPermissions(httptest.NewRequest("POST", "/workflows/validate", bytes.NewReader(body)), "workflow:read"), "test-tenant")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

const parseYAMLDoc = `workflow:
  name: onboard
  version: 1.0.0
  inputs:
    - name: region
      type: string
      required: true
  steps:
    - name: prep
      type: task
      module: file
      config:
        path: /tmp/x
    - name: gate
      type: approval
      approval:
        message: ship it?
        timeout: 1h
    - name: tell
      type: notify
      notify:
        url: https://notify.example.com/hook
        title: done
`

func postRaw(router *mux.Router, path string, body []byte) *httptest.ResponseRecorder {
	req := withTenantContext(httptest.NewRequest("POST", path, bytes.NewReader(body)), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestWorkflowHandler_ParseRenderParse_RoundTrip(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	rec := postRaw(router, "/workflows/parse-yaml", []byte(parseYAMLDoc))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var first ParseYAMLResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &first))
	assert.True(t, first.Valid)
	assert.Empty(t, first.Issues)
	require.Len(t, first.Workflow.Steps, 3)
	require.Len(t, first.Workflow.Inputs, 1)

	rec = postRaw(router, "/workflows/render-yaml", mustMarshal(first.Workflow))
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))

	rec = postRaw(router, "/workflows/parse-yaml", rec.Body.Bytes())
	require.Equal(t, http.StatusOK, rec.Code)
	var second ParseYAMLResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &second))
	assert.Equal(t, first.Workflow, second.Workflow)
}

func TestWorkflowHandler_ParseYAML_ReportsIssues(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	rec := postRaw(router, "/workflows/parse-yaml", []byte("workflow:\n  name: bad\n  steps:\n    - name: a\n      type: task\n"))
	require.Equal(t, http.StatusOK, rec.Code)
	var resp ParseYAMLResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.False(t, resp.Valid)
	assert.NotEmpty(t, resp.Issues)
}

func TestWorkflowHandler_ParseYAML_MalformedReturns400WithoutEcho(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	for _, doc := range []string{
		"workflow: [unclosed SECRETVALUE",
		"workflow:\n  name: x\n  timeout: SECRETVALUE\n  steps: []\n",
		"workflow:\n  name: [SECRETVALUE]\n",
	} {
		rec := postRaw(router, "/workflows/parse-yaml", []byte(doc))
		assert.Equal(t, http.StatusBadRequest, rec.Code, doc)
		assert.NotContains(t, rec.Body.String(), "SECRETVALUE")
		assert.NotContains(t, rec.Body.String(), "goroutine")
		assert.NotContains(t, rec.Body.String(), ".go:")
	}
}

func TestWorkflowHandler_ParseYAML_OversizeBodyReturns413(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	big := bytes.Repeat([]byte("a"), int(maxStructuredRequestBodyBytes)+1)
	// Through the global limit middleware the parser handler is never reached.
	reached := false
	guarded := (&Server{}).requestBodyLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		router.ServeHTTP(w, r)
	}))
	req := withTenantContext(httptest.NewRequest("POST", "/workflows/parse-yaml", bytes.NewReader(big)), "test-tenant")
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	assert.False(t, reached)

	// The handler also bounds its own read.
	rec = postRaw(router, "/workflows/parse-yaml", big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	rec = postRaw(router, "/workflows/render-yaml", big)
	assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}

func TestWorkflowHandler_RenderYAML_BadInput(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	assert.Equal(t, http.StatusBadRequest, postRaw(router, "/workflows/render-yaml", []byte("not-json")).Code)

	unrepresentable := []byte(`{"name":"w","steps":[{"name":"a","type":"http","http":{"url":"https://x.example.com"}}]}`)
	assert.Equal(t, http.StatusBadRequest, postRaw(router, "/workflows/render-yaml", unrepresentable).Code)
}

func TestWorkflowHandler_YAMLEndpoints_WriteNothing(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)

	require.Equal(t, http.StatusOK, postRaw(router, "/workflows/parse-yaml", []byte(parseYAMLDoc)).Code)
	require.Equal(t, http.StatusOK, postRaw(router, "/workflows/render-yaml", mustMarshal(CreateWorkflowRequest{Name: "w", Steps: []workflow.Step{validTaskStep("a")}})).Code)

	listReq := withTenantContext(httptest.NewRequest("GET", "/workflows", nil), "test-tenant")
	listRec := httptest.NewRecorder()
	router.ServeHTTP(listRec, listReq)
	var list map[string]interface{}
	require.NoError(t, json.Unmarshal(listRec.Body.Bytes(), &list))
	assert.EqualValues(t, 0, list["count"])
	execs, err := h.engine.ListExecutions(context.Background(), "test-tenant")
	require.NoError(t, err)
	assert.Empty(t, execs)
}

func TestWorkflowPermission_YAMLEndpoints_GatedOnRead(t *testing.T) {
	h, _, _ := newTestWorkflowHandlerAndEngine(t)
	router := newPermGatedWorkflowRouter(h)
	bodies := map[string][]byte{
		"/workflows/parse-yaml":  []byte(parseYAMLDoc),
		"/workflows/render-yaml": mustMarshal(CreateWorkflowRequest{Name: "w", Steps: []workflow.Step{validTaskStep("a")}}),
	}

	for path, body := range bodies {
		for perm, want := range map[string]int{"workflow:execute": http.StatusForbidden, "workflow:read": http.StatusOK} {
			req := withTenantContext(withPermissions(httptest.NewRequest("POST", path, bytes.NewReader(body)), perm), "test-tenant")
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			assert.Equal(t, want, rec.Code, "%s with %s", path, perm)
		}
	}
}

// --- list summary: trigger counts and last execution (Issue #4614) -----------

type listedWorkflowSummary struct {
	Name                string `json:"name"`
	TriggerCount        int    `json:"trigger_count"`
	EnabledTriggerCount int    `json:"enabled_trigger_count"`
	LastExecution       *struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		StartTime string `json:"start_time"`
	} `json:"last_execution"`
}

func listWorkflowSummaries(t *testing.T, router *mux.Router, tenantID string) (map[string]listedWorkflowSummary, string) {
	t.Helper()
	req := withTenantContext(httptest.NewRequest("GET", "/workflows", nil), tenantID)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var body struct {
		Workflows []listedWorkflowSummary `json:"workflows"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	out := map[string]listedWorkflowSummary{}
	for _, wf := range body.Workflows {
		out[wf.Name] = wf
	}
	return out, rec.Body.String()
}

func createManualTrigger(t *testing.T, mgr *trigger.TriggerManagerImpl, tenantID, id, workflowName string, enabled bool) {
	t.Helper()
	ctx := context.WithValue(context.Background(), ctxkeys.TenantID, tenantID)
	require.NoError(t, mgr.CreateTrigger(ctx, &trigger.Trigger{
		ID: id, Name: id, Type: trigger.TriggerTypeManual, WorkflowName: workflowName,
	}))
	if !enabled {
		require.NoError(t, mgr.DisableTrigger(ctx, id))
	}
}

func TestWorkflowHandler_ListWorkflows_NoTriggersOrRuns_ZerosAndNull(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	router := newWorkflowRouter(h)
	rec := postWorkflow(t, router, "/workflows", minimalWorkflowBody("quiet-wf"))
	require.Equal(t, http.StatusCreated, rec.Code)

	got, raw := listWorkflowSummaries(t, router, "test-tenant")
	wf, ok := got["quiet-wf"]
	require.True(t, ok)
	assert.Equal(t, 0, wf.TriggerCount)
	assert.Equal(t, 0, wf.EnabledTriggerCount)
	assert.Nil(t, wf.LastExecution)
	assert.Contains(t, raw, `"last_execution":null`)
	assert.Contains(t, raw, `"trigger_count":0`)
}

func TestWorkflowHandler_ListWorkflows_EnabledTriggerCountCountsOnlyEnabled(t *testing.T) {
	h, _ := newTestWorkflowHandler(t)
	mgr := trigger.NewControllerTriggerManager(nil, nil)
	h.triggerManager = mgr
	router := newWorkflowRouter(h)
	require.Equal(t, http.StatusCreated, postWorkflow(t, router, "/workflows", minimalWorkflowBody("trig-wf")).Code)
	require.Equal(t, http.StatusCreated, postWorkflow(t, router, "/workflows", minimalWorkflowBody("other-wf")).Code)

	createManualTrigger(t, mgr, "test-tenant", "t-on-1", "trig-wf", true)
	createManualTrigger(t, mgr, "test-tenant", "t-on-2", "trig-wf", true)
	createManualTrigger(t, mgr, "test-tenant", "t-off", "trig-wf", false)
	createManualTrigger(t, mgr, "test-tenant", "t-other", "other-wf", true)
	// Another tenant's trigger for the same workflow name is never counted.
	createManualTrigger(t, mgr, "tenant-b", "t-foreign", "trig-wf", true)

	got, _ := listWorkflowSummaries(t, router, "test-tenant")
	assert.Equal(t, 3, got["trig-wf"].TriggerCount)
	assert.Equal(t, 2, got["trig-wf"].EnabledTriggerCount)
	assert.Equal(t, 1, got["other-wf"].TriggerCount)
	assert.Equal(t, 1, got["other-wf"].EnabledTriggerCount)
}

func TestWorkflowHandler_ListWorkflows_LastExecutionIsTenantScoped(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	// The same workflow name exists in both tenants; each has its own run.
	execA := createAndExecuteWorkflow(t, router, engine, "shared-wf", "tenant-a", false)
	time.Sleep(10 * time.Millisecond)
	execB := createAndExecuteWorkflow(t, router, engine, "shared-wf", "tenant-b", false)
	require.NotEqual(t, execA, execB)

	gotA, _ := listWorkflowSummaries(t, router, "tenant-a")
	require.NotNil(t, gotA["shared-wf"].LastExecution)
	assert.Equal(t, execA, gotA["shared-wf"].LastExecution.ID, "tenant A must never see tenant B's run")
	assert.NotEmpty(t, gotA["shared-wf"].LastExecution.Status)
	assert.NotEmpty(t, gotA["shared-wf"].LastExecution.StartTime)

	gotB, _ := listWorkflowSummaries(t, router, "tenant-b")
	require.NotNil(t, gotB["shared-wf"].LastExecution)
	assert.Equal(t, execB, gotB["shared-wf"].LastExecution.ID)
}

func TestWorkflowHandler_ListWorkflows_LastExecutionIsMostRecent(t *testing.T) {
	h, _, engine := newTestWorkflowHandlerAndEngine(t)
	router := newWorkflowRouter(h)

	createAndExecuteWorkflow(t, router, engine, "recent-wf", "test-tenant", false)
	time.Sleep(10 * time.Millisecond)
	req := withTenantContext(httptest.NewRequest("POST", "/workflows/recent-wf/execute", bytes.NewReader([]byte("{}"))), "test-tenant")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

	got, _ := listWorkflowSummaries(t, router, "test-tenant")
	require.NotNil(t, got["recent-wf"].LastExecution)
	assert.Equal(t, resp["execution_id"], got["recent-wf"].LastExecution.ID)
}
