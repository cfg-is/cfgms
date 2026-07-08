// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	reportapi "github.com/cfgis/cfgms/features/reports/api"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServer_SetWorkflowHandler_RegistersRoutes_PostConstruction verifies that
// workflow and trigger routes are present when SetWorkflowHandler is called after
// New() — the production wiring order.  An unauthenticated request must return 401
// (auth middleware fired) not 404 (route absent).
func TestServer_SetWorkflowHandler_RegistersRoutes_PostConstruction(t *testing.T) {
	server := setupTestServer(t)

	// No workflow handler has been set; route must be absent (404).
	req := httptest.NewRequest("POST", "/api/v1/workflows", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"workflow route must be 404 before SetWorkflowHandler")

	// Wire a handler exactly as production does: after New() returns.
	// Include a real trigger manager so trigger routes are also registered.
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logging.NewNoopLogger(), nil, nil, nil)
	triggerMgr := trigger.NewControllerTriggerManager(nil, nil)
	handler := NewWorkflowHandler(engine, nil, triggerMgr, logging.NewNoopLogger())
	server.SetWorkflowHandler(handler)

	// Unauthenticated POST /api/v1/workflows must now return 401 (route present,
	// auth middleware rejected the caller) rather than 404.
	req = httptest.NewRequest("POST", "/api/v1/workflows", nil)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"POST /api/v1/workflows must return 401 after SetWorkflowHandler (auth enforced, not 404)")

	// Trigger routes must also be live after SetWorkflowHandler.
	req = httptest.NewRequest("GET", "/api/v1/triggers", nil)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"GET /api/v1/triggers must return 401 after SetWorkflowHandler (auth enforced, not 404)")
}

// TestServer_SetReportsHandler_RegistersRoutes_PostConstruction verifies that reports
// routes are live when SetReportsHandler is called after New() — the production wiring
// order.  An unauthenticated request must return 401, not 404.
func TestServer_SetReportsHandler_RegistersRoutes_PostConstruction(t *testing.T) {
	server := setupTestServer(t)

	// Route must be absent before SetReportsHandler.
	req := httptest.NewRequest("GET", "/api/v1/reports/dashboard/overview", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"reports route must be 404 before SetReportsHandler")

	// Wire the handler post-construction, exactly as production does.
	h := reportapi.New(nil, nil, logging.NewNoopLogger())
	server.SetReportsHandler(h)

	// Unauthenticated request must now return 401, not 404.
	req = httptest.NewRequest("GET", "/api/v1/reports/dashboard/overview", nil)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"GET /api/v1/reports/dashboard/overview must return 401 after SetReportsHandler (auth enforced, not 404)")
}

// TestServer_SetRollbackManager_RegistersRoutes_PostConstruction verifies that rollback
// routes are live when SetRollbackManager is called after New() — the production wiring
// order.  An unauthenticated request must return 401, not 404.
func TestServer_SetRollbackManager_RegistersRoutes_PostConstruction(t *testing.T) {
	server := setupTestServer(t)

	// Route must be absent before SetRollbackManager.
	req := httptest.NewRequest("GET", "/api/v1/rollback/points", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"rollback route must be 404 before SetRollbackManager")

	// Wire the manager post-construction, exactly as production does.
	server.SetRollbackManager(&testRollbackManager{})

	// Unauthenticated request must now return 401, not 404.
	req = httptest.NewRequest("GET", "/api/v1/rollback/points", nil)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"GET /api/v1/rollback/points must return 401 after SetRollbackManager (auth enforced, not 404)")
}

// TestServer_SetRollbackManager_EnforcesPermissionGate verifies that the config/rollback
// permission gate is applied to rollback routes when they are lazily registered.
// A caller with a valid API key but without config:rollback permission must receive 403.
func TestServer_SetRollbackManager_EnforcesPermissionGate(t *testing.T) {
	server := setupTestServer(t)
	server.SetRollbackManager(&testRollbackManager{})

	// Key without config:rollback permission.
	noPermKey := NewTestKey(t, server, []string{"steward:read"})
	req := httptest.NewRequest("GET", "/api/v1/rollback/points", nil)
	req.Header.Set("X-API-Key", noPermKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"rollback route must return 403 for caller without config:rollback permission")

	// Key with config:rollback permission must pass the gate (handler response, not 403 or 404).
	permKey := NewTestKey(t, server, []string{"config:rollback"})
	req = httptest.NewRequest("GET", "/api/v1/rollback/points", nil)
	req.Header.Set("X-API-Key", permKey)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"rollback route must not return 403 for caller with config:rollback permission")
	assert.NotEqual(t, http.StatusNotFound, rec.Code,
		"rollback route must not return 404 for caller with config:rollback permission")
}

// TestServer_SetWorkflowHandler_NilHandler_NoopSafe re-verifies (regression guard) that
// passing nil to SetWorkflowHandler does not panic and leaves workflowHandler nil.
func TestServer_SetWorkflowHandler_NilAfterSet_NoopSafe(t *testing.T) {
	server := setupTestServer(t)
	engine := workflow.NewEngine(workflow.NewWorkflowModuleFactory(nil, nil), logging.NewNoopLogger(), nil, nil, nil)
	handler := NewWorkflowHandler(engine, nil, nil, logging.NewNoopLogger())
	server.SetWorkflowHandler(handler)

	// Calling again with nil must not panic.
	assert.NotPanics(t, func() {
		server.SetWorkflowHandler(nil)
	}, "SetWorkflowHandler(nil) must not panic even after a prior non-nil set")
}
