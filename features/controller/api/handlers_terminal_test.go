// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal"
)

// capturingWSHandler is a hand-written test double for terminal.WebSocketHandler
// (not a mock framework) that records whether it was invoked and what steward_id
// it observed on the request query string. It lets these tests assert route
// registration, RBAC gating, and mux path-variable injection without opening a
// real WebSocket connection.
type capturingWSHandler struct {
	mu        sync.Mutex
	called    bool
	stewardID string
}

func (c *capturingWSHandler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.called = true
	c.stewardID = r.URL.Query().Get("steward_id")
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(r.URL.Query().Get("steward_id")))
}

func (c *capturingWSHandler) observed() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.called, c.stewardID
}

// Compile-time check: the double satisfies the interface SetTerminalHandler wants.
var _ terminal.WebSocketHandler = (*capturingWSHandler)(nil)

// TestServer_SetTerminalHandler_RegistersRoute_PostConstruction verifies that the
// terminal WebSocket route is absent until SetTerminalHandler is called, then
// present afterwards (an unauthenticated request returns 401, not 404).
func TestServer_SetTerminalHandler_RegistersRoute_PostConstruction(t *testing.T) {
	server := setupTestServer(t)

	// Route must be absent before SetTerminalHandler.
	req := httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"terminal route must be 404 before SetTerminalHandler")

	// Wire a handler post-construction, exactly as production does.
	server.SetTerminalHandler(&capturingWSHandler{})

	// Unauthenticated request must now return 401 (route present, auth enforced),
	// not 404.
	req = httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"GET /api/v1/terminal/ws/{steward_id} must return 401 after SetTerminalHandler (auth enforced, not 404)")
}

// TestServer_SetTerminalHandler_EnforcesPermissionGate verifies the
// steward:terminal RBAC gate is applied to the terminal route. A caller with a
// valid API key but without steward:terminal must receive 403; a caller with the
// permission must pass the gate.
func TestServer_SetTerminalHandler_EnforcesPermissionGate(t *testing.T) {
	server := setupTestServer(t)
	server.SetTerminalHandler(&capturingWSHandler{})

	// Key without steward:terminal permission → 403.
	noPermKey := NewTestKey(t, server, []string{"steward:read"})
	req := httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	req.Header.Set("X-API-Key", noPermKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"terminal route must return 403 for caller without steward:terminal permission")

	// Key with steward:terminal permission must pass the gate.
	permKey := NewTestKey(t, server, []string{"steward:terminal"})
	req = httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	req.Header.Set("X-API-Key", permKey)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"terminal route must not return 403 for caller with steward:terminal permission")
	assert.NotEqual(t, http.StatusNotFound, rec.Code,
		"terminal route must not return 404 for caller with steward:terminal permission")
}

// TestServer_SetTerminalHandler_InjectsStewardIDPathVar verifies that the mux
// {steward_id} path variable is injected into the query string so the pre-built
// WebSocket handler can read it via r.URL.Query().Get("steward_id").
func TestServer_SetTerminalHandler_InjectsStewardIDPathVar(t *testing.T) {
	server := setupTestServer(t)
	capture := &capturingWSHandler{}
	server.SetTerminalHandler(capture)

	permKey := NewTestKey(t, server, []string{"steward:terminal"})
	req := httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-xyz", nil)
	req.Header.Set("X-API-Key", permKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	called, stewardID := capture.observed()
	require.True(t, called, "authorized request must reach the wrapped WebSocket handler")
	assert.Equal(t, "steward-xyz", stewardID,
		"mux {steward_id} path variable must be injected into the query string")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "steward-xyz", rec.Body.String(),
		"wrapped handler must observe the injected steward_id")
}

// TestServer_SetTerminalHandler_ExplicitQueryNotOverwritten verifies that an
// explicit steward_id in the query string is preserved (the injection only fills
// an empty value).
func TestServer_SetTerminalHandler_ExplicitQueryNotOverwritten(t *testing.T) {
	server := setupTestServer(t)
	capture := &capturingWSHandler{}
	server.SetTerminalHandler(capture)

	permKey := NewTestKey(t, server, []string{"steward:terminal"})
	req := httptest.NewRequest("GET", "/api/v1/terminal/ws/path-steward?steward_id=query-steward", nil)
	req.Header.Set("X-API-Key", permKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	_, stewardID := capture.observed()
	assert.Equal(t, "query-steward", stewardID,
		"an explicit steward_id query value must not be overwritten by the path variable")
}

// TestServer_SetTerminalHandler_NilHandler_NoopSafe verifies that passing nil to
// SetTerminalHandler does not register a route and does not panic.
func TestServer_SetTerminalHandler_NilHandler_NoopSafe(t *testing.T) {
	server := setupTestServer(t)

	assert.NotPanics(t, func() {
		server.SetTerminalHandler(nil)
	}, "SetTerminalHandler(nil) must not panic")

	// No route must have been registered.
	req := httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code,
		"terminal route must remain absent (404) after SetTerminalHandler(nil)")
}
