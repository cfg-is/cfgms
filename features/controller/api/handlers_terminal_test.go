// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newRealTerminalWSHandler builds a real terminal.DefaultWebSocketHandler backed
// by a real terminal.DefaultSessionManager (no mocks or fakes). The returned
// session manager can be queried to observe what SetTerminalHandler's mux
// path-variable injection actually delivered to the handler. Recording storage
// is isolated in t.TempDir().
func newRealTerminalWSHandler(t *testing.T) (terminal.WebSocketHandler, terminal.SessionManager) {
	t.Helper()
	sessionMgr, err := terminal.NewSessionManager(&terminal.Config{
		RecordSessions:       true,
		RecordingStoragePath: t.TempDir(),
		SessionTimeout:       30 * time.Minute,
		MaxSessions:          100,
	}, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		if dsm, ok := sessionMgr.(*terminal.DefaultSessionManager); ok {
			_ = dsm.Stop(context.Background())
		}
	})

	// nil origin allowlist → same-origin only, which is satisfied when the test
	// dials the httptest server with an Origin matching that server's host.
	wsHandler, err := terminal.NewWebSocketHandler(sessionMgr, logging.NewNoopLogger(), nil)
	require.NoError(t, err)
	return wsHandler, sessionMgr
}

// wsURL converts an httptest server's http(s):// URL into a ws(s):// dial URL,
// appending the given path+query.
func wsURL(serverURL, pathAndQuery string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + pathAndQuery
}

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

	// Wire a real handler post-construction, exactly as production does.
	handler, _ := newRealTerminalWSHandler(t)
	server.SetTerminalHandler(handler)

	// Unauthenticated request must now return 401 (route present, auth enforced
	// by the middleware before HandleWebSocket runs), not 404.
	req = httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"GET /api/v1/terminal/ws/{steward_id} must return 401 after SetTerminalHandler (auth enforced, not 404)")
}

// TestServer_SetTerminalHandler_EnforcesPermissionGate verifies the
// steward:terminal RBAC gate is applied to the terminal route. A caller with a
// valid API key but without steward:terminal must receive 403 (returned by the
// auth middleware before HandleWebSocket is invoked); a caller with the
// permission must pass the gate and reach the real handler.
func TestServer_SetTerminalHandler_EnforcesPermissionGate(t *testing.T) {
	server := setupTestServer(t)
	handler, _ := newRealTerminalWSHandler(t)
	server.SetTerminalHandler(handler)

	// Key without steward:terminal permission → 403 (gate, before the handler).
	noPermKey := NewTestKey(t, server, []string{"steward:read"})
	req := httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	req.Header.Set("X-API-Key", noPermKey)
	req.Header.Set("Origin", "http://example.com") // matches httptest default host
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"terminal route must return 403 for caller without steward:terminal permission")

	// Key with steward:terminal permission must pass the gate and reach the real
	// handler. The request omits user_id, so the handler rejects it with 400 after
	// the gate — the point being it is neither 403 (gate) nor 404 (route absent).
	permKey := NewTestKey(t, server, []string{"steward:terminal"})
	req = httptest.NewRequest("GET", "/api/v1/terminal/ws/steward-1", nil)
	req.Header.Set("X-API-Key", permKey)
	req.Header.Set("Origin", "http://example.com")
	rec = httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"terminal route must not return 403 for caller with steward:terminal permission")
	assert.NotEqual(t, http.StatusNotFound, rec.Code,
		"terminal route must not return 404 for caller with steward:terminal permission")
}

// TestServer_SetTerminalHandler_InjectsStewardIDPathVar verifies that the mux
// {steward_id} path variable is injected into the query string so the pre-built
// WebSocket handler observes it. It opens a real WebSocket connection through the
// full server stack (auth + RBAC gate + mux injection + real handler) and asserts
// that the session the real handler created carries the injected steward_id.
func TestServer_SetTerminalHandler_InjectsStewardIDPathVar(t *testing.T) {
	server := setupTestServer(t)
	handler, sessionMgr := newRealTerminalWSHandler(t)
	server.SetTerminalHandler(handler)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	permKey := NewTestKey(t, server, []string{"steward:terminal"})
	header := http.Header{}
	header.Set("X-API-Key", permKey)
	header.Set("Origin", ts.URL) // same-origin as the httptest server

	conn, resp, err := websocket.DefaultDialer.Dial(
		wsURL(ts.URL, "/api/v1/terminal/ws/steward-xyz?user_id=u1&shell=bash"),
		header,
	)
	require.NoError(t, err, "authorized WebSocket dial must succeed")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	defer func() { _ = conn.Close() }()

	// The real handler creates the session after the upgrade; poll until it
	// appears, then assert it observed the injected {steward_id} path variable.
	require.Eventually(t, func() bool {
		return len(sessionMgr.GetActiveSessions()) == 1
	}, 2*time.Second, 10*time.Millisecond,
		"authorized request must reach the wrapped WebSocket handler and create a session")

	sessions := sessionMgr.GetActiveSessions()
	require.Len(t, sessions, 1)
	assert.Equal(t, "steward-xyz", sessions[0].StewardID,
		"mux {steward_id} path variable must be injected so the handler creates the session for it")
}

// TestServer_SetTerminalHandler_ExplicitQueryNotOverwritten verifies that an
// explicit steward_id in the query string is preserved (the injection only fills
// an empty value). It dials a real WebSocket whose path steward_id differs from an
// explicit query steward_id and asserts the created session used the query value.
func TestServer_SetTerminalHandler_ExplicitQueryNotOverwritten(t *testing.T) {
	server := setupTestServer(t)
	handler, sessionMgr := newRealTerminalWSHandler(t)
	server.SetTerminalHandler(handler)

	ts := httptest.NewServer(server.router)
	defer ts.Close()

	permKey := NewTestKey(t, server, []string{"steward:terminal"})
	header := http.Header{}
	header.Set("X-API-Key", permKey)
	header.Set("Origin", ts.URL)

	conn, resp, err := websocket.DefaultDialer.Dial(
		wsURL(ts.URL, "/api/v1/terminal/ws/path-steward?steward_id=query-steward&user_id=u1&shell=bash"),
		header,
	)
	require.NoError(t, err, "authorized WebSocket dial must succeed")
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)
	defer func() { _ = conn.Close() }()

	require.Eventually(t, func() bool {
		return len(sessionMgr.GetActiveSessions()) == 1
	}, 2*time.Second, 10*time.Millisecond,
		"authorized request must reach the wrapped WebSocket handler and create a session")

	sessions := sessionMgr.GetActiveSessions()
	require.Len(t, sessions, 1)
	assert.Equal(t, "query-steward", sessions[0].StewardID,
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
