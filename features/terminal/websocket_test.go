// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	testutil "github.com/cfgis/cfgms/pkg/testing"
)

// withTestTenant wraps an http.Handler to inject a test tenant ID into the request context.
func withTestTenant(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), ctxkeys.TenantID, "test-tenant")
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getTestShell returns the appropriate shell for the current platform
func getTestShell() string {
	if runtime.GOOS == "windows" {
		return "powershell"
	}
	return "bash"
}

// waitForSessionCleanup waits for sessions to be cleaned up with exponential backoff
func waitForSessionCleanup(t *testing.T, manager SessionManager, expectedCount int) {
	t.Helper()

	maxRetries := 10
	retryDelay := 10 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		time.Sleep(retryDelay)
		activeSessions := manager.GetActiveSessions()
		if len(activeSessions) == expectedCount {
			return
		}
		retryDelay *= 2 // Exponential backoff
		if retryDelay > 500*time.Millisecond {
			retryDelay = 500 * time.Millisecond // Cap at 500ms
		}
	}

	// Final assertion with detailed message
	activeSessions := manager.GetActiveSessions()
	assert.Len(t, activeSessions, expectedCount, "Expected %d sessions after cleanup, but found %d", expectedCount, len(activeSessions))
}

func TestWebSocketHandlerCreation(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)
	assert.NotNil(t, handler)
}

func TestWebSocketUpgrade(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)

	// Create test server with tenant middleware
	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Test WebSocket connection (use platform-appropriate shell)
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), headers)
	require.NoError(t, err)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Connection should be established
	assert.NotNil(t, conn)

	// Test connection close
	err = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	assert.NoError(t, err)
}

func TestWebSocketMessageHandling(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)

	// Create test server with tenant middleware
	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket (use platform-appropriate shell)
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), headers)
	require.NoError(t, err)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Test data message
	dataMsg := &TerminalMessage{
		Type: MessageTypeData,
		Data: []byte("echo 'hello world'\n"),
	}

	err = conn.WriteJSON(dataMsg)
	assert.NoError(t, err)

	// Test resize message
	resizeMsg := &TerminalMessage{
		Type: MessageTypeResize,
		Data: []byte(`{"cols": 120, "rows": 30}`),
	}

	err = conn.WriteJSON(resizeMsg)
	assert.NoError(t, err)

	// Give server time to process
	time.Sleep(100 * time.Millisecond)
}

func TestWebSocketAuthentication(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)

	tests := []struct {
		name       string
		queryPath  string
		wantStatus int
	}{
		{
			name:       "valid parameters",
			queryPath:  "?steward_id=test-steward&user_id=test-user&shell=bash",
			wantStatus: http.StatusSwitchingProtocols,
		},
		{
			name:       "missing steward_id",
			queryPath:  "?user_id=test-user&shell=bash",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "missing user_id",
			queryPath:  "?steward_id=test-steward&shell=bash",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid shell",
			queryPath:  "?steward_id=test-steward&user_id=test-user&shell=invalid",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "no parameters",
			queryPath:  "",
			wantStatus: http.StatusBadRequest,
		},
		{
			// All query params valid, but auth middleware has not set TenantID in context.
			name:       "missing tenant in context",
			queryPath:  "?steward_id=test-steward&user_id=test-user&shell=bash",
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// "valid parameters" requires the tenant ID to be present in context.
			var srv http.Handler = http.HandlerFunc(handler.HandleWebSocket)
			if tt.wantStatus == http.StatusSwitchingProtocols {
				srv = withTestTenant(srv)
			}

			// Create test server
			server := httptest.NewServer(srv)
			defer func() {
				server.Close() // Test server close doesn't return error
			}()

			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + tt.queryPath

			// Set same-origin header so the upgrader passes origin validation
			headers := http.Header{"Origin": {server.URL}}
			conn, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)

			if tt.wantStatus == http.StatusSwitchingProtocols {
				require.NoError(t, err)
				require.NotNil(t, conn)
				if err := conn.Close(); err != nil {
					t.Logf("Failed to close connection: %v", err)
				}
			} else {
				require.Error(t, err)
				require.NotNil(t, resp)
				assert.Equal(t, tt.wantStatus, resp.StatusCode)
			}
		})
	}
}

func TestWebSocketBidirectionalCommunication(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)

	// Create test server with tenant middleware
	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket (use platform-appropriate shell)
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), headers)
	require.NoError(t, err)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}()

	// Send command
	inputMsg := &TerminalMessage{
		Type: MessageTypeData,
		Data: []byte("echo 'test'\n"),
	}

	err = conn.WriteJSON(inputMsg)
	require.NoError(t, err)

	// Read response (in real implementation, this would come from the shell)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Logf("Failed to set read deadline: %v", err)
	}
	var outputMsg TerminalMessage
	err = conn.ReadJSON(&outputMsg)

	// In this test, we expect either an acknowledgment or timeout
	// The actual shell output would come through the steward connection
	if err == nil {
		assert.NotEmpty(t, outputMsg.Type)
	}
}

func TestWebSocketSessionCleanup(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)

	// Create test server with tenant middleware
	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket (use platform-appropriate shell)
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), headers)
	require.NoError(t, err)

	// Wait for session to be created (session creation is asynchronous)
	time.Sleep(100 * time.Millisecond)

	// Check that session was created
	activeSessions := manager.GetActiveSessions()
	assert.Len(t, activeSessions, 1)

	// Close connection
	if err := conn.Close(); err != nil {
		t.Logf("Failed to close connection: %v", err)
	}

	// Wait for session cleanup (cleanup is asynchronous)
	waitForSessionCleanup(t, manager, 0)
}

func TestWebSocketConcurrentConnections(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    10,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, logger, nil)
	require.NoError(t, err)

	// Create test server with tenant middleware
	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Create multiple concurrent connections (use platform-appropriate shell)
	connections := make([]*websocket.Conn, 3)
	headers := http.Header{"Origin": {server.URL}}
	for i := 0; i < 3; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(
			wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
			headers,
		)
		require.NoError(t, err)
		connections[i] = conn
	}

	// Give connections time to establish sessions
	time.Sleep(100 * time.Millisecond)

	// All sessions should be active
	activeSessions := manager.GetActiveSessions()
	assert.Len(t, activeSessions, 3)

	// Clean up connections
	for _, conn := range connections {
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	}

	// Wait for all sessions to be cleaned up (cleanup is asynchronous)
	waitForSessionCleanup(t, manager, 0)
}

// TestWebSocketOriginCheck verifies the origin enforcement logic.
func TestWebSocketOriginCheck(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	const queryParams = "?steward_id=test-steward&user_id=test-user&shell=bash"

	t.Run("same_origin_accepted", func(t *testing.T) {
		handler, err := NewWebSocketHandler(manager, logger, nil)
		require.NoError(t, err)

		server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + queryParams
		headers := http.Header{"Origin": {server.URL}}
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
		require.NoError(t, err, "same-origin request must be accepted")
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	})

	t.Run("cross_origin_rejected", func(t *testing.T) {
		handler, err := NewWebSocketHandler(manager, logger, nil)
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + queryParams
		headers := http.Header{"Origin": {"http://evil.example.com"}}
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, headers)
		require.Error(t, err, "cross-origin request must be rejected")
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("allowlist_origin_accepted", func(t *testing.T) {
		allowlist := []string{"trusted.example.com"}
		handler, err := NewWebSocketHandler(manager, logger, allowlist)
		require.NoError(t, err)

		server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + queryParams
		headers := http.Header{"Origin": {"http://trusted.example.com"}}
		conn, _, err := websocket.DefaultDialer.Dial(wsURL, headers)
		require.NoError(t, err, "allowlist-matched origin must be accepted")
		if err := conn.Close(); err != nil {
			t.Logf("Failed to close connection: %v", err)
		}
	})

	t.Run("empty_origin_rejected", func(t *testing.T) {
		handler, err := NewWebSocketHandler(manager, logger, nil)
		require.NoError(t, err)

		server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
		defer server.Close()

		wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + queryParams
		// No Origin header
		_, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
		require.Error(t, err, "missing Origin header must be rejected")
		require.NotNil(t, resp)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}

// TestGenerateSecureToken verifies the token is cryptographically random and properly encoded.
func TestGenerateSecureToken(t *testing.T) {
	token, err := generateSecureToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	// Must decode as valid base64url
	decoded, err := base64.URLEncoding.DecodeString(token)
	require.NoError(t, err, "token must be valid base64url-encoded")

	// 32 bytes of entropy → 44-char base64 with padding (or 43 without)
	assert.Equal(t, 32, len(decoded), "decoded token must be 32 bytes")

	// Two consecutive tokens must differ
	token2, err := generateSecureToken()
	require.NoError(t, err)
	assert.NotEqual(t, token, token2, "tokens must be unique")

	// Must not contain time or PID markers from the old format
	assert.NotContains(t, token, "terminal_token_")
}

// sessionIDInEntry returns the "session_id" value from the first log entry whose
// message exactly matches msg. Returns ("", false) when not found.
func sessionIDInEntry(entries []kvLogEntry, msg string) (string, bool) {
	for _, e := range entries {
		if e.msg != msg {
			continue
		}
		for i := 0; i+1 < len(e.kvs); i += 2 {
			if k, ok := e.kvs[i].(string); ok && k == "session_id" {
				if v, ok := e.kvs[i+1].(string); ok {
					return v, true
				}
			}
		}
	}
	return "", false
}

// failConn wraps net.Conn to return an error on Write when failWrites is set.
// Used to simulate a broken write path while leaving reads intact so that
// readMessages stays blocked and writeMessages can attempt (and fail) a ping.
type failConn struct {
	net.Conn
	mu         sync.Mutex
	failWrites bool
}

func (c *failConn) setFailWrites(v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failWrites = v
}

func (c *failConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	fail := c.failWrites
	c.mu.Unlock()
	if fail {
		return 0, net.ErrClosed
	}
	return c.Conn.Write(b)
}

// failListener wraps net.Listener and returns failConn wrappers so tests can
// inject write failures on all accepted connections after the fact.
type failListener struct {
	net.Listener
	mu    sync.Mutex
	conns []*failConn
}

func (l *failListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	fc := &failConn{Conn: conn}
	l.mu.Lock()
	l.conns = append(l.conns, fc)
	l.mu.Unlock()
	return fc, nil
}

func (l *failListener) setAllFailWrites(v bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.setFailWrites(v)
	}
}

// TestWebSocketSessionIDRedaction_Established verifies that the Info log
// "WebSocket terminal session established" passes session_id through RedactedID.
func TestWebSocketSessionIDRedaction_Established(t *testing.T) {
	capLogger := &kvCapturingLogger{}
	config := &Config{SessionTimeout: 30 * time.Minute, MaxSessions: 100, RecordSessions: true}
	manager, err := NewSessionManager(config, capLogger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, capLogger, nil)
	require.NoError(t, err)

	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(
		wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
		headers,
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Wait for session to be established and the log entry to be written.
	time.Sleep(100 * time.Millisecond)

	sessions := manager.GetActiveSessions()
	require.Len(t, sessions, 1)
	sessionID := sessions[0].ID

	entries := capLogger.allEntries()
	value, found := sessionIDInEntry(entries, "WebSocket terminal session established")
	require.True(t, found, "expected 'WebSocket terminal session established' log entry with session_id")
	assert.Equal(t, logging.RedactedID(sessionID), value, "session_id must be redacted in established log")
	assert.NotEqual(t, sessionID, value, "raw session ID must not appear in log")
	assert.True(t, strings.HasSuffix(value, "…"), "redacted ID must end with ellipsis")
}

// TestWebSocketSessionIDRedaction_Ended verifies that the Info log
// "WebSocket terminal session ended" passes session_id through RedactedID.
func TestWebSocketSessionIDRedaction_Ended(t *testing.T) {
	capLogger := &kvCapturingLogger{}
	config := &Config{SessionTimeout: 30 * time.Minute, MaxSessions: 100, RecordSessions: true}
	manager, err := NewSessionManager(config, capLogger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, capLogger, nil)
	require.NoError(t, err)

	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(
		wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
		headers,
	)
	require.NoError(t, err)

	// Wait for session to establish, then capture the session ID.
	time.Sleep(100 * time.Millisecond)
	sessions := manager.GetActiveSessions()
	require.Len(t, sessions, 1)
	sessionID := sessions[0].ID

	// Close the connection gracefully to trigger the session-ended log.
	_ = conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	_ = conn.Close()

	// Wait for HandleWebSocket to log "session ended".
	time.Sleep(200 * time.Millisecond)

	entries := capLogger.allEntries()
	value, found := sessionIDInEntry(entries, "WebSocket terminal session ended")
	require.True(t, found, "expected 'WebSocket terminal session ended' log entry with session_id")
	assert.Equal(t, logging.RedactedID(sessionID), value, "session_id must be redacted in ended log")
	assert.NotEqual(t, sessionID, value, "raw session ID must not appear in log")
	assert.True(t, strings.HasSuffix(value, "…"), "redacted ID must end with ellipsis")
}

// TestWebSocketSessionIDRedaction_ReadError verifies that the Warn log
// "WebSocket read error" passes session_id through RedactedID.
// A NormalClosure (1000) close frame is not in the server's expected-codes list
// [GoingAway, AbnormalClosure], so IsUnexpectedCloseError returns true and the
// Warn is emitted.
func TestWebSocketSessionIDRedaction_ReadError(t *testing.T) {
	capLogger := &kvCapturingLogger{}
	config := &Config{SessionTimeout: 30 * time.Minute, MaxSessions: 100, RecordSessions: true}
	manager, err := NewSessionManager(config, capLogger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, capLogger, nil)
	require.NoError(t, err)

	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(
		wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
		headers,
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	time.Sleep(100 * time.Millisecond)
	sessions := manager.GetActiveSessions()
	require.Len(t, sessions, 1)
	sessionID := sessions[0].ID

	// Send NormalClosure (1000) — not in server's expected-codes list → Warn logged.
	_ = conn.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))

	time.Sleep(200 * time.Millisecond)

	entries := capLogger.allEntries()
	value, found := sessionIDInEntry(entries, "WebSocket read error")
	require.True(t, found, "expected 'WebSocket read error' log entry with session_id")
	assert.Equal(t, logging.RedactedID(sessionID), value, "session_id must be redacted in read-error log")
	assert.NotEqual(t, sessionID, value, "raw session ID must not appear in log")
	assert.True(t, strings.HasSuffix(value, "…"), "redacted ID must end with ellipsis")
}

// TestWebSocketSessionIDRedaction_HandleMessageError verifies that the Error log
// "Failed to handle message" passes session_id through RedactedID.
// A Resize message with invalid JSON triggers the error path.
func TestWebSocketSessionIDRedaction_HandleMessageError(t *testing.T) {
	capLogger := &kvCapturingLogger{}
	config := &Config{SessionTimeout: 30 * time.Minute, MaxSessions: 100, RecordSessions: true}
	manager, err := NewSessionManager(config, capLogger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, capLogger, nil)
	require.NoError(t, err)

	server := httptest.NewServer(withTestTenant(http.HandlerFunc(handler.HandleWebSocket)))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	headers := http.Header{"Origin": {server.URL}}
	conn, _, err := websocket.DefaultDialer.Dial(
		wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
		headers,
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	time.Sleep(100 * time.Millisecond)
	sessions := manager.GetActiveSessions()
	require.Len(t, sessions, 1)
	sessionID := sessions[0].ID

	// Send a Resize message with invalid JSON data to trigger handleMessage error.
	badMsg := &TerminalMessage{
		Type: MessageTypeResize,
		Data: []byte("not-valid-json"),
	}
	err = conn.WriteJSON(badMsg)
	require.NoError(t, err)

	time.Sleep(200 * time.Millisecond)

	entries := capLogger.allEntries()
	value, found := sessionIDInEntry(entries, "Failed to handle message")
	require.True(t, found, "expected 'Failed to handle message' log entry with session_id")
	assert.Equal(t, logging.RedactedID(sessionID), value, "session_id must be redacted in handle-message-error log")
	assert.NotEqual(t, sessionID, value, "raw session ID must not appear in log")
	assert.True(t, strings.HasSuffix(value, "…"), "redacted ID must end with ellipsis")
}

// TestWebSocketSessionIDRedaction_PingFailure verifies that the Warn log
// "Failed to send ping" passes session_id through RedactedID.
// A failListener injects write failures on the server-side connection while
// leaving reads unblocked, so readMessages keeps running and the ping ticker
// can fire and fail.
func TestWebSocketSessionIDRedaction_PingFailure(t *testing.T) {
	capLogger := &kvCapturingLogger{}
	config := &Config{SessionTimeout: 30 * time.Minute, MaxSessions: 100, RecordSessions: true}
	manager, err := NewSessionManager(config, capLogger)
	require.NoError(t, err)

	handler, err := NewWebSocketHandler(manager, capLogger, nil)
	require.NoError(t, err)
	handler.pingInterval = 50 * time.Millisecond

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	fl := &failListener{Listener: rawLn}

	httpServer := &http.Server{
		Handler: withTestTenant(http.HandlerFunc(handler.HandleWebSocket)),
	}
	go func() { _ = httpServer.Serve(fl) }()
	defer func() { _ = httpServer.Close() }()

	wsURL := "ws://" + rawLn.Addr().String()
	headers := http.Header{"Origin": {"http://" + rawLn.Addr().String()}}
	conn, _, err := websocket.DefaultDialer.Dial(
		wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
		headers,
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	// Wait for the session to be established (first ping may already have succeeded).
	time.Sleep(100 * time.Millisecond)
	sessions := manager.GetActiveSessions()
	require.Len(t, sessions, 1)
	sessionID := sessions[0].ID

	// Fail all server-side writes; the next ping tick (≤50 ms away) will fail.
	fl.setAllFailWrites(true)

	// Wait for at least two ping intervals so the failure is certain to have fired.
	time.Sleep(150 * time.Millisecond)

	entries := capLogger.allEntries()
	value, found := sessionIDInEntry(entries, "Failed to send ping")
	require.True(t, found, "expected 'Failed to send ping' log entry with session_id")
	assert.Equal(t, logging.RedactedID(sessionID), value, "session_id must be redacted in ping-failure log")
	assert.NotEqual(t, sessionID, value, "raw session ID must not appear in log")
	assert.True(t, strings.HasSuffix(value, "…"), "redacted ID must end with ellipsis")

	// Close the client to unblock readMessages so the goroutine can finish.
	_ = conn.Close()
	waitForSessionCleanup(t, manager, 0)
}
