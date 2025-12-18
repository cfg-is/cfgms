// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package terminal

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testutil "github.com/cfgis/cfgms/pkg/testing"
)

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

	handler, err := NewWebSocketHandler(manager, logger)
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

	handler, err := NewWebSocketHandler(manager, logger)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Test WebSocket connection (use platform-appropriate shell)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), nil)
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

	handler, err := NewWebSocketHandler(manager, logger)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket (use platform-appropriate shell)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), nil)
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

	handler, err := NewWebSocketHandler(manager, logger)
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
			defer func() {
				server.Close() // Test server close doesn't return error
			}()

			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + tt.queryPath

			// Attempt WebSocket connection
			conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)

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

	handler, err := NewWebSocketHandler(manager, logger)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket (use platform-appropriate shell)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), nil)
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

	handler, err := NewWebSocketHandler(manager, logger)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket (use platform-appropriate shell)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(), nil)
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

	handler, err := NewWebSocketHandler(manager, logger)
	require.NoError(t, err)

	// Create test server
	server := httptest.NewServer(http.HandlerFunc(handler.HandleWebSocket))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Create multiple concurrent connections (use platform-appropriate shell)
	connections := make([]*websocket.Conn, 3)
	for i := 0; i < 3; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(
			wsURL+"?steward_id=test-steward&user_id=test-user&shell="+getTestShell(),
			nil,
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
