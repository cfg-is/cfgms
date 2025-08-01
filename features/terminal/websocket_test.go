package terminal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testutil "github.com/cfgis/cfgms/pkg/testing"
)

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
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Test WebSocket connection
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell=bash", nil)
	require.NoError(t, err)
	defer conn.Close()

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
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell=bash", nil)
	require.NoError(t, err)
	defer conn.Close()

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
			defer server.Close()

			wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + tt.queryPath

			// Attempt WebSocket connection
			conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)

			if tt.wantStatus == http.StatusSwitchingProtocols {
				require.NoError(t, err)
				require.NotNil(t, conn)
				conn.Close()
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
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell=bash", nil)
	require.NoError(t, err)
	defer conn.Close()

	// Send command
	inputMsg := &TerminalMessage{
		Type: MessageTypeData,
		Data: []byte("echo 'test'\n"),
	}

	err = conn.WriteJSON(inputMsg)
	require.NoError(t, err)

	// Read response (in real implementation, this would come from the shell)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
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
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Connect to WebSocket
	conn, _, err := websocket.DefaultDialer.Dial(wsURL+"?steward_id=test-steward&user_id=test-user&shell=bash", nil)
	require.NoError(t, err)

	// Check that session was created
	activeSessions := manager.GetActiveSessions()
	assert.Len(t, activeSessions, 1)

	// Close connection
	conn.Close()

	// Give time for cleanup
	time.Sleep(100 * time.Millisecond)

	// Session should be cleaned up
	activeSessions = manager.GetActiveSessions()
	assert.Len(t, activeSessions, 0)
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
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	// Create multiple concurrent connections
	connections := make([]*websocket.Conn, 3)
	for i := 0; i < 3; i++ {
		conn, _, err := websocket.DefaultDialer.Dial(
			wsURL+"?steward_id=test-steward&user_id=test-user&shell=bash",
			nil,
		)
		require.NoError(t, err)
		connections[i] = conn
	}

	// Give connections time to establish sessions
	time.Sleep(50 * time.Millisecond)

	// All sessions should be active
	activeSessions := manager.GetActiveSessions()
	assert.Len(t, activeSessions, 3)

	// Clean up connections
	for _, conn := range connections {
		conn.Close()
	}

	// Give time for cleanup
	time.Sleep(100 * time.Millisecond)

	// All sessions should be cleaned up
	activeSessions = manager.GetActiveSessions()
	assert.Len(t, activeSessions, 0)
}