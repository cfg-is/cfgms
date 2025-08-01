package terminal

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testutil "github.com/cfgis/cfgms/pkg/testing"
)

func TestSessionManagerCreation(t *testing.T) {
	logger := testutil.NewMockLogger(true)

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "with valid config",
			config: &Config{
				SessionTimeout: 30 * time.Minute,
				MaxSessions:    100,
				RecordSessions: true,
			},
			wantErr: false,
		},
		{
			name:    "with nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "with invalid timeout",
			config: &Config{
				SessionTimeout: 0,
				MaxSessions:    100,
				RecordSessions: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewSessionManager(tt.config, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, manager)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, manager)
			}
		})
	}
}

func TestSessionLifecycle(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)
	require.NotNil(t, manager)

	ctx := context.Background()

	// Test session creation
	sessionReq := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	}

	session, err := manager.CreateSession(ctx, sessionReq)
	require.NoError(t, err)
	require.NotNil(t, session)
	assert.NotEmpty(t, session.ID)
	assert.Equal(t, sessionReq.StewardID, session.StewardID)
	assert.Equal(t, sessionReq.UserID, session.UserID)

	// Test session retrieval
	retrievedSession, err := manager.GetSession(session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.ID, retrievedSession.ID)

	// Test session termination
	err = manager.TerminateSession(ctx, session.ID)
	assert.NoError(t, err)

	// Session should no longer exist
	_, err = manager.GetSession(session.ID)
	assert.Error(t, err)
}

func TestSessionConcurrency(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    5, // Limited for testing
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Create multiple sessions concurrently
	sessions := make([]*Session, 3)
	for i := 0; i < 3; i++ {
		sessionReq := &SessionRequest{
			StewardID: "test-steward-001",
			UserID:    "test-user",
			Shell:     "bash",
			Cols:      80,
			Rows:      24,
		}

		session, err := manager.CreateSession(ctx, sessionReq)
		require.NoError(t, err)
		sessions[i] = session
	}

	// All sessions should be tracked
	activeSessions := manager.GetActiveSessions()
	assert.Len(t, activeSessions, 3)

	// Clean up
	for _, session := range sessions {
		err := manager.TerminateSession(ctx, session.ID)
		assert.NoError(t, err)
	}
}

func TestSessionTimeout(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 100 * time.Millisecond, // Very short for testing
		MaxSessions:    100,
		RecordSessions: false, // Disable recording for this test
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	sessionReq := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	}

	session, err := manager.CreateSession(ctx, sessionReq)
	require.NoError(t, err)

	// Wait for timeout plus cleanup cycle
	time.Sleep(200 * time.Millisecond)

	// Manually trigger cleanup to ensure it runs in test
	defaultManager := manager.(*DefaultSessionManager)
	defaultManager.CleanupTimedOutSessions()

	// Session should be automatically cleaned up
	_, err = manager.GetSession(session.ID)
	assert.Error(t, err)
}

func TestMaxSessionsLimit(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    2, // Very limited for testing
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Create sessions up to the limit
	for i := 0; i < 2; i++ {
		sessionReq := &SessionRequest{
			StewardID: "test-steward-001",
			UserID:    "test-user",
			Shell:     "bash",
			Cols:      80,
			Rows:      24,
		}

		_, err := manager.CreateSession(ctx, sessionReq)
		require.NoError(t, err)
	}

	// Attempt to create one more session should fail
	sessionReq := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	}

	_, err = manager.CreateSession(ctx, sessionReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of sessions")
}

func TestSessionRecording(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: true,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	sessionReq := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     "bash",
		Cols:      80,
		Rows:      24,
	}

	session, err := manager.CreateSession(ctx, sessionReq)
	require.NoError(t, err)

	// Test data recording
	testData := []byte("echo 'hello world'\n")
	err = manager.RecordData(session.ID, testData, DataDirectionInput)
	assert.NoError(t, err)

	// Terminate session to close the recording
	err = manager.TerminateSession(ctx, session.ID)
	assert.NoError(t, err)

	// Test data retrieval
	recording, err := manager.GetSessionRecording(session.ID)
	assert.NoError(t, err)
	assert.NotNil(t, recording)
	assert.Contains(t, string(recording.Data), "hello world")
}