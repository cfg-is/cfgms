// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal/shell"
	"github.com/cfgis/cfgms/pkg/logging"
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
		TenantID:  "test-tenant",
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
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
			TenantID:  "test-tenant",
			StewardID: "test-steward-001",
			UserID:    "test-user",
			Shell:     shell.GetDefaultShell(),
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
		TenantID:  "test-tenant",
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}

	session, err := manager.CreateSession(ctx, sessionReq)
	require.NoError(t, err)

	// Poll until the session has actually timed out before triggering cleanup.
	require.Eventually(t, func() bool {
		return session.IsTimedOut(config.SessionTimeout)
	}, time.Second, time.Millisecond)

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
			TenantID:  "test-tenant",
			StewardID: "test-steward-001",
			UserID:    "test-user",
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}

		_, err := manager.CreateSession(ctx, sessionReq)
		require.NoError(t, err)
	}

	// Attempt to create one more session should fail
	sessionReq := &SessionRequest{
		TenantID:  "test-tenant",
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}

	_, err = manager.CreateSession(ctx, sessionReq)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maximum number of sessions")
}

// TestCleanupTimedOutSessions_AllSessionsCleaned verifies that all 10 timed-out
// sessions are torn down by CleanupTimedOutSessions.
func TestCleanupTimedOutSessions_AllSessionsCleaned(t *testing.T) {
	config := &Config{
		SessionTimeout: 10 * time.Millisecond,
		MaxSessions:    100,
		RecordSessions: false,
	}

	manager, err := NewSessionManager(config, logging.NewNoopLogger())
	require.NoError(t, err)

	ctx := context.Background()

	const sessionCount = 10
	sessions := make([]*Session, sessionCount)

	for i := 0; i < sessionCount; i++ {
		req := &SessionRequest{
			TenantID:  "test-tenant",
			StewardID: fmt.Sprintf("steward-%d", i),
			UserID:    fmt.Sprintf("user-%d", i),
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}
		sess, err := manager.CreateSession(ctx, req)
		require.NoError(t, err)
		sessions[i] = sess
	}

	// Poll until every session has timed out. Sessions are created sequentially,
	// so the last one timed out means all have; checking all is unambiguous.
	require.Eventually(t, func() bool {
		for _, sess := range sessions {
			if !sess.IsTimedOut(config.SessionTimeout) {
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond)

	manager.(*DefaultSessionManager).CleanupTimedOutSessions()

	for _, sess := range sessions {
		_, err := manager.GetSession(sess.ID)
		assert.Error(t, err, "timed-out session %s should be removed", sess.ID)
	}
}

// TestCleanupTimedOutSessions_ContinuesAfterPerSessionError verifies that a
// per-session TerminateSession failure is logged as a warning and does not
// abort the remaining sessions in the batch.
//
// afterCollectHook pre-terminates every timed-out session before the
// CleanupTimedOutSessions termination loop runs. The loop then gets
// "session not found" for each ID, which must produce a warn log and
// continue — not panic or abort.
func TestCleanupTimedOutSessions_ContinuesAfterPerSessionError(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 1 * time.Millisecond,
		MaxSessions:    100,
		RecordSessions: false,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	const sessionCount = 10
	sessions := make([]*Session, sessionCount)

	for i := 0; i < sessionCount; i++ {
		req := &SessionRequest{
			TenantID:  "test-tenant",
			StewardID: fmt.Sprintf("steward-%d", i),
			UserID:    fmt.Sprintf("user-%d", i),
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}
		sess, err := manager.CreateSession(ctx, req)
		require.NoError(t, err)
		sessions[i] = sess
	}

	// Poll until all sessions have timed out before installing the hook and triggering cleanup.
	require.Eventually(t, func() bool {
		for _, sess := range sessions {
			if !sess.IsTimedOut(config.SessionTimeout) {
				return false
			}
		}
		return true
	}, time.Second, time.Millisecond)

	defaultManager := manager.(*DefaultSessionManager)

	// Install a hook that terminates every collected session before the
	// termination loop begins. This guarantees the loop sees "session not
	// found" for all IDs in a deterministic, race-free way.
	//
	// The hook runs synchronously on the test goroutine (CleanupTimedOutSessions
	// is called directly below), so require.NoError is safe.
	defaultManager.afterCollectHook = func(ids []string) {
		hookCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, id := range ids {
			require.NoError(t, defaultManager.TerminateSession(hookCtx, id),
				"hook: pre-termination of session %s must succeed", id)
		}
	}

	defaultManager.CleanupTimedOutSessions()

	// All sessions must be gone (pre-terminated by the hook).
	for _, sess := range sessions {
		_, err := manager.GetSession(sess.ID)
		assert.Error(t, err, "session %s must be terminated", sess.ID)
	}

	// The termination loop must have logged a warning for each "session not
	// found" error instead of aborting.
	warnLogs := logger.GetLogs("warn")
	assert.NotEmpty(t, warnLogs, "warn logs should have been emitted for sessions that could not be found")
}

// TestCleanupTimedOutSessions_GetSessionDuringCleanup verifies that the lock is
// released before TerminateSession is called, allowing concurrent read operations.
//
// The afterCollectHook acts as a rendezvous: it signals when m.mu has been released
// and blocks until GetSession has confirmed concurrent access, proving the lock is
// not held during the termination loop.
func TestCleanupTimedOutSessions_GetSessionDuringCleanup(t *testing.T) {
	config := &Config{
		SessionTimeout: 1 * time.Millisecond,
		MaxSessions:    100,
		RecordSessions: false,
	}

	manager, err := NewSessionManager(config, logging.NewNoopLogger())
	require.NoError(t, err)

	ctx := context.Background()

	timedOutReq := &SessionRequest{
		TenantID:  "test-tenant",
		StewardID: "steward-timed-out",
		UserID:    "user-timed-out",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}
	timedOutSession, err := manager.CreateSession(ctx, timedOutReq)
	require.NoError(t, err)

	activeReq := &SessionRequest{
		TenantID:  "test-tenant",
		StewardID: "steward-active",
		UserID:    "user-active",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}
	activeSession, err := manager.CreateSession(ctx, activeReq)
	require.NoError(t, err)

	// Poll until the timed-out session has actually timed out.
	require.Eventually(t, func() bool {
		return timedOutSession.IsTimedOut(config.SessionTimeout)
	}, time.Second, time.Millisecond)

	// Bump the active session's LastActivity so it is NOT timed out.
	activeSession.UpdateActivity()

	defaultManager := manager.(*DefaultSessionManager)

	// hookReached is closed when cleanup has released m.mu and entered the hook.
	// hookDone is closed by the test goroutine to let cleanup proceed to TerminateSession.
	hookReached := make(chan struct{})
	hookDone := make(chan struct{})
	defaultManager.afterCollectHook = func(_ []string) {
		close(hookReached)
		<-hookDone
	}

	done := make(chan struct{})
	go func() {
		defaultManager.CleanupTimedOutSessions()
		close(done)
	}()

	// Wait until cleanup has released m.mu and is blocked in the hook.
	select {
	case <-hookReached:
	case <-time.After(5 * time.Second):
		t.Fatal("cleanup goroutine never released m.mu (hook not called within 5s)")
	}

	// GetSession (RLock) must succeed while the cleanup goroutine holds no lock.
	// If m.mu were still held this would block indefinitely.
	retrieved, err := manager.GetSession(activeSession.ID)
	assert.NoError(t, err, "GetSession must succeed while CleanupTimedOutSessions is in its termination loop")
	assert.Equal(t, activeSession.ID, retrieved.ID)

	// Unblock the cleanup goroutine so it can call TerminateSession.
	close(hookDone)

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CleanupTimedOutSessions deadlocked — m.mu was not released before calling TerminateSession")
	}

	_, err = manager.GetSession(timedOutSession.ID)
	assert.Error(t, err, "timed-out session should have been removed")

	_, err = manager.GetSession(activeSession.ID)
	assert.NoError(t, err, "active session should still exist")

	err = manager.TerminateSession(ctx, activeSession.ID)
	require.NoError(t, err)
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
		TenantID:  "test-tenant",
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
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

func TestCreateSession_TenantIDRequired(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 30 * time.Minute,
		MaxSessions:    100,
		RecordSessions: false,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("empty TenantID returns error", func(t *testing.T) {
		req := &SessionRequest{
			TenantID:  "",
			StewardID: "test-steward",
			UserID:    "test-user",
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}
		session, err := manager.CreateSession(ctx, req)
		assert.Error(t, err)
		assert.Nil(t, session)
		assert.Contains(t, err.Error(), "tenant ID required")
	})

	t.Run("non-empty TenantID succeeds", func(t *testing.T) {
		req := &SessionRequest{
			TenantID:  "my-tenant",
			StewardID: "test-steward",
			UserID:    "test-user",
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}
		session, err := manager.CreateSession(ctx, req)
		require.NoError(t, err)
		require.NotNil(t, session)

		// Cleanup
		err = manager.TerminateSession(ctx, session.ID)
		require.NoError(t, err)
	})
}
