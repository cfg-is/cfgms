// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"fmt"
	"sync"
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
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
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
			Shell:     shell.GetDefaultShell(),
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
	sessionIDs := make([]string, sessionCount)

	for i := 0; i < sessionCount; i++ {
		req := &SessionRequest{
			StewardID: fmt.Sprintf("steward-%d", i),
			UserID:    fmt.Sprintf("user-%d", i),
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}
		sess, err := manager.CreateSession(ctx, req)
		require.NoError(t, err)
		sessionIDs[i] = sess.ID
	}

	time.Sleep(100 * time.Millisecond)

	manager.(*DefaultSessionManager).CleanupTimedOutSessions()

	for _, id := range sessionIDs {
		_, err := manager.GetSession(id)
		assert.Error(t, err, "timed-out session %s should be removed", id)
	}
}

// TestCleanupTimedOutSessions_ContinuesAfterPerSessionError verifies that a
// per-session TerminateSession failure is logged as a warning and does not
// abort the remaining sessions in the batch.
//
// Two concurrent CleanupTimedOutSessions calls both collect the same session IDs
// (under lock, before any termination). When both loops then call TerminateSession
// concurrently, the second caller encounters "session not found" for sessions the
// first already removed — these must be warned and skipped, not panicked or aborted.
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
	sessionIDs := make([]string, sessionCount)

	for i := 0; i < sessionCount; i++ {
		req := &SessionRequest{
			StewardID: fmt.Sprintf("steward-%d", i),
			UserID:    fmt.Sprintf("user-%d", i),
			Shell:     shell.GetDefaultShell(),
			Cols:      80,
			Rows:      24,
		}
		sess, err := manager.CreateSession(ctx, req)
		require.NoError(t, err)
		sessionIDs[i] = sess.ID
	}

	time.Sleep(10 * time.Millisecond)

	defaultManager := manager.(*DefaultSessionManager)

	// Both goroutines collect identical ID slices (both under lock, before any
	// termination has started). Their termination loops then race; the second
	// caller gets "session not found" for sessions the first already deleted.
	var ready sync.WaitGroup
	ready.Add(2)
	var done sync.WaitGroup
	done.Add(2)
	go func() {
		defer done.Done()
		ready.Done()
		ready.Wait()
		defaultManager.CleanupTimedOutSessions()
	}()
	go func() {
		defer done.Done()
		ready.Done()
		ready.Wait()
		defaultManager.CleanupTimedOutSessions()
	}()
	done.Wait()

	// All sessions must be terminated regardless of which goroutine did the work.
	for _, id := range sessionIDs {
		_, err := manager.GetSession(id)
		assert.Error(t, err, "session %s must be terminated", id)
	}

	// At least some warn logs must have been emitted for the "session not found"
	// errors encountered by the goroutine that lost the race on each session.
	warnLogs := logger.GetLogs("warn")
	assert.NotEmpty(t, warnLogs, "warn logs should have been emitted for sessions that could not be found by the second cleanup")
}

// TestCleanupTimedOutSessions_GetSessionDuringCleanup verifies that the lock is
// released before TerminateSession is called, allowing concurrent read operations.
//
// Because TerminateSession itself acquires m.mu.Lock(), if CleanupTimedOutSessions
// held the lock during TerminateSession it would deadlock. Non-completion within 5 s
// is treated as a deadlock.
func TestCleanupTimedOutSessions_GetSessionDuringCleanup(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &Config{
		SessionTimeout: 1 * time.Millisecond,
		MaxSessions:    100,
		RecordSessions: false,
	}

	manager, err := NewSessionManager(config, logger)
	require.NoError(t, err)

	ctx := context.Background()

	timedOutReq := &SessionRequest{
		StewardID: "steward-timed-out",
		UserID:    "user-timed-out",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}
	timedOutSession, err := manager.CreateSession(ctx, timedOutReq)
	require.NoError(t, err)

	activeReq := &SessionRequest{
		StewardID: "steward-active",
		UserID:    "user-active",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}
	activeSession, err := manager.CreateSession(ctx, activeReq)
	require.NoError(t, err)
	_ = timedOutSession

	time.Sleep(10 * time.Millisecond)

	// Bump the active session's LastActivity so it is NOT timed out.
	activeSession.UpdateActivity()

	defaultManager := manager.(*DefaultSessionManager)

	done := make(chan struct{})
	go func() {
		defaultManager.CleanupTimedOutSessions()
		close(done)
	}()

	// GetSession (RLock) must succeed; if the write lock were held for the full
	// cleanup it would block until cleanup finishes (or deadlock if TerminateSession
	// is called while the lock is held).
	retrieved, err := manager.GetSession(activeSession.ID)
	assert.NoError(t, err, "GetSession must not block while CleanupTimedOutSessions is in its termination loop")
	assert.Equal(t, activeSession.ID, retrieved.ID)

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
