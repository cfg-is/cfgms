// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal/shell"
	"github.com/cfgis/cfgms/pkg/logging"
	testutil "github.com/cfgis/cfgms/pkg/testing"
)

func TestSessionCreation(t *testing.T) {
	logger := testutil.NewMockLogger(true)

	tests := []struct {
		name     string
		request  *SessionRequest
		wantErr  bool
		skipOnOS string
	}{
		{
			name: "valid default shell session",
			request: &SessionRequest{
				StewardID: "test-steward-001",
				UserID:    "test-user",
				Shell:     shell.GetDefaultShell(),
				Cols:      80,
				Rows:      24,
			},
			wantErr: false,
		},
		{
			name: "platform default shell session",
			request: &SessionRequest{
				StewardID: "test-steward-001",
				UserID:    "test-user",
				Shell:     shell.GetDefaultShell(),
				Cols:      80,
				Rows:      24,
			},
			wantErr: false, // Uses platform-appropriate default shell
		},
		{
			name: "powershell session (platform dependent)",
			request: &SessionRequest{
				StewardID: "test-steward-001",
				UserID:    "test-user",
				Shell:     "powershell",
				Cols:      120,
				Rows:      30,
			},
			wantErr: runtime.GOOS != "windows", // PowerShell only works on Windows
		},
		{
			name: "invalid shell",
			request: &SessionRequest{
				StewardID: "test-steward-001",
				UserID:    "test-user",
				Shell:     "invalid-shell",
				Cols:      80,
				Rows:      24,
			},
			wantErr: true,
		},
		{
			name: "missing steward ID",
			request: &SessionRequest{
				StewardID: "",
				UserID:    "test-user",
				Shell:     shell.GetDefaultShell(),
				Cols:      80,
				Rows:      24,
			},
			wantErr: true,
		},
		{
			name: "zero terminal dimensions (should use defaults)",
			request: &SessionRequest{
				StewardID: "test-steward-001",
				UserID:    "test-user",
				Shell:     shell.GetDefaultShell(),
				Cols:      0,
				Rows:      24,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipOnOS != "" && runtime.GOOS == tt.skipOnOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
				return
			}

			session, err := NewSession(tt.request, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, session)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, session)
				assert.NotEmpty(t, session.ID)
				assert.Equal(t, tt.request.StewardID, session.StewardID)
				assert.Equal(t, tt.request.UserID, session.UserID)
				assert.Equal(t, tt.request.Shell, session.Shell)
				// For the zero dimensions test, verify defaults were applied
				if tt.name == "zero terminal dimensions (should use defaults)" {
					assert.Equal(t, 80, session.Cols) // Default should be applied
					assert.Equal(t, 24, session.Rows) // Request value should be kept
				} else {
					assert.Equal(t, tt.request.Cols, session.Cols)
					assert.Equal(t, tt.request.Rows, session.Rows)
				}
			}
		})
	}
}

func TestSessionDataHandling(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	request := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}

	session, err := NewSession(request, logger)
	require.NoError(t, err)

	ctx := context.Background()

	// Start the session so shell is running
	err = session.Start(ctx)
	require.NoError(t, err)
	defer func() {
		if err := session.Close(ctx); err != nil {
			t.Logf("Failed to close session: %v", err)
		}
	}()

	// Test writing data to session
	testInput := []byte("echo 'hello world'\n")
	err = session.WriteData(ctx, testInput)
	assert.NoError(t, err)

	// Test session resize
	err = session.Resize(ctx, 120, 30)
	assert.NoError(t, err)
	assert.Equal(t, 120, session.Cols)
	assert.Equal(t, 30, session.Rows)

	// Test session close
	err = session.Close(ctx)
	assert.NoError(t, err)
	assert.True(t, session.IsClosed())
}

func TestSessionState(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	request := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}

	session, err := NewSession(request, logger)
	require.NoError(t, err)

	// Initially active
	assert.True(t, session.IsActive())
	assert.False(t, session.IsClosed())

	// Test activity update
	session.UpdateActivity()
	assert.True(t, time.Since(session.LastActivity) < time.Second)

	// Test timeout check - use a small sleep to ensure time passes
	// Windows has ~15ms clock resolution, so use a slightly larger timeout
	time.Sleep(10 * time.Millisecond)
	assert.False(t, session.IsTimedOut(30*time.Minute))
	assert.True(t, session.IsTimedOut(time.Millisecond))

	ctx := context.Background()

	// Close session
	err = session.Close(ctx)
	require.NoError(t, err)

	assert.False(t, session.IsActive())
	assert.True(t, session.IsClosed())
}

func TestSessionMetadata(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	request := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
		Env: map[string]string{
			"TERM": "xterm-256color",
			"PATH": "/usr/bin:/bin",
		},
	}

	session, err := NewSession(request, logger)
	require.NoError(t, err)

	// Test metadata extraction
	metadata := session.GetMetadata()
	assert.Equal(t, session.ID, metadata.SessionID)
	assert.Equal(t, request.StewardID, metadata.StewardID)
	assert.Equal(t, request.UserID, metadata.UserID)
	assert.Equal(t, request.Shell, metadata.Shell)
	assert.Equal(t, request.Env, metadata.Environment)
	assert.NotZero(t, metadata.CreatedAt)
}

func TestSessionRecordingIntegration(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	request := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}

	session, err := NewSession(request, logger)
	require.NoError(t, err)

	recorderConfig := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 10,
		Compression:    false,
	}
	recorder, err := NewSessionRecorder(recorderConfig, logger)
	require.NoError(t, err)

	session.SetRecorder(recorder)

	ctx := context.Background()

	// Simulate output data (does not require shell to be running)
	outputData := []byte("total 0\ndrwxr-xr-x  2 user user 4096 Jan  1 00:00 .\n")
	err = session.HandleOutput(ctx, outputData)
	assert.NoError(t, err)

	// Flush recording to disk before reading it back
	err = recorder.EndRecording(session.ID)
	require.NoError(t, err)

	// Verify output was persisted by the real recorder
	recording, err := recorder.GetRecording(session.ID)
	require.NoError(t, err)
	require.NotNil(t, recording)
	assert.Equal(t, session.ID, recording.SessionID)
	assert.Contains(t, string(recording.Data), "drwxr-xr-x")
}

// TestNewSession_RedactsSessionID verifies that NewSession never logs the raw
// session UUID and always logs the redacted prefix form under the session_id key.
func TestNewSession_RedactsSessionID(t *testing.T) {
	capLogger := &kvCapturingLogger{}
	req := &SessionRequest{
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		Cols:      80,
		Rows:      24,
	}

	session, err := NewSession(req, capLogger)
	require.NoError(t, err)
	require.NotNil(t, session)

	// Full UUID must not appear in any logged kv value.
	assert.False(t, capLogger.allKVContains(session.ID),
		"raw session UUID must not appear in any log kv value after NewSession")

	// Redacted form must be present under the session_id key.
	redacted := logging.RedactedID(session.ID)
	assert.True(t, capLogger.anyKVKeyHasValue("session_id", redacted),
		"redacted session_id (%q) must appear in log kv values after NewSession", redacted)
}
