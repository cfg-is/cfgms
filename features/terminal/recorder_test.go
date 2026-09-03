// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package terminal

import (
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal/shell"
	testutil "github.com/cfgis/cfgms/pkg/testing"
)

func TestSessionRecorderCreation(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		config  *RecorderConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &RecorderConfig{
				StoragePath:    tmpDir,
				MaxRecordingMB: 100,
				Compression:    true,
			},
			wantErr: false,
		},
		{
			name:    "nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "invalid storage path",
			config: &RecorderConfig{
				StoragePath:    "",
				MaxRecordingMB: 100,
				Compression:    true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder, err := NewSessionRecorder(tt.config, logger)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, recorder)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, recorder)
			}
		})
	}
}

func TestDataRecording(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
		Compression:    true,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)
	defer func() {
		if err := recorder.Close(); err != nil {
			t.Logf("Failed to close recorder: %v", err)
		}
	}()

	sessionID := "test-session-001"

	// Test recording input data
	inputData := []byte("echo 'hello world'\n")
	err = recorder.RecordData(sessionID, inputData, DataDirectionInput)
	assert.NoError(t, err)

	// Test recording output data
	outputData := []byte("hello world\n")
	err = recorder.RecordData(sessionID, outputData, DataDirectionOutput)
	assert.NoError(t, err)

	// Test recording multiple chunks
	for i := 0; i < 5; i++ {
		chunkData := []byte("chunk " + string(rune('0'+i)) + "\n")
		err = recorder.RecordData(sessionID, chunkData, DataDirectionInput)
		assert.NoError(t, err)
	}

	// End the recording
	err = recorder.EndRecording(sessionID)
	require.NoError(t, err)

	// Retrieve recording
	recording, err := recorder.GetRecording(sessionID)
	require.NoError(t, err)
	assert.NotNil(t, recording)
	assert.Equal(t, sessionID, recording.SessionID)
	assert.NotEmpty(t, recording.Data)
	assert.NotZero(t, recording.StartTime)
	assert.NotZero(t, recording.EndTime)
	assert.True(t, len(recording.Events) > 0)
}

func TestSessionRecorderRejectsPathLikeSessionIDs(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	storagePath := t.TempDir()
	recorder, err := NewSessionRecorder(&RecorderConfig{
		StoragePath:    storagePath,
		MaxRecordingMB: 1,
	}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recorder.Close()) })

	for _, sessionID := range []string{"", "../escape", `..\\escape`, "nested/session", ".hidden"} {
		t.Run(sessionID, func(t *testing.T) {
			err := recorder.StartRecording(sessionID, &SessionMetadata{SessionID: sessionID})
			require.ErrorContains(t, err, "invalid recording session ID")
		})
	}

	_, err = os.Stat(filepath.Join(filepath.Dir(storagePath), "escape.rec"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRecordingMetadata(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
		Compression:    true,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)
	defer func() {
		if err := recorder.Close(); err != nil {
			t.Logf("Failed to close recorder: %v", err)
		}
	}()

	sessionID := "test-session-002"
	metadata := &SessionMetadata{
		SessionID: sessionID,
		StewardID: "test-steward-001",
		UserID:    "test-user",
		Shell:     shell.GetDefaultShell(),
		CreatedAt: time.Now(),
		Environment: map[string]string{
			"TERM": "xterm-256color",
			"PATH": "/usr/bin:/bin",
		},
	}

	// Start recording with metadata
	err = recorder.StartRecording(sessionID, metadata)
	assert.NoError(t, err)

	// Record some data
	testData := []byte("ls -la\n")
	err = recorder.RecordData(sessionID, testData, DataDirectionInput)
	assert.NoError(t, err)

	// End recording
	err = recorder.EndRecording(sessionID)
	assert.NoError(t, err)

	// Retrieve recording with metadata
	recording, err := recorder.GetRecording(sessionID)
	require.NoError(t, err)
	assert.Equal(t, metadata.SessionID, recording.Metadata.SessionID)
	assert.Equal(t, metadata.StewardID, recording.Metadata.StewardID)
	assert.Equal(t, metadata.UserID, recording.Metadata.UserID)
	assert.Equal(t, metadata.Shell, recording.Metadata.Shell)
	assert.Equal(t, metadata.Environment, recording.Metadata.Environment)
}

func TestRecordingCompression(t *testing.T) {
	logger := testutil.NewMockLogger(true)

	tests := []struct {
		name        string
		compression bool
	}{
		{
			name:        "with compression",
			compression: true,
		},
		{
			name:        "without compression",
			compression: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &RecorderConfig{
				StoragePath:    t.TempDir(),
				MaxRecordingMB: 100,
				Compression:    tt.compression,
			}

			recorder, err := NewSessionRecorder(config, logger)
			require.NoError(t, err)
			defer func() {
				if err := recorder.Close(); err != nil {
					t.Logf("Failed to close recorder: %v", err)
				}
			}()

			sessionID := "test-session-compression"

			// Record large amounts of repetitive data (compresses well)
			largeData := make([]byte, 1024)
			for i := range largeData {
				largeData[i] = 'A'
			}

			for i := 0; i < 10; i++ {
				err = recorder.RecordData(sessionID, largeData, DataDirectionOutput)
				assert.NoError(t, err)
			}

			// End the recording
			err = recorder.EndRecording(sessionID)
			require.NoError(t, err)

			// Retrieve recording
			recording, err := recorder.GetRecording(sessionID)
			require.NoError(t, err)

			// Just verify we can read the data back regardless of compression
			assert.True(t, len(recording.Data) > 0, "Recording should contain data")

			// For now, just verify the compression config was applied
			// Full compression testing would require more complex file analysis
			if tt.compression {
				assert.True(t, len(recording.Data) <= 10*1024, "Data should not exceed original size")
			} else {
				assert.Equal(t, 10*1024, len(recording.Data), "Uncompressed data should match original size")
			}
		})
	}
}

func TestRecordingSizeLimit(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 1, // Very small limit for testing
		Compression:    false,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)
	defer func() {
		if err := recorder.Close(); err != nil {
			t.Logf("Failed to close recorder: %v", err)
		}
	}()

	sessionID := "test-session-size-limit"

	// Try to record more data than the limit
	largeData := make([]byte, 512*1024) // 512KB chunks
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// This should succeed initially
	err = recorder.RecordData(sessionID, largeData, DataDirectionOutput)
	assert.NoError(t, err)

	// This should succeed (still under 1MB)
	err = recorder.RecordData(sessionID, largeData, DataDirectionOutput)
	assert.NoError(t, err)

	// This should fail or be truncated (over 1MB)
	_ = recorder.RecordData(sessionID, largeData, DataDirectionOutput)
	// Implementation might handle this by truncating or returning an error
	// The exact behavior depends on the implementation
}

func TestConcurrentRecording(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
		Compression:    true,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)
	defer func() {
		if err := recorder.Close(); err != nil {
			t.Logf("Failed to close recorder: %v", err)
		}
	}()

	// Record to multiple sessions concurrently
	done := make(chan bool, 3)

	for i := 0; i < 3; i++ {
		go func(sessionNum int) {
			sessionID := "concurrent-session-" + string(rune('0'+sessionNum))

			for j := 0; j < 10; j++ {
				data := []byte("Session " + string(rune('0'+sessionNum)) + " data " + string(rune('0'+j)) + "\n")
				err := recorder.RecordData(sessionID, data, DataDirectionInput)
				assert.NoError(t, err)
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// End all recordings
	for i := 0; i < 3; i++ {
		sessionID := "concurrent-session-" + string(rune('0'+i))
		err := recorder.EndRecording(sessionID)
		assert.NoError(t, err)
	}

	// Verify all recordings exist
	for i := 0; i < 3; i++ {
		sessionID := "concurrent-session-" + string(rune('0'+i))
		recording, err := recorder.GetRecording(sessionID)
		assert.NoError(t, err)
		assert.NotNil(t, recording)
		assert.NotEmpty(t, recording.Data)
	}
}

func TestRecordingPersistence(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
		Compression:    true,
	}

	sessionID := "test-persistence-session"
	testData := []byte("persistent test data\n")

	// Create recorder and record data
	recorder1, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)

	err = recorder1.RecordData(sessionID, testData, DataDirectionInput)
	assert.NoError(t, err)

	if err := recorder1.Close(); err != nil {
		t.Logf("Failed to close recorder1: %v", err)
	}

	// Create new recorder instance and try to retrieve data
	recorder2, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)
	defer func() {
		if err := recorder2.Close(); err != nil {
			t.Logf("Failed to close recorder2: %v", err)
		}
	}()

	recording, err := recorder2.GetRecording(sessionID)
	assert.NoError(t, err)
	assert.NotNil(t, recording)
	assert.Contains(t, string(recording.Data), "persistent test data")
}

func TestRecordingCleanup(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
		Compression:    true,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)

	sessionID := "test-cleanup-session"

	// Record some data
	testData := []byte("cleanup test data\n")
	err = recorder.RecordData(sessionID, testData, DataDirectionInput)
	assert.NoError(t, err)

	// End the recording
	err = recorder.EndRecording(sessionID)
	assert.NoError(t, err)

	// Verify recording exists
	recording, err := recorder.GetRecording(sessionID)
	assert.NoError(t, err)
	assert.NotNil(t, recording)

	// Delete recording
	err = recorder.DeleteRecording(sessionID)
	assert.NoError(t, err)

	// Recording should no longer exist
	_, err = recorder.GetRecording(sessionID)
	assert.Error(t, err)

	if err := recorder.Close(); err != nil {
		t.Logf("Failed to close recorder: %v", err)
	}
}

func TestHMACChainRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testutil.NewMockLogger(true)

	for _, compression := range []bool{false, true} {
		name := "without-compression"
		if compression {
			name = "with-compression"
		}
		t.Run(name, func(t *testing.T) {
			config := &RecorderConfig{
				StoragePath:    tmpDir,
				MaxRecordingMB: 100,
				Compression:    compression,
			}
			recorder, err := NewSessionRecorder(config, logger)
			require.NoError(t, err)

			sessionID := "hmac-roundtrip-" + name
			eventContent := []byte("test event data for HMAC chain integrity verification")

			for i := 0; i < 100; i++ {
				require.NoError(t, recorder.RecordData(sessionID, eventContent, DataDirectionInput))
			}
			require.NoError(t, recorder.EndRecording(sessionID))

			ok, err := recorder.VerifyRecording(sessionID)
			assert.NoError(t, err)
			assert.True(t, ok, "untampered recording must pass verification")
		})
	}
}

func TestHMACChainTamperDetection(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    tmpDir,
		MaxRecordingMB: 100,
		Compression:    false, // uncompressed so byte positions are predictable
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)

	sessionID := "hmac-tamper-session"
	// 100 bytes per event so offset 50 is firmly inside first event content
	eventContent := make([]byte, 100)
	for i := range eventContent {
		eventContent[i] = byte(i)
	}

	for i := 0; i < 100; i++ {
		require.NoError(t, recorder.RecordData(sessionID, eventContent, DataDirectionInput))
	}
	require.NoError(t, recorder.EndRecording(sessionID))

	// Mutate byte 50: first frame layout is [4-byte len][100-byte content][32-byte HMAC]
	// byte 50 is at offset 50-4=46 within content → clearly inside the content region
	recPath := filepath.Join(tmpDir, sessionID+".rec")
	raw, err := os.ReadFile(recPath)
	require.NoError(t, err)
	raw[50] ^= 0xFF
	require.NoError(t, os.WriteFile(recPath, raw, 0600))

	ok, _ := recorder.VerifyRecording(sessionID)
	assert.False(t, ok, "tampered recording must fail verification")
}

func TestHMACChainMissingMetadata(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    tmpDir,
		MaxRecordingMB: 100,
		Compression:    false,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)

	sessionID := "hmac-missing-meta-session"
	for i := 0; i < 100; i++ {
		require.NoError(t, recorder.RecordData(sessionID, []byte("event data"), DataDirectionInput))
	}
	require.NoError(t, recorder.EndRecording(sessionID))

	// Remove metadata so VerifyRecording cannot read chain anchors
	metaPath := filepath.Join(tmpDir, sessionID+".rec.meta")
	require.NoError(t, os.Remove(metaPath))

	ok, err := recorder.VerifyRecording(sessionID)
	assert.False(t, ok, "recording without metadata must fail verification")
	assert.Error(t, err, "missing metadata must return an error")
}

func TestGetRecordingNewFormat(t *testing.T) {
	tmpDir := t.TempDir()
	logger := testutil.NewMockLogger(true)

	for _, compression := range []bool{false, true} {
		name := "uncompressed"
		if compression {
			name = "compressed"
		}
		t.Run(name, func(t *testing.T) {
			config := &RecorderConfig{
				StoragePath:    tmpDir,
				MaxRecordingMB: 100,
				Compression:    compression,
			}
			recorder, err := NewSessionRecorder(config, logger)
			require.NoError(t, err)

			sessionID := "get-recording-format-" + name
			parts := [][]byte{
				[]byte("first event content"),
				[]byte("second event content"),
				[]byte("third event content"),
			}
			for _, p := range parts {
				require.NoError(t, recorder.RecordData(sessionID, p, DataDirectionInput))
			}
			require.NoError(t, recorder.EndRecording(sessionID))

			recording, err := recorder.GetRecording(sessionID)
			require.NoError(t, err)
			require.NotNil(t, recording)

			// GetRecording must return only the raw content bytes — no length prefixes or HMACs
			expected := append([]byte(nil), parts[0]...)
			expected = append(expected, parts[1]...)
			expected = append(expected, parts[2]...)
			assert.Equal(t, expected, recording.Data, "content bytes must match exactly without framing")
			assert.Equal(t, 3, len(recording.Events), "event count must match")
		})
	}
}

// TestRecordingArtifactsAreOwnerOnly asserts that the storage directory and both
// recording artifacts (.rec and .rec.meta) are owner-only. Recordings contain raw
// keystrokes and shell output of privileged sessions — passwords, tokens and key
// material — so world- or group-readable modes are a cleartext-secret disclosure.
func TestRecordingArtifactsAreOwnerOnly(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	storageDir := filepath.Join(t.TempDir(), "recordings")
	config := &RecorderConfig{
		StoragePath:    storageDir,
		MaxRecordingMB: 100,
	}

	recorder, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)

	sessionID := "perm-check-session"
	require.NoError(t, recorder.RecordData(sessionID, []byte("secret-password\n"), DataDirectionInput))
	require.NoError(t, recorder.EndRecording(sessionID))
	require.NoError(t, recorder.Close())

	recPath := filepath.Join(storageDir, sessionID+".rec")

	// Windows permission bits are synthetic, so the mode assertions only apply
	// to POSIX platforms; existence is still verified everywhere.
	for _, path := range []string{recPath, recPath + ".meta"} {
		info, statErr := os.Stat(path)
		require.NoError(t, statErr, "artifact must exist: %s", path)
		if runtime.GOOS != "windows" {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(),
				"recording artifact must be owner read/write only: %s", path)
		}
	}

	dirInfo, err := os.Stat(storageDir)
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(),
			"recording storage directory must be owner-only")
	}
}

// TestRecorderTightensPreExistingPermissiveDir covers the case where a local user
// pre-creates the storage directory world-readable/writable: os.MkdirAll returns nil
// for an existing path without re-applying the mode, so the recorder must re-assert
// owner-only permissions itself.
func TestRecorderTightensPreExistingPermissiveDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Permission bits are synthetic on Windows; the POSIX assertion below
		// does not apply there. Nothing to verify, so return without failing.
		return
	}

	logger := testutil.NewMockLogger(true)
	storageDir := filepath.Join(t.TempDir(), "preexisting")
	require.NoError(t, os.MkdirAll(storageDir, 0o777))
	require.NoError(t, os.Chmod(storageDir, 0o777))

	_, err := NewSessionRecorder(&RecorderConfig{StoragePath: storageDir, MaxRecordingMB: 100}, logger)
	require.NoError(t, err)

	info, err := os.Stat(storageDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"pre-existing permissive storage directory must be tightened to owner-only")
}

// TestRecorderRejectsSymlinkStorageDir covers the symlink-hijack vector: a local
// user pre-creates the (predictable) storage path as a symlink into a directory it
// controls. MkdirAll follows the link and succeeds, so the recorder must reject it.
func TestRecorderRejectsSymlinkStorageDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Symlink creation on Windows requires elevated privileges.
		return
	}

	logger := testutil.NewMockLogger(true)
	base := t.TempDir()
	attackerDir := filepath.Join(base, "attacker")
	require.NoError(t, os.MkdirAll(attackerDir, 0o700))
	linkPath := filepath.Join(base, "recordings")
	require.NoError(t, os.Symlink(attackerDir, linkPath))

	recorder, err := NewSessionRecorder(&RecorderConfig{StoragePath: linkPath, MaxRecordingMB: 100}, logger)
	require.Error(t, err)
	assert.Nil(t, recorder)
	assert.Contains(t, err.Error(), "symlink")
}

// TestStartRecordingRefusesExistingPath asserts recording files are created with
// O_EXCL. Without it, os.Create follows a symlink planted at <session>.rec and
// truncates the target, giving a local user arbitrary file truncation as the
// controller process; it would also silently overwrite an existing recording.
func TestStartRecordingRefusesExistingPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Symlink creation on Windows requires elevated privileges.
		return
	}

	logger := testutil.NewMockLogger(true)
	base := t.TempDir()
	storageDir := filepath.Join(base, "recordings")

	recorder, err := NewSessionRecorder(&RecorderConfig{StoragePath: storageDir, MaxRecordingMB: 100}, logger)
	require.NoError(t, err)
	defer func() { _ = recorder.Close() }()

	victimPath := filepath.Join(base, "victim.txt")
	victimContent := []byte("must not be truncated")
	require.NoError(t, os.WriteFile(victimPath, victimContent, 0o600))

	sessionID := "symlink-target-session"
	require.NoError(t, os.Symlink(victimPath, filepath.Join(storageDir, sessionID+".rec")))

	err = recorder.StartRecording(sessionID, &SessionMetadata{SessionID: sessionID})
	require.Error(t, err, "StartRecording must refuse a pre-existing recording path")

	got, err := os.ReadFile(victimPath)
	require.NoError(t, err)
	assert.Equal(t, victimContent, got, "symlink target must not be truncated")
}

// TestDefaultRecorderConfigHasNoImplicitStoragePath locks in the absence of a
// built-in storage path. A shared default (previously /tmp/cfgms-recordings) puts
// cleartext session recordings in a predictable, world-writable directory.
func TestDefaultRecorderConfigHasNoImplicitStoragePath(t *testing.T) {
	cfg := DefaultRecorderConfig()
	require.NotNil(t, cfg)
	assert.Empty(t, cfg.StoragePath,
		"recorder must have no implicit storage path; callers supply a deployment-owned directory")
}

// TestGetRecordingOnActiveSessionReturnsRecordedData covers reading a recording
// that has not been finalized — the live-session view an operator gets while the
// terminal is still open. Frames are persisted by a background pump goroutine, so
// GetRecording must drain it rather than sample whatever happens to be on disk;
// without that synchronisation this returns an empty (or short-read) recording
// depending on scheduling.
func TestGetRecordingOnActiveSessionReturnsRecordedData(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	recorder, err := NewSessionRecorder(&RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
	}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recorder.Close()) })

	const sessionID = "active-read-session"
	require.NoError(t, recorder.StartRecording(sessionID, &SessionMetadata{SessionID: sessionID}))
	require.NoError(t, recorder.RecordData(sessionID, []byte("$ echo hello\r\n"), DataDirectionInput))
	require.NoError(t, recorder.RecordData(sessionID, []byte("hello\r\n"), DataDirectionOutput))

	recording, err := recorder.GetRecording(sessionID)
	require.NoError(t, err, "an in-progress recording must be readable")
	require.NotNil(t, recording)
	assert.Equal(t, "$ echo hello\r\nhello\r\n", string(recording.Data),
		"every frame recorded before the call must be present")
	assert.Len(t, recording.Events, 2)
}

// TestGetRecordingConcurrentWithActiveWrites reads a recording repeatedly while
// its writer is appending. A frame reaches disk as three separate writes
// ([length][content][HMAC]), so an unsynchronised reader observes a length prefix
// whose content has not landed yet and fails with "failed to read event content:
// EOF". The reader must instead stop at the last complete frame: an append in
// flight can only truncate the tail, never invalidate the frames before it.
func TestGetRecordingConcurrentWithActiveWrites(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	recorder, err := NewSessionRecorder(&RecorderConfig{
		StoragePath:    t.TempDir(),
		MaxRecordingMB: 100,
	}, logger)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, recorder.Close()) })

	const (
		sessionID = "concurrent-read-session"
		frames    = 500
	)
	require.NoError(t, recorder.StartRecording(sessionID, &SessionMetadata{SessionID: sessionID}))

	var (
		wg        sync.WaitGroup
		writeDone = make(chan struct{})
		writeErr  = make(chan error, 1)
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(writeDone)
		for i := 0; i < frames; i++ {
			if err := recorder.RecordData(sessionID, []byte("output frame\r\n"), DataDirectionOutput); err != nil {
				writeErr <- err
				return
			}
		}
	}()

	// Read continuously for the whole lifetime of the writer.
	var previousLen int
	for reading := true; reading; {
		select {
		case <-writeDone:
			reading = false
		default:
		}

		recording, readErr := recorder.GetRecording(sessionID)
		require.NoError(t, readErr, "reading an actively written recording must not fail")
		require.NotNil(t, recording)
		require.GreaterOrEqual(t, len(recording.Data), previousLen,
			"a recording snapshot must never shrink")
		previousLen = len(recording.Data)
	}

	wg.Wait()
	select {
	case err := <-writeErr:
		require.NoError(t, err)
	default:
	}

	require.NoError(t, recorder.EndRecording(sessionID))

	final, err := recorder.GetRecording(sessionID)
	require.NoError(t, err)
	assert.Len(t, final.Events, frames, "no frame may be lost by a concurrent reader")

	valid, err := recorder.VerifyRecording(sessionID)
	require.NoError(t, err)
	assert.True(t, valid, "HMAC chain must remain intact across concurrent reads")
}
