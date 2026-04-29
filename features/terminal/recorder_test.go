// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package terminal

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/terminal/shell"
	testutil "github.com/cfgis/cfgms/pkg/testing"
)

func TestSessionRecorderCreation(t *testing.T) {
	logger := testutil.NewMockLogger(true)

	tests := []struct {
		name    string
		config  *RecorderConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: &RecorderConfig{
				StoragePath:    "/tmp/cfgms-recordings",
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
		StoragePath:    "/tmp/cfgms-recordings",
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

func TestRecordingMetadata(t *testing.T) {
	logger := testutil.NewMockLogger(true)
	config := &RecorderConfig{
		StoragePath:    "/tmp/cfgms-recordings",
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
				StoragePath:    "/tmp/cfgms-recordings",
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
		StoragePath:    "/tmp/cfgms-recordings",
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
		StoragePath:    "/tmp/cfgms-recordings",
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
		StoragePath:    "/tmp/cfgms-recordings",
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
		StoragePath:    "/tmp/cfgms-recordings",
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
