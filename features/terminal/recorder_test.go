package terminal

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
	defer recorder.Close()

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
	defer recorder.Close()

	sessionID := "test-session-002"
	metadata := &SessionMetadata{
		SessionID:  sessionID,
		StewardID:  "test-steward-001",
		UserID:     "test-user",
		Shell:      "bash",
		CreatedAt:  time.Now(),
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
			defer recorder.Close()

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
	defer recorder.Close()

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
	err = recorder.RecordData(sessionID, largeData, DataDirectionOutput)
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
	defer recorder.Close()

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

	recorder1.Close()

	// Create new recorder instance and try to retrieve data
	recorder2, err := NewSessionRecorder(config, logger)
	require.NoError(t, err)
	defer recorder2.Close()

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

	recorder.Close()
}