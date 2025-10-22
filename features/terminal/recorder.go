// #nosec G304 - Terminal recorder requires file access for session recording and playback
package terminal

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultSessionRecorder implements the Recorder interface
type DefaultSessionRecorder struct {
	mu           sync.RWMutex
	config       *RecorderConfig
	logger       logging.Logger
	activeWrites map[string]*recordingWriter
	storagePath  string
}

// recordingWriter manages writing data for a single session
type recordingWriter struct {
	sessionID string
	file      *os.File
	gzWriter  *gzip.Writer
	events    []RecordEvent
	metadata  *SessionMetadata
	startTime time.Time
	size      int64
	maxSize   int64
	mu        sync.Mutex
}

// NewSessionRecorder creates a new session recorder
func NewSessionRecorder(config *RecorderConfig, logger logging.Logger) (*DefaultSessionRecorder, error) {
	if config == nil {
		return nil, fmt.Errorf("recorder config cannot be nil")
	}

	if config.StoragePath == "" {
		return nil, fmt.Errorf("storage path cannot be empty")
	}

	if config.MaxRecordingMB <= 0 {
		config.MaxRecordingMB = 100 // Default to 100MB
	}

	// Ensure storage directory exists
	if err := os.MkdirAll(config.StoragePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	recorder := &DefaultSessionRecorder{
		config:       config,
		logger:       logger,
		activeWrites: make(map[string]*recordingWriter),
		storagePath:  config.StoragePath,
	}

	logger.Info("Session recorder initialized",
		"storage_path", config.StoragePath,
		"max_recording_mb", config.MaxRecordingMB,
		"compression", config.Compression)

	return recorder, nil
}

// StartRecording starts recording a new session
func (r *DefaultSessionRecorder) StartRecording(sessionID string, metadata *SessionMetadata) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already recording
	if _, exists := r.activeWrites[sessionID]; exists {
		return fmt.Errorf("recording already active for session: %s", sessionID)
	}

	// Create recording file
	filename := fmt.Sprintf("%s.rec", sessionID)
	filepath := filepath.Join(r.storagePath, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create recording file: %w", err)
	}

	writer := &recordingWriter{
		sessionID: sessionID,
		file:      file,
		events:    make([]RecordEvent, 0),
		metadata:  metadata,
		startTime: time.Now(),
		maxSize:   int64(r.config.MaxRecordingMB * 1024 * 1024), // Convert MB to bytes
	}

	// Set up compression if enabled
	if r.config.Compression {
		writer.gzWriter = gzip.NewWriter(file)
	}

	r.activeWrites[sessionID] = writer

	r.logger.Info("Started recording session",
		"session_id", sessionID,
		"file", filepath,
		"compression", r.config.Compression)

	return nil
}

// RecordData records data for a session
func (r *DefaultSessionRecorder) RecordData(sessionID string, data []byte, direction DataDirection) error {
	r.mu.RLock()
	writer, exists := r.activeWrites[sessionID]
	r.mu.RUnlock()

	if !exists {
		// Auto-start recording if not already started
		metadata := &SessionMetadata{
			SessionID: sessionID,
			CreatedAt: time.Now(),
		}
		if err := r.StartRecording(sessionID, metadata); err != nil {
			return fmt.Errorf("failed to auto-start recording: %w", err)
		}

		r.mu.RLock()
		writer = r.activeWrites[sessionID]
		r.mu.RUnlock()
	}

	return writer.writeData(data, direction)
}

// EndRecording ends recording for a session
func (r *DefaultSessionRecorder) EndRecording(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	writer, exists := r.activeWrites[sessionID]
	if !exists {
		return fmt.Errorf("no active recording for session: %s", sessionID)
	}

	// Close the writer
	if err := writer.close(); err != nil {
		r.logger.Warn("Error closing recording writer", "session_id", sessionID, "error", err)
	}

	// Remove from active writes
	delete(r.activeWrites, sessionID)

	r.logger.Info("Ended recording session",
		"session_id", sessionID,
		"duration", time.Since(writer.startTime),
		"size_bytes", writer.size)

	return nil
}

// GetRecording retrieves a session recording
func (r *DefaultSessionRecorder) GetRecording(sessionID string) (*SessionRecording, error) {
	filename := fmt.Sprintf("%s.rec", sessionID)
	filepath := filepath.Join(r.storagePath, filename)

	// Check if file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return nil, fmt.Errorf("recording not found for session: %s", sessionID)
	}

	// Open file
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("failed to open recording file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore file close errors
		}
	}()

	// Read file content - check if file was actually compressed
	// We need to detect if this specific file was compressed by checking the first bytes
	var reader io.Reader = file

	// Try to create a gzip reader first - if it works, the file is compressed
	if r.config.Compression {
		// Reset file position
		if _, err := file.Seek(0, 0); err != nil {
			// Log error but continue with uncompressed read
			_ = err // Explicitly ignore seek errors
		}
		gzReader, err := gzip.NewReader(file)
		if err == nil {
			defer func() {
				if err := gzReader.Close(); err != nil {
					// Log error but continue
					_ = err // Explicitly ignore gzReader close errors
				}
			}()
			reader = gzReader
		} else {
			// If gzip reader creation fails, file isn't compressed, read as-is
			if _, err := file.Seek(0, 0); err != nil {
				// Log error but continue
				_ = err // Explicitly ignore seek errors for uncompressed read
			}
			reader = file
		}
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read recording data: %w", err)
	}

	// Try to read metadata file
	metadataPath := filepath + ".meta"
	var metadata SessionMetadata
	var events []RecordEvent

	if metadataFile, err := os.Open(metadataPath); err == nil {
		defer func() {
			if err := metadataFile.Close(); err != nil {
				// Log error but continue
				_ = err // Explicitly ignore metadata file close errors
			}
		}()

		type recordingMetadata struct {
			Metadata SessionMetadata `json:"metadata"`
			Events   []RecordEvent   `json:"events"`
		}

		var recMeta recordingMetadata
		if err := json.NewDecoder(metadataFile).Decode(&recMeta); err == nil {
			metadata = recMeta.Metadata
			events = recMeta.Events
		}
	}

	// Get file stats for timing info
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	recording := &SessionRecording{
		SessionID: sessionID,
		Metadata:  metadata,
		StartTime: metadata.CreatedAt,
		EndTime:   stat.ModTime(),
		Data:      data,
		Events:    events,
		Size:      stat.Size(),
	}

	return recording, nil
}

// DeleteRecording deletes a session recording
func (r *DefaultSessionRecorder) DeleteRecording(sessionID string) error {
	filename := fmt.Sprintf("%s.rec", sessionID)
	filepath := filepath.Join(r.storagePath, filename)
	metadataPath := filepath + ".meta"

	// Delete recording file
	if err := os.Remove(filepath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete recording file: %w", err)
	}

	// Delete metadata file if it exists
	if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
		r.logger.Warn("Failed to delete metadata file", "path", metadataPath, "error", err)
	}

	r.logger.Info("Deleted recording", "session_id", sessionID)
	return nil
}

// Close closes the recorder and cleans up resources
func (r *DefaultSessionRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Close all active writers
	for sessionID, writer := range r.activeWrites {
		if err := writer.close(); err != nil {
			r.logger.Warn("Error closing writer during recorder shutdown",
				"session_id", sessionID, "error", err)
		}
	}

	// Clear active writes
	r.activeWrites = make(map[string]*recordingWriter)

	r.logger.Info("Session recorder closed")
	return nil
}

// writeData writes data to the recording file
func (w *recordingWriter) writeData(data []byte, direction DataDirection) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check size limit
	if w.size+int64(len(data)) > w.maxSize {
		return fmt.Errorf("recording size limit exceeded for session: %s", w.sessionID)
	}

	// Create event
	event := RecordEvent{
		Timestamp: time.Now(),
		Direction: direction,
		Data:      data,
		Size:      len(data),
	}

	// Write data to file
	var writer io.Writer = w.file
	if w.gzWriter != nil {
		writer = w.gzWriter
	}

	if _, err := writer.Write(data); err != nil {
		return fmt.Errorf("failed to write recording data: %w", err)
	}

	// Flush gzip writer if used
	if w.gzWriter != nil {
		if err := w.gzWriter.Flush(); err != nil {
			return fmt.Errorf("failed to flush gzip writer: %w", err)
		}
	}

	// Update state
	w.events = append(w.events, event)
	w.size += int64(len(data))

	return nil
}

// close closes the recording writer and saves metadata
func (w *recordingWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	var err error

	// Close gzip writer if used
	if w.gzWriter != nil {
		if closeErr := w.gzWriter.Close(); closeErr != nil {
			err = closeErr
		}
	}

	// Close file
	if closeErr := w.file.Close(); closeErr != nil && err == nil {
		err = closeErr
	}

	// Save metadata
	metadataPath := w.file.Name() + ".meta"
	if metadataFile, metaErr := os.Create(metadataPath); metaErr == nil {
		defer func() {
			if err := metadataFile.Close(); err != nil {
				// Log error but continue
				_ = err // Explicitly ignore metadata file close errors
			}
		}()

		type recordingMetadata struct {
			Metadata SessionMetadata `json:"metadata"`
			Events   []RecordEvent   `json:"events"`
		}

		// Update metadata end time
		if w.metadata != nil {
			endTime := time.Now()
			w.metadata.EndedAt = &endTime
		}

		recMeta := recordingMetadata{
			Metadata: *w.metadata,
			Events:   w.events,
		}

		if jsonErr := json.NewEncoder(metadataFile).Encode(recMeta); jsonErr != nil && err == nil {
			err = jsonErr
		}
	} else if err == nil {
		err = metaErr
	}

	return err
}
