// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// #nosec G304 - Terminal recorder requires file access for session recording and playback
package terminal

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsInterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
)

// recordingMeta is the JSON structure written to <sessionID>.rec.meta.
// It captures chain integrity anchors (first/last checksum, event count) alongside
// session metadata so GetRecording and VerifyRecording can reconstruct the session.
type recordingMeta struct {
	SessionID     string            `json:"session_id"`
	StewardID     string            `json:"steward_id,omitempty"`
	UserID        string            `json:"user_id,omitempty"`
	Shell         string            `json:"shell,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	FirstChecksum string            `json:"first_checksum"`
	LastChecksum  string            `json:"last_checksum"`
	EventCount    int64             `json:"event_count"`
	StartedAt     time.Time         `json:"started_at"`
	EndedAt       *time.Time        `json:"ended_at,omitempty"`
	Compression   bool              `json:"compression"`
}

// RecorderOption is a functional option for NewSessionRecorder.
type RecorderOption func(*DefaultSessionRecorder, context.Context) error

// WithSecretsStore configures the recorder to load its HMAC signing key from
// the provided secrets store (slot: "terminal/recording-hmac-key"). If the key
// is absent it is generated and stored. Without this option an ephemeral random
// key is used — per-event integrity is preserved within the process run but the
// key does not survive restarts.
func WithSecretsStore(store secretsInterfaces.SecretStore) RecorderOption {
	return func(r *DefaultSessionRecorder, ctx context.Context) error {
		const keyName = "terminal/recording-hmac-key"
		secret, err := store.GetSecret(ctx, keyName)
		if err == nil && secret != nil && len(secret.Value) > 0 {
			raw, decodeErr := hex.DecodeString(secret.Value)
			if decodeErr == nil && len(raw) == 32 {
				r.hmacKey = raw
				return nil
			}
		}
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("failed to generate recording HMAC key: %w", err)
		}
		if err := store.StoreSecret(ctx, &secretsInterfaces.SecretRequest{
			Key:         keyName,
			Value:       hex.EncodeToString(key),
			Description: "HMAC signing key for session recording chain integrity",
		}); err != nil {
			r.logger.Warn("failed to persist recording HMAC key; using in-process key",
				"error", err)
		}
		r.hmacKey = key
		return nil
	}
}

// DefaultSessionRecorder implements the Recorder interface.
type DefaultSessionRecorder struct {
	mu           sync.RWMutex
	config       *RecorderConfig
	logger       logging.Logger
	activeWrites map[string]*recordingWriter
	storagePath  string
	hmacKey      []byte
}

// recordingWriter manages writing data for a single session in the binary
// length-prefixed format: [4-byte content len][content][32-byte HMAC].
type recordingWriter struct {
	sessionID        string
	file             *os.File
	useCompression   bool
	hmacKey          []byte
	sequence         int64
	previousChecksum []byte // all-zero for first event
	firstChecksum    []byte
	eventCount       int64
	events           []RecordEvent
	metadata         *SessionMetadata
	startTime        time.Time
	size             int64
	maxSize          int64
	mu               sync.Mutex
}

// computeEventChecksum binds (sequence, previous, content) under the HMAC key.
func computeEventChecksum(key []byte, sequence int64, previous []byte, content []byte) []byte {
	mac := hmac.New(sha256.New, key)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, uint64(sequence))
	mac.Write(seqBytes)
	mac.Write(previous)
	mac.Write(content)
	return mac.Sum(nil)
}

// NewSessionRecorder creates a new session recorder. Legacy .rec files without
// HMAC chain metadata are removed at startup.
func NewSessionRecorder(config *RecorderConfig, logger logging.Logger, opts ...RecorderOption) (*DefaultSessionRecorder, error) {
	if config == nil {
		return nil, fmt.Errorf("recorder config cannot be nil")
	}
	if config.StoragePath == "" {
		return nil, fmt.Errorf("storage path cannot be empty")
	}
	if config.MaxRecordingMB <= 0 {
		config.MaxRecordingMB = 100
	}
	if err := os.MkdirAll(config.StoragePath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	recorder := &DefaultSessionRecorder{
		config:       config,
		logger:       logger,
		activeWrites: make(map[string]*recordingWriter),
		storagePath:  config.StoragePath,
	}

	ctx := context.Background()
	for _, opt := range opts {
		if err := opt(recorder, ctx); err != nil {
			return nil, fmt.Errorf("failed to apply recorder option: %w", err)
		}
	}

	if recorder.hmacKey == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral recording HMAC key: %w", err)
		}
		recorder.hmacKey = key
		logger.Warn("recording HMAC key is ephemeral; use WithSecretsStore for cross-restart integrity")
	}

	recorder.cleanupLegacyFiles()

	logger.Info("Session recorder initialized",
		"storage_path", config.StoragePath,
		"max_recording_mb", config.MaxRecordingMB,
		"compression", config.Compression)

	return recorder, nil
}

// StartRecording starts recording a new session.
func (r *DefaultSessionRecorder) StartRecording(sessionID string, metadata *SessionMetadata) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.activeWrites[sessionID]; exists {
		return fmt.Errorf("recording already active for session: %s", sessionID)
	}

	filename := fmt.Sprintf("%s.rec", sessionID)
	filePath := filepath.Join(r.storagePath, filename)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create recording file: %w", err)
	}

	writer := &recordingWriter{
		sessionID:        sessionID,
		file:             file,
		useCompression:   r.config.Compression,
		hmacKey:          r.hmacKey,
		previousChecksum: make([]byte, 32), // all-zero sentinel for first event
		events:           make([]RecordEvent, 0),
		metadata:         metadata,
		startTime:        time.Now(),
		maxSize:          int64(r.config.MaxRecordingMB * 1024 * 1024),
	}

	r.activeWrites[sessionID] = writer

	r.logger.Info("Started recording session",
		"session_id", sessionID,
		"file", filePath,
		"compression", r.config.Compression)

	return nil
}

// RecordData records data for a session.
func (r *DefaultSessionRecorder) RecordData(sessionID string, data []byte, direction DataDirection) error {
	r.mu.RLock()
	writer, exists := r.activeWrites[sessionID]
	r.mu.RUnlock()

	if !exists {
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

// EndRecording ends recording for a session.
func (r *DefaultSessionRecorder) EndRecording(sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	writer, exists := r.activeWrites[sessionID]
	if !exists {
		return fmt.Errorf("no active recording for session: %s", sessionID)
	}

	if err := writer.close(); err != nil {
		r.logger.Warn("Error closing recording writer", "session_id", sessionID, "error", err)
	}

	delete(r.activeWrites, sessionID)

	r.logger.Info("Ended recording session",
		"session_id", sessionID,
		"duration", time.Since(writer.startTime),
		"size_bytes", writer.size)

	return nil
}

// GetRecording retrieves a session recording. It decodes the binary format,
// stripping length prefixes and HMACs, and returns only the content bytes.
func (r *DefaultSessionRecorder) GetRecording(sessionID string) (*SessionRecording, error) {
	recPath := filepath.Join(r.storagePath, fmt.Sprintf("%s.rec", sessionID))

	if _, err := os.Stat(recPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("recording not found for session: %s", sessionID)
	}

	// Read metadata (best-effort; fields default to zero values if absent).
	metaPath := recPath + ".meta"
	var meta recordingMeta
	if metaBytes, err := os.ReadFile(metaPath); err == nil {
		_ = json.Unmarshal(metaBytes, &meta)
	}

	file, err := os.Open(recPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open recording file: %w", err)
	}
	defer func() { _ = file.Close() }()

	allContent := make([]byte, 0)
	events := make([]RecordEvent, 0)

	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(file, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read event length: %w", err)
		}

		contentLen := binary.BigEndian.Uint32(lenBuf[:])
		frameContent := make([]byte, contentLen)
		if _, err := io.ReadFull(file, frameContent); err != nil {
			return nil, fmt.Errorf("failed to read event content: %w", err)
		}

		// Skip the 32-byte HMAC — callers get only the content bytes.
		if _, err := io.ReadFull(file, make([]byte, 32)); err != nil {
			return nil, fmt.Errorf("failed to read event HMAC: %w", err)
		}

		rawContent, err := maybeDecompress(frameContent, meta.Compression)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress event: %w", err)
		}

		allContent = append(allContent, rawContent...)
		events = append(events, RecordEvent{
			Data: rawContent,
			Size: len(rawContent),
		})
	}

	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file stats: %w", err)
	}

	sessionMeta := SessionMetadata{
		SessionID:   meta.SessionID,
		StewardID:   meta.StewardID,
		UserID:      meta.UserID,
		Shell:       meta.Shell,
		CreatedAt:   meta.StartedAt,
		EndedAt:     meta.EndedAt,
		Environment: meta.Environment,
	}

	return &SessionRecording{
		SessionID: sessionID,
		Metadata:  sessionMeta,
		StartTime: meta.StartedAt,
		EndTime:   stat.ModTime(),
		Data:      allContent,
		Events:    events,
		Size:      stat.Size(),
	}, nil
}

// VerifyRecording walks the .rec file, recomputes each event's HMAC, and
// confirms the chain against the first/last checksums stored in metadata.
// Returns (true, nil) for an intact recording, (false, error) otherwise.
func (r *DefaultSessionRecorder) VerifyRecording(sessionID string) (bool, error) {
	metaPath := filepath.Join(r.storagePath, sessionID+".rec.meta")
	metaBytes, err := os.ReadFile(metaPath)
	if err != nil {
		return false, fmt.Errorf("failed to read recording metadata: %w", err)
	}

	var meta recordingMeta
	if err := json.Unmarshal(metaBytes, &meta); err != nil {
		return false, fmt.Errorf("failed to parse recording metadata: %w", err)
	}

	expectedFirst, err := hex.DecodeString(meta.FirstChecksum)
	if err != nil || len(expectedFirst) != 32 {
		return false, fmt.Errorf("invalid first_checksum in metadata")
	}
	expectedLast, err := hex.DecodeString(meta.LastChecksum)
	if err != nil || len(expectedLast) != 32 {
		return false, fmt.Errorf("invalid last_checksum in metadata")
	}

	recPath := filepath.Join(r.storagePath, sessionID+".rec")
	file, err := os.Open(recPath)
	if err != nil {
		return false, fmt.Errorf("failed to open recording: %w", err)
	}
	defer func() { _ = file.Close() }()

	var (
		sequence      int64
		prevChecksum  = make([]byte, 32) // all-zero sentinel matches first event
		firstComputed []byte
		lastComputed  []byte
		eventCount    int64
	)

	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(file, lenBuf[:]); err != nil {
			if err == io.EOF {
				break
			}
			return false, fmt.Errorf("failed to read event length at event %d: %w", sequence+1, err)
		}

		contentLen := binary.BigEndian.Uint32(lenBuf[:])
		content := make([]byte, contentLen)
		if _, err := io.ReadFull(file, content); err != nil {
			return false, fmt.Errorf("failed to read event content at event %d: %w", sequence+1, err)
		}

		storedHMAC := make([]byte, 32)
		if _, err := io.ReadFull(file, storedHMAC); err != nil {
			return false, fmt.Errorf("failed to read event HMAC at event %d: %w", sequence+1, err)
		}

		sequence++
		computed := computeEventChecksum(r.hmacKey, sequence, prevChecksum, content)

		if !hmac.Equal(computed, storedHMAC) {
			return false, fmt.Errorf("HMAC mismatch at event %d: recording has been tampered", sequence)
		}

		if sequence == 1 {
			firstComputed = computed
		}
		lastComputed = computed
		prevChecksum = computed
		eventCount++
	}

	if eventCount != meta.EventCount {
		return false, fmt.Errorf("event count mismatch: file has %d events, metadata says %d", eventCount, meta.EventCount)
	}

	if eventCount > 0 {
		if !hmac.Equal(firstComputed, expectedFirst) {
			return false, fmt.Errorf("first checksum mismatch: metadata has been tampered")
		}
		if !hmac.Equal(lastComputed, expectedLast) {
			return false, fmt.Errorf("last checksum mismatch: metadata has been tampered")
		}
	}

	return true, nil
}

// DeleteRecording deletes a session recording.
func (r *DefaultSessionRecorder) DeleteRecording(sessionID string) error {
	recPath := filepath.Join(r.storagePath, fmt.Sprintf("%s.rec", sessionID))
	metaPath := recPath + ".meta"

	if err := os.Remove(recPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete recording file: %w", err)
	}
	if err := os.Remove(metaPath); err != nil && !os.IsNotExist(err) {
		r.logger.Warn("Failed to delete metadata file", "path", metaPath, "error", err)
	}

	r.logger.Info("Deleted recording", "session_id", sessionID)
	return nil
}

// Close closes the recorder and cleans up resources.
func (r *DefaultSessionRecorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for sessionID, writer := range r.activeWrites {
		if err := writer.close(); err != nil {
			r.logger.Warn("Error closing writer during recorder shutdown",
				"session_id", sessionID, "error", err)
		}
	}

	r.activeWrites = make(map[string]*recordingWriter)
	r.logger.Info("Session recorder closed")
	return nil
}

// cleanupLegacyFiles removes .rec files that lack HMAC chain metadata.
// Called once at startup; pre-prod recordings are not preserved.
func (r *DefaultSessionRecorder) cleanupLegacyFiles() {
	entries, err := os.ReadDir(r.storagePath)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".rec" {
			continue
		}
		recPath := filepath.Join(r.storagePath, entry.Name())
		metaPath := recPath + ".meta"

		isLegacy := true
		if metaBytes, err := os.ReadFile(metaPath); err == nil {
			var m recordingMeta
			if json.Unmarshal(metaBytes, &m) == nil && m.FirstChecksum != "" {
				isLegacy = false
			}
		}

		if isLegacy {
			r.logger.Info("Removing legacy recording without HMAC chain", "file", recPath)
			_ = os.Remove(recPath)
			_ = os.Remove(metaPath)
		}
	}
}

// writeData writes one event in the binary length-prefixed format:
// [4-byte content length][content bytes][32-byte HMAC].
// HMAC is computed over the post-compression bytes that land on disk.
func (w *recordingWriter) writeData(data []byte, direction DataDirection) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.size+int64(len(data)) > w.maxSize {
		return fmt.Errorf("recording size limit exceeded for session: %s", w.sessionID)
	}

	content, err := maybeCompress(data, w.useCompression)
	if err != nil {
		return fmt.Errorf("failed to compress event: %w", err)
	}

	// Sequence is 1-based; advance before computing HMAC.
	w.sequence++
	checksum := computeEventChecksum(w.hmacKey, w.sequence, w.previousChecksum, content)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(content)))

	if _, err := w.file.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("failed to write length prefix: %w", err)
	}
	if _, err := w.file.Write(content); err != nil {
		return fmt.Errorf("failed to write event content: %w", err)
	}
	if _, err := w.file.Write(checksum); err != nil {
		return fmt.Errorf("failed to write event checksum: %w", err)
	}

	if w.sequence == 1 {
		w.firstChecksum = checksum
	}
	w.previousChecksum = checksum
	w.eventCount++
	w.size += int64(len(data))

	w.events = append(w.events, RecordEvent{
		Timestamp: time.Now(),
		Direction: direction,
		Data:      data,
		Size:      len(data),
	})

	return nil
}

// close finalises the recording file and writes the metadata JSON.
func (w *recordingWriter) close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	closeErr := w.file.Close()

	metadataPath := w.file.Name() + ".meta"
	metaFile, createErr := os.Create(metadataPath)
	if createErr != nil {
		if closeErr != nil {
			return closeErr
		}
		return createErr
	}
	defer func() { _ = metaFile.Close() }()

	endTime := time.Now()

	// Encode chain anchors; use all-zero checksums when no events were written.
	firstCS := hex.EncodeToString(w.firstChecksum)
	lastCS := hex.EncodeToString(w.previousChecksum)
	if len(w.firstChecksum) == 0 {
		zero := make([]byte, 32)
		firstCS = hex.EncodeToString(zero)
		lastCS = hex.EncodeToString(zero)
	}

	meta := recordingMeta{
		SessionID:     w.sessionID,
		FirstChecksum: firstCS,
		LastChecksum:  lastCS,
		EventCount:    w.eventCount,
		StartedAt:     w.startTime,
		EndedAt:       &endTime,
		Compression:   w.useCompression,
	}
	if w.metadata != nil {
		meta.StewardID = w.metadata.StewardID
		meta.UserID = w.metadata.UserID
		meta.Shell = w.metadata.Shell
		meta.Environment = w.metadata.Environment
	}

	if jsonErr := json.NewEncoder(metaFile).Encode(meta); jsonErr != nil && closeErr == nil {
		return jsonErr
	}

	return closeErr
}

// maybeCompress gzip-compresses data into a fresh buffer when enabled.
func maybeCompress(data []byte, enabled bool) ([]byte, error) {
	if !enabled {
		return data, nil
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// maybeDecompress gzip-decompresses data when enabled.
func maybeDecompress(data []byte, enabled bool) ([]byte, error) {
	if !enabled {
		return data, nil
	}
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out, err := io.ReadAll(gr)
	_ = gr.Close()
	return out, err
}
