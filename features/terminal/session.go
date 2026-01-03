// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package terminal

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/features/terminal/shell"
	"github.com/cfgis/cfgms/pkg/logging"
)

// NewSession creates a new terminal session
func NewSession(req *SessionRequest, logger logging.Logger) (*Session, error) {
	if req == nil {
		return nil, fmt.Errorf("session request cannot be nil")
	}

	// Validate required fields
	if req.StewardID == "" {
		return nil, fmt.Errorf("steward_id is required")
	}
	if req.UserID == "" {
		return nil, fmt.Errorf("user_id is required")
	}
	if req.Shell == "" {
		req.Shell = shell.GetDefaultShell() // Default to platform-appropriate shell
	}
	if !ValidateShell(req.Shell) {
		return nil, fmt.Errorf("unsupported shell: %s", req.Shell)
	}

	// Validate terminal dimensions - set defaults but don't fail for zero values
	if req.Cols <= 0 {
		req.Cols = 80 // Default columns
	}
	if req.Rows <= 0 {
		req.Rows = 24 // Default rows
	}

	// Generate unique session ID
	sessionID := uuid.New().String()

	now := time.Now()
	session := &Session{
		ID:           sessionID,
		StewardID:    req.StewardID,
		UserID:       req.UserID,
		Shell:        req.Shell,
		Cols:         req.Cols,
		Rows:         req.Rows,
		CreatedAt:    now,
		LastActivity: now,
		Environment:  req.Env,
		closed:       false,
	}

	// Initialize shell executor
	factory := shell.NewFactory()
	shellConfig := &shell.Config{
		Shell:       req.Shell,
		Cols:        req.Cols,
		Rows:        req.Rows,
		Environment: req.Env,
	}

	executor, err := factory.CreateExecutor(shellConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create shell executor: %w", err)
	}

	session.executor = executor

	logger.Info("Created new terminal session",
		"session_id", sessionID,
		"steward_id", req.StewardID,
		"user_id", req.UserID,
		"shell", req.Shell,
		"cols", req.Cols,
		"rows", req.Rows)

	return session, nil
}

// WriteData writes data to the session
func (s *Session) WriteData(ctx context.Context, data []byte) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return fmt.Errorf("session is closed")
	}
	s.mu.RUnlock()

	s.UpdateActivity()

	// Record input data if recorder is set
	if s.recorder != nil {
		if err := s.recorder.RecordData(s.ID, data, DataDirectionInput); err != nil {
			// Log error but don't fail the write operation
			// This ensures terminal functionality continues even if recording fails
			_ = err // Explicitly ignore recording errors for resilience
		}
	}

	// Send data to shell executor
	if s.executor != nil {
		if err := s.executor.WriteData(ctx, data); err != nil {
			return fmt.Errorf("failed to write to shell: %w", err)
		}
	}

	return nil
}

// HandleOutput handles output data from the shell
func (s *Session) HandleOutput(ctx context.Context, data []byte) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return fmt.Errorf("session is closed")
	}
	s.mu.RUnlock()

	s.UpdateActivity()

	// Record output data if recorder is set
	if s.recorder != nil {
		if err := s.recorder.RecordData(s.ID, data, DataDirectionOutput); err != nil {
			// Log error but don't fail the operation
			_ = err // Explicitly ignore recording errors for resilience
		}
	}

	return nil
}

// Resize resizes the terminal
func (s *Session) Resize(ctx context.Context, cols, rows int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("session is closed")
	}

	if cols <= 0 || rows <= 0 {
		return fmt.Errorf("invalid terminal dimensions: cols=%d, rows=%d", cols, rows)
	}

	s.Cols = cols
	s.Rows = rows
	s.LastActivity = time.Now() // Update activity directly since we already hold the lock

	// Resize the shell executor
	if s.executor != nil {
		if err := s.executor.Resize(ctx, cols, rows); err != nil {
			return fmt.Errorf("failed to resize shell: %w", err)
		}
	}

	return nil
}

// Close closes the session
func (s *Session) Close(ctx context.Context) error {
	// First, check if already closed and mark as closing
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil // Already closed
	}
	s.closed = true

	// Store references to resources we need to clean up
	executor := s.executor
	recorder := s.recorder
	s.mu.Unlock()

	// Close shell executor - done without holding lock to prevent deadlock
	// This allows handleShellOutput to acquire the RLock and exit cleanly
	if executor != nil {
		if err := executor.Close(ctx); err != nil {
			// Log error but continue cleanup
			_ = err // Explicitly ignore close errors during cleanup
		}
	}

	// Close recorder if set
	if recorder != nil {
		if err := recorder.Close(); err != nil {
			// Log error but continue cleanup
			_ = err // Explicitly ignore close errors during cleanup
		}
	}

	return nil
}

// IsActive returns true if the session is active
func (s *Session) IsActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.closed
}

// IsClosed returns true if the session is closed
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// UpdateActivity updates the last activity timestamp
func (s *Session) UpdateActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActivity = time.Now()
}

// IsTimedOut returns true if the session has timed out
func (s *Session) IsTimedOut(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastActivity) > timeout
}

// GetMetadata returns session metadata
func (s *Session) GetMetadata() *SessionMetadata {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metadata := &SessionMetadata{
		SessionID:   s.ID,
		StewardID:   s.StewardID,
		UserID:      s.UserID,
		Shell:       s.Shell,
		CreatedAt:   s.CreatedAt,
		Environment: s.Environment,
	}

	if s.closed {
		endTime := time.Now()
		metadata.EndedAt = &endTime
	}

	return metadata
}

// SetRecorder sets the session recorder
func (s *Session) SetRecorder(recorder Recorder) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recorder = recorder
}

// Start starts the shell execution
func (s *Session) Start(ctx context.Context) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return fmt.Errorf("session is closed")
	}

	if s.executor == nil {
		s.mu.RUnlock()
		return fmt.Errorf("no shell executor available")
	}
	executor := s.executor // Copy reference while holding lock
	s.mu.RUnlock()

	// Start the shell executor
	if err := executor.Start(ctx, nil); err != nil {
		return fmt.Errorf("failed to start shell: %w", err)
	}

	// Start output handler
	go s.handleShellOutput(ctx)

	return nil
}

// handleShellOutput handles output from the shell executor
func (s *Session) handleShellOutput(ctx context.Context) {
	s.mu.RLock()
	if s.executor == nil {
		s.mu.RUnlock()
		return
	}
	outputChan := s.executor.OutputChannel()
	errorChan := s.executor.ErrorChannel()
	s.mu.RUnlock()

	for {
		select {
		case <-ctx.Done():
			return
		case data, ok := <-outputChan:
			if !ok {
				return // Channel closed
			}

			// Handle the output data (send to WebSocket, record, etc.)
			if err := s.HandleOutput(ctx, data); err != nil {
				// Log error but continue processing output
				_ = err // Explicitly ignore output handling errors for resilience
			}

		case err, ok := <-errorChan:
			if !ok {
				return // Channel closed
			}

			// Handle errors (could send error message to WebSocket)
			_ = err // For now, just ignore errors
		}
	}
}

// GetOutputChannel returns the shell output channel
func (s *Session) GetOutputChannel() <-chan []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.executor == nil {
		return nil
	}
	return s.executor.OutputChannel()
}

// GetErrorChannel returns the shell error channel
func (s *Session) GetErrorChannel() <-chan error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.executor == nil {
		return nil
	}
	return s.executor.ErrorChannel()
}
