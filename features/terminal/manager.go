// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package terminal

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultSessionManager implements the SessionManager interface
type DefaultSessionManager struct {
	mu        sync.RWMutex
	config    *Config
	logger    logging.Logger
	sessions  map[string]*Session
	recorder  Recorder
	cleanupCh chan string
	stopCh    chan struct{}
}

// NewSessionManager creates a new session manager
func NewSessionManager(config *Config, logger logging.Logger) (SessionManager, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	if config.SessionTimeout <= 0 {
		return nil, fmt.Errorf("session timeout must be positive")
	}

	if config.MaxSessions <= 0 {
		return nil, fmt.Errorf("max sessions must be positive")
	}

	manager := &DefaultSessionManager{
		config:    config,
		logger:    logger,
		sessions:  make(map[string]*Session),
		cleanupCh: make(chan string, 100),
		stopCh:    make(chan struct{}),
	}

	// Initialize recorder if recording is enabled
	if config.RecordSessions {
		recorderConfig := DefaultRecorderConfig()
		recorder, err := NewSessionRecorder(recorderConfig, logger)
		if err != nil {
			logger.Warn("Failed to initialize session recorder, continuing without recording", "error", err)
		} else {
			manager.recorder = recorder
		}
	}

	// Start background cleanup routine
	go manager.cleanupRoutine()

	logger.Info("Session manager initialized",
		"max_sessions", config.MaxSessions,
		"session_timeout", config.SessionTimeout,
		"record_sessions", config.RecordSessions)

	return manager, nil
}

// CreateSession creates a new terminal session
func (m *DefaultSessionManager) CreateSession(ctx context.Context, req *SessionRequest) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check session limit
	if len(m.sessions) >= m.config.MaxSessions {
		return nil, fmt.Errorf("maximum number of sessions (%d) reached", m.config.MaxSessions)
	}

	// Create new session
	session, err := NewSession(req, m.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Set recorder if available
	if m.recorder != nil {
		session.SetRecorder(m.recorder)

		// Start recording session
		metadata := session.GetMetadata()
		if recorder, ok := m.recorder.(*DefaultSessionRecorder); ok {
			if err := recorder.StartRecording(session.ID, metadata); err != nil {
				m.logger.Warn("Failed to start session recording", "session_id", session.ID, "error", err)
			}
		}
	}

	// Store session
	m.sessions[session.ID] = session

	m.logger.Info("Session created",
		"session_id", session.ID,
		"steward_id", session.StewardID,
		"user_id", session.UserID,
		"active_sessions", len(m.sessions))

	return session, nil
}

// GetSession retrieves a session by ID
func (m *DefaultSessionManager) GetSession(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	return session, nil
}

// TerminateSession terminates a session
func (m *DefaultSessionManager) TerminateSession(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Close the session
	if err := session.Close(ctx); err != nil {
		m.logger.Warn("Error closing session", "session_id", sessionID, "error", err)
	}

	// End recording if recorder is available
	if m.recorder != nil {
		if recorder, ok := m.recorder.(*DefaultSessionRecorder); ok {
			if err := recorder.EndRecording(sessionID); err != nil {
				m.logger.Warn("Failed to end session recording", "session_id", sessionID, "error", err)
			}
		}
	}

	// Remove from active sessions
	delete(m.sessions, sessionID)

	m.logger.Info("Session terminated",
		"session_id", sessionID,
		"active_sessions", len(m.sessions))

	return nil
}

// GetActiveSessions returns all active sessions
func (m *DefaultSessionManager) GetActiveSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*Session, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// RecordData records data for a session
func (m *DefaultSessionManager) RecordData(sessionID string, data []byte, direction DataDirection) error {
	if m.recorder == nil {
		return fmt.Errorf("recording is not enabled")
	}

	return m.recorder.RecordData(sessionID, data, direction)
}

// GetSessionRecording retrieves a session recording
func (m *DefaultSessionManager) GetSessionRecording(sessionID string) (*SessionRecording, error) {
	if m.recorder == nil {
		return nil, fmt.Errorf("recording is not enabled")
	}

	return m.recorder.GetRecording(sessionID)
}

// cleanupRoutine runs in the background to clean up timed-out sessions
func (m *DefaultSessionManager) cleanupRoutine() {
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.CleanupTimedOutSessions()
		case sessionID := <-m.cleanupCh:
			m.cleanupSession(sessionID)
		case <-m.stopCh:
			return
		}
	}
}

// CleanupTimedOutSessions removes sessions that have timed out
func (m *DefaultSessionManager) CleanupTimedOutSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	timedOutSessions := make([]string, 0)

	for sessionID, session := range m.sessions {
		if session.IsTimedOut(m.config.SessionTimeout) {
			timedOutSessions = append(timedOutSessions, sessionID)
		}
	}

	// Clean up timed-out sessions
	for _, sessionID := range timedOutSessions {
		session := m.sessions[sessionID]

		// Close the session
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := session.Close(ctx); err != nil {
			m.logger.Warn("Error closing timed-out session", "session_id", sessionID, "error", err)
		}
		cancel()

		// End recording if available
		if m.recorder != nil {
			if recorder, ok := m.recorder.(*DefaultSessionRecorder); ok {
				if err := recorder.EndRecording(sessionID); err != nil {
					m.logger.Warn("Failed to end recording for timed-out session", "session_id", sessionID, "error", err)
				}
			}
		}

		// Remove from active sessions
		delete(m.sessions, sessionID)

		m.logger.Info("Session timed out and cleaned up",
			"session_id", sessionID,
			"timeout", m.config.SessionTimeout)
	}

	if len(timedOutSessions) > 0 {
		m.logger.Info("Cleaned up timed-out sessions",
			"count", len(timedOutSessions),
			"active_sessions", len(m.sessions))
	}
}

// cleanupSession cleans up a specific session
func (m *DefaultSessionManager) cleanupSession(sessionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := m.TerminateSession(ctx, sessionID); err != nil {
		m.logger.Warn("Failed to cleanup session", "session_id", sessionID, "error", err)
	}
}

// RequestCleanup requests cleanup of a session (called from WebSocket handler)
func (m *DefaultSessionManager) RequestCleanup(sessionID string) {
	select {
	case m.cleanupCh <- sessionID:
	default:
		m.logger.Warn("Cleanup channel full, session may not be cleaned up immediately", "session_id", sessionID)
	}
}

// Stop stops the session manager and cleans up resources
func (m *DefaultSessionManager) Stop(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Signal cleanup routine to stop
	close(m.stopCh)

	// Close all active sessions
	for sessionID, session := range m.sessions {
		if err := session.Close(ctx); err != nil {
			m.logger.Warn("Error closing session during shutdown", "session_id", sessionID, "error", err)
		}
	}

	// Close recorder if available
	if m.recorder != nil {
		if err := m.recorder.Close(); err != nil {
			m.logger.Warn("Error closing recorder during shutdown", "error", err)
		}
	}

	m.logger.Info("Session manager stopped", "sessions_closed", len(m.sessions))
	return nil
}
