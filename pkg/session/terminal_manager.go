// Package session provides terminal session management using RuntimeStore
package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/terminal"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TerminalSessionManager manages terminal sessions using pluggable storage
// This replaces the original DefaultSessionManager with Epic 6 compliance
type TerminalSessionManager struct {
	sessionManager SessionManager
	config         *terminal.Config
	logger         logging.Logger
	recorder       terminal.Recorder

	// Session mapping for existing terminal interface compatibility
	activeSessions map[string]*terminal.Session
	mutex          sync.RWMutex
}

// NewTerminalSessionManager creates a terminal session manager with pluggable storage
// persistentSessions: if true, terminal sessions survive controller restarts (uses database storage)
// if false, terminal sessions are ephemeral (uses memory storage, existing behavior)
func NewTerminalSessionManager(
	sessionManager SessionManager,
	config *terminal.Config,
	logger logging.Logger,
	persistentSessions bool,
) (*TerminalSessionManager, error) {

	if sessionManager == nil {
		return nil, fmt.Errorf("session manager is required")
	}
	if config == nil {
		return nil, fmt.Errorf("terminal config is required")
	}
	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	manager := &TerminalSessionManager{
		sessionManager: sessionManager,
		config:         config,
		logger:         logger,
		activeSessions: make(map[string]*terminal.Session),
	}

	// Initialize recorder if recording is enabled
	if config.RecordSessions {
		recorderConfig := terminal.DefaultRecorderConfig()
		recorder, err := terminal.NewSessionRecorder(recorderConfig, logger)
		if err != nil {
			logger.Warn("Failed to initialize session recorder, continuing without recording", "error", err)
		} else {
			manager.recorder = recorder
		}
	}

	// Restore active sessions if persistent sessions are enabled
	if persistentSessions {
		if err := manager.restoreActiveSessions(context.Background()); err != nil {
			logger.Warn("Failed to restore active terminal sessions", "error", err)
		}
	}

	logger.Info("Terminal session manager initialized",
		"max_sessions", config.MaxSessions,
		"session_timeout", config.SessionTimeout,
		"record_sessions", config.RecordSessions,
		"persistent_sessions", persistentSessions)

	return manager, nil
}

// CreateSession creates a new terminal session using RuntimeStore
// Epic 6 Compliance: Only persistent sessions use durable storage (database/git)
// Ephemeral sessions use memory storage and are lost on controller restart
func (m *TerminalSessionManager) CreateSession(ctx context.Context, req *terminal.SessionRequest) (*terminal.Session, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check session limit
	if len(m.activeSessions) >= m.config.MaxSessions {
		return nil, fmt.Errorf("maximum number of sessions (%d) reached", m.config.MaxSessions)
	}

	// Create terminal session object
	terminalSession, err := terminal.NewSession(req, m.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create terminal session: %w", err)
	}

	// Set recorder if available
	if m.recorder != nil {
		terminalSession.SetRecorder(m.recorder)
		metadata := terminalSession.GetMetadata()
		if recorder, ok := m.recorder.(*terminal.DefaultSessionRecorder); ok {
			if err := recorder.StartRecording(terminalSession.ID, metadata); err != nil {
				m.logger.Warn("Failed to start session recording", "session_id", terminalSession.ID, "error", err)
			}
		}
	}

	// Create session in RuntimeStore
	sessionReq := &TerminalSessionRequest{
		SessionCreateRequest: SessionCreateRequest{
			SessionID:   terminalSession.ID,
			UserID:      req.UserID,
			TenantID:    "default", // TODO: Extract from request or context
			SessionType: interfaces.SessionTypeTerminal,
			Timeout:     m.config.SessionTimeout,
			ClientInfo:  &interfaces.ClientInfo{
				// TODO: Extract from request context
			},
			Metadata: map[string]string{
				"shell":      req.Shell,
				"steward_id": req.StewardID,
			},
			SessionData: &interfaces.TerminalSessionData{
				StewardID:        req.StewardID,
				Shell:            req.Shell,
				Cols:             req.Cols,
				Rows:             req.Rows,
				Environment:      req.Env,
				RecordingEnabled: m.config.RecordSessions,
			},
			SecurityContext: map[string]interface{}{
				"terminal_access": true,
				"steward_id":      req.StewardID,
			},
		},
		StewardID:   req.StewardID,
		Shell:       req.Shell,
		Cols:        req.Cols,
		Rows:        req.Rows,
		Environment: req.Env,
	}

	// Store in unified session manager
	runtimeSession, err := m.sessionManager.CreateSession(ctx, &sessionReq.SessionCreateRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create session in runtime store: %w", err)
	}

	// Store in local active sessions for compatibility
	m.activeSessions[terminalSession.ID] = terminalSession

	m.logger.Info("Terminal session created",
		"session_id", terminalSession.ID,
		"steward_id", req.StewardID,
		"user_id", req.UserID,
		"shell", req.Shell,
		"persistent", runtimeSession.Persistent,
		"active_sessions", len(m.activeSessions))

	return terminalSession, nil
}

// GetSession retrieves a terminal session by ID
func (m *TerminalSessionManager) GetSession(sessionID string) (*terminal.Session, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Try local cache first for performance
	if session, exists := m.activeSessions[sessionID]; exists {
		return session, nil
	}

	// If not in cache, try to restore from storage
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	runtimeSession, err := m.sessionManager.GetSession(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}

	// Reconstruct terminal session from runtime session
	terminalSession, err := m.restoreTerminalSession(runtimeSession)
	if err != nil {
		return nil, fmt.Errorf("failed to restore terminal session: %w", err)
	}

	// Add to local cache
	m.activeSessions[sessionID] = terminalSession

	return terminalSession, nil
}

// TerminateSession terminates a session and removes it from storage
func (m *TerminalSessionManager) TerminateSession(ctx context.Context, sessionID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Get session from local cache or storage
	session, exists := m.activeSessions[sessionID]
	if !exists {
		// Try to get from storage
		if runtimeSession, err := m.sessionManager.GetSession(ctx, sessionID); err == nil {
			if restored, err := m.restoreTerminalSession(runtimeSession); err == nil {
				session = restored
			}
		}
	}

	if session == nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	// Close the terminal session
	if err := session.Close(ctx); err != nil {
		m.logger.Warn("Error closing terminal session", "session_id", sessionID, "error", err)
	}

	// End recording if recorder is available
	if m.recorder != nil {
		if recorder, ok := m.recorder.(*terminal.DefaultSessionRecorder); ok {
			if err := recorder.EndRecording(sessionID); err != nil {
				m.logger.Warn("Failed to end session recording", "session_id", sessionID, "error", err)
			}
		}
	}

	// Terminate in unified session manager
	if err := m.sessionManager.TerminateSession(ctx, sessionID, "user_requested"); err != nil {
		m.logger.Warn("Failed to terminate session in runtime store", "session_id", sessionID, "error", err)
	}

	// Remove from local cache
	delete(m.activeSessions, sessionID)

	m.logger.Info("Terminal session terminated",
		"session_id", sessionID,
		"active_sessions", len(m.activeSessions))

	return nil
}

// GetActiveSessions returns all active terminal sessions
func (m *TerminalSessionManager) GetActiveSessions() []*terminal.Session {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	sessions := make([]*terminal.Session, 0, len(m.activeSessions))
	for _, session := range m.activeSessions {
		sessions = append(sessions, session)
	}

	return sessions
}

// RecordData records data for a session (compatibility with existing interface)
func (m *TerminalSessionManager) RecordData(sessionID string, data []byte, direction terminal.DataDirection) error {
	if m.recorder == nil {
		return fmt.Errorf("recording is not enabled")
	}

	return m.recorder.RecordData(sessionID, data, direction)
}

// GetSessionRecording retrieves a session recording (compatibility with existing interface)
func (m *TerminalSessionManager) GetSessionRecording(sessionID string) (*terminal.SessionRecording, error) {
	if m.recorder == nil {
		return nil, fmt.Errorf("recording is not enabled")
	}

	return m.recorder.GetRecording(sessionID)
}

// CleanupTimedOutSessions removes sessions that have timed out
// This now delegates to the unified session manager's cleanup
func (m *TerminalSessionManager) CleanupTimedOutSessions() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get list of expired sessions from unified manager
	filter := &interfaces.SessionFilter{
		Type:   interfaces.SessionTypeTerminal,
		Status: interfaces.SessionStatusActive,
	}

	sessions, err := m.sessionManager.ListSessions(ctx, filter)
	if err != nil {
		m.logger.Warn("Failed to list terminal sessions for cleanup", "error", err)
		return
	}

	var expiredSessions []string
	now := time.Now()

	for _, session := range sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, session.SessionID)
		}
	}

	// Clean up expired sessions
	for _, sessionID := range expiredSessions {
		if err := m.TerminateSession(ctx, sessionID); err != nil {
			m.logger.Warn("Failed to cleanup expired session", "session_id", sessionID, "error", err)
		}
	}

	if len(expiredSessions) > 0 {
		m.logger.Info("Cleaned up expired terminal sessions",
			"count", len(expiredSessions),
			"active_sessions", len(m.activeSessions))
	}
}

// UpdateSessionActivity updates the last activity time for a session
func (m *TerminalSessionManager) UpdateSessionActivity(ctx context.Context, sessionID string) error {
	now := time.Now()
	updates := &SessionUpdateRequest{
		LastActivity: &now,
		ModifiedBy:   "terminal_activity",
	}

	_, err := m.sessionManager.UpdateSession(ctx, sessionID, updates)
	if err != nil {
		m.logger.Warn("Failed to update session activity", "session_id", sessionID, "error", err)
	}

	return err
}

// Stop stops the terminal session manager and performs cleanup
func (m *TerminalSessionManager) Stop(ctx context.Context) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.logger.Info("Stopping terminal session manager")

	// Close all active sessions
	for sessionID, session := range m.activeSessions {
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

	// Clear active sessions
	m.activeSessions = make(map[string]*terminal.Session)

	m.logger.Info("Terminal session manager stopped")
	return nil
}

// Helper methods

// restoreActiveSessions restores active terminal sessions from storage on startup
func (m *TerminalSessionManager) restoreActiveSessions(ctx context.Context) error {
	filter := &interfaces.SessionFilter{
		Type:   interfaces.SessionTypeTerminal,
		Status: interfaces.SessionStatusActive,
	}

	sessions, err := m.sessionManager.ListSessions(ctx, filter)
	if err != nil {
		return fmt.Errorf("failed to list active terminal sessions: %w", err)
	}

	restoredCount := 0
	for _, runtimeSession := range sessions {
		// Check if session is expired
		if time.Now().After(runtimeSession.ExpiresAt) {
			// Clean up expired session
			_ = m.sessionManager.TerminateSession(ctx, runtimeSession.SessionID, "expired_on_startup")
			continue
		}

		// Restore terminal session
		terminalSession, err := m.restoreTerminalSession(runtimeSession)
		if err != nil {
			m.logger.Warn("Failed to restore terminal session",
				"session_id", runtimeSession.SessionID,
				"error", err)
			continue
		}

		m.activeSessions[runtimeSession.SessionID] = terminalSession
		restoredCount++
	}

	if restoredCount > 0 {
		m.logger.Info("Restored active terminal sessions",
			"count", restoredCount,
			"total_active", len(m.activeSessions))
	}

	return nil
}

// restoreTerminalSession converts a runtime session back to a terminal session
func (m *TerminalSessionManager) restoreTerminalSession(runtimeSession *interfaces.Session) (*terminal.Session, error) {
	// Extract terminal session data
	terminalData, ok := runtimeSession.SessionData.(*interfaces.TerminalSessionData)
	if !ok {
		// Try to decode from interface{} if needed
		if dataMap, ok := runtimeSession.SessionData.(map[string]interface{}); ok {
			terminalData = &interfaces.TerminalSessionData{}
			if stewardID, ok := dataMap["steward_id"].(string); ok {
				terminalData.StewardID = stewardID
			}
			if shell, ok := dataMap["shell"].(string); ok {
				terminalData.Shell = shell
			}
			if cols, ok := dataMap["cols"].(float64); ok {
				terminalData.Cols = int(cols)
			}
			if rows, ok := dataMap["rows"].(float64); ok {
				terminalData.Rows = int(rows)
			}
			if env, ok := dataMap["environment"].(map[string]interface{}); ok {
				terminalData.Environment = make(map[string]string)
				for k, v := range env {
					if str, ok := v.(string); ok {
						terminalData.Environment[k] = str
					}
				}
			}
		} else {
			return nil, fmt.Errorf("invalid terminal session data format")
		}
	}

	// Create session request for restoration
	req := &terminal.SessionRequest{
		StewardID: terminalData.StewardID,
		UserID:    runtimeSession.UserID,
		Shell:     terminalData.Shell,
		Cols:      terminalData.Cols,
		Rows:      terminalData.Rows,
		Env:       terminalData.Environment,
	}

	// Create new terminal session with restored data
	session, err := terminal.NewSession(req, m.logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create restored terminal session: %w", err)
	}

	// Update session with restored metadata
	session.ID = runtimeSession.SessionID
	// Note: We don't restore shell executor state as that's ephemeral

	return session, nil
}
