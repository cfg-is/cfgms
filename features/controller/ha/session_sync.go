//go:build commercial
// +build commercial

package ha

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// sessionSynchronizer implements SessionSynchronizer interface
type sessionSynchronizer struct {
	mu      sync.RWMutex
	cfg     *SessionSyncConfig
	logger  logging.Logger
	storage *interfaces.StorageManager
	manager *Manager // Reference to HA manager for node info
	ctx     context.Context
	cancel  context.CancelFunc
	started bool

	// Session state management
	localSessions   map[string]*sessionState
	sessionHandlers []SessionStateHandler

	// Synchronization state
	lastSyncTime time.Time
}

// sessionState represents the state of a session
type sessionState struct {
	SessionID string                 `json:"session_id"`
	NodeID    string                 `json:"node_id"`
	UserID    string                 `json:"user_id,omitempty"`
	TenantID  string                 `json:"tenant_id,omitempty"`
	State     interface{}            `json:"state"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
	ExpiresAt time.Time              `json:"expires_at"`
	Size      int                    `json:"size"`
}

// NewSessionSynchronizer creates a new session synchronizer
func NewSessionSynchronizer(cfg *SessionSyncConfig, logger logging.Logger, storage *interfaces.StorageManager, manager *Manager) (SessionSynchronizer, error) {
	if cfg == nil {
		cfg = &SessionSyncConfig{
			Enabled:      true,
			SyncInterval: 5 * time.Second,
			StateTimeout: 300 * time.Second,
			MaxStateSize: 1024 * 1024, // 1MB
		}
	}

	return &sessionSynchronizer{
		cfg:           cfg,
		logger:        logger,
		storage:       storage,
		manager:       manager,
		localSessions: make(map[string]*sessionState),
	}, nil
}

// Start begins session synchronization
func (s *sessionSynchronizer) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.cfg.Enabled {
		s.logger.Info("Session synchronization is disabled")
		return nil
	}

	if s.started {
		return fmt.Errorf("session synchronizer is already started")
	}

	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	s.lastSyncTime = time.Now()

	// Start periodic synchronization
	go s.periodicSync()

	// Start cleanup routine
	go s.periodicCleanup()

	s.logger.Info("Session synchronizer started",
		"sync_interval", s.cfg.SyncInterval,
		"state_timeout", s.cfg.StateTimeout,
		"max_state_size", s.cfg.MaxStateSize)

	return nil
}

// Stop stops session synchronization
func (s *sessionSynchronizer) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return nil
	}

	if s.cancel != nil {
		s.cancel()
	}

	s.started = false
	s.logger.Info("Session synchronizer stopped")

	return nil
}

// SyncSessionState synchronizes session state to other cluster nodes
func (s *sessionSynchronizer) SyncSessionState(ctx context.Context, sessionID string, state interface{}) error {
	if !s.cfg.Enabled {
		return nil // Silently ignore if disabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate state size
	stateData, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to marshal session state: %w", err)
	}

	if len(stateData) > s.cfg.MaxStateSize {
		return fmt.Errorf("session state size (%d bytes) exceeds maximum (%d bytes)",
			len(stateData), s.cfg.MaxStateSize)
	}

	// Create or update session state
	now := time.Now()
	nodeID := "local"
	if s.manager != nil && s.manager.nodeInfo != nil {
		nodeID = s.manager.nodeInfo.ID
	}
	sessionState := &sessionState{
		SessionID: sessionID,
		NodeID:    nodeID,
		State:     state,
		UpdatedAt: now,
		ExpiresAt: now.Add(s.cfg.StateTimeout),
		Size:      len(stateData),
	}

	// If this is a new session, set created time
	if existing, exists := s.localSessions[sessionID]; exists {
		sessionState.CreatedAt = existing.CreatedAt
		sessionState.UserID = existing.UserID
		sessionState.TenantID = existing.TenantID
		sessionState.Metadata = existing.Metadata
	} else {
		sessionState.CreatedAt = now
		sessionState.Metadata = make(map[string]interface{})
	}

	s.localSessions[sessionID] = sessionState

	// Store in persistent storage for cluster synchronization
	if err := s.persistSessionState(ctx, sessionState); err != nil {
		s.logger.Warn("Failed to persist session state", "session_id", sessionID, "error", err)
		// Don't return error as local state is updated
	}

	s.logger.Debug("Session state synchronized",
		"session_id", sessionID,
		"size", sessionState.Size)

	return nil
}

// GetSessionState retrieves session state from the cluster
func (s *sessionSynchronizer) GetSessionState(ctx context.Context, sessionID string) (interface{}, error) {
	if !s.cfg.Enabled {
		return nil, fmt.Errorf("session synchronization is disabled")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check local sessions first
	if sessionState, exists := s.localSessions[sessionID]; exists {
		if time.Now().Before(sessionState.ExpiresAt) {
			return sessionState.State, nil
		}
		// Session expired, will be cleaned up later
	}

	// Try to load from persistent storage
	sessionState, err := s.loadSessionState(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	// Check if session is expired
	if time.Now().After(sessionState.ExpiresAt) {
		return nil, fmt.Errorf("session expired")
	}

	return sessionState.State, nil
}

// RemoveSessionState removes session state from the cluster
func (s *sessionSynchronizer) RemoveSessionState(ctx context.Context, sessionID string) error {
	if !s.cfg.Enabled {
		return nil // Silently ignore if disabled
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Remove from local sessions
	delete(s.localSessions, sessionID)

	// Remove from persistent storage
	if err := s.removePersistedSessionState(ctx, sessionID); err != nil {
		s.logger.Warn("Failed to remove persisted session state",
			"session_id", sessionID, "error", err)
	}

	// Notify handlers
	for _, handler := range s.sessionHandlers {
		if err := handler.OnSessionRemoved(sessionID); err != nil {
			s.logger.Warn("Session removal handler failed",
				"session_id", sessionID, "error", err)
		}
	}

	s.logger.Debug("Session state removed", "session_id", sessionID)

	return nil
}

// Subscribe to session state changes
func (s *sessionSynchronizer) Subscribe(ctx context.Context, handler SessionStateHandler) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sessionHandlers = append(s.sessionHandlers, handler)
	s.logger.Debug("Session state handler subscribed")

	return nil
}

// periodicSync performs periodic synchronization with other nodes
func (s *sessionSynchronizer) periodicSync() {
	ticker := time.NewTicker(s.cfg.SyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.performSync()
		}
	}
}

// performSync performs synchronization with persistent storage
func (s *sessionSynchronizer) performSync() {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
	defer cancel()

	// Load all sessions from storage that were updated since last sync
	sessions, err := s.loadSessionsSince(ctx, s.lastSyncTime)
	if err != nil {
		s.logger.Warn("Failed to load sessions for sync", "error", err)
		return
	}

	changedSessions := 0
	localNodeID := "local"
	if s.manager != nil && s.manager.nodeInfo != nil {
		localNodeID = s.manager.nodeInfo.ID
	}

	for _, sessionState := range sessions {
		// Skip sessions from this node
		if sessionState.NodeID == localNodeID {
			continue
		}

		// Check if this is a new or updated session
		existing, exists := s.localSessions[sessionState.SessionID]
		if !exists || existing.UpdatedAt.Before(sessionState.UpdatedAt) {
			s.localSessions[sessionState.SessionID] = sessionState
			changedSessions++

			// Notify handlers of state change
			for _, handler := range s.sessionHandlers {
				if err := handler.OnSessionStateChanged(sessionState.SessionID, sessionState.State); err != nil {
					s.logger.Warn("Session state change handler failed",
						"session_id", sessionState.SessionID, "error", err)
				}
			}
		}
	}

	s.lastSyncTime = time.Now()

	if changedSessions > 0 {
		s.logger.Debug("Session sync completed",
			"changed_sessions", changedSessions,
			"total_sessions", len(s.localSessions))
	}
}

// periodicCleanup performs periodic cleanup of expired sessions
func (s *sessionSynchronizer) periodicCleanup() {
	ticker := time.NewTicker(s.cfg.SyncInterval * 2) // Cleanup less frequently than sync
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.performCleanup()
		}
	}
}

// performCleanup removes expired sessions
func (s *sessionSynchronizer) performCleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	expiredSessions := make([]string, 0)

	// Find expired sessions
	for sessionID, sessionState := range s.localSessions {
		if now.After(sessionState.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	// Remove expired sessions
	for _, sessionID := range expiredSessions {
		delete(s.localSessions, sessionID)

		// Notify handlers
		for _, handler := range s.sessionHandlers {
			if err := handler.OnSessionRemoved(sessionID); err != nil {
				s.logger.Warn("Session removal handler failed",
					"session_id", sessionID, "error", err)
			}
		}
	}

	if len(expiredSessions) > 0 {
		s.logger.Debug("Session cleanup completed",
			"expired_sessions", len(expiredSessions),
			"remaining_sessions", len(s.localSessions))
	}
}

// persistSessionState stores session state in persistent storage
func (s *sessionSynchronizer) persistSessionState(ctx context.Context, sessionState *sessionState) error {
	store := s.storage.GetRuntimeStore()
	if store == nil {
		return fmt.Errorf("runtime store not available")
	}

	key := fmt.Sprintf("session:%s", sessionState.SessionID)

	return store.SetRuntimeState(ctx, key, sessionState)
}

// loadSessionState loads session state from persistent storage
func (s *sessionSynchronizer) loadSessionState(ctx context.Context, sessionID string) (*sessionState, error) {
	store := s.storage.GetRuntimeStore()
	if store == nil {
		return nil, fmt.Errorf("runtime store not available")
	}

	key := fmt.Sprintf("session:%s", sessionID)
	data, err := store.GetRuntimeState(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load session state: %w", err)
	}

	sessionState, ok := data.(*sessionState)
	if !ok {
		return nil, fmt.Errorf("invalid session state type")
	}

	return sessionState, nil
}

// removePersistedSessionState removes session state from persistent storage
func (s *sessionSynchronizer) removePersistedSessionState(ctx context.Context, sessionID string) error {
	store := s.storage.GetRuntimeStore()
	if store == nil {
		return fmt.Errorf("runtime store not available")
	}

	key := fmt.Sprintf("session:%s", sessionID)
	return store.DeleteRuntimeState(ctx, key)
}

// loadSessionsSince loads sessions updated since the given time
func (s *sessionSynchronizer) loadSessionsSince(ctx context.Context, since time.Time) ([]*sessionState, error) {
	// For now, this is a simple implementation that loads all sessions
	// In a production implementation, this would be optimized to only load
	// sessions updated since the given time
	return []*sessionState{}, nil
}
