// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package session provides unified session management with pluggable storage
package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// UnifiedSessionManager provides session management with pluggable storage backends
// It supports both ephemeral (in-memory) and persistent (database/git) sessions
type UnifiedSessionManager struct {
	// Storage backends
	ephemeralStore  interfaces.RuntimeStore // For ephemeral sessions (memory provider)
	persistentStore interfaces.RuntimeStore // For persistent sessions (database provider)

	// Configuration
	config *Config
	logger logging.Logger

	// Session routing - determines which sessions should be persistent
	persistenceRules *PersistenceRules

	// Cleanup management
	stopCleanup chan struct{}
	cleanupWG   sync.WaitGroup
}

// Config contains configuration for the unified session manager
type Config struct {
	// Session lifecycle
	DefaultSessionTimeout time.Duration `json:"default_session_timeout"`
	MaxSessions           int           `json:"max_sessions"`

	// Cleanup settings
	CleanupInterval time.Duration `json:"cleanup_interval"`

	// Persistence settings
	PersistentSessionTypes []interfaces.SessionType `json:"persistent_session_types"`
	ForcePersistenceForJIT bool                     `json:"force_persistence_for_jit"`

	// Audit integration
	EnableAuditTrail bool `json:"enable_audit_trail"`
}

// PersistenceRules defines which sessions should be stored persistently vs ephemeral
type PersistenceRules struct {
	// Session types that should always be persistent
	PersistentTypes map[interfaces.SessionType]bool

	// JIT sessions are always persistent due to compliance requirements
	PersistJIT bool

	// Custom rule function for complex logic
	CustomRule func(session *interfaces.Session) bool
}

// NewUnifiedSessionManager creates a new unified session manager with pluggable storage
func NewUnifiedSessionManager(
	ephemeralStore interfaces.RuntimeStore,
	persistentStore interfaces.RuntimeStore,
	config *Config,
	logger logging.Logger,
) (*UnifiedSessionManager, error) {

	if ephemeralStore == nil {
		return nil, fmt.Errorf("ephemeral store is required")
	}

	if config == nil {
		config = DefaultConfig()
	}

	if logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	manager := &UnifiedSessionManager{
		ephemeralStore:  ephemeralStore,
		persistentStore: persistentStore,
		config:          config,
		logger:          logger,
		stopCleanup:     make(chan struct{}),
		persistenceRules: &PersistenceRules{
			PersistentTypes: make(map[interfaces.SessionType]bool),
			PersistJIT:      true, // JIT sessions always persistent for compliance
		},
	}

	// Configure persistence rules
	for _, sessionType := range config.PersistentSessionTypes {
		manager.persistenceRules.PersistentTypes[sessionType] = true
	}

	// Start background cleanup
	manager.startCleanupRoutine()

	logger.Info("Unified session manager initialized",
		"ephemeral_store", ephemeralStore != nil,
		"persistent_store", persistentStore != nil,
		"max_sessions", config.MaxSessions,
		"default_timeout", config.DefaultSessionTimeout,
		"cleanup_interval", config.CleanupInterval)

	return manager, nil
}

// CreateSession creates a new session using appropriate storage backend
func (m *UnifiedSessionManager) CreateSession(ctx context.Context, req *SessionCreateRequest) (*interfaces.Session, error) {
	// Validate request
	if err := req.Validate(); err != nil {
		return nil, fmt.Errorf("invalid session request: %w", err)
	}

	// Create session object
	session := &interfaces.Session{
		SessionID:       req.SessionID,
		UserID:          req.UserID,
		TenantID:        req.TenantID,
		SessionType:     req.SessionType,
		CreatedAt:       time.Now(),
		LastActivity:    time.Now(),
		ExpiresAt:       time.Now().Add(req.Timeout),
		Status:          interfaces.SessionStatusActive,
		ClientInfo:      req.ClientInfo,
		Metadata:        req.Metadata,
		SessionData:     req.SessionData,
		SecurityContext: req.SecurityContext,
		ComplianceFlags: req.ComplianceFlags,
		CreatedBy:       req.CreatedBy,
	}

	// Determine persistence based on rules
	session.Persistent = m.shouldBePersistent(session)

	// Route to appropriate storage
	store := m.getStoreForSession(session)
	if store == nil {
		return nil, fmt.Errorf("no suitable storage available for session type %s (persistent=%v)",
			session.SessionType, session.Persistent)
	}

	// Store session
	if err := store.CreateSession(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session in %s store: %w",
			m.getStoreType(store), err)
	}

	m.logger.Info("Session created",
		"session_id", session.SessionID,
		"user_id", session.UserID,
		"session_type", session.SessionType,
		"persistent", session.Persistent,
		"store_type", m.getStoreType(store),
		"expires_at", session.ExpiresAt)

	return session, nil
}

// GetSession retrieves a session by ID from appropriate storage
func (m *UnifiedSessionManager) GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error) {
	// Try ephemeral store first (faster lookup)
	if session, err := m.ephemeralStore.GetSession(ctx, sessionID); err == nil {
		return session, nil
	}

	// Try persistent store if available
	if m.persistentStore != nil {
		if session, err := m.persistentStore.GetSession(ctx, sessionID); err == nil {
			return session, nil
		}
	}

	return nil, fmt.Errorf("session %s not found", sessionID)
}

// UpdateSession updates an existing session
func (m *UnifiedSessionManager) UpdateSession(ctx context.Context, sessionID string, updates *SessionUpdateRequest) (*interfaces.Session, error) {
	// Get current session to determine storage location
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return nil, err
	}

	// Apply updates
	if updates.LastActivity != nil {
		session.LastActivity = *updates.LastActivity
	}
	if updates.ExpiresAt != nil {
		session.ExpiresAt = *updates.ExpiresAt
	}
	if updates.Status != "" {
		session.Status = updates.Status
	}
	if updates.Metadata != nil {
		// Merge metadata
		if session.Metadata == nil {
			session.Metadata = make(map[string]string)
		}
		for k, v := range updates.Metadata {
			session.Metadata[k] = v
		}
	}
	if updates.SessionData != nil {
		session.SessionData = updates.SessionData
	}
	if updates.ModifiedBy != "" {
		now := time.Now()
		session.ModifiedAt = &now
		session.ModifiedBy = updates.ModifiedBy
	}

	// Update in appropriate store
	store := m.getStoreForSession(session)
	if store == nil {
		return nil, fmt.Errorf("no suitable storage available for session")
	}

	if err := store.UpdateSession(ctx, sessionID, session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	m.logger.Info("Session updated",
		"session_id", sessionID,
		"store_type", m.getStoreType(store))

	return session, nil
}

// TerminateSession terminates a session and removes it from storage
func (m *UnifiedSessionManager) TerminateSession(ctx context.Context, sessionID string, reason string) error {
	// Get session to determine storage location
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	// Mark as terminated before deletion
	session.Status = interfaces.SessionStatusTerminated
	now := time.Now()
	session.ModifiedAt = &now

	// Update to record termination
	store := m.getStoreForSession(session)
	if store != nil {
		_ = store.UpdateSession(ctx, sessionID, session)
	}

	// Delete from storage
	if store != nil {
		if err := store.DeleteSession(ctx, sessionID); err != nil {
			m.logger.Warn("Failed to delete session from storage",
				"session_id", sessionID,
				"error", err)
		}
	}

	m.logger.Info("Session terminated",
		"session_id", sessionID,
		"reason", reason,
		"store_type", m.getStoreType(store))

	return nil
}

// ListSessions returns sessions matching the filter across both stores
func (m *UnifiedSessionManager) ListSessions(ctx context.Context, filter *interfaces.SessionFilter) ([]*interfaces.Session, error) {
	var allSessions []*interfaces.Session

	// Get sessions from ephemeral store
	ephemeralSessions, err := m.ephemeralStore.ListSessions(ctx, filter)
	if err != nil {
		m.logger.Warn("Failed to list sessions from ephemeral store", "error", err)
	} else {
		allSessions = append(allSessions, ephemeralSessions...)
	}

	// Get sessions from persistent store if available
	if m.persistentStore != nil {
		persistentSessions, err := m.persistentStore.ListSessions(ctx, filter)
		if err != nil {
			m.logger.Warn("Failed to list sessions from persistent store", "error", err)
		} else {
			allSessions = append(allSessions, persistentSessions...)
		}
	}

	return allSessions, nil
}

// GetActiveSessionsCount returns total count of active sessions across all stores
func (m *UnifiedSessionManager) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	var totalCount int64

	// Count ephemeral sessions
	if count, err := m.ephemeralStore.GetActiveSessionsCount(ctx); err == nil {
		totalCount += count
	}

	// Count persistent sessions if available
	if m.persistentStore != nil {
		if count, err := m.persistentStore.GetActiveSessionsCount(ctx); err == nil {
			totalCount += count
		}
	}

	return totalCount, nil
}

// ExtendSessionTTL extends the TTL of a session
func (m *UnifiedSessionManager) ExtendSessionTTL(ctx context.Context, sessionID string, additionalTTL time.Duration) error {
	session, err := m.GetSession(ctx, sessionID)
	if err != nil {
		return err
	}

	store := m.getStoreForSession(session)
	if store == nil {
		return fmt.Errorf("no suitable storage available for session")
	}

	// Calculate new TTL from current time
	currentTTL := time.Until(session.ExpiresAt)
	newTTL := currentTTL + additionalTTL

	return store.SetSessionTTL(ctx, sessionID, newTTL)
}

// CleanupExpiredSessions removes expired sessions from both stores
func (m *UnifiedSessionManager) CleanupExpiredSessions(ctx context.Context) (int, error) {
	var totalCleaned int

	// Clean ephemeral store
	if cleaned, err := m.ephemeralStore.CleanupExpiredSessions(ctx); err == nil {
		totalCleaned += cleaned
	} else {
		m.logger.Warn("Failed to cleanup ephemeral sessions", "error", err)
	}

	// Clean persistent store if available
	if m.persistentStore != nil {
		if cleaned, err := m.persistentStore.CleanupExpiredSessions(ctx); err == nil {
			totalCleaned += cleaned
		} else {
			m.logger.Warn("Failed to cleanup persistent sessions", "error", err)
		}
	}

	if totalCleaned > 0 {
		m.logger.Info("Cleaned up expired sessions", "count", totalCleaned)
	}

	return totalCleaned, nil
}

// GetStats returns combined statistics from both stores
func (m *UnifiedSessionManager) GetStats(ctx context.Context) (*SessionManagerStats, error) {
	stats := &SessionManagerStats{
		EphemeralStats:  nil,
		PersistentStats: nil,
		TotalSessions:   0,
		ActiveSessions:  0,
	}

	// Get ephemeral stats
	if ephemeralStats, err := m.ephemeralStore.GetStats(ctx); err == nil {
		stats.EphemeralStats = ephemeralStats
		stats.TotalSessions += ephemeralStats.TotalSessions
		stats.ActiveSessions += ephemeralStats.ActiveSessions
	}

	// Get persistent stats if available
	if m.persistentStore != nil {
		if persistentStats, err := m.persistentStore.GetStats(ctx); err == nil {
			stats.PersistentStats = persistentStats
			stats.TotalSessions += persistentStats.TotalSessions
			stats.ActiveSessions += persistentStats.ActiveSessions
		}
	}

	return stats, nil
}

// HealthCheck verifies both stores are healthy
func (m *UnifiedSessionManager) HealthCheck(ctx context.Context) error {
	// Check ephemeral store
	if err := m.ephemeralStore.HealthCheck(ctx); err != nil {
		return fmt.Errorf("ephemeral store health check failed: %w", err)
	}

	// Check persistent store if available
	if m.persistentStore != nil {
		if err := m.persistentStore.HealthCheck(ctx); err != nil {
			return fmt.Errorf("persistent store health check failed: %w", err)
		}
	}

	return nil
}

// Stop stops the session manager and cleanup routines
func (m *UnifiedSessionManager) Stop(ctx context.Context) error {
	m.logger.Info("Stopping unified session manager")

	// Stop cleanup routine
	close(m.stopCleanup)
	m.cleanupWG.Wait()

	// Perform final cleanup
	_, _ = m.CleanupExpiredSessions(ctx)

	m.logger.Info("Unified session manager stopped")
	return nil
}

// Helper methods

// shouldBePersistent determines if a session should be stored persistently
func (m *UnifiedSessionManager) shouldBePersistent(session *interfaces.Session) bool {
	// JIT sessions are always persistent for compliance
	if session.SessionType == interfaces.SessionTypeJIT {
		return true
	}

	// Check configured persistent types
	if m.persistenceRules.PersistentTypes[session.SessionType] {
		return true
	}

	// Apply custom rule if available
	if m.persistenceRules.CustomRule != nil {
		return m.persistenceRules.CustomRule(session)
	}

	// Default to ephemeral
	return false
}

// getStoreForSession returns the appropriate store for a session
func (m *UnifiedSessionManager) getStoreForSession(session *interfaces.Session) interfaces.RuntimeStore {
	if session.Persistent {
		if m.persistentStore != nil {
			return m.persistentStore
		}
		// Fallback to ephemeral if persistent not available
		m.logger.Warn("Persistent store not available, using ephemeral for persistent session",
			"session_id", session.SessionID)
	}
	return m.ephemeralStore
}

// getStoreType returns a string description of the store type
func (m *UnifiedSessionManager) getStoreType(store interfaces.RuntimeStore) string {
	if store == m.ephemeralStore {
		return "ephemeral"
	}
	if store == m.persistentStore {
		return "persistent"
	}
	return "unknown"
}

// startCleanupRoutine starts the background cleanup routine
func (m *UnifiedSessionManager) startCleanupRoutine() {
	m.cleanupWG.Add(1)
	go func() {
		defer m.cleanupWG.Done()

		ticker := time.NewTicker(m.config.CleanupInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, _ = m.CleanupExpiredSessions(ctx)
				cancel()
			case <-m.stopCleanup:
				return
			}
		}
	}()
}

// DefaultConfig returns default configuration for the session manager
func DefaultConfig() *Config {
	return &Config{
		DefaultSessionTimeout: 30 * time.Minute,
		MaxSessions:           1000,
		CleanupInterval:       5 * time.Minute,
		PersistentSessionTypes: []interfaces.SessionType{
			interfaces.SessionTypeJIT, // JIT sessions always persistent
		},
		ForcePersistenceForJIT: true,
		EnableAuditTrail:       true,
	}
}
