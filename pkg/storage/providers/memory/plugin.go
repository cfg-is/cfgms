// Package memory implements in-memory storage provider for CFGMS
// Provides fast, ephemeral storage ideal for development, testing, and runtime sessions
package memory

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// MemoryProvider implements the StorageProvider interface using in-memory maps
// Ideal for ephemeral sessions and development/testing environments
type MemoryProvider struct{}

// Name returns the provider name
func (p *MemoryProvider) Name() string {
	return "memory"
}

// Description returns a human-readable description
func (p *MemoryProvider) Description() string {
	return "Fast in-memory storage for ephemeral sessions and development/testing"
}

// GetVersion returns the provider version
func (p *MemoryProvider) GetVersion() string {
	return "1.0.0"
}

// GetCapabilities returns the provider's capabilities
func (p *MemoryProvider) GetCapabilities() interfaces.ProviderCapabilities {
	return interfaces.ProviderCapabilities{
		SupportsTransactions:    false, // No transaction support in memory
		SupportsVersioning:      false, // No versioning in memory
		SupportsFullTextSearch:  false, // Limited search capabilities
		SupportsEncryption:      false, // No encryption in memory
		SupportsCompression:     false, // No compression in memory
		SupportsReplication:     false, // Single instance only
		SupportsSharding:        false, // Single instance storage
		MaxBatchSize:           10000,  // Large batch size for fast memory ops
		MaxConfigSize:          100 * 1024 * 1024, // 100MB per config in memory
		MaxAuditRetentionDays:  30,     // Limited retention for memory
	}
}

// Available checks if the memory provider is available (always true)
func (p *MemoryProvider) Available() (bool, error) {
	return true, nil
}

// CreateClientTenantStore creates an in-memory client tenant store
func (p *MemoryProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	// TODO: Implement in-memory client tenant store
	return nil, fmt.Errorf("ClientTenantStore not implemented for memory provider")
}

// CreateConfigStore creates an in-memory configuration store
func (p *MemoryProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	// TODO: Implement in-memory config store
	return nil, fmt.Errorf("ConfigStore not implemented for memory provider")
}

// CreateAuditStore creates an in-memory audit store
func (p *MemoryProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	// TODO: Implement in-memory audit store
	return nil, fmt.Errorf("AuditStore not implemented for memory provider")
}

// CreateRBACStore creates an in-memory RBAC store
func (p *MemoryProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	// TODO: Implement in-memory RBAC store
	return nil, fmt.Errorf("RBACStore not implemented for memory provider")
}

// CreateRuntimeStore creates an in-memory runtime store for sessions and runtime state
func (p *MemoryProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	store := &MemoryRuntimeStore{
		sessions:     make(map[string]*interfaces.Session),
		runtimeState: make(map[string]interface{}),
		stats: &interfaces.RuntimeStoreStats{
			SessionsByType:   make(map[string]int64),
			SessionsByStatus: make(map[string]int64),
			ProviderStats:    make(map[string]interface{}),
		},
		startTime: time.Now(),
	}

	// Start background cleanup routine
	go store.backgroundCleanup()

	return store, nil
}

// MemoryRuntimeStore implements RuntimeStore interface using in-memory maps
type MemoryRuntimeStore struct {
	sessions     map[string]*interfaces.Session
	runtimeState map[string]interface{}
	mutex        sync.RWMutex
	stats        *interfaces.RuntimeStoreStats
	startTime    time.Time
}

// Session Management Implementation

// CreateSession stores a session in memory
func (s *MemoryRuntimeStore) CreateSession(ctx context.Context, session *interfaces.Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if session already exists
	if _, exists := s.sessions[session.SessionID]; exists {
		return fmt.Errorf("session %s already exists", session.SessionID)
	}

	// Store session
	s.sessions[session.SessionID] = session

	// Update statistics
	s.stats.TotalSessions++
	if session.IsActive() {
		s.stats.ActiveSessions++
	}
	s.stats.SessionsByType[string(session.SessionType)]++
	s.stats.SessionsByStatus[string(session.Status)]++

	return nil
}

// GetSession retrieves a session by ID
func (s *MemoryRuntimeStore) GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session %s not found", sessionID)
	}

	return session, nil
}

// UpdateSession updates an existing session
func (s *MemoryRuntimeStore) UpdateSession(ctx context.Context, sessionID string, session *interfaces.Session) error {
	if err := session.Validate(); err != nil {
		return fmt.Errorf("session validation failed: %w", err)
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if session exists
	oldSession, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Update statistics
	if oldSession.Status != session.Status {
		s.stats.SessionsByStatus[string(oldSession.Status)]--
		s.stats.SessionsByStatus[string(session.Status)]++
	}

	if !oldSession.IsActive() && session.IsActive() {
		s.stats.ActiveSessions++
	} else if oldSession.IsActive() && !session.IsActive() {
		s.stats.ActiveSessions--
	}

	// Update session
	session.ModifiedAt = &[]time.Time{time.Now()}[0]
	s.sessions[sessionID] = session

	return nil
}

// DeleteSession removes a session from memory
func (s *MemoryRuntimeStore) DeleteSession(ctx context.Context, sessionID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	// Update statistics
	s.stats.TotalSessions--
	if session.IsActive() {
		s.stats.ActiveSessions--
	}
	s.stats.SessionsByType[string(session.SessionType)]--
	s.stats.SessionsByStatus[string(session.Status)]--

	delete(s.sessions, sessionID)
	return nil
}

// ListSessions returns sessions matching the filter
func (s *MemoryRuntimeStore) ListSessions(ctx context.Context, filters *interfaces.SessionFilter) ([]*interfaces.Session, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var results []*interfaces.Session
	for _, session := range s.sessions {
		if s.matchesFilter(session, filters) {
			results = append(results, session)
		}
	}

	// Apply pagination if specified
	if filters != nil && filters.Limit > 0 {
		start := filters.Offset
		if start >= len(results) {
			return []*interfaces.Session{}, nil
		}
		end := start + filters.Limit
		if end > len(results) {
			end = len(results)
		}
		results = results[start:end]
	}

	return results, nil
}

// Session Lifecycle Management

// SetSessionTTL sets the TTL for a session (updates ExpiresAt)
func (s *MemoryRuntimeStore) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	session, exists := s.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session %s not found", sessionID)
	}

	session.ExpiresAt = time.Now().Add(ttl)
	session.ModifiedAt = &[]time.Time{time.Now()}[0]

	return nil
}

// CleanupExpiredSessions removes expired sessions and returns count
func (s *MemoryRuntimeStore) CleanupExpiredSessions(ctx context.Context) (int, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	now := time.Now()
	var expiredSessions []string

	// Find expired sessions
	for sessionID, session := range s.sessions {
		if now.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	// Remove expired sessions and update stats
	for _, sessionID := range expiredSessions {
		session := s.sessions[sessionID]
		s.stats.TotalSessions--
		if session.IsActive() {
			s.stats.ActiveSessions--
		}
		s.stats.SessionsByType[string(session.SessionType)]--
		s.stats.SessionsByStatus[string(session.Status)]--
		s.stats.ExpiredSessions++
		delete(s.sessions, sessionID)
	}

	return len(expiredSessions), nil
}

// ListExpiredSessions returns IDs of expired sessions
func (s *MemoryRuntimeStore) ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var expiredSessions []string
	for sessionID, session := range s.sessions {
		if cutoff.After(session.ExpiresAt) {
			expiredSessions = append(expiredSessions, sessionID)
		}
	}

	return expiredSessions, nil
}

// Runtime State Management

// SetRuntimeState stores runtime state
func (s *MemoryRuntimeStore) SetRuntimeState(ctx context.Context, key string, value interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.runtimeState[key] = value
	s.stats.RuntimeStateKeys = int64(len(s.runtimeState))

	return nil
}

// GetRuntimeState retrieves runtime state
func (s *MemoryRuntimeStore) GetRuntimeState(ctx context.Context, key string) (interface{}, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	value, exists := s.runtimeState[key]
	if !exists {
		return nil, fmt.Errorf("runtime state key %s not found", key)
	}

	return value, nil
}

// DeleteRuntimeState removes runtime state
func (s *MemoryRuntimeStore) DeleteRuntimeState(ctx context.Context, key string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if _, exists := s.runtimeState[key]; !exists {
		return fmt.Errorf("runtime state key %s not found", key)
	}

	delete(s.runtimeState, key)
	s.stats.RuntimeStateKeys = int64(len(s.runtimeState))

	return nil
}

// ListRuntimeKeys returns runtime state keys with optional prefix filter
func (s *MemoryRuntimeStore) ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var keys []string
	for key := range s.runtimeState {
		if prefix == "" || strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}

	return keys, nil
}

// Batch Operations

// CreateSessionsBatch creates multiple sessions
func (s *MemoryRuntimeStore) CreateSessionsBatch(ctx context.Context, sessions []*interfaces.Session) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Validate all sessions first
	for _, session := range sessions {
		if err := session.Validate(); err != nil {
			return fmt.Errorf("session %s validation failed: %w", session.SessionID, err)
		}
		if _, exists := s.sessions[session.SessionID]; exists {
			return fmt.Errorf("session %s already exists", session.SessionID)
		}
	}

	// Store all sessions
	for _, session := range sessions {
		s.sessions[session.SessionID] = session
		s.stats.TotalSessions++
		if session.IsActive() {
			s.stats.ActiveSessions++
		}
		s.stats.SessionsByType[string(session.SessionType)]++
		s.stats.SessionsByStatus[string(session.Status)]++
	}

	return nil
}

// DeleteSessionsBatch deletes multiple sessions
func (s *MemoryRuntimeStore) DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check all sessions exist first
	for _, sessionID := range sessionIDs {
		if _, exists := s.sessions[sessionID]; !exists {
			return fmt.Errorf("session %s not found", sessionID)
		}
	}

	// Delete all sessions
	for _, sessionID := range sessionIDs {
		session := s.sessions[sessionID]
		s.stats.TotalSessions--
		if session.IsActive() {
			s.stats.ActiveSessions--
		}
		s.stats.SessionsByType[string(session.SessionType)]--
		s.stats.SessionsByStatus[string(session.Status)]--
		delete(s.sessions, sessionID)
	}

	return nil
}

// Session Queries

// GetSessionsByUser returns sessions for a specific user
func (s *MemoryRuntimeStore) GetSessionsByUser(ctx context.Context, userID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{UserID: userID}
	return s.ListSessions(ctx, filter)
}

// GetSessionsByTenant returns sessions for a specific tenant
func (s *MemoryRuntimeStore) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{TenantID: tenantID}
	return s.ListSessions(ctx, filter)
}

// GetSessionsByType returns sessions of a specific type
func (s *MemoryRuntimeStore) GetSessionsByType(ctx context.Context, sessionType interfaces.SessionType) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{Type: sessionType}
	return s.ListSessions(ctx, filter)
}

// GetActiveSessionsCount returns the count of active sessions
func (s *MemoryRuntimeStore) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return s.stats.ActiveSessions, nil
}

// Health and Maintenance

// HealthCheck verifies the store is healthy
func (s *MemoryRuntimeStore) HealthCheck(ctx context.Context) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Memory store is always healthy if we can access it
	return nil
}

// GetStats returns runtime store statistics
func (s *MemoryRuntimeStore) GetStats(ctx context.Context) (*interfaces.RuntimeStoreStats, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Update dynamic stats
	s.stats.ProviderStats["uptime"] = time.Since(s.startTime).String()
	s.stats.ProviderStats["memory_sessions"] = len(s.sessions)
	s.stats.ProviderStats["memory_runtime_keys"] = len(s.runtimeState)

	// Calculate average session lifetime
	var totalLifetime time.Duration
	var closedSessions int64
	for _, session := range s.sessions {
		if session.Status == interfaces.SessionStatusTerminated ||
		   session.Status == interfaces.SessionStatusExpired {
			lifetime := session.ExpiresAt.Sub(session.CreatedAt)
			totalLifetime += lifetime
			closedSessions++
		}
	}

	if closedSessions > 0 {
		s.stats.AverageSessionLifetime = totalLifetime / time.Duration(closedSessions)
	}

	return s.stats, nil
}

// Vacuum performs cleanup/optimization (no-op for memory)
func (s *MemoryRuntimeStore) Vacuum(ctx context.Context) error {
	// For memory store, just run cleanup
	_, err := s.CleanupExpiredSessions(ctx)
	return err
}

// Helper methods

// matchesFilter checks if a session matches the given filter
func (s *MemoryRuntimeStore) matchesFilter(session *interfaces.Session, filter *interfaces.SessionFilter) bool {
	if filter == nil {
		return true
	}

	if filter.UserID != "" && session.UserID != filter.UserID {
		return false
	}
	if filter.TenantID != "" && session.TenantID != filter.TenantID {
		return false
	}
	if filter.Type != "" && session.SessionType != filter.Type {
		return false
	}
	if filter.Status != "" && session.Status != filter.Status {
		return false
	}

	// Time-based filters
	if filter.CreatedAfter != nil && session.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}
	if filter.CreatedBefore != nil && session.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}
	if filter.ActiveAfter != nil && session.LastActivity.Before(*filter.ActiveAfter) {
		return false
	}
	if filter.ActiveBefore != nil && session.LastActivity.After(*filter.ActiveBefore) {
		return false
	}

	// Client filters
	if filter.IPAddress != "" && session.ClientInfo != nil && session.ClientInfo.IPAddress != filter.IPAddress {
		return false
	}
	if filter.Platform != "" && session.ClientInfo != nil && session.ClientInfo.Platform != filter.Platform {
		return false
	}

	return true
}

// backgroundCleanup runs periodic cleanup of expired sessions
func (s *MemoryRuntimeStore) backgroundCleanup() {
	ticker := time.NewTicker(5 * time.Minute) // Cleanup every 5 minutes
	defer ticker.Stop()

	for range ticker.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if count, err := s.CleanupExpiredSessions(ctx); err == nil && count > 0 {
			// Log cleanup if needed (would use proper logger in production)
		}
		cancel()
	}
}

// Memory provider is NOT registered as a global storage provider
// It is only used internally by components for performance optimization (caching, ephemeral sessions)
// This prevents the foot-gun of accidentally configuring all persistent data to use memory storage
//
// Components that need memory optimization should instantiate MemoryProvider directly:
//   memoryProvider := &memory.MemoryProvider{}
//   runtimeStore, err := memoryProvider.CreateRuntimeStore(config)