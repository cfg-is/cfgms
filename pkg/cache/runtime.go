// Package cache provides shared runtime cache utilities with MSP-scale features
package cache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// CacheConfig defines configuration for the runtime cache
type CacheConfig struct {
	// Name identifies the cache instance (for logging/debugging)
	Name string

	// Size limits to prevent memory exhaustion in large deployments
	MaxSessions       int           // Maximum number of sessions to store
	MaxRuntimeItems   int           // Maximum number of runtime state items

	// TTL/Expiration settings for automatic cleanup
	DefaultTTL        time.Duration // Default expiration time for items
	CleanupInterval   time.Duration // How often to run background cleanup

	// Eviction strategy when cache is full
	EvictionPolicy    EvictionPolicy // FIFO, LRU, or LFU eviction policy
}

// DefaultCacheConfig returns a sensible default configuration
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Name:              "runtime-cache",
		MaxSessions:       1000,
		MaxRuntimeItems:   500,
		DefaultTTL:        2 * time.Hour,
		CleanupInterval:   5 * time.Minute,
		EvictionPolicy:    EvictionLRU, // Use LRU for production workloads
	}
}

// EvictionPolicy defines the cache eviction strategy
type EvictionPolicy int

const (
	// EvictionFIFO removes oldest items first (simple, fast)
	EvictionFIFO EvictionPolicy = iota
	// EvictionLRU removes least recently used items (access-time based)
	EvictionLRU
	// EvictionLFU removes least frequently used items (access-count based)
	EvictionLFU
)

// CacheEntry represents a cached item with expiration and access tracking
type CacheEntry struct {
	Value        interface{}
	ExpiresAt    time.Time
	CreatedAt    time.Time // When the entry was created
	LastAccessed time.Time // When the entry was last accessed (for LRU)
	AccessCount  int64     // Number of times accessed (for LFU)
}

// IsExpired checks if the cache entry has expired
func (e *CacheEntry) IsExpired() bool {
	return time.Now().After(e.ExpiresAt)
}

// CacheStats provides operational visibility for cache performance
type CacheStats struct {
	// Basic metrics
	Hits            int64     // Cache hits
	Misses          int64     // Cache misses
	Evictions       int64     // Items evicted due to size limits
	
	// Size information
	Size            int       // Current number of items
	MaxSize         int       // Maximum configured size
	
	// Cleanup information
	LastCleanup     time.Time // Last cleanup run time
	ItemsExpired    int64     // Total items expired during cleanup
}

// RuntimeCache implements RuntimeStore interface with MSP-scale features
type RuntimeCache struct {
	config       CacheConfig
	sessions     map[string]*CacheEntry
	runtimeState map[string]*CacheEntry
	stats        CacheStats
	mutex        *sync.RWMutex
	stopCleanup  chan struct{}
	cleanupDone  *sync.WaitGroup
}

// NewRuntimeCache creates a new runtime cache with the specified configuration
func NewRuntimeCache(config CacheConfig) *RuntimeCache {
	cache := &RuntimeCache{
		config:       config,
		sessions:     make(map[string]*CacheEntry),
		runtimeState: make(map[string]*CacheEntry),
		stats:        CacheStats{MaxSize: config.MaxSessions + config.MaxRuntimeItems},
		mutex:        &sync.RWMutex{},
		stopCleanup:  make(chan struct{}),
		cleanupDone:  &sync.WaitGroup{},
	}
	
	// Start background cleanup if cleanup interval is configured
	if config.CleanupInterval > 0 {
		cache.startCleanupRoutine()
	}
	
	return cache
}

// Close stops the cleanup routine and releases resources
func (c *RuntimeCache) Close() {
	if c.cleanupDone != nil {
		close(c.stopCleanup)
		c.cleanupDone.Wait()
	}
}

// startCleanupRoutine starts the background cleanup goroutine
func (c *RuntimeCache) startCleanupRoutine() {
	c.cleanupDone.Add(1)
	go func() {
		defer c.cleanupDone.Done()
		ticker := time.NewTicker(c.config.CleanupInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-c.stopCleanup:
				return
			case <-ticker.C:
				c.cleanupExpiredItems()
			}
		}
	}()
}

// cleanupExpiredItems removes expired entries from both sessions and runtime state
func (c *RuntimeCache) cleanupExpiredItems() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	now := time.Now()
	expired := int64(0)
	
	// Clean expired sessions
	for id, entry := range c.sessions {
		if entry.IsExpired() {
			delete(c.sessions, id)
			expired++
		}
	}
	
	// Clean expired runtime state items
	for key, entry := range c.runtimeState {
		if entry.IsExpired() {
			delete(c.runtimeState, key)
			expired++
		}
	}
	
	c.stats.LastCleanup = now
	c.stats.ItemsExpired += expired
	c.updateSizeStats()
}

// updateSizeStats updates the size statistics (must be called while holding mutex)
func (c *RuntimeCache) updateSizeStats() {
	c.stats.Size = len(c.sessions) + len(c.runtimeState)
}

// enforceMaxSessions removes oldest sessions if we exceed the limit
func (c *RuntimeCache) enforceMaxSessions() {
	if len(c.sessions) <= c.config.MaxSessions {
		return
	}
	
	// Simple eviction: remove oldest sessions first
	// In a production system, might want LRU or other policies
	count := len(c.sessions) - c.config.MaxSessions
	evicted := 0
	
	for id := range c.sessions {
		if evicted >= count {
			break
		}
		delete(c.sessions, id)
		evicted++
	}
	
	c.stats.Evictions += int64(evicted)
}

// enforceMaxRuntimeItems removes oldest runtime items if we exceed the limit
func (c *RuntimeCache) enforceMaxRuntimeItems() {
	if len(c.runtimeState) <= c.config.MaxRuntimeItems {
		return
	}
	
	count := len(c.runtimeState) - c.config.MaxRuntimeItems
	evicted := 0
	
	for key := range c.runtimeState {
		if evicted >= count {
			break
		}
		delete(c.runtimeState, key)
		evicted++
	}
	
	c.stats.Evictions += int64(evicted)
}

// GetCacheStats returns current cache-specific statistics
func (c *RuntimeCache) GetCacheStats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	stats := c.stats
	stats.Size = len(c.sessions) + len(c.runtimeState)
	return stats
}

// Session Management Methods - implementing interfaces.RuntimeStore

// CreateSession creates a new session
func (c *RuntimeCache) CreateSession(ctx context.Context, session *interfaces.Session) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if session == nil {
		c.stats.Misses++
		return fmt.Errorf("session cannot be nil")
	}
	
	if err := session.Validate(); err != nil {
		c.stats.Misses++
		return fmt.Errorf("invalid session: %w", err)
	}
	
	if _, exists := c.sessions[session.SessionID]; exists {
		c.stats.Misses++
		return fmt.Errorf("session already exists: %s", session.SessionID)
	}
	
	// Use session's ExpiresAt or default TTL
	expiresAt := session.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(c.config.DefaultTTL)
	}
	
	c.sessions[session.SessionID] = &CacheEntry{
		Value:     session,
		ExpiresAt: expiresAt,
	}
	
	c.enforceMaxSessions()
	c.updateSizeStats()
	c.stats.Hits++
	
	return nil
}

// GetSession retrieves a session by ID
func (c *RuntimeCache) GetSession(ctx context.Context, sessionID string) (*interfaces.Session, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	entry, exists := c.sessions[sessionID]
	if !exists {
		c.stats.Misses++
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	
	if entry.IsExpired() {
		c.stats.Misses++
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	
	c.stats.Hits++
	return entry.Value.(*interfaces.Session), nil
}

// UpdateSession updates an existing session
func (c *RuntimeCache) UpdateSession(ctx context.Context, sessionID string, session *interfaces.Session) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}
	
	if err := session.Validate(); err != nil {
		return fmt.Errorf("invalid session: %w", err)
	}
	
	entry, exists := c.sessions[sessionID]
	if !exists || entry.IsExpired() {
		c.stats.Misses++
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	// Use session's ExpiresAt or keep existing expiration
	expiresAt := session.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = entry.ExpiresAt
	}
	
	c.sessions[sessionID] = &CacheEntry{
		Value:     session,
		ExpiresAt: expiresAt,
	}
	
	c.stats.Hits++
	return nil
}

// DeleteSession removes a session
func (c *RuntimeCache) DeleteSession(ctx context.Context, sessionID string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	if _, exists := c.sessions[sessionID]; !exists {
		c.stats.Misses++
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	delete(c.sessions, sessionID)
	c.updateSizeStats()
	c.stats.Hits++
	return nil
}

// ListSessions returns sessions matching the filter
func (c *RuntimeCache) ListSessions(ctx context.Context, filters *interfaces.SessionFilter) ([]*interfaces.Session, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var result []*interfaces.Session
	
	for _, entry := range c.sessions {
		if entry.IsExpired() {
			continue
		}
		
		session := entry.Value.(*interfaces.Session)
		if c.matchesFilter(session, filters) {
			result = append(result, session)
		}
	}
	
	c.stats.Hits++
	return result, nil
}

// SetSessionTTL sets session TTL
func (c *RuntimeCache) SetSessionTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	entry, exists := c.sessions[sessionID]
	if !exists || entry.IsExpired() {
		c.stats.Misses++
		return fmt.Errorf("session not found: %s", sessionID)
	}
	
	session := entry.Value.(*interfaces.Session)
	session.ExpiresAt = time.Now().Add(ttl)
	entry.ExpiresAt = session.ExpiresAt
	
	c.stats.Hits++
	return nil
}

// CleanupExpiredSessions removes expired sessions
func (c *RuntimeCache) CleanupExpiredSessions(ctx context.Context) (int, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	count := 0
	
	for id, entry := range c.sessions {
		if entry.IsExpired() {
			delete(c.sessions, id)
			count++
		}
	}
	
	c.updateSizeStats()
	c.stats.ItemsExpired += int64(count)
	return count, nil
}

// ListExpiredSessions returns IDs of expired sessions
func (c *RuntimeCache) ListExpiredSessions(ctx context.Context, cutoff time.Time) ([]string, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var result []string
	
	for id, entry := range c.sessions {
		if entry.ExpiresAt.Before(cutoff) {
			result = append(result, id)
		}
	}
	
	return result, nil
}

// Runtime State Methods

// SetRuntimeState sets runtime state with default TTL
func (c *RuntimeCache) SetRuntimeState(ctx context.Context, key string, value interface{}) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	c.runtimeState[key] = &CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(c.config.DefaultTTL),
	}
	
	c.enforceMaxRuntimeItems()
	c.updateSizeStats()
	c.stats.Hits++
	
	return nil
}

// GetRuntimeState retrieves runtime state
func (c *RuntimeCache) GetRuntimeState(ctx context.Context, key string) (interface{}, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	entry, exists := c.runtimeState[key]
	if !exists {
		c.stats.Misses++
		return nil, fmt.Errorf("runtime state key not found: %s", key)
	}
	
	if entry.IsExpired() {
		c.stats.Misses++
		return nil, fmt.Errorf("runtime state key not found: %s", key)
	}
	
	c.stats.Hits++
	return entry.Value, nil
}

// DeleteRuntimeState removes runtime state
func (c *RuntimeCache) DeleteRuntimeState(ctx context.Context, key string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	delete(c.runtimeState, key)
	c.updateSizeStats()
	return nil
}

// ListRuntimeKeys returns runtime state keys with the given prefix
func (c *RuntimeCache) ListRuntimeKeys(ctx context.Context, prefix string) ([]string, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	var result []string
	
	for key, entry := range c.runtimeState {
		if entry.IsExpired() {
			continue
		}
		
		if strings.HasPrefix(key, prefix) {
			result = append(result, key)
		}
	}
	
	return result, nil
}

// Batch Operations

// CreateSessionsBatch creates multiple sessions atomically
func (c *RuntimeCache) CreateSessionsBatch(ctx context.Context, sessions []*interfaces.Session) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	// Validate all sessions first
	for _, session := range sessions {
		if session == nil {
			return fmt.Errorf("session cannot be nil")
		}
		
		if err := session.Validate(); err != nil {
			return fmt.Errorf("invalid session: %w", err)
		}
		
		if _, exists := c.sessions[session.SessionID]; exists {
			return fmt.Errorf("session already exists: %s", session.SessionID)
		}
	}
	
	// Create all sessions
	for _, session := range sessions {
		expiresAt := session.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = time.Now().Add(c.config.DefaultTTL)
		}
		
		c.sessions[session.SessionID] = &CacheEntry{
			Value:     session,
			ExpiresAt: expiresAt,
		}
	}
	
	c.enforceMaxSessions()
	c.updateSizeStats()
	c.stats.Hits++
	
	return nil
}

// DeleteSessionsBatch deletes multiple sessions
func (c *RuntimeCache) DeleteSessionsBatch(ctx context.Context, sessionIDs []string) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	
	for _, id := range sessionIDs {
		delete(c.sessions, id)
	}
	
	c.updateSizeStats()
	return nil
}

// Query Methods

// GetSessionsByUser returns sessions for a specific user
func (c *RuntimeCache) GetSessionsByUser(ctx context.Context, userID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{UserID: userID}
	return c.ListSessions(ctx, filter)
}

// GetSessionsByTenant returns sessions for a specific tenant
func (c *RuntimeCache) GetSessionsByTenant(ctx context.Context, tenantID string) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{TenantID: tenantID}
	return c.ListSessions(ctx, filter)
}

// GetSessionsByType returns sessions of a specific type
func (c *RuntimeCache) GetSessionsByType(ctx context.Context, sessionType interfaces.SessionType) ([]*interfaces.Session, error) {
	filter := &interfaces.SessionFilter{Type: sessionType}
	return c.ListSessions(ctx, filter)
}

// GetActiveSessionsCount returns the count of active sessions
func (c *RuntimeCache) GetActiveSessionsCount(ctx context.Context) (int64, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	count := int64(0)
	for _, entry := range c.sessions {
		if entry.IsExpired() {
			continue
		}
		
		session := entry.Value.(*interfaces.Session)
		if session.IsActive() {
			count++
		}
	}
	
	return count, nil
}

// Health and Maintenance

// HealthCheck always returns nil for in-memory cache (always healthy)
func (c *RuntimeCache) HealthCheck(ctx context.Context) error {
	return nil
}

// GetStats returns comprehensive runtime store statistics
func (c *RuntimeCache) GetStats(ctx context.Context) (*interfaces.RuntimeStoreStats, error) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	
	stats := &interfaces.RuntimeStoreStats{
		TotalSessions:    int64(len(c.sessions)),
		ActiveSessions:   0,
		ExpiredSessions:  0,
		SessionsByType:   make(map[string]int64),
		SessionsByStatus: make(map[string]int64),
		RuntimeStateKeys: int64(len(c.runtimeState)),
		StorageSize:      0, // Not calculated for in-memory
		LastCleanupAt:    &c.stats.LastCleanup,
	}
	
	for _, entry := range c.sessions {
		if entry.IsExpired() {
			stats.ExpiredSessions++
			continue
		}
		
		session := entry.Value.(*interfaces.Session)
		if session.IsActive() {
			stats.ActiveSessions++
		}
		
		stats.SessionsByType[string(session.SessionType)]++
		stats.SessionsByStatus[string(session.Status)]++
	}
	
	return stats, nil
}

// Vacuum performs cache cleanup and optimization
func (c *RuntimeCache) Vacuum(ctx context.Context) error {
	_, err := c.CleanupExpiredSessions(ctx)
	return err
}

// Helper method for filtering sessions
func (c *RuntimeCache) matchesFilter(session *interfaces.Session, filter *interfaces.SessionFilter) bool {
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
	
	return true
}