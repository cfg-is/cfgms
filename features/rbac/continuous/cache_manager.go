// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/cache"
)

// CacheManager provides high-performance caching for authorization decisions
// Now uses centralized pkg/cache with session indexing for O(1) invalidation
type CacheManager struct {
	// L1 Cache (in-memory, fastest access) - uses pkg/cache
	l1Cache *cache.Cache

	// L2 Cache (session-based, longer retention) - uses pkg/cache
	l2Cache *cache.Cache

	// Session index for O(1) session invalidation
	// Maps sessionID -> list of cache keys
	sessionIndex map[string][]string
	indexMutex   sync.RWMutex

	// Cache configuration
	config *CacheConfig

	// Cache maintenance
	started bool
	mutex   sync.RWMutex
}

// CachedAuthDecision represents a cached authorization decision
// Simplified - TTL, access tracking, and eviction now handled by pkg/cache
type CachedAuthDecision struct {
	// Cache metadata (reduced - pkg/cache handles TTL and access tracking)
	CacheKey   string     `json:"cache_key"`
	CacheLevel CacheLevel `json:"cache_level"`
	ValidUntil time.Time  `json:"valid_until"`

	// Authorization data
	Request        *ContinuousAuthRequest `json:"request"`
	AccessResponse *common.AccessResponse `json:"access_response"`

	// Context data for invalidation indexing
	SessionID    string `json:"session_id"`
	SubjectID    string `json:"subject_id"`
	PermissionID string `json:"permission_id"`
	TenantID     string `json:"tenant_id"`
	ContextHash  string `json:"context_hash"` // Hash of request context

	// Decision metadata
	DecisionID   string      `json:"decision_id"`
	DecisionTime time.Time   `json:"decision_time"`
	Source       CacheSource `json:"source"`
}

// CacheLevel defines the cache level
type CacheLevel string

const (
	CacheLevelL1 CacheLevel = "l1" // Fast in-memory cache
	CacheLevelL2 CacheLevel = "l2" // Session-based cache
	CacheLevelL3 CacheLevel = "l3" // Distributed cache (future)
)

// CacheSource defines the source of cached data
type CacheSource string

const (
	CacheSourceRBAC       CacheSource = "rbac"
	CacheSourceJIT        CacheSource = "jit"
	CacheSourceRisk       CacheSource = "risk"
	CacheSourceContinuous CacheSource = "continuous"
	CacheSourceExternal   CacheSource = "external"
)

// CacheConfig contains caching configuration
type CacheConfig struct {
	// L1 Cache settings
	L1MaxSize         int           `json:"l1_max_size"`
	L1TTL             time.Duration `json:"l1_ttl"`
	L1CleanupInterval time.Duration `json:"l1_cleanup_interval"`

	// L2 Cache settings
	L2MaxSize         int           `json:"l2_max_size"`
	L2TTL             time.Duration `json:"l2_ttl"`
	L2CleanupInterval time.Duration `json:"l2_cleanup_interval"`

	// Performance settings
	MaxLatencyMs      int  `json:"max_latency_ms"`
	EnableCompression bool `json:"enable_compression"`
	EnableEncryption  bool `json:"enable_encryption"`

	// Cache behavior
	CacheNegativeResults bool    `json:"cache_negative_results"`
	CacheFailures        bool    `json:"cache_failures"`
	RefreshThreshold     float64 `json:"refresh_threshold"` // Refresh when TTL < threshold

	// Distributed cache (future)
	EnableDistributed bool   `json:"enable_distributed"`
	RedisURL          string `json:"redis_url,omitempty"`
	RedisPassword     string `json:"redis_password,omitempty"`
}

// CacheStats tracks cache performance statistics
type CacheStats struct {
	// Hit/Miss statistics
	TotalRequests int64   `json:"total_requests"`
	CacheHits     int64   `json:"cache_hits"`
	CacheMisses   int64   `json:"cache_misses"`
	HitRate       float64 `json:"hit_rate"`

	// Performance statistics
	AverageLatencyMs float64 `json:"average_latency_ms"`
	L1LatencyMs      float64 `json:"l1_latency_ms"`
	L2LatencyMs      float64 `json:"l2_latency_ms"`

	// Cache level statistics
	L1Hits   int64 `json:"l1_hits"`
	L1Misses int64 `json:"l1_misses"`
	L2Hits   int64 `json:"l2_hits"`
	L2Misses int64 `json:"l2_misses"`

	// Cache size and memory
	L1Size        int     `json:"l1_size"`
	L2Size        int     `json:"l2_size"`
	TotalSize     int     `json:"total_size"`
	MemoryUsageMB float64 `json:"memory_usage_mb"`

	// Eviction statistics
	L1Evictions    int64 `json:"l1_evictions"`
	L2Evictions    int64 `json:"l2_evictions"`
	ExpiredEntries int64 `json:"expired_entries"`

	// Invalidation statistics
	Invalidations     int64 `json:"invalidations"`
	BulkInvalidations int64 `json:"bulk_invalidations"`

	// Time tracking
	LastCleanup time.Time `json:"last_cleanup"`
	LastStats   time.Time `json:"last_stats"`
}

// CacheInvalidationRequest represents a request to invalidate cache entries
type CacheInvalidationRequest struct {
	InvalidationType InvalidationType `json:"invalidation_type"`
	SessionID        string           `json:"session_id,omitempty"`
	SubjectID        string           `json:"subject_id,omitempty"`
	TenantID         string           `json:"tenant_id,omitempty"`
	PermissionID     string           `json:"permission_id,omitempty"`
	Reason           string           `json:"reason"`
	RequestedBy      string           `json:"requested_by"`
	Timestamp        time.Time        `json:"timestamp"`
}

// InvalidationType defines types of cache invalidation
type InvalidationType string

const (
	InvalidationTypeSession    InvalidationType = "session"    // Invalidate all entries for a session
	InvalidationTypeSubject    InvalidationType = "subject"    // Invalidate all entries for a subject
	InvalidationTypeTenant     InvalidationType = "tenant"     // Invalidate all entries for a tenant
	InvalidationTypePermission InvalidationType = "permission" // Invalidate specific permission
	InvalidationTypeAll        InvalidationType = "all"        // Invalidate all cache entries
)

// NewCacheManager creates a new cache manager using centralized pkg/cache
func NewCacheManager(ttl time.Duration, maxLatencyMs int) *CacheManager {
	config := &CacheConfig{
		L1MaxSize:            10000, // 10k entries in L1
		L1TTL:                ttl,   // Use provided TTL
		L1CleanupInterval:    1 * time.Minute,
		L2MaxSize:            100000,  // 100k entries in L2
		L2TTL:                ttl * 2, // L2 has longer TTL
		L2CleanupInterval:    5 * time.Minute,
		MaxLatencyMs:         maxLatencyMs,
		CacheNegativeResults: false, // Don't cache denials by default
		CacheFailures:        false, // Don't cache failures by default
		RefreshThreshold:     0.8,   // Refresh when 80% of TTL passed
	}

	// Create L1 cache using pkg/cache with LRU eviction
	l1Config := cache.CacheConfig{
		Name:            "continuous-auth-l1",
		MaxRuntimeItems: config.L1MaxSize,
		DefaultTTL:      config.L1TTL,
		CleanupInterval: config.L1CleanupInterval,
		EvictionPolicy:  cache.EvictionLRU,
	}

	// Create L2 cache using pkg/cache with LRU eviction
	l2Config := cache.CacheConfig{
		Name:            "continuous-auth-l2",
		MaxRuntimeItems: config.L2MaxSize,
		DefaultTTL:      config.L2TTL,
		CleanupInterval: config.L2CleanupInterval,
		EvictionPolicy:  cache.EvictionLRU,
	}

	return &CacheManager{
		l1Cache:      cache.NewCache(l1Config),
		l2Cache:      cache.NewCache(l2Config),
		sessionIndex: make(map[string][]string),
		config:       config,
	}
}

// Start initializes and starts the cache manager
// Simplified - pkg/cache handles its own cleanup routines
func (cm *CacheManager) Start(ctx context.Context) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.started {
		return fmt.Errorf("cache manager is already started")
	}

	cm.started = true
	return nil
}

// Stop gracefully stops the cache manager
// Simplified - delegates cleanup to pkg/cache
func (cm *CacheManager) Stop() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if !cm.started {
		return fmt.Errorf("cache manager is not started")
	}

	// Close pkg/cache instances (stops their cleanup routines)
	cm.l1Cache.Close()
	cm.l2Cache.Close()

	cm.started = false
	return nil
}

// GetCachedAuth retrieves a cached authorization decision
// Simplified to use pkg/cache - pkg/cache handles expiration and access tracking
func (cm *CacheManager) GetCachedAuth(request *ContinuousAuthRequest) *CachedAuthDecision {
	// Generate cache key
	cacheKey := cm.generateCacheKey(request)

	// Try L1 cache first (fastest) - pkg/cache handles expiration
	if value, found := cm.l1Cache.Get(cacheKey); found {
		if cached, ok := value.(*CachedAuthDecision); ok {
			return cached
		}
	}

	// Try L2 cache - pkg/cache handles expiration
	if value, found := cm.l2Cache.Get(cacheKey); found {
		if cached, ok := value.(*CachedAuthDecision); ok {
			// Promote to L1 for faster access
			cm.promoteToL1(cacheKey, cached)
			return cached
		}
	}

	// Cache miss
	return nil
}

// CacheAuth caches an authorization decision
// Simplified to use pkg/cache with session index tracking
func (cm *CacheManager) CacheAuth(request *ContinuousAuthRequest, response *ContinuousAuthResponse) error {
	// Don't cache failures unless configured to do so
	if !response.AccessResponse.Granted && !cm.config.CacheNegativeResults {
		return nil
	}

	cacheKey := cm.generateCacheKey(request)

	cached := &CachedAuthDecision{
		CacheKey:       cacheKey,
		CacheLevel:     CacheLevelL1,
		ValidUntil:     response.ValidUntil,
		Request:        request,
		AccessResponse: response.AccessResponse,
		SessionID:      request.SessionID,
		SubjectID:      request.SubjectId,
		PermissionID:   request.PermissionId,
		TenantID:       request.TenantId,
		ContextHash:    cm.hashRequestContext(request),
		DecisionID:     response.DecisionID,
		DecisionTime:   response.DecisionTime,
		Source:         CacheSourceContinuous,
	}

	// Store in both L1 and L2 using pkg/cache
	ttl := time.Until(response.ValidUntil)
	if ttl < 0 {
		return nil // Already expired
	}

	if err := cm.l1Cache.Set(cacheKey, cached, ttl); err != nil {
		return fmt.Errorf("failed to cache auth in L1: %w", err)
	}
	if err := cm.l2Cache.Set(cacheKey, cached, ttl*2); err != nil {
		return fmt.Errorf("failed to cache auth in L2: %w", err)
	}

	// Update session index for O(1) session invalidation
	cm.indexMutex.Lock()
	cm.sessionIndex[request.SessionID] = append(cm.sessionIndex[request.SessionID], cacheKey)
	cm.indexMutex.Unlock()

	return nil
}

// InvalidateCache invalidates cache entries based on the request
func (cm *CacheManager) InvalidateCache(request *CacheInvalidationRequest) error {
	request.Timestamp = time.Now()

	switch request.InvalidationType {
	case InvalidationTypeSession:
		return cm.invalidateSession(request.SessionID, request.Reason)
	case InvalidationTypeSubject:
		return cm.invalidateSubject(request.SubjectID, request.Reason)
	case InvalidationTypeTenant:
		return cm.invalidateTenant(request.TenantID, request.Reason)
	case InvalidationTypePermission:
		return cm.invalidatePermission(request.PermissionID, request.Reason)
	case InvalidationTypeAll:
		return cm.invalidateAll(request.Reason)
	default:
		return fmt.Errorf("unknown invalidation type: %s", request.InvalidationType)
	}
}

// EvictSessionCache removes all cached entries for a session
// Simplified - uses session index for O(1) lookup
func (cm *CacheManager) EvictSessionCache(sessionID string) {
	if err := cm.invalidateSession(sessionID, "session_terminated"); err != nil {
		// Log error but don't fail the eviction
		// This is a best-effort cleanup operation
		return
	}
}

// EvictSubjectPermissions removes cached permissions for specific permissions
// Simplified to use pkg/cache and session index
func (cm *CacheManager) EvictSubjectPermissions(sessionID string, permissions []string) {
	// Get all keys for this session
	cm.indexMutex.RLock()
	keys, exists := cm.sessionIndex[sessionID]
	cm.indexMutex.RUnlock()

	if !exists {
		return
	}

	// Remove specific permissions
	for _, permission := range permissions {
		for _, key := range keys {
			// Check if cache key contains the permission
			if cm.keyContainsPermission(key, permission) {
				cm.l1Cache.Delete(key)
				cm.l2Cache.Delete(key)
			}
		}
	}
}

// GetHitRate returns the current cache hit rate
// Simplified - derives from pkg/cache statistics
func (cm *CacheManager) GetHitRate() float64 {
	l1Stats := cm.l1Cache.Stats()
	l2Stats := cm.l2Cache.Stats()

	totalHits := l1Stats.Hits + l2Stats.Hits
	totalMisses := l1Stats.Misses + l2Stats.Misses
	totalRequests := totalHits + totalMisses

	if totalRequests == 0 {
		return 0.0
	}
	return float64(totalHits) / float64(totalRequests)
}

// GetCacheStats returns current cache statistics
// Simplified - aggregates stats from pkg/cache instances
func (cm *CacheManager) GetCacheStats() *CacheStats {
	l1Stats := cm.l1Cache.Stats()
	l2Stats := cm.l2Cache.Stats()

	totalHits := l1Stats.Hits + l2Stats.Hits
	totalMisses := l1Stats.Misses + l2Stats.Misses
	totalRequests := totalHits + totalMisses

	hitRate := 0.0
	if totalRequests > 0 {
		hitRate = float64(totalHits) / float64(totalRequests)
	}

	return &CacheStats{
		TotalRequests:  totalRequests,
		CacheHits:      totalHits,
		CacheMisses:    totalMisses,
		HitRate:        hitRate,
		L1Hits:         l1Stats.Hits,
		L1Misses:       l1Stats.Misses,
		L2Hits:         l2Stats.Hits,
		L2Misses:       l2Stats.Misses,
		L1Size:         l1Stats.Size,
		L2Size:         l2Stats.Size,
		TotalSize:      l1Stats.Size + l2Stats.Size,
		L1Evictions:    l1Stats.Evictions,
		L2Evictions:    l2Stats.Evictions,
		ExpiredEntries: l1Stats.ItemsExpired + l2Stats.ItemsExpired,
		LastCleanup:    l1Stats.LastCleanup,
		LastStats:      time.Now(),
	}
}

// Internal cache operations

// promoteToL1 promotes a cache entry from L2 to L1
// Simplified - just add to L1 cache, pkg/cache handles eviction
func (cm *CacheManager) promoteToL1(cacheKey string, cached *CachedAuthDecision) {
	ttl := time.Until(cached.ValidUntil)
	if ttl > 0 {
		// Ignore error - L1 promotion is a performance optimization, not critical
		_ = cm.l1Cache.Set(cacheKey, cached, ttl)
	}
}

// Cache invalidation methods

func (cm *CacheManager) invalidateSession(sessionID, reason string) error {
	// Use session index for O(1) lookup of all keys for this session
	cm.indexMutex.Lock()
	keys, exists := cm.sessionIndex[sessionID]
	if exists {
		delete(cm.sessionIndex, sessionID)
	}
	cm.indexMutex.Unlock()

	if !exists {
		return nil // No entries for this session
	}

	// Remove all keys from both caches using pkg/cache
	for _, key := range keys {
		cm.l1Cache.Delete(key)
		cm.l2Cache.Delete(key)
	}

	return nil
}

func (cm *CacheManager) invalidateSubject(subjectID, reason string) error {
	// Simplified - iterate through L1 cache entries to find matches
	keysToRemove := make([]string, 0)
	for _, key := range cm.l1Cache.Keys() {
		if value, found := cm.l1Cache.Get(key); found {
			if cached, ok := value.(*CachedAuthDecision); ok && cached.SubjectID == subjectID {
				keysToRemove = append(keysToRemove, key)
			}
		}
	}

	// Remove from both L1 and L2
	for _, key := range keysToRemove {
		cm.l1Cache.Delete(key)
		cm.l2Cache.Delete(key)
		// Also clean up session index
		cm.removeKeyFromSessionIndex(key)
	}

	return nil
}

func (cm *CacheManager) invalidateTenant(tenantID, reason string) error {
	// Simplified - iterate through L1 cache entries to find matches
	keysToRemove := make([]string, 0)
	for _, key := range cm.l1Cache.Keys() {
		if value, found := cm.l1Cache.Get(key); found {
			if cached, ok := value.(*CachedAuthDecision); ok && cached.TenantID == tenantID {
				keysToRemove = append(keysToRemove, key)
			}
		}
	}

	// Remove from both L1 and L2
	for _, key := range keysToRemove {
		cm.l1Cache.Delete(key)
		cm.l2Cache.Delete(key)
		cm.removeKeyFromSessionIndex(key)
	}

	return nil
}

func (cm *CacheManager) invalidatePermission(permissionID, reason string) error {
	// Simplified - iterate through L1 cache entries to find matches
	keysToRemove := make([]string, 0)
	for _, key := range cm.l1Cache.Keys() {
		if value, found := cm.l1Cache.Get(key); found {
			if cached, ok := value.(*CachedAuthDecision); ok && cached.PermissionID == permissionID {
				keysToRemove = append(keysToRemove, key)
			}
		}
	}

	// Remove from both L1 and L2
	for _, key := range keysToRemove {
		cm.l1Cache.Delete(key)
		cm.l2Cache.Delete(key)
		cm.removeKeyFromSessionIndex(key)
	}

	return nil
}

func (cm *CacheManager) invalidateAll(reason string) error {
	// Simplified - use pkg/cache Clear() method
	cm.l1Cache.Clear()
	cm.l2Cache.Clear()

	// Clear session index
	cm.indexMutex.Lock()
	cm.sessionIndex = make(map[string][]string)
	cm.indexMutex.Unlock()

	return nil
}

// Helper methods

// removeKeyFromSessionIndex removes a key from the session index
func (cm *CacheManager) removeKeyFromSessionIndex(key string) {
	cm.indexMutex.Lock()
	defer cm.indexMutex.Unlock()

	// Find and remove the key from all session indices
	for sessionID, keys := range cm.sessionIndex {
		for i, k := range keys {
			if k == key {
				// Remove key from slice
				cm.sessionIndex[sessionID] = append(keys[:i], keys[i+1:]...)
				// If session now has no keys, remove the session entry
				if len(cm.sessionIndex[sessionID]) == 0 {
					delete(cm.sessionIndex, sessionID)
				}
				return
			}
		}
	}
}

// Utility methods

func (cm *CacheManager) generateCacheKey(request *ContinuousAuthRequest) string {
	// Generate a cache key from request components
	return fmt.Sprintf("%s:%s:%s:%s:%s",
		request.TenantId,
		request.SubjectId,
		request.PermissionId,
		request.ResourceId,
		cm.hashRequestContext(request))
}

func (cm *CacheManager) hashRequestContext(request *ContinuousAuthRequest) string {
	// Simple hash of request context
	// In production, would use proper hash function
	return fmt.Sprintf("ctx-%d", len(request.ResourceContext))
}

func (cm *CacheManager) keyContainsPermission(key, permission string) bool {
	// Check if cache key contains the permission
	return len(key) > len(permission) && key[len(key)-len(permission):] == permission
}
