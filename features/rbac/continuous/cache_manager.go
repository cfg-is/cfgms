package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// CacheManager provides high-performance caching for authorization decisions
type CacheManager struct {
	// L1 Cache (in-memory, fastest access)
	l1Cache       map[string]*CachedAuthDecision
	l1Mutex       sync.RWMutex
	l1MaxSize     int
	l1TTL         time.Duration
	
	// L2 Cache (session-based, longer retention)
	l2Cache       map[string]map[string]*CachedAuthDecision // sessionID -> permissionKey -> decision
	l2Mutex       sync.RWMutex
	l2MaxSize     int
	l2TTL         time.Duration
	
	// Cache configuration
	config        *CacheConfig
	
	// Performance tracking
	stats         CacheStats
	
	// Cache maintenance
	cleanupTicker *time.Ticker
	stopChannel   chan struct{}
	started       bool
	
	mutex         sync.RWMutex
}

// CachedAuthDecision represents a cached authorization decision
type CachedAuthDecision struct {
	// Cache metadata
	CacheKey      string                 `json:"cache_key"`
	CacheLevel    CacheLevel             `json:"cache_level"`
	CreatedAt     time.Time              `json:"created_at"`
	ValidUntil    time.Time              `json:"valid_until"`
	AccessCount   int64                  `json:"access_count"`
	LastAccessed  time.Time              `json:"last_accessed"`
	
	// Authorization data
	Request       *ContinuousAuthRequest `json:"request"`
	AccessResponse *common.AccessResponse `json:"access_response"`
	
	// Context data for validation
	SessionID     string                 `json:"session_id"`
	SubjectID     string                 `json:"subject_id"`
	PermissionID  string                 `json:"permission_id"`
	TenantID      string                 `json:"tenant_id"`
	ContextHash   string                 `json:"context_hash"` // Hash of request context
	
	// Decision metadata
	DecisionID    string                 `json:"decision_id"`
	DecisionTime  time.Time              `json:"decision_time"`
	Source        CacheSource            `json:"source"`
	
	// Invalidation tracking
	InvalidatedBy []string               `json:"invalidated_by"`
	InvalidatedAt time.Time              `json:"invalidated_at,omitempty"`
	
	mutex         sync.RWMutex
}

// CacheLevel defines the cache level
type CacheLevel string

const (
	CacheLevelL1      CacheLevel = "l1"       // Fast in-memory cache
	CacheLevelL2      CacheLevel = "l2"       // Session-based cache
	CacheLevelL3      CacheLevel = "l3"       // Distributed cache (future)
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
	MaxLatencyMs      int           `json:"max_latency_ms"`
	EnableCompression bool          `json:"enable_compression"`
	EnableEncryption  bool          `json:"enable_encryption"`
	
	// Cache behavior
	CacheNegativeResults bool        `json:"cache_negative_results"`
	CacheFailures       bool          `json:"cache_failures"`
	RefreshThreshold    float64       `json:"refresh_threshold"`  // Refresh when TTL < threshold
	
	// Distributed cache (future)
	EnableDistributed   bool          `json:"enable_distributed"`
	RedisURL           string         `json:"redis_url,omitempty"`
	RedisPassword      string         `json:"redis_password,omitempty"`
}

// CacheStats tracks cache performance statistics
type CacheStats struct {
	// Hit/Miss statistics
	TotalRequests     int64     `json:"total_requests"`
	CacheHits         int64     `json:"cache_hits"`
	CacheMisses       int64     `json:"cache_misses"`
	HitRate           float64   `json:"hit_rate"`
	
	// Performance statistics
	AverageLatencyMs  float64   `json:"average_latency_ms"`
	L1LatencyMs       float64   `json:"l1_latency_ms"`
	L2LatencyMs       float64   `json:"l2_latency_ms"`
	
	// Cache level statistics
	L1Hits            int64     `json:"l1_hits"`
	L1Misses          int64     `json:"l1_misses"`
	L2Hits            int64     `json:"l2_hits"`
	L2Misses          int64     `json:"l2_misses"`
	
	// Cache size and memory
	L1Size            int       `json:"l1_size"`
	L2Size            int       `json:"l2_size"`
	TotalSize         int       `json:"total_size"`
	MemoryUsageMB     float64   `json:"memory_usage_mb"`
	
	// Eviction statistics
	L1Evictions       int64     `json:"l1_evictions"`
	L2Evictions       int64     `json:"l2_evictions"`
	ExpiredEntries    int64     `json:"expired_entries"`
	
	// Invalidation statistics
	Invalidations     int64     `json:"invalidations"`
	BulkInvalidations int64     `json:"bulk_invalidations"`
	
	// Time tracking
	LastCleanup       time.Time `json:"last_cleanup"`
	LastStats         time.Time `json:"last_stats"`
	
	mutex            sync.RWMutex
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
	InvalidationTypeSession    InvalidationType = "session"     // Invalidate all entries for a session
	InvalidationTypeSubject    InvalidationType = "subject"     // Invalidate all entries for a subject
	InvalidationTypeTenant     InvalidationType = "tenant"      // Invalidate all entries for a tenant
	InvalidationTypePermission InvalidationType = "permission"  // Invalidate specific permission
	InvalidationTypeAll        InvalidationType = "all"         // Invalidate all cache entries
)

// NewCacheManager creates a new cache manager
func NewCacheManager(ttl time.Duration, maxLatencyMs int) *CacheManager {
	config := &CacheConfig{
		L1MaxSize:         10000,              // 10k entries in L1
		L1TTL:             ttl,                // Use provided TTL
		L1CleanupInterval: 1 * time.Minute,    // Cleanup every minute
		L2MaxSize:         100000,             // 100k entries in L2
		L2TTL:             ttl * 2,            // L2 has longer TTL
		L2CleanupInterval: 5 * time.Minute,    // Cleanup every 5 minutes
		MaxLatencyMs:      maxLatencyMs,
		CacheNegativeResults: false,           // Don't cache denials by default
		CacheFailures:     false,              // Don't cache failures by default
		RefreshThreshold:  0.8,                // Refresh when 80% of TTL passed
	}

	return &CacheManager{
		l1Cache:   make(map[string]*CachedAuthDecision),
		l2Cache:   make(map[string]map[string]*CachedAuthDecision),
		l1MaxSize: config.L1MaxSize,
		l1TTL:     config.L1TTL,
		l2MaxSize: config.L2MaxSize,
		l2TTL:     config.L2TTL,
		config:    config,
		stopChannel: make(chan struct{}),
		stats: CacheStats{
			LastStats: time.Now(),
		},
	}
}

// Start initializes and starts the cache manager
func (cm *CacheManager) Start(ctx context.Context) error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if cm.started {
		return fmt.Errorf("cache manager is already started")
	}

	// Start cache maintenance
	cm.cleanupTicker = time.NewTicker(cm.config.L1CleanupInterval)
	go cm.maintenanceLoop(ctx)

	cm.started = true
	return nil
}

// Stop gracefully stops the cache manager
func (cm *CacheManager) Stop() error {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	if !cm.started {
		return fmt.Errorf("cache manager is not started")
	}

	// Stop maintenance
	if cm.cleanupTicker != nil {
		cm.cleanupTicker.Stop()
	}
	close(cm.stopChannel)

	cm.started = false
	return nil
}

// GetCachedAuth retrieves a cached authorization decision
func (cm *CacheManager) GetCachedAuth(request *ContinuousAuthRequest) *CachedAuthDecision {
	startTime := time.Now()
	defer func() {
		latency := time.Since(startTime)
		cm.updateLatencyStats(latency)
	}()

	// Increment total requests
	cm.incrementTotalRequests()

	// Generate cache key
	cacheKey := cm.generateCacheKey(request)

	// Try L1 cache first (fastest)
	if cached := cm.getFromL1(cacheKey); cached != nil {
		cm.incrementHit(CacheLevelL1)
		return cached
	}

	// Try L2 cache (session-based)
	if cached := cm.getFromL2(request.SessionID, cacheKey); cached != nil {
		// Promote to L1 for faster access
		cm.promoteToL1(cacheKey, cached)
		cm.incrementHit(CacheLevelL2)
		return cached
	}

	// Cache miss
	cm.incrementMiss()
	return nil
}

// CacheAuth caches an authorization decision
func (cm *CacheManager) CacheAuth(request *ContinuousAuthRequest, response *ContinuousAuthResponse) error {
	// Don't cache failures unless configured to do so
	if !response.AccessResponse.Granted && !cm.config.CacheNegativeResults {
		return nil
	}

	cacheKey := cm.generateCacheKey(request)
	
	cached := &CachedAuthDecision{
		CacheKey:       cacheKey,
		CacheLevel:     CacheLevelL1,
		CreatedAt:      time.Now(),
		ValidUntil:     response.ValidUntil,
		AccessCount:    1,
		LastAccessed:   time.Now(),
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

	// Store in both L1 and L2
	cm.storeInL1(cacheKey, cached)
	cm.storeInL2(request.SessionID, cacheKey, cached)

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
func (cm *CacheManager) EvictSessionCache(sessionID string) {
	cm.invalidateSession(sessionID, "session_terminated")
}

// EvictSubjectPermissions removes cached permissions for specific permissions
func (cm *CacheManager) EvictSubjectPermissions(sessionID string, permissions []string) {
	cm.l2Mutex.Lock()
	defer cm.l2Mutex.Unlock()

	sessionCache, exists := cm.l2Cache[sessionID]
	if !exists {
		return
	}

	// Remove specific permissions
	for _, permission := range permissions {
		for key := range sessionCache {
			// Check if cache key contains the permission
			if cm.keyContainsPermission(key, permission) {
				delete(sessionCache, key)
				
				// Also remove from L1
				cm.l1Mutex.Lock()
				delete(cm.l1Cache, key)
				cm.l1Mutex.Unlock()
			}
		}
	}

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.Invalidations++
	cm.stats.mutex.Unlock()
}

// GetHitRate returns the current cache hit rate
func (cm *CacheManager) GetHitRate() float64 {
	cm.stats.mutex.RLock()
	defer cm.stats.mutex.RUnlock()
	return cm.stats.HitRate
}

// GetCacheStats returns current cache statistics
func (cm *CacheManager) GetCacheStats() *CacheStats {
	cm.stats.mutex.RLock()
	defer cm.stats.mutex.RUnlock()

	// Return a copy to prevent external modification
	return &CacheStats{
		TotalRequests:     cm.stats.TotalRequests,
		CacheHits:         cm.stats.CacheHits,
		CacheMisses:       cm.stats.CacheMisses,
		HitRate:           cm.stats.HitRate,
		AverageLatencyMs:  cm.stats.AverageLatencyMs,
		L1LatencyMs:       cm.stats.L1LatencyMs,
		L2LatencyMs:       cm.stats.L2LatencyMs,
		L1Hits:            cm.stats.L1Hits,
		L1Misses:          cm.stats.L1Misses,
		L2Hits:            cm.stats.L2Hits,
		L2Misses:          cm.stats.L2Misses,
		L1Size:            cm.stats.L1Size,
		L2Size:            cm.stats.L2Size,
		TotalSize:         cm.stats.TotalSize,
		MemoryUsageMB:     cm.stats.MemoryUsageMB,
		L1Evictions:       cm.stats.L1Evictions,
		L2Evictions:       cm.stats.L2Evictions,
		ExpiredEntries:    cm.stats.ExpiredEntries,
		Invalidations:     cm.stats.Invalidations,
		BulkInvalidations: cm.stats.BulkInvalidations,
		LastCleanup:       cm.stats.LastCleanup,
		LastStats:         cm.stats.LastStats,
	}
}

// Internal cache operations

// getFromL1 retrieves a cached decision from L1 cache
func (cm *CacheManager) getFromL1(cacheKey string) *CachedAuthDecision {
	cm.l1Mutex.RLock()
	defer cm.l1Mutex.RUnlock()

	cached, exists := cm.l1Cache[cacheKey]
	if !exists {
		return nil
	}

	// Check expiration
	if time.Now().After(cached.ValidUntil) {
		// Entry expired, remove it
		go cm.removeExpiredL1Entry(cacheKey)
		return nil
	}

	// Update access statistics
	cached.mutex.Lock()
	cached.AccessCount++
	cached.LastAccessed = time.Now()
	cached.mutex.Unlock()

	return cached
}

// getFromL2 retrieves a cached decision from L2 cache
func (cm *CacheManager) getFromL2(sessionID, cacheKey string) *CachedAuthDecision {
	cm.l2Mutex.RLock()
	defer cm.l2Mutex.RUnlock()

	sessionCache, exists := cm.l2Cache[sessionID]
	if !exists {
		return nil
	}

	cached, exists := sessionCache[cacheKey]
	if !exists {
		return nil
	}

	// Check expiration
	if time.Now().After(cached.ValidUntil) {
		// Entry expired, remove it
		go cm.removeExpiredL2Entry(sessionID, cacheKey)
		return nil
	}

	// Update access statistics
	cached.mutex.Lock()
	cached.AccessCount++
	cached.LastAccessed = time.Now()
	cached.mutex.Unlock()

	return cached
}

// storeInL1 stores a cached decision in L1 cache
func (cm *CacheManager) storeInL1(cacheKey string, cached *CachedAuthDecision) {
	cm.l1Mutex.Lock()
	defer cm.l1Mutex.Unlock()

	// Check if L1 cache is full
	if len(cm.l1Cache) >= cm.l1MaxSize {
		cm.evictFromL1()
	}

	cached.CacheLevel = CacheLevelL1
	cm.l1Cache[cacheKey] = cached
	
	// Update size statistics
	cm.updateCacheSizeStats()
}

// storeInL2 stores a cached decision in L2 cache
func (cm *CacheManager) storeInL2(sessionID, cacheKey string, cached *CachedAuthDecision) {
	cm.l2Mutex.Lock()
	defer cm.l2Mutex.Unlock()

	// Initialize session cache if needed
	if cm.l2Cache[sessionID] == nil {
		cm.l2Cache[sessionID] = make(map[string]*CachedAuthDecision)
	}

	// Check if L2 cache is full
	totalL2Size := cm.getTotalL2Size()
	if totalL2Size >= cm.l2MaxSize {
		cm.evictFromL2()
	}

	cached.CacheLevel = CacheLevelL2
	cm.l2Cache[sessionID][cacheKey] = cached
	
	// Update size statistics
	cm.updateCacheSizeStats()
}

// promoteToL1 promotes a cache entry from L2 to L1
func (cm *CacheManager) promoteToL1(cacheKey string, cached *CachedAuthDecision) {
	// Create a copy for L1
	l1Cached := *cached
	l1Cached.CacheLevel = CacheLevelL1
	
	cm.storeInL1(cacheKey, &l1Cached)
}

// Cache invalidation methods

func (cm *CacheManager) invalidateSession(sessionID, reason string) error {
	// Remove from L2 cache
	cm.l2Mutex.Lock()
	delete(cm.l2Cache, sessionID)
	cm.l2Mutex.Unlock()

	// Remove related entries from L1 cache
	cm.l1Mutex.Lock()
	keysToRemove := make([]string, 0)
	for key, cached := range cm.l1Cache {
		if cached.SessionID == sessionID {
			keysToRemove = append(keysToRemove, key)
		}
	}
	for _, key := range keysToRemove {
		delete(cm.l1Cache, key)
	}
	cm.l1Mutex.Unlock()

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.Invalidations++
	cm.stats.mutex.Unlock()

	return nil
}

func (cm *CacheManager) invalidateSubject(subjectID, reason string) error {
	// Remove from L1 cache
	cm.l1Mutex.Lock()
	keysToRemove := make([]string, 0)
	for key, cached := range cm.l1Cache {
		if cached.SubjectID == subjectID {
			keysToRemove = append(keysToRemove, key)
		}
	}
	for _, key := range keysToRemove {
		delete(cm.l1Cache, key)
	}
	cm.l1Mutex.Unlock()

	// Remove from L2 cache
	cm.l2Mutex.Lock()
	for sessionID, sessionCache := range cm.l2Cache {
		keysToRemove = make([]string, 0)
		for key, cached := range sessionCache {
			if cached.SubjectID == subjectID {
				keysToRemove = append(keysToRemove, key)
			}
		}
		for _, key := range keysToRemove {
			delete(sessionCache, key)
		}
		
		// Remove empty session caches
		if len(sessionCache) == 0 {
			delete(cm.l2Cache, sessionID)
		}
	}
	cm.l2Mutex.Unlock()

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.BulkInvalidations++
	cm.stats.mutex.Unlock()

	return nil
}

func (cm *CacheManager) invalidateTenant(tenantID, reason string) error {
	// Remove from L1 cache
	cm.l1Mutex.Lock()
	keysToRemove := make([]string, 0)
	for key, cached := range cm.l1Cache {
		if cached.TenantID == tenantID {
			keysToRemove = append(keysToRemove, key)
		}
	}
	for _, key := range keysToRemove {
		delete(cm.l1Cache, key)
	}
	cm.l1Mutex.Unlock()

	// Remove from L2 cache
	cm.l2Mutex.Lock()
	for sessionID, sessionCache := range cm.l2Cache {
		keysToRemove = make([]string, 0)
		for key, cached := range sessionCache {
			if cached.TenantID == tenantID {
				keysToRemove = append(keysToRemove, key)
			}
		}
		for _, key := range keysToRemove {
			delete(sessionCache, key)
		}
		
		// Remove empty session caches
		if len(sessionCache) == 0 {
			delete(cm.l2Cache, sessionID)
		}
	}
	cm.l2Mutex.Unlock()

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.BulkInvalidations++
	cm.stats.mutex.Unlock()

	return nil
}

func (cm *CacheManager) invalidatePermission(permissionID, reason string) error {
	// Remove from L1 cache
	cm.l1Mutex.Lock()
	keysToRemove := make([]string, 0)
	for key, cached := range cm.l1Cache {
		if cached.PermissionID == permissionID {
			keysToRemove = append(keysToRemove, key)
		}
	}
	for _, key := range keysToRemove {
		delete(cm.l1Cache, key)
	}
	cm.l1Mutex.Unlock()

	// Remove from L2 cache
	cm.l2Mutex.Lock()
	for sessionID, sessionCache := range cm.l2Cache {
		keysToRemove = make([]string, 0)
		for key, cached := range sessionCache {
			if cached.PermissionID == permissionID {
				keysToRemove = append(keysToRemove, key)
			}
		}
		for _, key := range keysToRemove {
			delete(sessionCache, key)
		}
		
		// Remove empty session caches
		if len(sessionCache) == 0 {
			delete(cm.l2Cache, sessionID)
		}
	}
	cm.l2Mutex.Unlock()

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.Invalidations++
	cm.stats.mutex.Unlock()

	return nil
}

func (cm *CacheManager) invalidateAll(reason string) error {
	// Clear L1 cache
	cm.l1Mutex.Lock()
	cm.l1Cache = make(map[string]*CachedAuthDecision)
	cm.l1Mutex.Unlock()

	// Clear L2 cache
	cm.l2Mutex.Lock()
	cm.l2Cache = make(map[string]map[string]*CachedAuthDecision)
	cm.l2Mutex.Unlock()

	// Update statistics
	cm.stats.mutex.Lock()
	cm.stats.BulkInvalidations++
	cm.stats.mutex.Unlock()

	return nil
}

// Cache eviction methods

func (cm *CacheManager) evictFromL1() {
	// Simple LRU eviction - remove oldest entry
	var oldestKey string
	var oldestTime time.Time = time.Now()

	for key, cached := range cm.l1Cache {
		if cached.LastAccessed.Before(oldestTime) {
			oldestTime = cached.LastAccessed
			oldestKey = key
		}
	}

	if oldestKey != "" {
		delete(cm.l1Cache, oldestKey)
		cm.stats.mutex.Lock()
		cm.stats.L1Evictions++
		cm.stats.mutex.Unlock()
	}
}

func (cm *CacheManager) evictFromL2() {
	// Find session with oldest entries
	var oldestSessionID string
	var oldestTime time.Time = time.Now()

	for sessionID, sessionCache := range cm.l2Cache {
		for _, cached := range sessionCache {
			if cached.LastAccessed.Before(oldestTime) {
				oldestTime = cached.LastAccessed
				oldestSessionID = sessionID
				break
			}
		}
	}

	if oldestSessionID != "" {
		// Remove oldest entries from the session
		sessionCache := cm.l2Cache[oldestSessionID]
		toRemove := len(sessionCache) / 4 // Remove 25% of entries
		if toRemove == 0 {
			toRemove = 1
		}

		removed := 0
		for key, cached := range sessionCache {
			if removed >= toRemove {
				break
			}
			if cached.LastAccessed.Equal(oldestTime) || cached.LastAccessed.Before(time.Now().Add(-1*time.Hour)) {
				delete(sessionCache, key)
				removed++
			}
		}

		cm.stats.mutex.Lock()
		cm.stats.L2Evictions += int64(removed)
		cm.stats.mutex.Unlock()
	}
}

// Background maintenance

func (cm *CacheManager) maintenanceLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-cm.stopChannel:
			return
		case <-cm.cleanupTicker.C:
			cm.performMaintenance()
		}
	}
}

func (cm *CacheManager) performMaintenance() {
	// Clean expired entries
	cm.cleanupExpiredEntries()
	
	// Update statistics
	cm.updateStatistics()
	
	// Update last cleanup time
	cm.stats.mutex.Lock()
	cm.stats.LastCleanup = time.Now()
	cm.stats.mutex.Unlock()
}

func (cm *CacheManager) cleanupExpiredEntries() {
	now := time.Now()
	expiredCount := 0

	// Clean L1 cache
	cm.l1Mutex.Lock()
	keysToRemove := make([]string, 0)
	for key, cached := range cm.l1Cache {
		if now.After(cached.ValidUntil) {
			keysToRemove = append(keysToRemove, key)
		}
	}
	for _, key := range keysToRemove {
		delete(cm.l1Cache, key)
		expiredCount++
	}
	cm.l1Mutex.Unlock()

	// Clean L2 cache
	cm.l2Mutex.Lock()
	for sessionID, sessionCache := range cm.l2Cache {
		keysToRemove = make([]string, 0)
		for key, cached := range sessionCache {
			if now.After(cached.ValidUntil) {
				keysToRemove = append(keysToRemove, key)
			}
		}
		for _, key := range keysToRemove {
			delete(sessionCache, key)
			expiredCount++
		}
		
		// Remove empty session caches
		if len(sessionCache) == 0 {
			delete(cm.l2Cache, sessionID)
		}
	}
	cm.l2Mutex.Unlock()

	// Update expired entries statistics
	if expiredCount > 0 {
		cm.stats.mutex.Lock()
		cm.stats.ExpiredEntries += int64(expiredCount)
		cm.stats.mutex.Unlock()
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

func (cm *CacheManager) removeExpiredL1Entry(cacheKey string) {
	cm.l1Mutex.Lock()
	defer cm.l1Mutex.Unlock()
	delete(cm.l1Cache, cacheKey)
}

func (cm *CacheManager) removeExpiredL2Entry(sessionID, cacheKey string) {
	cm.l2Mutex.Lock()
	defer cm.l2Mutex.Unlock()
	
	if sessionCache, exists := cm.l2Cache[sessionID]; exists {
		delete(sessionCache, cacheKey)
		if len(sessionCache) == 0 {
			delete(cm.l2Cache, sessionID)
		}
	}
}

func (cm *CacheManager) getTotalL2Size() int {
	total := 0
	for _, sessionCache := range cm.l2Cache {
		total += len(sessionCache)
	}
	return total
}

// Statistics methods

func (cm *CacheManager) incrementTotalRequests() {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()
	cm.stats.TotalRequests++
}

func (cm *CacheManager) incrementHit(level CacheLevel) {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()
	
	cm.stats.CacheHits++
	switch level {
	case CacheLevelL1:
		cm.stats.L1Hits++
	case CacheLevelL2:
		cm.stats.L2Hits++
	}
	
	cm.updateHitRate()
}

func (cm *CacheManager) incrementMiss() {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()
	
	cm.stats.CacheMisses++
	cm.stats.L1Misses++
	cm.stats.L2Misses++
	
	cm.updateHitRate()
}

func (cm *CacheManager) updateHitRate() {
	// Called with stats mutex held
	if cm.stats.TotalRequests > 0 {
		cm.stats.HitRate = float64(cm.stats.CacheHits) / float64(cm.stats.TotalRequests)
	}
}

func (cm *CacheManager) updateLatencyStats(latency time.Duration) {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()
	
	// Update average latency using exponential moving average
	alpha := 0.1
	newLatency := float64(latency.Milliseconds())
	cm.stats.AverageLatencyMs = (1-alpha)*cm.stats.AverageLatencyMs + alpha*newLatency
}

func (cm *CacheManager) updateCacheSizeStats() {
	cm.stats.mutex.Lock()
	defer cm.stats.mutex.Unlock()
	
	cm.stats.L1Size = len(cm.l1Cache)
	cm.stats.L2Size = cm.getTotalL2Size()
	cm.stats.TotalSize = cm.stats.L1Size + cm.stats.L2Size
}

func (cm *CacheManager) updateStatistics() {
	cm.updateCacheSizeStats()
	
	cm.stats.mutex.Lock()
	cm.stats.LastStats = time.Now()
	cm.stats.mutex.Unlock()
}