package transform

import (
	"sync"
	"time"
)

// MemoryTransformCache provides an in-memory implementation of TransformCache
//
// This cache implementation uses an in-memory map with TTL-based expiration.
// It's suitable for single-instance deployments and provides good performance
// for short-lived transform results.
//
// For production deployments with multiple instances, consider implementing
// a distributed cache using Redis or similar technology.
type MemoryTransformCache struct {
	// cache stores the cached results
	cache map[string]*cacheEntry

	// stats tracks cache statistics
	stats TransformCacheStats

	// mutex protects concurrent access
	mutex sync.RWMutex

	// cleanupInterval defines how often to run cleanup
	cleanupInterval time.Duration

	// maxSize limits the maximum number of cached items
	maxSize int

	// stopCleanup is used to stop the cleanup goroutine
	stopCleanup chan struct{}
}

// cacheEntry represents a single cached item
type cacheEntry struct {
	// result is the cached transform result
	result TransformResult

	// expiresAt is when this entry expires
	expiresAt time.Time

	// size is the approximate size in bytes
	size int64
}

// NewMemoryTransformCache creates a new in-memory transform cache
func NewMemoryTransformCache(maxSize int, cleanupInterval time.Duration) *MemoryTransformCache {
	cache := &MemoryTransformCache{
		cache:           make(map[string]*cacheEntry),
		cleanupInterval: cleanupInterval,
		maxSize:         maxSize,
		stopCleanup:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanupLoop()

	return cache
}

// DefaultMemoryTransformCache creates a cache with sensible defaults
func DefaultMemoryTransformCache() *MemoryTransformCache {
	return NewMemoryTransformCache(1000, 5*time.Minute)
}

// Get retrieves a cached result
func (c *MemoryTransformCache) Get(key string) (TransformResult, bool) {
	c.mutex.RLock()
	entry, exists := c.cache[key]

	if !exists {
		c.mutex.RUnlock()
		// Update stats with write lock
		c.mutex.Lock()
		c.stats.MissCount++
		c.updateHitRatio()
		c.mutex.Unlock()
		return TransformResult{}, false
	}

	// Check if expired
	if time.Now().After(entry.expiresAt) {
		c.mutex.RUnlock()
		// Don't update stats here - let cleanup handle removal
		// Just return not found
		return TransformResult{}, false
	}

	result := entry.result
	c.mutex.RUnlock()

	// Update stats with write lock
	c.mutex.Lock()
	c.stats.HitCount++
	c.updateHitRatio()
	c.mutex.Unlock()

	return result, true
}

// Set stores a result in cache
func (c *MemoryTransformCache) Set(key string, result TransformResult, ttl time.Duration) {
	if ttl <= 0 {
		return // Don't cache items with zero or negative TTL
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Calculate approximate size
	size := c.calculateSize(result)

	// Check if we need to make room
	if len(c.cache) >= c.maxSize {
		c.evictOldest()
	}

	// Create new entry
	entry := &cacheEntry{
		result:    result,
		expiresAt: time.Now().Add(ttl),
		size:      size,
	}

	// Store in cache
	c.cache[key] = entry
	c.stats.Size = int64(len(c.cache))
	c.stats.MemoryUsage += size
}

// Delete removes a cached result
func (c *MemoryTransformCache) Delete(key string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if entry, exists := c.cache[key]; exists {
		delete(c.cache, key)
		c.stats.Size = int64(len(c.cache))
		c.stats.MemoryUsage -= entry.size
	}
}

// Clear removes all cached results
func (c *MemoryTransformCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.cache = make(map[string]*cacheEntry)
	c.stats.Size = 0
	c.stats.MemoryUsage = 0
}

// Stats returns cache statistics
func (c *MemoryTransformCache) Stats() TransformCacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := c.stats
	stats.Size = int64(len(c.cache))

	return stats
}

// Stop stops the cache cleanup goroutine
func (c *MemoryTransformCache) Stop() {
	close(c.stopCleanup)
}

// cleanupLoop runs periodic cleanup of expired entries
func (c *MemoryTransformCache) cleanupLoop() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanup()
		case <-c.stopCleanup:
			return
		}
	}
}

// cleanup removes expired entries
func (c *MemoryTransformCache) cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	var keysToDelete []string

	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			keysToDelete = append(keysToDelete, key)
		}
	}

	for _, key := range keysToDelete {
		if entry, exists := c.cache[key]; exists {
			delete(c.cache, key)
			c.stats.MemoryUsage -= entry.size
		}
	}

	c.stats.Size = int64(len(c.cache))
}

// evictOldest removes the oldest entry to make room for new ones
func (c *MemoryTransformCache) evictOldest() {
	if len(c.cache) == 0 {
		return
	}

	var oldestKey string
	var oldestTime time.Time

	// Find the oldest entry
	for key, entry := range c.cache {
		if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
		}
	}

	// Remove the oldest entry
	if entry, exists := c.cache[oldestKey]; exists {
		delete(c.cache, oldestKey)
		c.stats.MemoryUsage -= entry.size
	}
}

// calculateSize estimates the memory size of a transform result
func (c *MemoryTransformCache) calculateSize(result TransformResult) int64 {
	// This is a rough estimation
	size := int64(0)

	// Count data map
	for key, value := range result.Data {
		size += int64(len(key))
		size += c.estimateValueSize(value)
	}

	// Count metadata map
	for key, value := range result.Metadata {
		size += int64(len(key))
		size += c.estimateValueSize(value)
	}

	// Count strings
	size += int64(len(result.Error))
	size += int64(len(result.TransformName))
	size += int64(len(result.CacheKey))

	// Count warnings slice
	for _, warning := range result.Warnings {
		size += int64(len(warning))
	}

	// Add some overhead for struct fields
	size += 64

	return size
}

// estimateValueSize estimates the size of an interface{} value
func (c *MemoryTransformCache) estimateValueSize(value interface{}) int64 {
	switch v := value.(type) {
	case string:
		return int64(len(v))
	case int, int32, int64, float32, float64, bool:
		return 8
	case []interface{}:
		size := int64(0)
		for _, item := range v {
			size += c.estimateValueSize(item)
		}
		return size
	case map[string]interface{}:
		size := int64(0)
		for key, val := range v {
			size += int64(len(key))
			size += c.estimateValueSize(val)
		}
		return size
	default:
		// Default size for unknown types
		return 16
	}
}

// updateHitRatio updates the cache hit ratio
func (c *MemoryTransformCache) updateHitRatio() {
	total := c.stats.HitCount + c.stats.MissCount
	if total > 0 {
		c.stats.HitRatio = float64(c.stats.HitCount) / float64(total)
	}
}

// NoOpTransformCache provides a no-operation cache implementation
//
// This cache implementation does nothing and can be used when caching
// is disabled or not needed.
type NoOpTransformCache struct{}

// NewNoOpTransformCache creates a new no-op cache
func NewNoOpTransformCache() *NoOpTransformCache {
	return &NoOpTransformCache{}
}

// Get always returns not found
func (c *NoOpTransformCache) Get(key string) (TransformResult, bool) {
	return TransformResult{}, false
}

// Set does nothing
func (c *NoOpTransformCache) Set(key string, result TransformResult, ttl time.Duration) {
	// No-op
}

// Delete does nothing
func (c *NoOpTransformCache) Delete(key string) {
	// No-op
}

// Clear does nothing
func (c *NoOpTransformCache) Clear() {
	// No-op
}

// Stats returns empty statistics
func (c *NoOpTransformCache) Stats() TransformCacheStats {
	return TransformCacheStats{}
}
