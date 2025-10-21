// Package cache provides general-purpose in-memory caching with TTL and eviction
package cache

import (
	"fmt"
	"sync"
	"time"
)

// Cache provides general-purpose in-memory caching with TTL, eviction, and statistics
// This is the core cache implementation used by all providers (secrets, storage, sessions, etc.)
type Cache struct {
	items       map[string]*CacheEntry
	config      CacheConfig
	stats       CacheStats
	mutex       *sync.RWMutex
	stopCleanup chan struct{}
	cleanupDone *sync.WaitGroup
}

// NewCache creates a new general-purpose cache with the specified configuration
func NewCache(config CacheConfig) *Cache {
	cache := &Cache{
		items:       make(map[string]*CacheEntry),
		config:      config,
		stats:       CacheStats{MaxSize: config.MaxRuntimeItems},
		mutex:       &sync.RWMutex{},
		stopCleanup: make(chan struct{}),
		cleanupDone: &sync.WaitGroup{},
	}

	// Start background cleanup if cleanup interval is configured
	if config.CleanupInterval > 0 {
		cache.startCleanupRoutine()
	}

	return cache
}

// Get retrieves a value from the cache
// Returns (value, true) if found and not expired, (nil, false) if not found or expired
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	entry, exists := c.items[key]
	if !exists {
		c.stats.Misses++
		return nil, false
	}

	// Check expiration
	if entry.IsExpired() {
		c.stats.Misses++
		return nil, false
	}

	c.stats.Hits++
	return entry.Value, true
}

// Set stores a value in the cache with the specified TTL
// If TTL is 0, uses the cache's default TTL
func (c *Cache) Set(key string, value interface{}, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	c.items[key] = &CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}

	// Enforce size limits
	c.enforceMaxSize()
	c.updateSizeStats()

	return nil
}

// Delete removes a value from the cache
// Returns true if the item was deleted, false if it didn't exist
func (c *Cache) Delete(key string) bool {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if _, exists := c.items[key]; !exists {
		return false
	}

	delete(c.items, key)
	c.updateSizeStats()
	return true
}

// Clear removes all items from the cache
func (c *Cache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.items = make(map[string]*CacheEntry)
	c.stats.Size = 0
}

// Keys returns all keys currently in the cache
func (c *Cache) Keys() []string {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	keys := make([]string, 0, len(c.items))
	for key := range c.items {
		keys = append(keys, key)
	}
	return keys
}

// Size returns the current number of items in the cache
func (c *Cache) Size() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.items)
}

// Stats returns current cache statistics
func (c *Cache) Stats() CacheStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	stats := c.stats
	stats.Size = len(c.items)
	return stats
}

// Close stops the cleanup routine and releases resources
func (c *Cache) Close() {
	if c.cleanupDone != nil {
		close(c.stopCleanup)
		c.cleanupDone.Wait()
	}
}

// GetMany retrieves multiple values from the cache in a single call
// Returns a map of key -> value for found items
func (c *Cache) GetMany(keys []string) map[string]interface{} {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	result := make(map[string]interface{})
	for _, key := range keys {
		if entry, exists := c.items[key]; exists && !entry.IsExpired() {
			result[key] = entry.Value
			c.stats.Hits++
		} else {
			c.stats.Misses++
		}
	}

	return result
}

// SetMany stores multiple key-value pairs in the cache with the same TTL
// If TTL is 0, uses the cache's default TTL
func (c *Cache) SetMany(items map[string]interface{}, ttl time.Duration) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if ttl == 0 {
		ttl = c.config.DefaultTTL
	}

	expiresAt := time.Now().Add(ttl)
	for key, value := range items {
		c.items[key] = &CacheEntry{
			Value:     value,
			ExpiresAt: expiresAt,
		}
	}

	// Enforce size limits
	c.enforceMaxSize()
	c.updateSizeStats()

	return nil
}

// DeleteMany removes multiple keys from the cache
// Returns the number of items actually deleted
func (c *Cache) DeleteMany(keys []string) int {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	deleted := 0
	for _, key := range keys {
		if _, exists := c.items[key]; exists {
			delete(c.items, key)
			deleted++
		}
	}

	c.updateSizeStats()
	return deleted
}

// startCleanupRoutine starts the background cleanup goroutine
func (c *Cache) startCleanupRoutine() {
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

// cleanupExpiredItems removes expired entries from the cache
func (c *Cache) cleanupExpiredItems() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	expired := int64(0)

	for key, entry := range c.items {
		if entry.IsExpired() {
			delete(c.items, key)
			expired++
		}
	}

	c.stats.LastCleanup = now
	c.stats.ItemsExpired += expired
	c.updateSizeStats()
}

// updateSizeStats updates the size statistics (must be called while holding mutex)
func (c *Cache) updateSizeStats() {
	c.stats.Size = len(c.items)
}

// enforceMaxSize removes oldest items if we exceed the limit (must be called while holding mutex)
// Uses simple FIFO eviction - in production, could be LRU
func (c *Cache) enforceMaxSize() {
	maxSize := c.config.MaxRuntimeItems
	if maxSize <= 0 {
		return // No size limit
	}

	if len(c.items) <= maxSize {
		return
	}

	// Simple eviction: remove items until we're under the limit
	// In production, could track access times for LRU
	count := len(c.items) - maxSize
	evicted := 0

	for key := range c.items {
		if evicted >= count {
			break
		}
		delete(c.items, key)
		evicted++
	}

	c.stats.Evictions += int64(evicted)
}

// Helper functions for debugging

// DumpKeys returns all keys with their expiration times (for debugging)
func (c *Cache) DumpKeys() map[string]time.Time {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	dump := make(map[string]time.Time)
	for key, entry := range c.items {
		dump[key] = entry.ExpiresAt
	}
	return dump
}

// String returns a string representation of cache stats
func (c *Cache) String() string {
	stats := c.Stats()
	return fmt.Sprintf("Cache[%s]: size=%d/%d hits=%d misses=%d evictions=%d expired=%d",
		c.config.Name, stats.Size, stats.MaxSize, stats.Hits, stats.Misses,
		stats.Evictions, stats.ItemsExpired)
}
