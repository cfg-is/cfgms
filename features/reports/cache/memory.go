package cache

import (
	"context"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
)

// MemoryCache implements an in-memory cache for reports
type MemoryCache struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	report    *interfaces.Report
	expiresAt time.Time
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache() *MemoryCache {
	c := &MemoryCache{
		cache: make(map[string]cacheEntry),
	}
	
	// Start cleanup goroutine
	go c.cleanup()
	
	return c
}

// Get retrieves a report from the cache
func (c *MemoryCache) Get(ctx context.Context, key string) (*interfaces.Report, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.cache[key]
	if !exists {
		return nil, ErrCacheMiss
	}
	
	// Check if expired
	if time.Now().After(entry.expiresAt) {
		// Don't delete here to avoid upgrading to write lock
		// The cleanup goroutine will handle expired entries
		return nil, ErrCacheMiss
	}
	
	return entry.report, nil
}

// Set stores a report in the cache with the specified TTL
func (c *MemoryCache) Set(ctx context.Context, key string, report *interfaces.Report, ttl time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[key] = cacheEntry{
		report:    report,
		expiresAt: time.Now().Add(ttl),
	}
	
	return nil
}

// Delete removes a report from the cache
func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.cache, key)
	return nil
}

// Clear removes all reports from the cache
func (c *MemoryCache) Clear(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache = make(map[string]cacheEntry)
	return nil
}

// Size returns the number of entries in the cache
func (c *MemoryCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	return len(c.cache)
}

// Stats returns cache statistics
func (c *MemoryCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	total := len(c.cache)
	expired := 0
	now := time.Now()
	
	for _, entry := range c.cache {
		if now.After(entry.expiresAt) {
			expired++
		}
	}
	
	return CacheStats{
		Entries: total,
		Expired: expired,
		Active:  total - expired,
	}
}

// cleanup periodically removes expired entries
func (c *MemoryCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		c.cleanupExpired()
	}
}

// cleanupExpired removes expired entries from the cache
func (c *MemoryCache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.expiresAt) {
			delete(c.cache, key)
		}
	}
}