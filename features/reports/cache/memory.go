// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package cache

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	pkgcache "github.com/cfgis/cfgms/pkg/cache"
)

// MemoryCache implements an in-memory cache for reports using pkg/cache
type MemoryCache struct {
	cache *pkgcache.Cache
}

// NewMemoryCache creates a new in-memory cache
func NewMemoryCache() *MemoryCache {
	config := pkgcache.CacheConfig{
		Name:            "reports-memory",
		MaxRuntimeItems: 10000, // Reasonable default for report caching
		DefaultTTL:      15 * time.Minute,
		CleanupInterval: 5 * time.Minute,
		EvictionPolicy:  pkgcache.EvictionLRU,
	}

	return &MemoryCache{
		cache: pkgcache.NewCache(config),
	}
}

// Get retrieves a report from the cache
func (c *MemoryCache) Get(ctx context.Context, key string) (*interfaces.Report, error) {
	value, found := c.cache.Get(key)
	if !found {
		return nil, ErrCacheMiss
	}

	if report, ok := value.(*interfaces.Report); ok {
		return report, nil
	}

	return nil, ErrCacheMiss
}

// Set stores a report in the cache with the specified TTL
func (c *MemoryCache) Set(ctx context.Context, key string, report *interfaces.Report, ttl time.Duration) error {
	return c.cache.Set(key, report, ttl)
}

// Delete removes a report from the cache
func (c *MemoryCache) Delete(ctx context.Context, key string) error {
	c.cache.Delete(key)
	return nil
}

// Clear removes all reports from the cache
func (c *MemoryCache) Clear(ctx context.Context) error {
	c.cache.Clear()
	return nil
}

// Size returns the number of entries in the cache
func (c *MemoryCache) Size() int {
	return c.cache.Size()
}

// Stats returns cache statistics
func (c *MemoryCache) Stats() CacheStats {
	pkgStats := c.cache.Stats()

	// Calculate expired entries by checking if they would be removed
	// pkg/cache removes expired entries automatically during cleanup
	// so we just return the current size as active
	return CacheStats{
		Entries: pkgStats.Size,
		Expired: 0, // pkg/cache auto-removes expired entries
		Active:  pkgStats.Size,
	}
}

// Close stops the cache cleanup routine
func (c *MemoryCache) Close() {
	c.cache.Close()
}
