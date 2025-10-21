package zerotrust

import (
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
)

// PolicyCache provides L1/L2 cache architecture for policy evaluation results
// Now uses centralized pkg/cache.Cache for both tiers
type PolicyCache struct {
	l1Cache *cache.Cache // Hot data (1K entries)
	l2Cache *cache.Cache // Warm data (10K entries)

	cacheTTL time.Duration
	mutex    sync.RWMutex
}

// NewPolicyCache creates a new policy cache with L1 and L2 tiers
// Uses pkg/cache with LRU eviction for both tiers
func NewPolicyCache(ttl time.Duration) *PolicyCache {
	// L1 cache: Small, fast cache for frequently accessed data
	l1Config := cache.CacheConfig{
		Name:              "zerotrust-l1",
		MaxRuntimeItems:   1000,
		DefaultTTL:        ttl,
		CleanupInterval:   1 * time.Minute,
		EvictionPolicy:    cache.EvictionLRU,
	}

	// L2 cache: Larger cache for less frequently accessed data
	l2Config := cache.CacheConfig{
		Name:              "zerotrust-l2",
		MaxRuntimeItems:   10000,
		DefaultTTL:        ttl,
		CleanupInterval:   1 * time.Minute,
		EvictionPolicy:    cache.EvictionLRU,
	}

	return &PolicyCache{
		l1Cache:  cache.NewCache(l1Config),
		l2Cache:  cache.NewCache(l2Config),
		cacheTTL: ttl,
	}
}

// Get retrieves a cached policy evaluation result
// Checks L1 first, then L2, and promotes frequently accessed items
func (p *PolicyCache) Get(key string) *PolicyEvaluationResult {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Check L1 cache first (hot data)
	if value, found := p.l1Cache.Get(key); found {
		if result, ok := value.(*PolicyEvaluationResult); ok {
			return result
		}
	}

	// Check L2 cache (warm data)
	if value, found := p.l2Cache.Get(key); found {
		if result, ok := value.(*PolicyEvaluationResult); ok {
			// Promote to L1 if accessed frequently
			// pkg/cache tracks AccessCount automatically via LRU tracking
			// We use a simpler heuristic: promote on every L2 hit
			// This is actually better than the previous "AccessCount > 5" logic
			// because pkg/cache's LRU will automatically evict cold L1 entries
			p.promoteToL1(key, result)
			return result
		}
	}

	return nil
}

// Put stores a policy evaluation result in the cache
// Initially stores in L2 cache
func (p *PolicyCache) Put(key string, result *PolicyEvaluationResult) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Store in L2 cache initially
	// Will be promoted to L1 on subsequent accesses
	p.l2Cache.Set(key, result, p.cacheTTL)
}

// promoteToL1 moves an entry from L2 to L1 for frequently accessed data
func (p *PolicyCache) promoteToL1(key string, result *PolicyEvaluationResult) {
	// Note: This is called while holding read lock, so we don't modify L2
	// Just add to L1 - pkg/cache's LRU will handle eviction
	// We accept the small overhead of duplicates across L1/L2 for thread safety
	p.l1Cache.Set(key, result, p.cacheTTL)
}

// GetStats returns cache statistics
// Aggregates statistics from both L1 and L2 caches
func (p *PolicyCache) GetStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	l1Stats := p.l1Cache.Stats()
	l2Stats := p.l2Cache.Stats()

	totalHits := l1Stats.Hits + l2Stats.Hits
	totalMisses := l1Stats.Misses + l2Stats.Misses
	totalRequests := totalHits + totalMisses

	hitRate := float64(0)
	if totalRequests > 0 {
		hitRate = float64(totalHits) / float64(totalRequests)
	}

	return map[string]interface{}{
		"hits":       totalHits,
		"misses":     totalMisses,
		"hit_rate":   hitRate,
		"evictions":  l1Stats.Evictions + l2Stats.Evictions,
		"l1_size":    l1Stats.Size,
		"l2_size":    l2Stats.Size,
		"total_size": l1Stats.Size + l2Stats.Size,
		"max_size":   l1Stats.MaxSize + l2Stats.MaxSize,
	}
}

// Close closes both cache instances and stops cleanup routines
func (p *PolicyCache) Close() {
	p.l1Cache.Close()
	p.l2Cache.Close()
}
