package zerotrust

import (
	"sync"
	"time"
)

// PolicyCache provides L1/L2 cache architecture for policy evaluation results
type PolicyCache struct {
	l1Cache      *L1Cache
	l2Cache      *L2Cache
	cacheTTL     time.Duration
	maxCacheSize int
	
	// Statistics
	hits      int64
	misses    int64
	evictions int64
	
	mutex sync.RWMutex
}

// CacheEntry represents a cached policy evaluation result
type CacheEntry struct {
	Key          string
	Result       *PolicyEvaluationResult
	CreatedAt    time.Time
	ExpiresAt    time.Time
	AccessCount  int64
	LastAccessed time.Time
}

// L1Cache provides fast access to hot data
type L1Cache struct {
	entries     map[string]*CacheEntry
	accessOrder []string
	maxSize     int
	mutex       sync.RWMutex
}

// L2Cache provides storage for warm data  
type L2Cache struct {
	entries  map[string]*CacheEntry
	lruOrder []string
	maxSize  int
	mutex    sync.RWMutex
}

// NewPolicyCache creates a new policy cache with L1 and L2 tiers
func NewPolicyCache(ttl time.Duration) *PolicyCache {
	cache := &PolicyCache{
		l1Cache:      NewL1Cache(1000),  // 1K entries for hot data
		l2Cache:      NewL2Cache(10000), // 10K entries for warm data
		cacheTTL:     ttl,
		maxCacheSize: 11000,
	}
	
	// Start background cleanup process
	go cache.cleanupLoop()
	
	return cache
}

// Get retrieves a cached policy evaluation result
func (p *PolicyCache) Get(key string) *PolicyEvaluationResult {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	// Check L1 cache first
	if entry := p.l1Cache.Get(key); entry != nil {
		p.hits++
		return entry.Result
	}
	
	// Check L2 cache
	if entry := p.l2Cache.Get(key); entry != nil {
		// Promote to L1 cache if accessed frequently
		if entry.AccessCount > 5 {
			p.l1Cache.Put(key, entry)
		}
		p.hits++
		return entry.Result
	}
	
	p.misses++
	return nil
}

// Put stores a policy evaluation result in the cache
func (p *PolicyCache) Put(key string, result *PolicyEvaluationResult) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	now := time.Now()
	entry := &CacheEntry{
		Key:          key,
		Result:       result,
		CreatedAt:    now,
		ExpiresAt:    now.Add(p.cacheTTL),
		AccessCount:  1,
		LastAccessed: now,
	}
	
	// Store in L2 cache initially
	p.l2Cache.Put(key, entry)
}

// GetStats returns cache statistics
func (p *PolicyCache) GetStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	totalRequests := p.hits + p.misses
	hitRate := float64(0)
	if totalRequests > 0 {
		hitRate = float64(p.hits) / float64(totalRequests)
	}
	
	return map[string]interface{}{
		"hits":            p.hits,
		"misses":          p.misses,
		"hit_rate":        hitRate,
		"evictions":       p.evictions,
		"l1_size":         p.l1Cache.Size(),
		"l2_size":         p.l2Cache.Size(),
		"total_size":      p.l1Cache.Size() + p.l2Cache.Size(),
		"max_size":        p.maxCacheSize,
	}
}

// cleanupLoop periodically removes expired entries
func (p *PolicyCache) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		p.cleanup()
	}
}

func (p *PolicyCache) cleanup() {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	now := time.Now()
	
	// Cleanup L1 cache
	expired := p.l1Cache.RemoveExpired(now)
	p.evictions += int64(expired)
	
	// Cleanup L2 cache
	expired = p.l2Cache.RemoveExpired(now)
	p.evictions += int64(expired)
}

// L1Cache implementation (fast, small cache for hot data)

func NewL1Cache(maxSize int) *L1Cache {
	return &L1Cache{
		entries:     make(map[string]*CacheEntry),
		accessOrder: make([]string, 0, maxSize),
		maxSize:     maxSize,
	}
}

func (l1 *L1Cache) Get(key string) *CacheEntry {
	l1.mutex.RLock()
	entry, exists := l1.entries[key]
	l1.mutex.RUnlock()
	
	if !exists {
		return nil
	}
	
	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		l1.Remove(key)
		return nil
	}
	
	// Update access information
	l1.mutex.Lock()
	entry.AccessCount++
	entry.LastAccessed = time.Now()
	l1.updateAccessOrder(key)
	l1.mutex.Unlock()
	
	return entry
}

func (l1 *L1Cache) Put(key string, entry *CacheEntry) {
	l1.mutex.Lock()
	defer l1.mutex.Unlock()
	
	// Check if we need to evict
	if len(l1.entries) >= l1.maxSize {
		l1.evictLRU()
	}
	
	l1.entries[key] = entry
	l1.accessOrder = append(l1.accessOrder, key)
}

func (l1 *L1Cache) Remove(key string) {
	l1.mutex.Lock()
	defer l1.mutex.Unlock()
	
	delete(l1.entries, key)
	l1.removeFromAccessOrder(key)
}

func (l1 *L1Cache) Size() int {
	l1.mutex.RLock()
	defer l1.mutex.RUnlock()
	return len(l1.entries)
}

func (l1 *L1Cache) RemoveExpired(now time.Time) int {
	l1.mutex.Lock()
	defer l1.mutex.Unlock()
	
	var expiredKeys []string
	for key, entry := range l1.entries {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	for _, key := range expiredKeys {
		delete(l1.entries, key)
		l1.removeFromAccessOrder(key)
	}
	
	return len(expiredKeys)
}

func (l1 *L1Cache) updateAccessOrder(key string) {
	// Move key to end of access order (most recently used)
	l1.removeFromAccessOrder(key)
	l1.accessOrder = append(l1.accessOrder, key)
}

func (l1 *L1Cache) removeFromAccessOrder(key string) {
	for i, k := range l1.accessOrder {
		if k == key {
			l1.accessOrder = append(l1.accessOrder[:i], l1.accessOrder[i+1:]...)
			break
		}
	}
}

func (l1 *L1Cache) evictLRU() {
	if len(l1.accessOrder) > 0 {
		// Remove least recently used (first in access order)
		lruKey := l1.accessOrder[0]
		delete(l1.entries, lruKey)
		l1.accessOrder = l1.accessOrder[1:]
	}
}

// L2Cache implementation (larger cache for warm data)

func NewL2Cache(maxSize int) *L2Cache {
	return &L2Cache{
		entries:  make(map[string]*CacheEntry),
		lruOrder: make([]string, 0, maxSize),
		maxSize:  maxSize,
	}
}

func (l2 *L2Cache) Get(key string) *CacheEntry {
	l2.mutex.RLock()
	entry, exists := l2.entries[key]
	l2.mutex.RUnlock()
	
	if !exists {
		return nil
	}
	
	// Check if expired
	if time.Now().After(entry.ExpiresAt) {
		l2.Remove(key)
		return nil
	}
	
	// Update access information
	l2.mutex.Lock()
	entry.AccessCount++
	entry.LastAccessed = time.Now()
	l2.updateLRUOrder(key)
	l2.mutex.Unlock()
	
	return entry
}

func (l2 *L2Cache) Put(key string, entry *CacheEntry) {
	l2.mutex.Lock()
	defer l2.mutex.Unlock()
	
	// Check if we need to evict
	if len(l2.entries) >= l2.maxSize {
		l2.evictLRU()
	}
	
	l2.entries[key] = entry
	l2.lruOrder = append(l2.lruOrder, key)
}

func (l2 *L2Cache) Remove(key string) {
	l2.mutex.Lock()
	defer l2.mutex.Unlock()
	
	delete(l2.entries, key)
	l2.removeFromLRUOrder(key)
}

func (l2 *L2Cache) Size() int {
	l2.mutex.RLock()
	defer l2.mutex.RUnlock()
	return len(l2.entries)
}

func (l2 *L2Cache) RemoveExpired(now time.Time) int {
	l2.mutex.Lock()
	defer l2.mutex.Unlock()
	
	var expiredKeys []string
	for key, entry := range l2.entries {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}
	
	for _, key := range expiredKeys {
		delete(l2.entries, key)
		l2.removeFromLRUOrder(key)
	}
	
	return len(expiredKeys)
}

func (l2 *L2Cache) updateLRUOrder(key string) {
	// Move key to end of LRU order (most recently used)
	l2.removeFromLRUOrder(key)
	l2.lruOrder = append(l2.lruOrder, key)
}

func (l2 *L2Cache) removeFromLRUOrder(key string) {
	for i, k := range l2.lruOrder {
		if k == key {
			l2.lruOrder = append(l2.lruOrder[:i], l2.lruOrder[i+1:]...)
			break
		}
	}
}

func (l2 *L2Cache) evictLRU() {
	if len(l2.lruOrder) > 0 {
		// Remove least recently used (first in LRU order)
		lruKey := l2.lruOrder[0]
		delete(l2.entries, lruKey)
		l2.lruOrder = l2.lruOrder[1:]
	}
}