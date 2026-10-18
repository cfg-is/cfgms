// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cache

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evictRecorder records OnEvict calls. The callback calls back into the cache, which
// would deadlock if the callback ran while the cache mutex was held.
type evictRecorder struct {
	mu    sync.Mutex
	calls map[string]int
	c     *Cache
}

func (r *evictRecorder) onEvict(key string, _ interface{}) {
	if r.c != nil {
		// Deadlocks if the cache mutex were still held (Size takes the read lock).
		_ = r.c.Size()
		_ = r.c.Keys()
		_, _ = r.c.Get("probe")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[key]++
}

func (r *evictRecorder) snapshot() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.calls))
	for k, v := range r.calls {
		out[k] = v
	}
	return out
}

func newEvictCache(t *testing.T, cfg CacheConfig) (*Cache, *evictRecorder) {
	t.Helper()
	rec := &evictRecorder{calls: map[string]int{}}
	cfg.OnEvict = rec.onEvict
	c := NewCache(cfg)
	rec.c = c
	t.Cleanup(c.Close)
	return c, rec
}

func callsFor(rec *evictRecorder) map[string]int { return rec.snapshot() }

func TestCacheOnEvict_SizeLimit(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{MaxRuntimeItems: 2, DefaultTTL: time.Hour, EvictionPolicy: EvictionLRU})
	require.NoError(t, c.Set("a", 1, 0))
	require.NoError(t, c.Set("b", 2, 0))
	_, _ = c.Get("a") // b is now least recently used
	require.NoError(t, c.Set("c", 3, 0))

	assert.Equal(t, map[string]int{"b": 1}, callsFor(rec))
	assert.Equal(t, 2, c.Size())
}

func TestCacheOnEvict_SetManySizeLimit(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{MaxRuntimeItems: 1, DefaultTTL: time.Hour, EvictionPolicy: EvictionFIFO})
	require.NoError(t, c.Set("a", 1, 0))
	require.NoError(t, c.SetMany(map[string]interface{}{"b": 2}, 0))

	assert.Equal(t, map[string]int{"a": 1}, callsFor(rec))
}

func TestCacheOnEvict_TTLExpiry(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{
		MaxRuntimeItems: 10,
		DefaultTTL:      time.Millisecond,
		CleanupInterval: 5 * time.Millisecond,
	})
	require.NoError(t, c.Set("a", 1, 0))

	require.Eventually(t, func() bool { return callsFor(rec)["a"] == 1 }, 2*time.Second, 5*time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	assert.Equal(t, map[string]int{"a": 1}, callsFor(rec), "expired key must be reported exactly once")
}

func TestCacheOnEvict_Delete(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{DefaultTTL: time.Hour})
	require.NoError(t, c.Set("a", 1, 0))

	assert.False(t, c.Delete("missing"))
	assert.True(t, c.Delete("a"))
	assert.Equal(t, map[string]int{"a": 1}, callsFor(rec), "missing keys must not fire the callback")
}

func TestCacheOnEvict_DeleteMany(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{DefaultTTL: time.Hour})
	require.NoError(t, c.SetMany(map[string]interface{}{"a": 1, "b": 2, "c": 3}, 0))

	assert.Equal(t, 2, c.DeleteMany([]string{"a", "b", "missing"}))
	assert.Equal(t, map[string]int{"a": 1, "b": 1}, callsFor(rec))
}

func TestCacheOnEvict_Clear(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{DefaultTTL: time.Hour})
	require.NoError(t, c.SetMany(map[string]interface{}{"a": 1, "b": 2}, 0))

	c.Clear()
	assert.Equal(t, map[string]int{"a": 1, "b": 1}, callsFor(rec))
	assert.Equal(t, 0, c.Size())
}

func TestCacheOnEvict_Overwrite(t *testing.T) {
	c, rec := newEvictCache(t, CacheConfig{DefaultTTL: time.Hour})
	require.NoError(t, c.Set("a", 1, 0))
	require.NoError(t, c.Set("a", 2, 0))
	require.NoError(t, c.SetMany(map[string]interface{}{"a": 3}, 0))

	assert.Equal(t, map[string]int{"a": 2}, callsFor(rec), "each replaced value is reported once")
	v, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, 3, v)
}

func TestCacheOnEvict_ReceivesEvictedValue(t *testing.T) {
	var got []interface{}
	c := NewCache(CacheConfig{DefaultTTL: time.Hour, OnEvict: func(_ string, v interface{}) { got = append(got, v) }})
	t.Cleanup(c.Close)
	require.NoError(t, c.Set("a", "old", 0))
	c.Delete("a")

	assert.Equal(t, []interface{}{"old"}, got)
}
