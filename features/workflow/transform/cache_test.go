// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transform

import (
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/cache"
	"github.com/stretchr/testify/assert"
)

// fakeClock is a controllable clock for deterministic TTL testing.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func TestDefaultMemoryTransformCache(t *testing.T) {
	c := DefaultMemoryTransformCache()
	assert.NotNil(t, c)
	c.Close()
}

func TestMemoryTransformCache_Basic(t *testing.T) {
	c := NewMemoryTransformCache(1000, time.Minute)
	defer c.Close()

	key := "test_key"
	result := TransformResult{
		Data:     map[string]interface{}{"output": "test_value"},
		Success:  true,
		Duration: time.Millisecond * 50,
	}

	c.Set(key, result, time.Hour)

	cachedResult, found := c.Get(key)
	assert.True(t, found)
	assert.Equal(t, result.Data, cachedResult.Data)
	assert.Equal(t, result.Success, cachedResult.Success)
}

func TestMemoryTransformCache_NotFound(t *testing.T) {
	c := NewMemoryTransformCache(1000, time.Minute)
	defer c.Close()

	_, found := c.Get("non_existent")
	assert.False(t, found)
}

func TestMemoryTransformCache_Delete(t *testing.T) {
	c := NewMemoryTransformCache(1000, time.Minute)
	defer c.Close()

	result := TransformResult{Data: map[string]interface{}{"x": 1}, Success: true}
	c.Set("key1", result, time.Hour)

	_, found := c.Get("key1")
	assert.True(t, found)

	c.Delete("key1")

	_, found = c.Get("key1")
	assert.False(t, found)
}

func TestMemoryTransformCache_Clear(t *testing.T) {
	c := NewMemoryTransformCache(1000, time.Minute)
	defer c.Close()

	result := TransformResult{
		Data:    map[string]interface{}{"output": "test_value"},
		Success: true,
	}

	c.Set("key1", result, time.Hour)

	_, found := c.Get("key1")
	assert.True(t, found)

	c.Clear()

	_, found = c.Get("key1")
	assert.False(t, found)
}

func TestMemoryTransformCache_Stats(t *testing.T) {
	c := NewMemoryTransformCache(1000, time.Minute)
	defer c.Close()

	result := TransformResult{Data: map[string]interface{}{"x": 1}, Success: true}
	c.Set("key1", result, time.Hour)

	c.Get("key1")    // hit
	c.Get("key1")    // hit
	c.Get("missing") // miss

	stats := c.Stats()
	assert.Equal(t, int64(2), stats.HitCount)
	assert.Equal(t, int64(1), stats.MissCount)
	assert.InDelta(t, 2.0/3.0, stats.HitRatio, 0.001)
	assert.Equal(t, int64(1), stats.Size)
	assert.Equal(t, int64(0), stats.MemoryUsage)
}

func TestMemoryTransformCache_TTLExpiry(t *testing.T) {
	clk := &fakeClock{now: time.Now()}
	c := newMemoryTransformStoreFromConfig(cache.CacheConfig{
		Name:            "test-ttl",
		MaxRuntimeItems: 100,
		DefaultTTL:      time.Minute,
		CleanupInterval: 0, // disable background cleanup goroutine
		EvictionPolicy:  cache.EvictionLRU,
		Clock:           clk,
	})
	defer c.Close()

	result := TransformResult{Data: map[string]interface{}{"x": 1}, Success: true}
	c.Set("key", result, 5*time.Second)

	_, found := c.Get("key")
	assert.True(t, found, "entry should be present before TTL expiry")

	clk.Advance(10 * time.Second)

	_, found = c.Get("key")
	assert.False(t, found, "entry should be absent after TTL advance")
}

func TestNoOpTransformCache(t *testing.T) {
	c := &noOpTransformStore{}

	result := TransformResult{
		Data:    map[string]interface{}{"output": "test_value"},
		Success: true,
	}

	c.Set("key", result, time.Hour)

	_, found := c.Get("key")
	assert.False(t, found)

	c.Delete("key")
	c.Clear()

	stats := c.Stats()
	assert.Equal(t, int64(0), stats.Size)
	assert.Equal(t, int64(0), stats.HitCount)
	assert.Equal(t, int64(0), stats.MissCount)
}
