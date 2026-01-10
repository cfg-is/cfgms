// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transform

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDefaultMemoryTransformCache(t *testing.T) {
	cache := DefaultMemoryTransformCache()
	assert.NotNil(t, cache)
}

func TestMemoryTransformCache_Basic(t *testing.T) {
	cache := NewMemoryTransformCache(1000, time.Minute)

	key := "test_key"
	result := TransformResult{
		Data:     map[string]interface{}{"output": "test_value"},
		Success:  true,
		Duration: time.Millisecond * 50,
	}

	// Test setting and getting
	cache.Set(key, result, time.Hour)

	cachedResult, found := cache.Get(key)
	assert.True(t, found)
	assert.Equal(t, result.Data, cachedResult.Data)
	assert.Equal(t, result.Success, cachedResult.Success)
}

func TestMemoryTransformCache_NotFound(t *testing.T) {
	cache := NewMemoryTransformCache(1000, time.Minute)

	// Test getting non-existent key
	_, found := cache.Get("non_existent")
	assert.False(t, found)
}

func TestMemoryTransformCache_Clear(t *testing.T) {
	cache := NewMemoryTransformCache(1000, time.Minute)

	result := TransformResult{
		Data:    map[string]interface{}{"output": "test_value"},
		Success: true,
	}

	// Add item
	cache.Set("key1", result, time.Hour)

	// Verify it exists
	_, found := cache.Get("key1")
	assert.True(t, found)

	// Clear cache
	cache.Clear()

	// Verify it's gone
	_, found = cache.Get("key1")
	assert.False(t, found)
}

func TestNoOpTransformCache(t *testing.T) {
	cache := &NoOpTransformCache{}

	result := TransformResult{
		Data:    map[string]interface{}{"output": "test_value"},
		Success: true,
	}

	// Set should do nothing
	cache.Set("key", result, time.Hour)

	// Get should always return not found
	_, found := cache.Get("key")
	assert.False(t, found)

	// Delete should do nothing
	cache.Delete("key")

	// Clear should do nothing
	cache.Clear()

	// Stats should return zeros
	stats := cache.Stats()
	assert.Equal(t, int64(0), stats.Size)
	assert.Equal(t, int64(0), stats.HitCount)
	assert.Equal(t, int64(0), stats.MissCount)
}
