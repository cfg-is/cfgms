// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cache

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	pkgcache "github.com/cfgis/cfgms/pkg/cache"
)

func TestMemoryCache_Stats_ExpiredCount(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	report := &interfaces.Report{ID: "r1", Type: interfaces.ReportTypeCompliance}

	// Stats().Expired maps pkg/cache.CacheStats.ItemsExpired; starts at 0 before any cleanup.
	initialStats := c.Stats()
	assert.Equal(t, 0, initialStats.Expired, "expired count must start at 0")

	require.NoError(t, c.Set(ctx, "key1", report, 10*time.Millisecond))
	require.NoError(t, c.Set(ctx, "key2", report, 10*time.Millisecond))
	assert.Equal(t, 2, c.Stats().Entries)
}

func TestMemoryCache_Get_ReturnsMissAfterTTL(t *testing.T) {
	// Use no cleanup interval so the test only exercises TTL expiry on Get,
	// not the background cleanup goroutine.
	c := newMemoryCacheWithConfig(pkgcache.CacheConfig{
		Name:            "test-ttl",
		MaxRuntimeItems: 100,
		DefaultTTL:      10 * time.Millisecond,
		CleanupInterval: 0,
		EvictionPolicy:  pkgcache.EvictionLRU,
	})
	defer c.Close()

	ctx := context.Background()
	report := &interfaces.Report{ID: "r1", Type: interfaces.ReportTypeCompliance}

	require.NoError(t, c.Set(ctx, "key1", report, 10*time.Millisecond))

	// Confirm item is present before TTL elapses.
	got, err := c.Get(ctx, "key1")
	require.NoError(t, err)
	assert.Equal(t, report.ID, got.ID)

	// Sleep just past the 10ms TTL to let it deterministically expire.
	// pkg/cache.Cache.Get calls c.isExpired() synchronously on every read
	// (cache.go: "if c.isExpired(entry) { return nil, false }") — there is no
	// background-goroutine dependency here; the 20ms is only to advance wall-clock
	// past the 10ms TTL, not to race a cleanup ticker.
	time.Sleep(20 * time.Millisecond)

	_, err = c.Get(ctx, "key1")
	assert.ErrorIs(t, err, ErrCacheMiss, "Get must return ErrCacheMiss after TTL expires")
}

func TestMemoryCache_Stats_ActiveMatchesSize(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	report := &interfaces.Report{ID: "r2", Type: interfaces.ReportTypeDrift}

	require.NoError(t, c.Set(ctx, "k1", report, time.Hour))
	require.NoError(t, c.Set(ctx, "k2", report, time.Hour))

	stats := c.Stats()
	assert.Equal(t, 2, stats.Entries)
	assert.Equal(t, 2, stats.Active)
	assert.Equal(t, stats.Entries, stats.Active)
}

func TestMemoryCache_GetSetDelete(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	report := &interfaces.Report{ID: "test-report", Type: interfaces.ReportTypeCompliance}

	require.NoError(t, c.Set(ctx, "key", report, time.Hour))

	got, err := c.Get(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, report.ID, got.ID)

	require.NoError(t, c.Delete(ctx, "key"))

	_, err = c.Get(ctx, "key")
	assert.ErrorIs(t, err, ErrCacheMiss)
}

func TestMemoryCache_Clear(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	ctx := context.Background()
	r := &interfaces.Report{ID: "r"}
	require.NoError(t, c.Set(ctx, "a", r, time.Hour))
	require.NoError(t, c.Set(ctx, "b", r, time.Hour))

	assert.Equal(t, 2, c.Size())

	require.NoError(t, c.Clear(ctx))
	assert.Equal(t, 0, c.Size())
}

func TestMemoryCache_Miss(t *testing.T) {
	c := NewMemoryCache()
	defer c.Close()

	_, err := c.Get(context.Background(), "nonexistent")
	assert.ErrorIs(t, err, ErrCacheMiss)
}
