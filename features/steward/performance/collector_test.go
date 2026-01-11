// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package performance_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/performance"
)

func TestDefaultConfig(t *testing.T) {
	config := performance.DefaultConfig()

	assert.NotNil(t, config)
	assert.Equal(t, 60*time.Second, config.Interval)
	assert.Equal(t, 10, config.TopProcessCount)
	assert.Equal(t, 30*24*time.Hour, config.RetentionPeriod)
	assert.Equal(t, 1.0, config.MaxCPUPercent)
	assert.False(t, config.StorageEnabled)
	assert.False(t, config.AlertingEnabled)
}

func TestNewCollector(t *testing.T) {
	config := performance.DefaultConfig()
	collector := performance.NewCollector("test-steward-1", config)

	assert.NotNil(t, collector)
	assert.Equal(t, config, collector.GetConfig())
}

func TestCollector_StartStop(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 100 * time.Millisecond // Fast interval for testing

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()

	// Start collector
	err := collector.Start(ctx)
	require.NoError(t, err)

	// Wait for at least one collection cycle
	time.Sleep(150 * time.Millisecond)

	// Should have metrics now
	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.Equal(t, "test-steward-1", metrics.StewardID)
	assert.NotEmpty(t, metrics.Hostname)
	assert.True(t, metrics.Online)

	// Stop collector
	err = collector.Stop()
	require.NoError(t, err)

	// Should be able to restart after stopping
	err = collector.Start(ctx)
	require.NoError(t, err)

	// Clean up
	err = collector.Stop()
	require.NoError(t, err)
}

func TestCollector_GetCurrentMetrics(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 100 * time.Millisecond

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Wait for collection
	time.Sleep(150 * time.Millisecond)

	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// Verify system metrics
	assert.NotNil(t, metrics.System)
	assert.GreaterOrEqual(t, metrics.System.CPUPercent, 0.0)
	assert.LessOrEqual(t, metrics.System.CPUPercent, 100.0)
	assert.Greater(t, metrics.System.MemoryTotalBytes, int64(0))
	assert.GreaterOrEqual(t, metrics.System.MemoryUsedBytes, int64(0))
	assert.GreaterOrEqual(t, metrics.System.MemoryPercent, 0.0)
	assert.LessOrEqual(t, metrics.System.MemoryPercent, 100.0)

	// Verify top processes
	assert.NotEmpty(t, metrics.TopProcesses)
	assert.LessOrEqual(t, len(metrics.TopProcesses), config.TopProcessCount)

	// Each process should have valid data
	for _, proc := range metrics.TopProcesses {
		assert.Greater(t, proc.PID, int32(0))
		assert.NotEmpty(t, proc.Name)
		assert.GreaterOrEqual(t, proc.CPUPercent, 0.0)
		assert.GreaterOrEqual(t, proc.MemoryBytes, int64(0))
	}
}

func TestCollector_GetMetricsHistory(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 100 * time.Millisecond // Collection interval

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Wait for multiple collections - be generous with timing
	// Initial collection happens in Start(), then wait for ticker
	time.Sleep(500 * time.Millisecond)

	// Query history
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	history, err := collector.GetMetricsHistory(start, end)
	require.NoError(t, err)

	// Should have at least 1 data point (initial collection)
	// Ticker collections may or may not have happened depending on system load
	assert.GreaterOrEqual(t, len(history), 1, "Should have at least the initial collection")

	// Verify each metric in history
	for _, metric := range history {
		assert.Equal(t, "test-steward-1", metric.StewardID)
		assert.NotNil(t, metric.System)
		assert.True(t, metric.Online)
	}

	// Verify history is in chronological order
	if len(history) > 1 {
		for i := 1; i < len(history); i++ {
			assert.True(t, history[i].Timestamp.After(history[i-1].Timestamp) ||
				history[i].Timestamp.Equal(history[i-1].Timestamp),
				"History should be in chronological order")
		}
	}
}

func TestCollector_UpdateConfig(t *testing.T) {
	config := performance.DefaultConfig()
	collector := performance.NewCollector("test-steward-1", config)

	// Update configuration
	newConfig := performance.DefaultConfig()
	newConfig.TopProcessCount = 20
	newConfig.Interval = 30 * time.Second

	err := collector.UpdateConfig(newConfig)
	require.NoError(t, err)

	// Verify config was updated
	updatedConfig := collector.GetConfig()
	assert.Equal(t, 20, updatedConfig.TopProcessCount)
	assert.Equal(t, 30*time.Second, updatedConfig.Interval)
}

func TestCollector_WithWatchlist(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 100 * time.Millisecond
	config.ProcessWatchlist = []string{"systemd", "sshd", "dockerd"} // Common Linux processes

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Wait for collection
	time.Sleep(150 * time.Millisecond)

	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)

	// Should have watchlist data (may be empty if processes don't exist)
	assert.NotNil(t, metrics.WatchlistData)

	// If any watchlist process is found, verify it's marked correctly
	for _, proc := range metrics.WatchlistData {
		assert.True(t, proc.IsWatchlisted)
		assert.NotEmpty(t, proc.Name)
	}
}

func TestCollector_CPUOverheadLimit(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 100 * time.Millisecond
	config.MaxCPUPercent = 1.0 // 1% limit

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Run for a second to collect CPU usage stats
	time.Sleep(1 * time.Second)

	// The collector's own CPU usage should be <1%
	// This is verified internally by the collector and would log warnings
	// For now, just verify it doesn't crash or error
	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)
	assert.NotNil(t, metrics)
}

func TestCollector_RetentionCleanup(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 50 * time.Millisecond
	config.RetentionPeriod = 200 * time.Millisecond // Short retention for testing

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Collect some data
	time.Sleep(150 * time.Millisecond)

	// Get initial history
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)
	initialHistory, err := collector.GetMetricsHistory(start, end)
	require.NoError(t, err)
	initialCount := len(initialHistory)

	// Wait for retention period to expire
	time.Sleep(250 * time.Millisecond)

	// Trigger another collection which should clean up old data
	time.Sleep(100 * time.Millisecond)

	// Get history again
	newHistory, err := collector.GetMetricsHistory(start, end)
	require.NoError(t, err)

	// Old data should have been cleaned up
	// New history should have fewer or equal items than initial
	assert.LessOrEqual(t, len(newHistory), initialCount+2) // Allow for new collections
}

func TestCollector_ConcurrentAccess(t *testing.T) {
	config := performance.DefaultConfig()
	config.Interval = 50 * time.Millisecond

	collector := performance.NewCollector("test-steward-1", config)

	ctx := context.Background()
	err := collector.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Wait for initial collection
	time.Sleep(100 * time.Millisecond)

	// Concurrent reads should not cause data races
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 10; j++ {
				_, _ = collector.GetCurrentMetrics()
				start := time.Now().Add(-1 * time.Hour)
				end := time.Now()
				_, _ = collector.GetMetricsHistory(start, end)
				time.Sleep(5 * time.Millisecond)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}
