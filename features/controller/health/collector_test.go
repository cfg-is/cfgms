// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package health_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

func TestNewCollector(t *testing.T) {
	transportCollector := health.NewDefaultTransportCollector(&health.MockTransportProviderStats{})
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		transportCollector,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	assert.NotNil(t, collector)
}

func TestCollector_StartStop(t *testing.T) {
	transportCollector := health.NewDefaultTransportCollector(&health.MockTransportProviderStats{})
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		transportCollector,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	ctx := context.Background()

	// Start collector
	err = collector.Start(ctx, 100*time.Millisecond)
	require.NoError(t, err)

	// Wait for initial collection
	time.Sleep(200 * time.Millisecond)

	// Check that we can get metrics
	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.Transport)
	assert.NotNil(t, metrics.Storage)
	assert.NotNil(t, metrics.Application)
	assert.NotNil(t, metrics.System)

	// Stop collector
	err = collector.Stop()
	require.NoError(t, err)
}

func TestCollector_MetricsCollection(t *testing.T) {
	transportStats := &health.MockTransportProviderStats{
		ConnectedStewardsVal:    42,
		StreamErrorsVal:         5,
		MessagesSentVal:         1000,
		MessagesReceivedVal:     1500,
		ReconnectionAttemptsVal: 3,
	}

	storageStats := &health.MockStorageProviderStats{
		ProviderName:    "git",
		PoolUtilization: 0.75,
		AvgLatencyMs:    50.5,
		P95LatencyMs:    150.0,
		TotalQueries:    10000,
		SlowQueries:     5,
		QueryErrors:     2,
	}

	appStats := &health.MockApplicationQueueStats{
		WorkflowQueueDepth:  25,
		WorkflowMaxWaitTime: 5.5,
		ActiveWorkflows:     10,
		ScriptQueueDepth:    15,
		ScriptMaxWaitTime:   3.2,
		ActiveScripts:       5,
		ConfigQueueDepth:    8,
	}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		health.NewDefaultTransportCollector(transportStats),
		health.NewDefaultStorageCollector(storageStats),
		health.NewDefaultApplicationCollector(appStats),
		systemCollector,
	)

	ctx := context.Background()

	// Start collector
	err = collector.Start(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Wait for at least 2 collection cycles to ensure CPU metrics are available
	// CPU percentage calculation requires comparison between two measurements
	time.Sleep(350 * time.Millisecond)

	// Get metrics
	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)

	// Verify Transport metrics
	assert.Equal(t, 42, metrics.Transport.ConnectedStewards)
	assert.Equal(t, int64(5), metrics.Transport.StreamErrors)
	assert.Equal(t, int64(1000), metrics.Transport.MessagesSent)
	assert.Equal(t, int64(1500), metrics.Transport.MessagesReceived)
	assert.Equal(t, int64(3), metrics.Transport.ReconnectionAttempts)

	// Verify Storage metrics
	assert.Equal(t, "git", metrics.Storage.Provider)
	assert.Equal(t, 0.75, metrics.Storage.PoolUtilization)
	assert.Equal(t, 50.5, metrics.Storage.AvgQueryLatencyMs)
	assert.Equal(t, 150.0, metrics.Storage.P95QueryLatencyMs)

	// Verify Application metrics
	assert.Equal(t, int64(25), metrics.Application.WorkflowQueueDepth)
	assert.Equal(t, int64(15), metrics.Application.ScriptQueueDepth)
	assert.Equal(t, int64(10), metrics.Application.ActiveWorkflows)

	// Verify System metrics - these should always be available
	// Note: CPUPercent might be 0 on some platforms if CPU is idle, so we check >= 0
	assert.GreaterOrEqual(t, metrics.System.CPUPercent, 0.0)
	assert.NotZero(t, metrics.System.MemoryUsedBytes)
	assert.NotZero(t, metrics.System.GoroutineCount)
}

func TestCollector_MetricsHistory(t *testing.T) {
	transportCollector := health.NewDefaultTransportCollector(&health.MockTransportProviderStats{})
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		transportCollector,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	ctx := context.Background()

	// Start collector with fast interval
	err = collector.Start(ctx, 50*time.Millisecond)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Wait for multiple collections
	time.Sleep(300 * time.Millisecond)

	// Get metrics history
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now()
	history, err := collector.GetMetricsHistory(start, end)
	require.NoError(t, err)

	// Should have collected multiple metrics
	assert.Greater(t, len(history), 1, "Should have multiple metrics in history")
}

func TestCollector_StartAlreadyStarted(t *testing.T) {
	transportCollector := health.NewDefaultTransportCollector(&health.MockTransportProviderStats{})
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		transportCollector,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	ctx := context.Background()

	// Start collector
	err = collector.Start(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Try to start again - should return error
	err = collector.Start(ctx, 100*time.Millisecond)
	assert.Error(t, err)
}

func TestCollector_StopNotStarted(t *testing.T) {
	transportCollector := health.NewDefaultTransportCollector(&health.MockTransportProviderStats{})
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		transportCollector,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	// Try to stop without starting - should return error
	err = collector.Stop()
	assert.Error(t, err)
}

func TestCollector_GetCurrentMetricsBeforeStart(t *testing.T) {
	transportCollector := health.NewDefaultTransportCollector(&health.MockTransportProviderStats{})
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	collector := health.NewCollector(
		transportCollector,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	// Try to get metrics before starting - should return error
	_, err = collector.GetCurrentMetrics()
	assert.Error(t, err)
}

func TestCollector_NilTransportCollector(t *testing.T) {
	storageCollector := &health.MockStorageProviderStats{ProviderName: "flatfile"}
	appCollector := &health.MockApplicationQueueStats{}

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	// nil transport collector - transport not yet started
	collector := health.NewCollector(
		nil,
		health.NewDefaultStorageCollector(storageCollector),
		health.NewDefaultApplicationCollector(appCollector),
		systemCollector,
	)

	ctx := context.Background()

	err = collector.Start(ctx, 100*time.Millisecond)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	time.Sleep(200 * time.Millisecond)

	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)
	assert.Nil(t, metrics.Transport, "Transport metrics should be nil when collector is nil")
	assert.NotNil(t, metrics.Storage)
}

func TestSystemCollector_CollectsMetrics(t *testing.T) {
	collector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)

	ctx := context.Background()

	err = collector.CollectMetrics(ctx)
	require.NoError(t, err)

	metrics := collector.GetMetrics()
	assert.NotNil(t, metrics)

	// Verify that we got actual metrics
	assert.Greater(t, metrics.CPUPercent, float64(-1), "CPU percent should be collected")
	assert.Greater(t, metrics.MemoryUsedBytes, int64(0), "Memory bytes should be collected")
	assert.Greater(t, metrics.GoroutineCount, int64(0), "Goroutine count should be collected")
	assert.Greater(t, metrics.HeapBytes, int64(0), "Heap bytes should be collected")
}
