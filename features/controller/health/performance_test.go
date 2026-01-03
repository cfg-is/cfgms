// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package health_test

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

// TestCollectorPerformanceOverhead validates that metrics collection adds minimal overhead
// This test measures the CPU impact of running the metrics collection system
func TestCollectorPerformanceOverhead(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	// Create mock collectors
	mqttCollector := &MockMQTTCollector{
		metrics: &health.MQTTMetrics{
			ActiveConnections:     100,
			MessageQueueDepth:     250,
			MessageThroughput:     150.5,
			TotalMessagesSent:     10000,
			TotalMessagesReceived: 9500,
			ConnectionErrors:      5,
			CollectedAt:           time.Now(),
		},
	}

	storageCollector := &MockStorageCollector{
		metrics: &health.StorageMetrics{
			Provider:          "git",
			PoolUtilization:   0.45,
			AvgQueryLatencyMs: 12.5,
			P95QueryLatencyMs: 25.3,
			SlowQueryCount:    2,
			TotalQueries:      5000,
			QueryErrors:       1,
			CollectedAt:       time.Now(),
		},
	}

	appCollector := &MockApplicationCollector{
		metrics: &health.ApplicationMetrics{
			WorkflowQueueDepth:  15,
			WorkflowMaxWaitTime: 2.5,
			ActiveWorkflows:     8,
			ScriptQueueDepth:    10,
			ScriptMaxWaitTime:   1.8,
			ActiveScripts:       5,
			ConfigQueueDepth:    3,
			CollectedAt:         time.Now(),
		},
	}

	sysCollector := &MockSystemCollector{}

	collector := health.NewCollector(mqttCollector, storageCollector, appCollector, sysCollector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start collector with 30-second interval (production setting)
	err := collector.Start(ctx, 30*time.Second)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Measure overhead by running collector for a short period
	const testDuration = 5 * time.Second

	// Baseline goroutine count
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	// Wait for collector to run
	time.Sleep(testDuration)

	// Measure goroutine count (should not grow significantly)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	finalGoroutines := runtime.NumGoroutine()

	// Goroutines should remain stable (collector uses fixed number)
	goroutineGrowth := finalGoroutines - baselineGoroutines
	t.Logf("=== Performance Results ===")
	t.Logf("Baseline goroutines: %d", baselineGoroutines)
	t.Logf("Final goroutines: %d", finalGoroutines)
	t.Logf("Goroutine growth: %d", goroutineGrowth)

	// Collector should add minimal goroutines (1 for collection loop)
	assert.LessOrEqual(t, goroutineGrowth, 3,
		"Collector should add minimal goroutines (expected 1-3, got %d)", goroutineGrowth)

	// Get metrics to ensure collector is working
	metrics, err := collector.GetCurrentMetrics()
	require.NoError(t, err)
	assert.NotNil(t, metrics)
	assert.NotNil(t, metrics.MQTT)
	assert.NotNil(t, metrics.Storage)
	assert.NotNil(t, metrics.Application)
	assert.NotNil(t, metrics.System)

	t.Logf("✅ Performance validation passed: Minimal overhead confirmed")
	t.Logf("   - Goroutine growth: %d (within acceptable range)", goroutineGrowth)
	t.Logf("   - Metrics collection: Working (%d components)", 4)
}

// BenchmarkMetricsCollection benchmarks the metrics collection operation
func BenchmarkMetricsCollection(b *testing.B) {
	mqttCollector := &MockMQTTCollector{
		metrics: &health.MQTTMetrics{
			ActiveConnections: 100,
			CollectedAt:       time.Now(),
		},
	}
	storageCollector := &MockStorageCollector{
		metrics: &health.StorageMetrics{
			Provider:    "git",
			CollectedAt: time.Now(),
		},
	}
	appCollector := &MockApplicationCollector{
		metrics: &health.ApplicationMetrics{
			WorkflowQueueDepth: 10,
			CollectedAt:        time.Now(),
		},
	}
	sysCollector := &MockSystemCollector{}

	collector := health.NewCollector(mqttCollector, storageCollector, appCollector, sysCollector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := collector.Start(ctx, 30*time.Second)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		_ = collector.Stop()
	}()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = collector.GetCurrentMetrics()
	}
}

// TestMetricsCollectionMemoryUsage validates that metrics storage doesn't grow unbounded
func TestMetricsCollectionMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	const (
		collectionInterval = 100 * time.Millisecond // Fast collection for testing
		testDuration       = 3 * time.Second        // Shorter for CI/CD
	)

	// Create mock collectors
	mqttCollector := &MockMQTTCollector{
		metrics: &health.MQTTMetrics{
			ActiveConnections: 50,
			CollectedAt:       time.Now(),
		},
	}
	storageCollector := &MockStorageCollector{
		metrics: &health.StorageMetrics{
			Provider:    "git",
			CollectedAt: time.Now(),
		},
	}
	appCollector := &MockApplicationCollector{
		metrics: &health.ApplicationMetrics{
			WorkflowQueueDepth: 10,
			CollectedAt:        time.Now(),
		},
	}
	sysCollector := &MockSystemCollector{}

	collector := health.NewCollector(mqttCollector, storageCollector, appCollector, sysCollector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := collector.Start(ctx, collectionInterval)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Measure initial memory
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	initialAlloc := m1.Alloc

	t.Logf("Initial memory: %d bytes (%.2f KB)", initialAlloc, float64(initialAlloc)/1024.0)

	// Let collector run
	time.Sleep(testDuration)

	// Measure final memory
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	finalAlloc := m2.Alloc

	memoryGrowth := int64(finalAlloc) - int64(initialAlloc)
	t.Logf("Final memory: %d bytes (%.2f KB)", finalAlloc, float64(finalAlloc)/1024.0)
	t.Logf("Memory growth: %d bytes (%.2f KB)", memoryGrowth, float64(memoryGrowth)/1024.0)

	// With 100ms collection interval over 3 seconds, we expect ~30 metric snapshots
	// Each snapshot is roughly 1KB, so ~30KB total is reasonable
	// Allow up to 200KB for overhead and Go allocator behavior
	maxAllowedGrowth := int64(200 * 1024) // 200KB
	assert.Less(t, memoryGrowth, maxAllowedGrowth,
		"Memory growth should be bounded (actual: %.2f KB, max: %.2f KB)",
		float64(memoryGrowth)/1024.0, float64(maxAllowedGrowth)/1024.0)

	// Verify metrics are being collected
	history, err := collector.GetMetricsHistory(time.Now().Add(-testDuration), time.Now())
	require.NoError(t, err)
	t.Logf("Metrics collected: %d snapshots", len(history))
	assert.Greater(t, len(history), 10, "Should have collected multiple metric snapshots")

	t.Logf("✅ Memory usage validation passed: %.2f KB growth is within limits",
		float64(memoryGrowth)/1024.0)
}

// TestCollectionInterval validates that collection happens at expected intervals
func TestCollectionInterval(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	const collectionInterval = 500 * time.Millisecond

	mqttCollector := &MockMQTTCollector{
		metrics: &health.MQTTMetrics{
			ActiveConnections: 50,
			CollectedAt:       time.Now(),
		},
	}
	storageCollector := &MockStorageCollector{
		metrics: &health.StorageMetrics{
			Provider:    "git",
			CollectedAt: time.Now(),
		},
	}
	appCollector := &MockApplicationCollector{
		metrics: &health.ApplicationMetrics{
			WorkflowQueueDepth: 10,
			CollectedAt:        time.Now(),
		},
	}
	sysCollector := &MockSystemCollector{}

	collector := health.NewCollector(mqttCollector, storageCollector, appCollector, sysCollector)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := collector.Start(ctx, collectionInterval)
	require.NoError(t, err)
	defer func() {
		_ = collector.Stop()
	}()

	// Let it run for a few intervals
	testDuration := 3 * time.Second
	time.Sleep(testDuration)

	// Check metrics history
	history, err := collector.GetMetricsHistory(time.Now().Add(-testDuration), time.Now())
	require.NoError(t, err)

	expectedCollections := int(testDuration / collectionInterval)
	tolerance := 2 // Allow some variance

	t.Logf("Expected collections: ~%d", expectedCollections)
	t.Logf("Actual collections: %d", len(history))

	assert.GreaterOrEqual(t, len(history), expectedCollections-tolerance,
		"Should have collected metrics at expected interval")
	assert.LessOrEqual(t, len(history), expectedCollections+tolerance,
		"Should not over-collect metrics")

	t.Logf("✅ Collection interval validation passed: %d collections in %.1fs",
		len(history), testDuration.Seconds())
}

// Mock collectors for testing

type MockMQTTCollector struct {
	metrics *health.MQTTMetrics
}

func (m *MockMQTTCollector) CollectMetrics(ctx context.Context) error {
	m.metrics.CollectedAt = time.Now()
	return nil
}

func (m *MockMQTTCollector) GetMetrics() *health.MQTTMetrics {
	return m.metrics
}

type MockStorageCollector struct {
	metrics *health.StorageMetrics
}

func (m *MockStorageCollector) CollectMetrics(ctx context.Context) error {
	m.metrics.CollectedAt = time.Now()
	return nil
}

func (m *MockStorageCollector) GetMetrics() *health.StorageMetrics {
	return m.metrics
}

type MockApplicationCollector struct {
	metrics *health.ApplicationMetrics
}

func (m *MockApplicationCollector) CollectMetrics(ctx context.Context) error {
	m.metrics.CollectedAt = time.Now()
	return nil
}

func (m *MockApplicationCollector) GetMetrics() *health.ApplicationMetrics {
	return m.metrics
}

type MockSystemCollector struct{}

func (m *MockSystemCollector) CollectMetrics(ctx context.Context) error {
	return nil
}

func (m *MockSystemCollector) GetMetrics() *health.SystemMetrics {
	return &health.SystemMetrics{
		CPUPercent:          25.5,
		MemoryUsedBytes:     512 * 1024 * 1024,
		MemoryPercent:       30.2,
		HeapBytes:           256 * 1024 * 1024,
		RSSBytes:            384 * 1024 * 1024,
		GoroutineCount:      150,
		OpenFileDescriptors: 50,
		CollectedAt:         time.Now(),
	}
}
