// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package performance_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/performance"
)

func TestMemoryStorageBackend(t *testing.T) {
	storage := performance.NewMemoryStorageBackend()

	ctx := context.Background()

	// Connect
	err := storage.Connect(ctx)
	require.NoError(t, err)
	defer func() {
		_ = storage.Close()
	}()

	// Verify storage type
	assert.Equal(t, "memory", storage.GetStorageType())

	// Write metrics
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Hostname:  "test-host",
		Timestamp: time.Now(),
		System: &performance.SystemMetrics{
			CPUPercent:    50.0,
			MemoryPercent: 60.0,
		},
		Online: true,
	}

	err = storage.WriteMetrics(ctx, metrics)
	require.NoError(t, err)

	// Query metrics
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	results, err := storage.QueryMetrics(ctx, "test-steward-1", start, end)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, "test-steward-1", results[0].StewardID)
}

func TestMemoryStorageBackend_MultipleMetrics(t *testing.T) {
	storage := performance.NewMemoryStorageBackend()

	ctx := context.Background()
	err := storage.Connect(ctx)
	require.NoError(t, err)
	defer func() {
		_ = storage.Close()
	}()

	// Write multiple metrics
	for i := 0; i < 5; i++ {
		metrics := &performance.PerformanceMetrics{
			StewardID: "test-steward-1",
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			System: &performance.SystemMetrics{
				CPUPercent: float64(i * 10),
			},
			Online: true,
		}

		err = storage.WriteMetrics(ctx, metrics)
		require.NoError(t, err)
	}

	// Query all metrics
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	results, err := storage.QueryMetrics(ctx, "test-steward-1", start, end)
	require.NoError(t, err)
	assert.Len(t, results, 5)
}

func TestMemoryStorageBackend_DeleteOldMetrics(t *testing.T) {
	storage := performance.NewMemoryStorageBackend()

	ctx := context.Background()
	err := storage.Connect(ctx)
	require.NoError(t, err)
	defer func() {
		_ = storage.Close()
	}()

	// Write metrics with different timestamps
	oldMetric := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now().Add(-2 * time.Hour),
		Online:    true,
	}
	err = storage.WriteMetrics(ctx, oldMetric)
	require.NoError(t, err)

	newMetric := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		Online:    true,
	}
	err = storage.WriteMetrics(ctx, newMetric)
	require.NoError(t, err)

	// Delete old metrics (older than 1 hour)
	err = storage.DeleteOldMetrics(ctx, 1*time.Hour)
	require.NoError(t, err)

	// Query should only return new metric
	start := time.Now().Add(-3 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	results, err := storage.QueryMetrics(ctx, "test-steward-1", start, end)
	require.NoError(t, err)
	assert.Len(t, results, 1)
	assert.True(t, results[0].Timestamp.After(time.Now().Add(-1*time.Hour)))
}

func TestMemoryStorageBackend_MultipleStewards(t *testing.T) {
	storage := performance.NewMemoryStorageBackend()

	ctx := context.Background()
	err := storage.Connect(ctx)
	require.NoError(t, err)
	defer func() {
		_ = storage.Close()
	}()

	// Write metrics for different stewards
	for i := 1; i <= 3; i++ {
		metrics := &performance.PerformanceMetrics{
			StewardID: fmt.Sprintf("steward-%d", i),
			Timestamp: time.Now(),
			Online:    true,
		}

		err = storage.WriteMetrics(ctx, metrics)
		require.NoError(t, err)
	}

	// Query each steward
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	for i := 1; i <= 3; i++ {
		stewardID := fmt.Sprintf("steward-%d", i)
		results, err := storage.QueryMetrics(ctx, stewardID, start, end)
		require.NoError(t, err)
		assert.Len(t, results, 1)
		assert.Equal(t, stewardID, results[0].StewardID)
	}
}

func TestNoOpStorageBackend(t *testing.T) {
	storage := performance.NewNoOpStorageBackend()

	ctx := context.Background()

	// Connect
	err := storage.Connect(ctx)
	require.NoError(t, err)
	defer func() {
		_ = storage.Close()
	}()

	// Verify storage type
	assert.Equal(t, "noop", storage.GetStorageType())

	// Write metrics (should succeed but do nothing)
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		Online:    true,
	}

	err = storage.WriteMetrics(ctx, metrics)
	require.NoError(t, err)

	// Query should return empty results
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	results, err := storage.QueryMetrics(ctx, "test-steward-1", start, end)
	require.NoError(t, err)
	assert.Empty(t, results)

	// Delete should succeed but do nothing
	err = storage.DeleteOldMetrics(ctx, 1*time.Hour)
	require.NoError(t, err)
}
