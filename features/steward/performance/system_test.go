package performance_test

import (
	"context"
	"testing"

	"github.com/cfgis/cfgms/features/steward/performance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemCollector_CollectMetrics(t *testing.T) {
	collector := performance.NewSystemCollector()

	ctx := context.Background()
	metrics, err := collector.CollectMetrics(ctx)
	require.NoError(t, err)
	require.NotNil(t, metrics)

	// Verify CPU metrics
	assert.GreaterOrEqual(t, metrics.CPUPercent, 0.0)
	assert.LessOrEqual(t, metrics.CPUPercent, 100.0)

	// Verify memory metrics
	assert.Greater(t, metrics.MemoryTotalBytes, int64(0))
	assert.GreaterOrEqual(t, metrics.MemoryUsedBytes, int64(0))
	assert.GreaterOrEqual(t, metrics.MemoryPercent, 0.0)
	assert.LessOrEqual(t, metrics.MemoryPercent, 100.0)

	// Verify timestamps
	assert.False(t, metrics.CollectedAt.IsZero())
}

func TestSystemCollector_GetPlatform(t *testing.T) {
	collector := performance.NewSystemCollector()

	platform := collector.GetPlatform()
	assert.NotEmpty(t, platform)
	assert.Contains(t, []string{"linux", "windows", "darwin"}, platform)
}

func TestSystemCollector_MultipleCollections(t *testing.T) {
	collector := performance.NewSystemCollector()

	ctx := context.Background()

	// First collection
	metrics1, err := collector.CollectMetrics(ctx)
	require.NoError(t, err)
	require.NotNil(t, metrics1)

	// Second collection (should have disk/network rates now)
	metrics2, err := collector.CollectMetrics(ctx)
	require.NoError(t, err)
	require.NotNil(t, metrics2)

	// Disk and network rates may be 0 or positive (depends on activity)
	assert.GreaterOrEqual(t, metrics2.DiskReadBytesPerSec, int64(0))
	assert.GreaterOrEqual(t, metrics2.DiskWriteBytesPerSec, int64(0))
	assert.GreaterOrEqual(t, metrics2.NetRecvBytesPerSec, int64(0))
	assert.GreaterOrEqual(t, metrics2.NetSentBytesPerSec, int64(0))
}
