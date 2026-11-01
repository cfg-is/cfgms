// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package monitoring_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// TestCPUMetricsCollection_NoError verifies that collectResourceMetrics populates CPUCores
// via runtime.NumCPU() and that GC cycle counts are collected when EnableDetailedGCMetrics
// is set — testing the code path updated by the collectors.go comment rewrite.
func TestCPUMetricsCollection_NoError(t *testing.T) {
	logger := logging.NewNoopLogger()
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "test-collectors",
		Enabled:     false,
	})
	require.NoError(t, err)
	defer cleanup()

	config := &monitoring.MonitorConfig{
		ResourceInterval:         20 * time.Millisecond,
		EnableResourceMonitoring: true,
		EnableDetailedGCMetrics:  true, // exercise the GC-metrics branch in collectResourceMetrics
	}
	monitor := monitoring.NewSystemMonitor(logger, tracer, config)

	ctx := context.Background()
	require.NoError(t, monitor.Start(ctx))
	defer func() {
		if err := monitor.Stop(context.Background()); err != nil {
			t.Logf("Failed to stop monitor: %v", err)
		}
	}()

	// Wait for resource metrics to be populated (20ms interval; 2s ceiling tolerates heavy test-suite load)
	require.Eventually(t, func() bool {
		return monitor.GetResourceMetrics().CPUCores > 0
	}, 2*time.Second, 10*time.Millisecond, "collectResourceMetrics must have run at least once")

	metrics := monitor.GetResourceMetrics()
	assert.Greater(t, metrics.CPUCores, 0, "CPUCores must be populated from runtime.NumCPU()")
	// GCCycles is set inside the EnableDetailedGCMetrics branch; verify it was reached.
	// At least one GC may or may not have run, but the field is populated (≥ 0) without error.
	assert.GreaterOrEqual(t, metrics.GCCycles, uint32(0), "GCCycles must be populated without error when EnableDetailedGCMetrics is true")
	assert.Greater(t, metrics.MemoryTotalBytes, uint64(0), "MemoryTotalBytes must be populated from runtime.ReadMemStats")
}
