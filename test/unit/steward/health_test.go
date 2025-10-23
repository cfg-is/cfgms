// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package steward_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward"
	"github.com/cfgis/cfgms/test/unit"
)

func TestHealthMonitorCreation(t *testing.T) {
	setup := unit.NewTestSetup(t)
	monitor := steward.NewHealthMonitor(setup.Logger)

	require.NotNil(t, monitor)
	metrics := monitor.GetMetrics()
	assert.Equal(t, steward.StatusHealthy, metrics.Status)
	assert.Equal(t, 0, metrics.TaskCount)
	assert.Equal(t, time.Duration(0), metrics.AverageTaskLatency)
	assert.Equal(t, 0, metrics.ConfigErrors)
	assert.Equal(t, 0, metrics.RecoveryAttempts)
}

func TestHealthMonitorMetrics(t *testing.T) {
	setup := unit.NewTestSetup(t)
	monitor := steward.NewHealthMonitor(setup.Logger)

	// Record some task latencies
	monitor.RecordTaskLatency(50 * time.Millisecond)
	monitor.RecordTaskLatency(150 * time.Millisecond)

	metrics := monitor.GetMetrics()
	assert.Equal(t, 2, metrics.TaskCount)
	assert.Equal(t, 100*time.Millisecond, metrics.AverageTaskLatency)

	// Record some config errors
	monitor.RecordConfigError()
	monitor.RecordConfigError()

	metrics = monitor.GetMetrics()
	assert.Equal(t, 2, metrics.ConfigErrors)
}

func TestHealthMonitorStatusChanges(t *testing.T) {
	setup := unit.NewTestSetup(t)
	monitor := steward.NewHealthMonitor(setup.Logger)

	// Test manual status changes
	monitor.SetStatus(steward.StatusDegraded)
	metrics := monitor.GetMetrics()
	assert.Equal(t, steward.StatusDegraded, metrics.Status)

	monitor.SetStatus(steward.StatusUnhealthy)
	metrics = monitor.GetMetrics()
	assert.Equal(t, steward.StatusUnhealthy, metrics.Status)

	monitor.SetStatus(steward.StatusHealthy)
	metrics = monitor.GetMetrics()
	assert.Equal(t, steward.StatusHealthy, metrics.Status)
}

func TestHealthMonitorLifecycle(t *testing.T) {
	setup := unit.NewTestSetup(t)
	monitor := steward.NewHealthMonitor(setup.Logger)

	// Start the monitor in a goroutine
	go monitor.Start(setup.Ctx)

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)

	// Verify it's running
	assert.True(t, monitor.IsRunning())

	// Stop the monitor
	monitor.Stop()

	// Verify it's stopped
	assert.False(t, monitor.IsRunning())
}

func TestHealthMonitorAutoStatusChange(t *testing.T) {
	setup := unit.NewTestSetup(t)
	monitor := steward.NewHealthMonitor(setup.Logger)

	// Set lower thresholds for testing
	monitor.SetConfigErrorThreshold(2)
	monitor.SetLatencyThreshold(100 * time.Millisecond)

	// Test config error threshold
	monitor.RecordConfigError()
	monitor.RecordConfigError() // Should trigger degraded status
	metrics := monitor.GetMetrics()
	assert.Equal(t, steward.StatusDegraded, metrics.Status)

	monitor.RecordConfigError()
	monitor.RecordConfigError() // Should trigger unhealthy status
	metrics = monitor.GetMetrics()
	assert.Equal(t, steward.StatusUnhealthy, metrics.Status)

	// Reset metrics and test latency threshold
	monitor.ResetMetrics()
	monitor.RecordTaskLatency(150 * time.Millisecond) // Should trigger degraded status
	metrics = monitor.GetMetrics()
	assert.Equal(t, steward.StatusDegraded, metrics.Status)
}

func TestHealthMonitorConcurrentAccess(t *testing.T) {
	setup := unit.NewTestSetup(t)
	monitor := steward.NewHealthMonitor(setup.Logger)

	// Start multiple goroutines to access the monitor concurrently
	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				monitor.RecordTaskLatency(time.Duration(j) * time.Millisecond)
				monitor.RecordConfigError()
				_ = monitor.GetMetrics()
			}
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify metrics were recorded correctly
	metrics := monitor.GetMetrics()
	assert.Equal(t, 1000, metrics.TaskCount)
	assert.Equal(t, 1000, metrics.ConfigErrors)
}
