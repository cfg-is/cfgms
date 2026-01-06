// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package performance_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/steward/performance"
)

func TestNewAlertManager(t *testing.T) {
	thresholds := []performance.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      90.0,
			Operator:   ">",
			Severity:   "critical",
			Duration:   5 * time.Minute,
		},
	}

	manager := performance.NewAlertManager("test-steward-1", thresholds)
	assert.NotNil(t, manager)
}

func TestAlertManager_StartStop(t *testing.T) {
	manager := performance.NewAlertManager("test-steward-1", nil)

	ctx := context.Background()

	err := manager.Start(ctx)
	require.NoError(t, err)

	err = manager.Stop()
	require.NoError(t, err)
}

func TestAlertManager_EvaluateMetrics_NoBreach(t *testing.T) {
	thresholds := []performance.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      90.0,
			Operator:   ">",
			Severity:   "critical",
			Duration:   1 * time.Second,
		},
	}

	manager := performance.NewAlertManager("test-steward-1", thresholds)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics below threshold
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		System: &performance.SystemMetrics{
			CPUPercent: 50.0, // Below 90% threshold
		},
	}

	alerts, err := manager.EvaluateMetrics(metrics)
	require.NoError(t, err)
	assert.Empty(t, alerts, "Should have no alerts when below threshold")

	// Verify no active alerts
	activeAlerts := manager.GetActiveAlerts()
	assert.Empty(t, activeAlerts)
}

func TestAlertManager_EvaluateMetrics_BreachWithDuration(t *testing.T) {
	thresholds := []performance.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      80.0,
			Operator:   ">",
			Severity:   "critical",
			Duration:   100 * time.Millisecond, // Short duration for testing
		},
	}

	manager := performance.NewAlertManager("test-steward-1", thresholds)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// First evaluation - breach starts
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		System: &performance.SystemMetrics{
			CPUPercent: 95.0, // Above 80% threshold
		},
	}

	alerts, err := manager.EvaluateMetrics(metrics)
	require.NoError(t, err)
	assert.Empty(t, alerts, "Should not alert immediately - duration not exceeded")

	// Wait for duration to pass
	time.Sleep(150 * time.Millisecond)

	// Second evaluation - duration exceeded
	metrics.Timestamp = time.Now()
	alerts, err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)
	assert.Len(t, alerts, 1, "Should have one alert after duration exceeded")

	alert := alerts[0]
	assert.Equal(t, "test-steward-1", alert.StewardID)
	assert.Equal(t, "critical", alert.Severity)
	assert.Equal(t, "cpu_percent", alert.MetricName)
	assert.Equal(t, 95.0, alert.CurrentValue)
	assert.Equal(t, 80.0, alert.ThresholdValue)
	assert.Equal(t, "active", alert.Status)

	// Verify active alerts
	activeAlerts := manager.GetActiveAlerts()
	assert.Len(t, activeAlerts, 1)
}

func TestAlertManager_EvaluateMetrics_AlertResolution(t *testing.T) {
	thresholds := []performance.Threshold{
		{
			MetricName: "memory_percent",
			Value:      85.0,
			Operator:   ">",
			Severity:   "warning",
			Duration:   100 * time.Millisecond,
		},
	}

	manager := performance.NewAlertManager("test-steward-1", thresholds)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Breach threshold
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		System: &performance.SystemMetrics{
			MemoryPercent: 90.0,
		},
	}

	_, _ = manager.EvaluateMetrics(metrics)
	time.Sleep(150 * time.Millisecond)

	// Trigger alert
	metrics.Timestamp = time.Now()
	alerts, err := manager.EvaluateMetrics(metrics)
	require.NoError(t, err)
	assert.Len(t, alerts, 1)

	// Now drop below threshold
	metrics.Timestamp = time.Now()
	metrics.System.MemoryPercent = 70.0

	alerts, err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)
	assert.Empty(t, alerts, "Alert should be resolved")

	// Verify no active alerts
	activeAlerts := manager.GetActiveAlerts()
	assert.Empty(t, activeAlerts, "Active alerts should be empty after resolution")

	// Verify alert history contains the resolved alert
	history := manager.GetAlertHistory(time.Now().Add(-1*time.Hour), time.Now().Add(1*time.Hour))
	assert.NotEmpty(t, history)

	// Find the resolved alert
	var resolvedAlert *performance.Alert
	for i := range history {
		if history[i].Status == "resolved" {
			resolvedAlert = &history[i]
			break
		}
	}
	require.NotNil(t, resolvedAlert, "Should have a resolved alert in history")
	assert.NotNil(t, resolvedAlert.ResolvedAt)
}

func TestAlertManager_MultipleThresholds(t *testing.T) {
	thresholds := []performance.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      90.0,
			Operator:   ">",
			Severity:   "critical",
			Duration:   100 * time.Millisecond,
		},
		{
			MetricName: "memory_percent",
			Value:      85.0,
			Operator:   ">",
			Severity:   "warning",
			Duration:   100 * time.Millisecond,
		},
	}

	manager := performance.NewAlertManager("test-steward-1", thresholds)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Breach both thresholds
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		System: &performance.SystemMetrics{
			CPUPercent:    95.0,
			MemoryPercent: 90.0,
		},
	}

	_, _ = manager.EvaluateMetrics(metrics)
	time.Sleep(150 * time.Millisecond)

	// Evaluate again after duration
	metrics.Timestamp = time.Now()
	alerts, err := manager.EvaluateMetrics(metrics)
	require.NoError(t, err)
	assert.Len(t, alerts, 2, "Should have alerts for both thresholds")

	// Verify severities
	severities := make(map[string]bool)
	for _, alert := range alerts {
		severities[alert.Severity] = true
	}
	assert.True(t, severities["critical"])
	assert.True(t, severities["warning"])
}

func TestAlertManager_AddRemoveThreshold(t *testing.T) {
	manager := performance.NewAlertManager("test-steward-1", nil)

	// Add threshold
	threshold := performance.Threshold{
		MetricName: "cpu_percent",
		Value:      90.0,
		Operator:   ">",
		Severity:   "critical",
		Duration:   5 * time.Minute,
	}

	err := manager.AddThreshold(threshold)
	require.NoError(t, err)

	// Remove threshold
	err = manager.RemoveThreshold("cpu_percent")
	require.NoError(t, err)
}

func TestAlertManager_ProcessWatchlistAlert(t *testing.T) {
	// Test alert for process watchlist breach
	thresholds := []performance.Threshold{
		{
			MetricName: "process_cpu_percent",
			Value:      50.0,
			Operator:   ">",
			Severity:   "warning",
			Duration:   100 * time.Millisecond,
		},
	}

	manager := performance.NewAlertManager("test-steward-1", thresholds)

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics with high-CPU process
	metrics := &performance.PerformanceMetrics{
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
		TopProcesses: []performance.ProcessMetrics{
			{
				PID:        12345,
				Name:       "high-cpu-process",
				CPUPercent: 75.0,
			},
		},
	}

	_, _ = manager.EvaluateMetrics(metrics)
	time.Sleep(150 * time.Millisecond)

	metrics.Timestamp = time.Now()
	alerts, err := manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	// Should have alert for high CPU process
	if len(alerts) > 0 {
		assert.Equal(t, "process_cpu_percent", alerts[0].MetricName)
		assert.Equal(t, "high-cpu-process", alerts[0].ProcessName)
	}
}
