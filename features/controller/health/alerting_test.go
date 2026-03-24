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

func TestNewAlertManager(t *testing.T) {
	thresholds := []health.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      80,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   5 * time.Minute,
		},
	}

	smtpConfig := health.SMTPConfig{
		Host: "smtp.example.com",
		Port: 587,
		From: "alerts@cfgms.example.com",
		To:   []string{"ops@example.com"},
	}

	manager := health.NewAlertManager(thresholds, smtpConfig)
	assert.NotNil(t, manager)
}

func TestAlertManager_StartStop(t *testing.T) {
	manager := health.NewAlertManager([]health.Threshold{}, health.SMTPConfig{})

	ctx := context.Background()

	// Start manager
	err := manager.Start(ctx)
	require.NoError(t, err)

	// Stop manager
	err = manager.Stop()
	require.NoError(t, err)
}

func TestAlertManager_ThresholdBreach(t *testing.T) {
	thresholds := []health.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      80,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   100 * time.Millisecond, // Short duration for testing
		},
	}

	manager := health.NewAlertManager(thresholds, health.SMTPConfig{})

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics that breach the threshold
	metrics := &health.ControllerMetrics{
		Timestamp: time.Now(),
		System: &health.SystemMetrics{
			CPUPercent:     90, // Above threshold
			MemoryPercent:  50,
			GoroutineCount: 100,
			CollectedAt:    time.Now(),
		},
	}

	// First evaluation - breach tracked but no alert yet (duration not met)
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	alerts := manager.GetActiveAlerts()
	assert.Equal(t, 0, len(alerts), "Should not have alerts yet (duration not met)")

	// Wait for duration to be met
	time.Sleep(150 * time.Millisecond)

	// Second evaluation - should trigger alert
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	alerts = manager.GetActiveAlerts()
	assert.Equal(t, 1, len(alerts), "Should have one active alert")
	assert.Equal(t, "cpu_percent", alerts[0].MetricName)
	assert.Equal(t, health.SeverityCritical, alerts[0].Severity)
	assert.Equal(t, "active", alerts[0].Status)
}

func TestAlertManager_ThresholdResolution(t *testing.T) {
	thresholds := []health.Threshold{
		{
			MetricName: "memory_percent",
			Value:      85,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   100 * time.Millisecond,
		},
	}

	manager := health.NewAlertManager(thresholds, health.SMTPConfig{})

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics that breach the threshold
	metricsBreached := &health.ControllerMetrics{
		Timestamp: time.Now(),
		System: &health.SystemMetrics{
			CPUPercent:     50,
			MemoryPercent:  90, // Above threshold
			GoroutineCount: 100,
			CollectedAt:    time.Now(),
		},
	}

	// Trigger breach
	err = manager.EvaluateMetrics(metricsBreached)
	require.NoError(t, err)

	time.Sleep(150 * time.Millisecond)

	// Trigger alert
	err = manager.EvaluateMetrics(metricsBreached)
	require.NoError(t, err)

	alerts := manager.GetActiveAlerts()
	assert.Equal(t, 1, len(alerts), "Should have one active alert")

	// Create metrics that no longer breach the threshold
	metricsNormal := &health.ControllerMetrics{
		Timestamp: time.Now(),
		System: &health.SystemMetrics{
			CPUPercent:     50,
			MemoryPercent:  70, // Below threshold
			GoroutineCount: 100,
			CollectedAt:    time.Now(),
		},
	}

	// Evaluate with normal metrics - should resolve alert
	err = manager.EvaluateMetrics(metricsNormal)
	require.NoError(t, err)

	alerts = manager.GetActiveAlerts()
	assert.Equal(t, 0, len(alerts), "Alert should be resolved")
}

func TestAlertManager_RateLimiting(t *testing.T) {
	thresholds := []health.Threshold{
		{
			MetricName: "workflow_queue_depth",
			Value:      100,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   50 * time.Millisecond,
		},
	}

	manager := health.NewAlertManager(thresholds, health.SMTPConfig{})

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics that breach the threshold
	metrics := &health.ControllerMetrics{
		Timestamp: time.Now(),
		Application: &health.ApplicationMetrics{
			WorkflowQueueDepth:  150, // Above threshold
			WorkflowMaxWaitTime: 10.0,
			ActiveWorkflows:     50,
			CollectedAt:         time.Now(),
		},
	}

	// First breach
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Trigger first alert
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	alerts := manager.GetActiveAlerts()
	assert.Equal(t, 1, len(alerts))
	firstAlertID := alerts[0].ID

	// Immediately trigger another evaluation - should use same alert (rate limited)
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	alerts = manager.GetActiveAlerts()
	assert.Equal(t, 1, len(alerts), "Should still have only one alert due to rate limiting")
	assert.Equal(t, firstAlertID, alerts[0].ID, "Should be the same alert")
}

func TestAlertManager_MultipleThresholds(t *testing.T) {
	thresholds := []health.Threshold{
		{
			MetricName: "cpu_percent",
			Value:      80,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   50 * time.Millisecond,
		},
		{
			MetricName: "memory_percent",
			Value:      85,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   50 * time.Millisecond,
		},
	}

	manager := health.NewAlertManager(thresholds, health.SMTPConfig{})

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics that breach both thresholds
	metrics := &health.ControllerMetrics{
		Timestamp: time.Now(),
		System: &health.SystemMetrics{
			CPUPercent:     90, // Above threshold
			MemoryPercent:  90, // Above threshold
			GoroutineCount: 100,
			CollectedAt:    time.Now(),
		},
	}

	// Trigger breaches
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Trigger alerts
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	alerts := manager.GetActiveAlerts()
	assert.Equal(t, 2, len(alerts), "Should have two active alerts")
}

func TestAlertManager_AddRemoveThreshold(t *testing.T) {
	manager := health.NewAlertManager([]health.Threshold{}, health.SMTPConfig{})

	// Add threshold
	threshold := health.Threshold{
		MetricName: "storage_p95_latency_ms",
		Value:      1000,
		Operator:   ">",
		Severity:   health.SeverityCritical,
		Duration:   5 * time.Minute,
	}

	err := manager.AddThreshold(threshold)
	require.NoError(t, err)

	// Remove threshold
	err = manager.RemoveThreshold("storage_p95_latency_ms")
	require.NoError(t, err)
}

func TestAlertManager_GetAlertHistory(t *testing.T) {
	thresholds := []health.Threshold{
		{
			MetricName: "transport_stream_errors",
			Value:      100,
			Operator:   ">",
			Severity:   health.SeverityCritical,
			Duration:   50 * time.Millisecond,
		},
	}

	manager := health.NewAlertManager(thresholds, health.SMTPConfig{})

	ctx := context.Background()
	err := manager.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = manager.Stop()
	}()

	// Create metrics that breach the threshold
	metrics := &health.ControllerMetrics{
		Timestamp: time.Now(),
		Transport: &health.TransportMetrics{
			ConnectedStewards: 50,
			StreamErrors:      200, // Above threshold
			MessagesSent:      1000,
			CollectedAt:       time.Now(),
		},
	}

	// Trigger breach
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	// Trigger alert
	err = manager.EvaluateMetrics(metrics)
	require.NoError(t, err)

	// Get alert history
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)
	history := manager.GetAlertHistory(start, end)

	assert.Greater(t, len(history), 0, "Should have alerts in history")
}

func TestAlertManager_OperatorEvaluation(t *testing.T) {
	tests := []struct {
		name      string
		operator  string
		value     float64
		threshold float64
		expected  bool
	}{
		{"greater than true", ">", 100, 80, true},
		{"greater than false", ">", 70, 80, false},
		{"greater or equal true (greater)", ">=", 100, 80, true},
		{"greater or equal true (equal)", ">=", 80, 80, true},
		{"greater or equal false", ">=", 70, 80, false},
		{"less than true", "<", 70, 80, true},
		{"less than false", "<", 90, 80, false},
		{"less or equal true (less)", "<=", 70, 80, true},
		{"less or equal true (equal)", "<=", 80, 80, true},
		{"less or equal false", "<=", 90, 80, false},
		{"equal true", "==", 80, 80, true},
		{"equal false", "==", 81, 80, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thresholds := []health.Threshold{
				{
					MetricName: "test_metric",
					Value:      tt.threshold,
					Operator:   tt.operator,
					Severity:   health.SeverityCritical,
					Duration:   50 * time.Millisecond,
				},
			}

			manager := health.NewAlertManager(thresholds, health.SMTPConfig{})

			ctx := context.Background()
			err := manager.Start(ctx)
			require.NoError(t, err)
			defer func() {
				_ = manager.Stop()
			}()

			// Create metrics with the test value
			metrics := &health.ControllerMetrics{
				Timestamp: time.Now(),
				System: &health.SystemMetrics{
					CPUPercent:     tt.value,
					MemoryPercent:  50,
					GoroutineCount: 100,
					CollectedAt:    time.Now(),
				},
			}

			// Use cpu_percent for testing
			thresholds[0].MetricName = "cpu_percent"
			_ = manager.AddThreshold(thresholds[0])

			// Trigger evaluation
			err = manager.EvaluateMetrics(metrics)
			require.NoError(t, err)

			time.Sleep(100 * time.Millisecond)

			// Trigger alert check
			err = manager.EvaluateMetrics(metrics)
			require.NoError(t, err)

			alerts := manager.GetActiveAlerts()
			if tt.expected {
				assert.Greater(t, len(alerts), 0, "Should have alert when condition is true")
			} else {
				assert.Equal(t, 0, len(alerts), "Should not have alert when condition is false")
			}
		})
	}
}

func TestDefaultThresholds(t *testing.T) {
	thresholds := health.DefaultThresholds()

	assert.Greater(t, len(thresholds), 0, "Should have default thresholds")

	// Verify all thresholds are CRITICAL severity
	for _, threshold := range thresholds {
		assert.Equal(t, health.SeverityCritical, threshold.Severity, "All default thresholds should be CRITICAL")
		assert.NotEmpty(t, threshold.MetricName, "Threshold should have a metric name")
		assert.NotEmpty(t, threshold.Operator, "Threshold should have an operator")
		assert.Greater(t, threshold.Value, float64(0), "Threshold value should be positive")
		assert.Greater(t, threshold.Duration, time.Duration(0), "Threshold duration should be positive")
	}
}
