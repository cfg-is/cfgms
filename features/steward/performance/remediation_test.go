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

func TestNewRemediationEngine(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")
	assert.NotNil(t, engine)
}

func TestRemediationEngine_StartStop(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")

	ctx := context.Background()

	err := engine.Start(ctx)
	require.NoError(t, err)

	err = engine.Stop()
	require.NoError(t, err)
}

func TestRemediationEngine_TriggerRemediation(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")

	ctx := context.Background()
	err := engine.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = engine.Stop()
	}()

	// Create an alert
	alert := performance.Alert{
		ID:             "alert-123",
		StewardID:      "test-steward-1",
		Timestamp:      time.Now(),
		Severity:       "critical",
		Title:          "High CPU Usage",
		Description:    "CPU usage exceeded 90%",
		MetricName:     "cpu_percent",
		CurrentValue:   95.0,
		ThresholdValue: 90.0,
		Status:         "active",
	}

	// Trigger remediation
	action, err := engine.TriggerRemediation(ctx, alert, "workflow-restart-service")
	require.NoError(t, err)
	require.NotNil(t, action)

	assert.NotEmpty(t, action.ID)
	assert.Equal(t, "alert-123", action.AlertID)
	assert.Equal(t, "workflow-restart-service", action.WorkflowID)
	assert.Equal(t, "triggered", action.Status)
	assert.False(t, action.TriggeredAt.IsZero())
}

func TestRemediationEngine_GetRemediationStatus(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")

	ctx := context.Background()
	err := engine.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = engine.Stop()
	}()

	// Create and trigger remediation
	alert := performance.Alert{
		ID:        "alert-123",
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
	}

	action, err := engine.TriggerRemediation(ctx, alert, "workflow-1")
	require.NoError(t, err)

	// Get status
	status, err := engine.GetRemediationStatus(action.ID)
	require.NoError(t, err)
	assert.Equal(t, action.ID, status.ID)
	assert.Equal(t, "alert-123", status.AlertID)
}

func TestRemediationEngine_SimulatedWorkflowCompletion(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")

	ctx := context.Background()
	err := engine.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = engine.Stop()
	}()

	// Trigger remediation
	alert := performance.Alert{
		ID:        "alert-123",
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
	}

	action, err := engine.TriggerRemediation(ctx, alert, "workflow-1")
	require.NoError(t, err)

	// Wait for simulated workflow completion
	time.Sleep(200 * time.Millisecond)

	// Check status - should be completed
	status, err := engine.GetRemediationStatus(action.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", status.Status)
	assert.NotNil(t, status.CompletedAt)
	assert.NotEmpty(t, status.Result)
}

func TestRemediationEngine_GetRemediationHistory(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")

	ctx := context.Background()
	err := engine.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = engine.Stop()
	}()

	// Trigger multiple remediations
	for i := 0; i < 3; i++ {
		alert := performance.Alert{
			ID:        fmt.Sprintf("alert-%d", i),
			StewardID: "test-steward-1",
			Timestamp: time.Now(),
		}

		_, err := engine.TriggerRemediation(ctx, alert, fmt.Sprintf("workflow-%d", i))
		require.NoError(t, err)
	}

	// Get history
	start := time.Now().Add(-1 * time.Hour)
	end := time.Now().Add(1 * time.Hour)

	history := engine.GetRemediationHistory(start, end)
	assert.Len(t, history, 3)
}

func TestRemediationEngine_DuplicateAlertRemediation(t *testing.T) {
	engine := performance.NewRemediationEngine("test-steward-1")

	ctx := context.Background()
	err := engine.Start(ctx)
	require.NoError(t, err)
	defer func() {
		_ = engine.Stop()
	}()

	// Create an alert
	alert := performance.Alert{
		ID:        "alert-123",
		StewardID: "test-steward-1",
		Timestamp: time.Now(),
	}

	// Trigger remediation first time
	action1, err := engine.TriggerRemediation(ctx, alert, "workflow-1")
	require.NoError(t, err)

	// Trigger remediation again for same alert
	action2, err := engine.TriggerRemediation(ctx, alert, "workflow-1")
	require.NoError(t, err)

	// Should return the same action
	assert.Equal(t, action1.ID, action2.ID)
}
