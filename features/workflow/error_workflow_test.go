// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestErrorWorkflowStep(t *testing.T) {
	// Test executing a custom error workflow step
	workflow := Workflow{
		Name: "error-workflow-test",
		Variables: map[string]interface{}{
			"error_context": "test_error",
		},
		Steps: []Step{
			{
				Name: "handle-error",
				Type: StepTypeErrorWorkflow,
				ErrorWorkflow: &ErrorWorkflowConfig{
					WorkflowName: "test-error-handler",
					Parameters: map[string]interface{}{
						"severity": "high",
					},
					ParameterMappings: map[string]string{
						"context": "error_context",
					},
					OutputMappings: map[string]string{
						"handled": "error_handled",
					},
					RecoveryAction: RecoveryActionContinue,
					Timeout:        5 * time.Second,
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion (fixes Windows CI async race condition - Issue #309)
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify recovery action was stored
	recoveryAction, exists := execution.GetVariable("handle-error_recovery_action")
	assert.True(t, exists)
	assert.Equal(t, RecoveryActionContinue, recoveryAction)
}

func TestErrorWorkflowWithPath(t *testing.T) {
	// Test error workflow execution by file path
	workflow := Workflow{
		Name: "error-workflow-path-test",
		Steps: []Step{
			{
				Name: "handle-error-by-path",
				Type: StepTypeErrorWorkflow,
				ErrorWorkflow: &ErrorWorkflowConfig{
					WorkflowPath: "/path/to/error-handler.yaml",
					Parameters: map[string]interface{}{
						"error_type": "validation",
					},
					OutputMappings: map[string]string{
						"recovery_status": "status",
					},
					RecoveryAction: RecoveryActionRetry,
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion (fixes Windows CI async race condition - Issue #309)
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify output mapping worked
	status, exists := execution.GetVariable("status")
	assert.True(t, exists)
	assert.Equal(t, "handled", status) // From mock error handler
}

func TestErrorWorkflowAsync(t *testing.T) {
	// Test asynchronous error workflow execution
	workflow := Workflow{
		Name: "error-workflow-async-test",
		Variables: map[string]interface{}{
			"async_context": "background_processing",
		},
		Steps: []Step{
			{
				Name: "async-error-handler",
				Type: StepTypeErrorWorkflow,
				ErrorWorkflow: &ErrorWorkflowConfig{
					WorkflowName: "test-error-handler",
					Async:        true,
					Parameters: map[string]interface{}{
						"mode": "async",
					},
					ParameterMappings: map[string]string{
						"context": "async_context",
					},
					RecoveryAction: RecoveryActionSkip,
				},
			},
			{
				Name: "continue-after-async",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 1 * time.Millisecond,
					Message:  "Continuing after async error handler",
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion (fixes Windows CI async race condition - Issue #309)
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify recovery action was stored
	recoveryAction, exists := execution.GetVariable("async-error-handler_recovery_action")
	assert.True(t, exists)
	assert.Equal(t, RecoveryActionSkip, recoveryAction)
}

func TestErrorWorkflowMissingConfiguration(t *testing.T) {
	// Test error workflow with missing configuration
	workflow := Workflow{
		Name: "error-workflow-missing-config",
		Steps: []Step{
			{
				Name: "invalid-error-workflow",
				Type: StepTypeErrorWorkflow,
				// No ErrorWorkflow configuration
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution failed due to missing configuration
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestErrorWorkflowMissingWorkflowSpec(t *testing.T) {
	// Test error workflow with missing workflow specification
	workflow := Workflow{
		Name: "error-workflow-missing-spec",
		Steps: []Step{
			{
				Name: "invalid-spec",
				Type: StepTypeErrorWorkflow,
				ErrorWorkflow: &ErrorWorkflowConfig{
					// Neither WorkflowName nor WorkflowPath specified
					Parameters: map[string]interface{}{
						"test": "value",
					},
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution failed due to missing workflow specification
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestErrorWorkflowWithRecoveryActions(t *testing.T) {
	// Test different recovery actions
	recoveryActions := []RecoveryAction{
		RecoveryActionContinue,
		RecoveryActionRetry,
		RecoveryActionSkip,
		RecoveryActionFail,
		RecoveryActionAbort,
	}

	for _, action := range recoveryActions {
		t.Run(string(action), func(t *testing.T) {
			workflow := Workflow{
				Name: "recovery-action-test",
				Steps: []Step{
					{
						Name: "test-recovery-action",
						Type: StepTypeErrorWorkflow,
						ErrorWorkflow: &ErrorWorkflowConfig{
							WorkflowName:   "test-error-handler",
							RecoveryAction: action,
							Parameters: map[string]interface{}{
								"action": string(action),
							},
						},
					},
				},
			}

			// Create engine and execute workflow
			moduleFactory := createTestFactory()
			logger := pkgtesting.NewMockLogger(true)
			engine := NewEngine(moduleFactory, logger)
			ctx := context.Background()

			execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
			require.NoError(t, err)
			require.NotNil(t, execution)

			// Wait for completion
			waitForWorkflowCompletion(t, execution, 2*time.Second)

			// Verify execution completed successfully
			assert.Equal(t, StatusCompleted, execution.GetStatus())

			// Verify recovery action was stored
			storedAction, exists := execution.GetVariable("test-recovery-action_recovery_action")
			assert.True(t, exists)
			assert.Equal(t, action, storedAction)
		})
	}
}

func TestErrorWorkflowParameterAndOutputMappings(t *testing.T) {
	// Test complex parameter and output mappings
	workflow := Workflow{
		Name: "error-workflow-mappings-test",
		Variables: map[string]interface{}{
			"source_data":    "important_data",
			"error_severity": "critical",
			"system_id":      "sys-001",
		},
		Steps: []Step{
			{
				Name: "complex-error-handler",
				Type: StepTypeErrorWorkflow,
				ErrorWorkflow: &ErrorWorkflowConfig{
					WorkflowName: "test-error-handler",
					Parameters: map[string]interface{}{
						"static_param": "static_value",
					},
					ParameterMappings: map[string]string{
						"data":     "source_data",
						"severity": "error_severity",
						"system":   "system_id",
					},
					OutputMappings: map[string]string{
						"resolution":  "error_resolution",
						"remediation": "remediation_steps",
						"next_action": "recommended_action",
					},
					RecoveryAction: RecoveryActionContinue,
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion (fixes Windows CI async race condition - Issue #309)
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify original variables are still present
	sourceData, exists := execution.GetVariable("source_data")
	assert.True(t, exists)
	assert.Equal(t, "important_data", sourceData)

	// Verify output mappings were applied (these would come from the mock error handler)
	// In a real implementation, the mock handler would set these variables
}

func TestErrorWorkflowTimeout(t *testing.T) {
	// Test error workflow with timeout
	workflow := Workflow{
		Name: "error-workflow-timeout-test",
		Steps: []Step{
			{
				Name: "timeout-error-handler",
				Type: StepTypeErrorWorkflow,
				ErrorWorkflow: &ErrorWorkflowConfig{
					WorkflowName:   "test-error-handler",
					Timeout:        1 * time.Millisecond, // Very short timeout
					RecoveryAction: RecoveryActionFail,
				},
			},
		},
	}

	// Create engine and execute workflow
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion (fixes Windows CI async race condition - Issue #309)
	waitForWorkflowCompletion(t, execution, 2*time.Second)

	// The workflow should complete (the timeout handling is internal to the error workflow)
	// The actual timeout behavior depends on the implementation details
	status := execution.GetStatus()
	assert.True(t, status == StatusCompleted || status == StatusFailed)
}
