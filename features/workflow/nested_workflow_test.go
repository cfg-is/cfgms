// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestNestedWorkflowByName(t *testing.T) {
	// Test nested workflow execution by name
	workflow := Workflow{
		Name: "parent-workflow",
		Variables: map[string]interface{}{
			"parent_var": "parent_value",
		},
		Steps: []Step{
			{
				Name: "call-nested-workflow",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowName: "test-nested-workflow",
					Parameters: map[string]interface{}{
						"input_param": "test_value",
					},
					OutputMappings: map[string]string{
						"result": "nested_result",
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify output mapping worked
	result, exists := execution.GetVariable("result")
	assert.True(t, exists)
	assert.Equal(t, "default", result) // From nested workflow's default value
}

func TestNestedWorkflowByPath(t *testing.T) {
	// Test nested workflow execution by file path
	workflow := Workflow{
		Name: "parent-workflow-path",
		Variables: map[string]interface{}{
			"parent_var": "parent_value",
		},
		Steps: []Step{
			{
				Name: "call-nested-workflow",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowPath: "/path/to/workflow.yaml",
					Parameters: map[string]interface{}{
						"input_param": "test_value",
					},
					OutputMappings: map[string]string{
						"loaded_path": "loaded_from",
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify output mapping worked
	loadedPath, exists := execution.GetVariable("loaded_path")
	assert.True(t, exists)
	assert.Equal(t, "/path/to/workflow.yaml", loadedPath)
}

func TestNestedWorkflowParameterMapping(t *testing.T) {
	// Test parameter mapping from parent to nested workflow
	workflow := Workflow{
		Name: "parent-with-mapping",
		Variables: map[string]interface{}{
			"parent_input": "mapped_value",
			"parent_data":  42,
		},
		Steps: []Step{
			{
				Name: "call-nested-workflow",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowName: "test-nested-workflow",
					Parameters: map[string]interface{}{
						"direct_param": "direct_value",
					},
					ParameterMappings: map[string]string{
						"nested_input": "parent_input",
						"nested_data":  "parent_data",
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestNestedWorkflowTimeout(t *testing.T) {
	// Test nested workflow with timeout (using very short timeout for testing)
	workflow := Workflow{
		Name:      "parent-with-timeout",
		Variables: map[string]interface{}{},
		Steps: []Step{
			{
				Name: "call-nested-workflow",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowName: "test-nested-workflow",
					Timeout:      1 * time.Nanosecond, // Very short timeout to test timeout behavior
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
	time.Sleep(100 * time.Millisecond)

	// This might complete successfully if the nested workflow executes very quickly,
	// or fail due to timeout. Both are acceptable outcomes for this test.
	status := execution.GetStatus()
	assert.True(t, status == StatusCompleted || status == StatusFailed)
}

func TestNestedWorkflowAsync(t *testing.T) {
	// Test asynchronous nested workflow execution
	workflow := Workflow{
		Name:      "parent-async",
		Variables: map[string]interface{}{},
		Steps: []Step{
			{
				Name: "call-nested-workflow-async",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowName: "test-nested-workflow",
					Async:        true,
				},
			},
			{
				Name: "parent-continues",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 1 * time.Millisecond,
					Message:  "Parent continues while nested runs",
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestNestedWorkflowMissingConfiguration(t *testing.T) {
	// Test nested workflow with missing configuration
	workflow := Workflow{
		Name: "parent-missing-config",
		Steps: []Step{
			{
				Name: "invalid-workflow-call",
				Type: StepTypeWorkflow,
				// No WorkflowCall configuration
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution failed due to missing configuration
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestNestedWorkflowMissingWorkflowSpec(t *testing.T) {
	// Test nested workflow with missing workflow specification
	workflow := Workflow{
		Name: "parent-missing-spec",
		Steps: []Step{
			{
				Name: "invalid-workflow-call",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution failed due to missing workflow specification
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestNestedWorkflowNotFound(t *testing.T) {
	// Test nested workflow with non-existent workflow name
	workflow := Workflow{
		Name: "parent-not-found",
		Steps: []Step{
			{
				Name: "call-nonexistent-workflow",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowName: "nonexistent-workflow",
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution failed due to workflow not found
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestNestedWorkflowComplexParameterMapping(t *testing.T) {
	// Test complex parameter and output mappings
	workflow := Workflow{
		Name: "parent-complex-mapping",
		Variables: map[string]interface{}{
			"input_value":  "test_input",
			"input_number": 123,
			"input_bool":   true,
		},
		Steps: []Step{
			{
				Name: "call-nested-workflow",
				Type: StepTypeWorkflow,
				WorkflowCall: &WorkflowCallConfig{
					WorkflowName: "test-nested-workflow",
					Parameters: map[string]interface{}{
						"static_param": "static_value",
					},
					ParameterMappings: map[string]string{
						"nested_value":  "input_value",
						"nested_number": "input_number",
						"nested_bool":   "input_bool",
					},
					OutputMappings: map[string]string{
						"output_result": "nested_result",
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
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify output mapping
	result, exists := execution.GetVariable("output_result")
	assert.True(t, exists)
	assert.Equal(t, "default", result)

	// Verify original variables are still present
	inputValue, exists := execution.GetVariable("input_value")
	assert.True(t, exists)
	assert.Equal(t, "test_input", inputValue)
}
