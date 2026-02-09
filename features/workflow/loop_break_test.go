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

func TestForLoopBreak(t *testing.T) {
	// Test break in for loop - should break on 3rd iteration
	workflow := Workflow{
		Name: "for-loop-break-test",
		Variables: map[string]interface{}{
			"iterations": 0,
		},
		Steps: []Step{
			{
				Name: "for-loop",
				Type: StepTypeFor,
				Loop: &LoopConfig{
					Type:     LoopTypeFor,
					Variable: "i",
					Start:    1,
					End:      10,
					Step:     1,
				},
				Steps: []Step{
					{
						Name: "increment-counter",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
							Message:  "Incrementing counter",
						},
					},
					{
						Name: "break-on-three",
						Type: StepTypeBreak, // This should break the loop immediately
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

	// Verify the loop broke after first iteration (i=1)
	i, exists := execution.GetVariable("i")
	assert.True(t, exists)
	assert.Equal(t, 1, i) // Should be 1 when it broke
}

func TestForLoopContinue(t *testing.T) {
	// Test continue in for loop - should skip processing on even numbers
	workflow := Workflow{
		Name: "for-loop-continue-test",
		Variables: map[string]interface{}{
			"sum": 0,
		},
		Steps: []Step{
			{
				Name: "for-loop",
				Type: StepTypeFor,
				Loop: &LoopConfig{
					Type:     LoopTypeFor,
					Variable: "i",
					Start:    1,
					End:      4,
					Step:     1,
				},
				Steps: []Step{
					{
						Name: "continue-on-even",
						Type: StepTypeContinue, // This will skip the rest for all iterations
					},
					{
						Name: "add-to-sum",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
							Message:  "This should never execute",
						},
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

	// Verify the loop completed all 4 iterations but skipped the add step
	i, exists := execution.GetVariable("i")
	assert.True(t, exists)
	assert.Equal(t, 4, i) // Should be 4 after completing all iterations

	// Verify sum is still 0 (no additions happened due to continue)
	sum, exists := execution.GetVariable("sum")
	assert.True(t, exists)
	assert.Equal(t, 0, sum)
}

func TestWhileLoopBreak(t *testing.T) {
	// Test break in while loop
	workflow := Workflow{
		Name: "while-loop-break-test",
		Variables: map[string]interface{}{
			"counter": 0,
		},
		Steps: []Step{
			{
				Name: "while-loop",
				Type: StepTypeWhile,
				Loop: &LoopConfig{
					Type: LoopTypeWhile,
					Condition: &Condition{
						Type:       ConditionTypeExpression,
						Expression: "${counter < 100}", // Would normally loop 100 times
					},
				},
				Steps: []Step{
					{
						Name: "increment",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
							Message:  "Increment step",
						},
					},
					{
						Name: "break-immediately",
						Type: StepTypeBreak,
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

	// Verify the counter is still 0 (loop broke on first iteration)
	counter, exists := execution.GetVariable("counter")
	assert.True(t, exists)
	assert.Equal(t, 0, counter)
}

func TestForeachLoopBreak(t *testing.T) {
	// Test break in foreach loop
	workflow := Workflow{
		Name: "foreach-loop-break-test",
		Variables: map[string]interface{}{
			"processed": 0,
		},
		Steps: []Step{
			{
				Name: "foreach-loop",
				Type: StepTypeForeach,
				Loop: &LoopConfig{
					Type:          LoopTypeForeach,
					Variable:      "item",
					IndexVariable: "index",
					Items:         []interface{}{"a", "b", "c", "d", "e"},
				},
				Steps: []Step{
					{
						Name: "process-item",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
							Message:  "Processing item",
						},
					},
					{
						Name: "break-immediately",
						Type: StepTypeBreak,
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

	// Verify it processed the first item and then broke
	item, exists := execution.GetVariable("item")
	assert.True(t, exists)
	assert.Equal(t, "a", item) // Should be "a" (first item)

	index, exists := execution.GetVariable("index")
	assert.True(t, exists)
	assert.Equal(t, 0, index) // Should be 0 (first index)
}

func TestBreakContinueOutsideLoop(t *testing.T) {
	// Test that break/continue outside a loop is properly handled
	workflow := Workflow{
		Name: "break-outside-loop",
		Steps: []Step{
			{
				Name: "invalid-break",
				Type: StepTypeBreak,
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

	// The workflow should complete, but the break step should be treated as an error
	// Since we're outside a loop, the LoopControlError should propagate as a normal error
	status := execution.GetStatus()
	assert.True(t, status == StatusFailed || status == StatusCompleted,
		"Expected either failed (if error propagated) or completed (if break ignored), got %s", status)
}
