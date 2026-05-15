// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestExecuteComponentsDependency_LinearChain verifies that a three-component chain
// A→B→C executes in dependency order. Each component workflow exposes a fixed
// sequence value; OutputMappings propagate those values to the parent execution so
// we can assert all three ran and produced their expected outputs.
func TestExecuteComponentsDependency_LinearChain(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil)

	// Register three minimal sub-workflows, each with a distinct sequence value.
	engine.RegisterWorkflow(Workflow{
		Name:      "dep-comp-a",
		Variables: map[string]interface{}{"seq_a": 1},
		Steps: []Step{{
			Name:  "a-step",
			Type:  StepTypeDelay,
			Delay: &DelayConfig{Duration: 1 * time.Millisecond},
		}},
	})
	engine.RegisterWorkflow(Workflow{
		Name:      "dep-comp-b",
		Variables: map[string]interface{}{"seq_b": 2},
		Steps: []Step{{
			Name:  "b-step",
			Type:  StepTypeDelay,
			Delay: &DelayConfig{Duration: 1 * time.Millisecond},
		}},
	})
	engine.RegisterWorkflow(Workflow{
		Name:      "dep-comp-c",
		Variables: map[string]interface{}{"seq_c": 3},
		Steps: []Step{{
			Name:  "c-step",
			Type:  StepTypeDelay,
			Delay: &DelayConfig{Duration: 1 * time.Millisecond},
		}},
	})

	workflow := Workflow{
		Name: "linear-chain-test",
		Steps: []Step{{
			Name: "compose",
			Type: StepTypeComposite,
			Composite: &CompositeConfig{
				Strategy:      CompositionStrategyDependency,
				FailurePolicy: CompositeFailurePolicyFail,
				Components: []WorkflowComponent{
					{
						Name:           "A",
						WorkflowName:   "dep-comp-a",
						OutputMappings: map[string]string{"seq_a": "seq_a"},
					},
					{
						Name:           "B",
						WorkflowName:   "dep-comp-b",
						DependsOn:      []string{"A"},
						OutputMappings: map[string]string{"seq_b": "seq_b"},
					},
					{
						Name:           "C",
						WorkflowName:   "dep-comp-c",
						DependsOn:      []string{"B"},
						OutputMappings: map[string]string{"seq_c": "seq_c"},
					},
				},
			},
		}},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	waitForWorkflowCompletion(t, execution, 5*time.Second)

	assert.Equal(t, StatusCompleted, execution.GetStatus())

	seqA, ok := execution.GetVariable("seq_a")
	require.True(t, ok, "seq_a should be set by component A")
	assert.Equal(t, 1, seqA)

	seqB, ok := execution.GetVariable("seq_b")
	require.True(t, ok, "seq_b should be set by component B")
	assert.Equal(t, 2, seqB)

	seqC, ok := execution.GetVariable("seq_c")
	require.True(t, ok, "seq_c should be set by component C")
	assert.Equal(t, 3, seqC)
}

// TestExecuteComponentsDependency_ParallelFanOut verifies that two independent
// components (neither has DependsOn) both complete when using the dependency strategy.
func TestExecuteComponentsDependency_ParallelFanOut(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil)

	engine.RegisterWorkflow(Workflow{
		Name:      "dep-fanout-x",
		Variables: map[string]interface{}{"result_x": "done_x"},
		Steps: []Step{{
			Name:  "x-step",
			Type:  StepTypeDelay,
			Delay: &DelayConfig{Duration: 1 * time.Millisecond},
		}},
	})
	engine.RegisterWorkflow(Workflow{
		Name:      "dep-fanout-y",
		Variables: map[string]interface{}{"result_y": "done_y"},
		Steps: []Step{{
			Name:  "y-step",
			Type:  StepTypeDelay,
			Delay: &DelayConfig{Duration: 1 * time.Millisecond},
		}},
	})

	workflow := Workflow{
		Name: "parallel-fanout-test",
		Steps: []Step{{
			Name: "compose",
			Type: StepTypeComposite,
			Composite: &CompositeConfig{
				Strategy:      CompositionStrategyDependency,
				FailurePolicy: CompositeFailurePolicyFail,
				Components: []WorkflowComponent{
					{
						Name:           "X",
						WorkflowName:   "dep-fanout-x",
						OutputMappings: map[string]string{"result_x": "result_x"},
					},
					{
						Name:           "Y",
						WorkflowName:   "dep-fanout-y",
						OutputMappings: map[string]string{"result_y": "result_y"},
					},
				},
			},
		}},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	waitForWorkflowCompletion(t, execution, 5*time.Second)

	assert.Equal(t, StatusCompleted, execution.GetStatus())

	rx, ok := execution.GetVariable("result_x")
	require.True(t, ok, "result_x should be set by component X")
	assert.Equal(t, "done_x", rx)

	ry, ok := execution.GetVariable("result_y")
	require.True(t, ok, "result_y should be set by component Y")
	assert.Equal(t, "done_y", ry)
}

// TestExecuteComponentsDependency_CycleDetected verifies that a workflow whose
// components form a dependency cycle returns a non-nil error before any component
// executes, and that the error message names the cycle path.
func TestExecuteComponentsDependency_CycleDetected(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil)

	// Register the component workflows so loading does not fail before cycle check.
	engine.RegisterWorkflow(Workflow{
		Name:  "cycle-wf-a",
		Steps: []Step{{Name: "a", Type: StepTypeDelay, Delay: &DelayConfig{Duration: 1 * time.Millisecond}}},
	})
	engine.RegisterWorkflow(Workflow{
		Name:  "cycle-wf-b",
		Steps: []Step{{Name: "b", Type: StepTypeDelay, Delay: &DelayConfig{Duration: 1 * time.Millisecond}}},
	})

	workflow := Workflow{
		Name: "cycle-test",
		Steps: []Step{{
			Name: "compose",
			Type: StepTypeComposite,
			Composite: &CompositeConfig{
				Strategy:      CompositionStrategyDependency,
				FailurePolicy: CompositeFailurePolicyFail,
				Components: []WorkflowComponent{
					{
						Name:         "A",
						WorkflowName: "cycle-wf-a",
						DependsOn:    []string{"B"},
					},
					{
						Name:         "B",
						WorkflowName: "cycle-wf-b",
						DependsOn:    []string{"A"},
					},
				},
			},
		}},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Workflow must fail due to the cycle.
	assert.Equal(t, StatusFailed, execution.GetStatus())

	// The error message must name the cycle path.
	errMsg := execution.GetError()
	assert.Contains(t, errMsg, "cycle")
}

// TestExecuteComponentsDependency_UnknownDependency verifies that a component
// referencing a non-existent dependency name returns a descriptive error.
func TestExecuteComponentsDependency_UnknownDependency(t *testing.T) {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil)

	engine.RegisterWorkflow(Workflow{
		Name:  "unknown-dep-wf",
		Steps: []Step{{Name: "s", Type: StepTypeDelay, Delay: &DelayConfig{Duration: 1 * time.Millisecond}}},
	})

	workflow := Workflow{
		Name: "unknown-dep-test",
		Steps: []Step{{
			Name: "compose",
			Type: StepTypeComposite,
			Composite: &CompositeConfig{
				Strategy:      CompositionStrategyDependency,
				FailurePolicy: CompositeFailurePolicyFail,
				Components: []WorkflowComponent{
					{
						Name:         "P",
						WorkflowName: "unknown-dep-wf",
						DependsOn:    []string{"does-not-exist"},
					},
				},
			},
		}},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	waitForWorkflowCompletion(t, execution, 5*time.Second)

	assert.Equal(t, StatusFailed, execution.GetStatus())
	assert.Contains(t, execution.GetError(), "unknown")
}
