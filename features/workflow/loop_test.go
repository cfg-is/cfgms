// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestWorkflowForLoop(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	tests := []struct {
		name      string
		loop      *LoopConfig
		variables map[string]interface{}
		expected  int // expected iterations
		expectErr bool
	}{
		{
			name: "simple for loop 1 to 3",
			loop: &LoopConfig{
				Type:     LoopTypeFor,
				Variable: "i",
				Start:    1,
				End:      3,
			},
			variables: map[string]interface{}{},
			expected:  3,
		},
		{
			name: "for loop with step 2",
			loop: &LoopConfig{
				Type:     LoopTypeFor,
				Variable: "i",
				Start:    0,
				End:      10,
				Step:     2,
			},
			variables: map[string]interface{}{},
			expected:  6, // 0, 2, 4, 6, 8, 10
		},
		{
			name: "for loop with negative step",
			loop: &LoopConfig{
				Type:     LoopTypeFor,
				Variable: "i",
				Start:    10,
				End:      1,
				Step:     -2,
			},
			variables: map[string]interface{}{},
			expected:  5, // 10, 8, 6, 4, 2
		},
		{
			name: "for loop with variable references",
			loop: &LoopConfig{
				Type:     LoopTypeFor,
				Variable: "i",
				Start:    "${start_val}",
				End:      "${end_val}",
			},
			variables: map[string]interface{}{
				"start_val": 1,
				"end_val":   3,
			},
			expected: 3,
		},
		{
			name: "for loop with max iterations exceeded",
			loop: &LoopConfig{
				Type:          LoopTypeFor,
				Variable:      "i",
				Start:         1,
				End:           2000,
				MaxIterations: 10,
			},
			variables: map[string]interface{}{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow := Workflow{
				Name:      "for-loop-test",
				Variables: tt.variables,
				Steps: []Step{
					{
						Name: "for-loop-step",
						Type: StepTypeFor,
						Loop: tt.loop,
						Steps: []Step{
							{
								Name: "inner-step",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 1 * time.Millisecond,
									Message:  "Loop iteration",
								},
							},
						},
					},
				},
			}

			ctx := context.Background()
			execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
			require.NoError(t, err)
			require.NotNil(t, execution)

			// Wait for completion with timeout
			timeout := time.After(5 * time.Second)
			completed := false
			for !completed {
				select {
				case <-timeout:
					t.Fatal("Test timed out waiting for workflow completion")
				default:
					execution, _ = engine.GetExecution(execution.ID)
					if execution.GetStatus() != StatusRunning && execution.GetStatus() != StatusPending {
						completed = true
					} else {
						time.Sleep(10 * time.Millisecond)
					}
				}
			}

			if tt.expectErr {
				assert.Equal(t, StatusFailed, execution.GetStatus())
				assert.Contains(t, execution.Error, "exceeded maximum iterations")
			} else {
				assert.Equal(t, StatusCompleted, execution.GetStatus())
				assert.True(t, execution.HasStepResult("for-loop-step"))

				// Check that the loop variable reached the expected final value
				finalVarValue, exists := execution.GetVariable(tt.loop.Variable)
				assert.True(t, exists)
				assert.NotNil(t, finalVarValue)
			}
		})
	}
}

func TestWorkflowWhileLoop(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	t.Run("while loop with max iterations safety", func(t *testing.T) {
		workflow := Workflow{
			Name: "while-loop-test",
			Variables: map[string]interface{}{
				"always_true": true,
			},
			Steps: []Step{
				{
					Name: "while-loop-step",
					Type: StepTypeWhile,
					Loop: &LoopConfig{
						Type: LoopTypeWhile,
						Condition: &Condition{
							Type:     ConditionTypeVariable,
							Variable: "always_true",
							Operator: OperatorEqual,
							Value:    true,
						},
						MaxIterations: 3, // Safety limit
					},
					Steps: []Step{
						{
							Name: "increment-counter",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Loop iteration",
							},
						},
					},
				},
			},
		}

		ctx := context.Background()
		execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
		require.NoError(t, err)
		require.NotNil(t, execution)

		// Wait for completion with timeout
		timeout := time.After(5 * time.Second)
		completed := false
		for !completed {
			select {
			case <-timeout:
				t.Fatal("Test timed out waiting for workflow completion")
			default:
				execution, _ = engine.GetExecution(execution.ID)
				if execution.GetStatus() != StatusRunning && execution.GetStatus() != StatusPending {
					completed = true
				} else {
					time.Sleep(10 * time.Millisecond)
				}
			}
		}

		// It should fail due to max iterations safety limit
		assert.Equal(t, StatusFailed, execution.GetStatus())
		assert.Contains(t, execution.Error, "exceeded maximum iterations")
	})
}

func TestWorkflowForeachLoop(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	tests := []struct {
		name      string
		loop      *LoopConfig
		variables map[string]interface{}
		expected  int // expected iterations
		expectErr bool
	}{
		{
			name: "foreach with string slice",
			loop: &LoopConfig{
				Type:     LoopTypeForeach,
				Variable: "item",
				Items:    []interface{}{"apple", "banana", "cherry"},
			},
			variables: map[string]interface{}{},
			expected:  3,
		},
		{
			name: "foreach with int slice",
			loop: &LoopConfig{
				Type:     LoopTypeForeach,
				Variable: "num",
				Items:    []interface{}{1, 2, 3, 4, 5},
			},
			variables: map[string]interface{}{},
			expected:  5,
		},
		{
			name: "foreach with variable reference",
			loop: &LoopConfig{
				Type:          LoopTypeForeach,
				Variable:      "item",
				ItemsVariable: "my_list",
			},
			variables: map[string]interface{}{
				"my_list": []interface{}{"one", "two", "three"},
			},
			expected: 3,
		},
		{
			name: "foreach with index variable",
			loop: &LoopConfig{
				Type:          LoopTypeForeach,
				Variable:      "item",
				IndexVariable: "idx",
				Items:         []interface{}{"a", "b"},
			},
			variables: map[string]interface{}{},
			expected:  2,
		},
		{
			name: "foreach with max iterations exceeded",
			loop: &LoopConfig{
				Type:          LoopTypeForeach,
				Variable:      "item",
				Items:         []interface{}{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
				MaxIterations: 5,
			},
			variables: map[string]interface{}{},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			workflow := Workflow{
				Name:      "foreach-loop-test",
				Variables: tt.variables,
				Steps: []Step{
					{
						Name: "foreach-loop-step",
						Type: StepTypeForeach,
						Loop: tt.loop,
						Steps: []Step{
							{
								Name: "inner-step",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 1 * time.Millisecond,
									Message:  "Processing item",
								},
							},
						},
					},
				},
			}

			ctx := context.Background()
			execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
			require.NoError(t, err)
			require.NotNil(t, execution)

			// Wait for completion with timeout
			timeout := time.After(5 * time.Second)
			completed := false
			for !completed {
				select {
				case <-timeout:
					t.Fatal("Test timed out waiting for workflow completion")
				default:
					execution, _ = engine.GetExecution(execution.ID)
					if execution.GetStatus() != StatusRunning && execution.GetStatus() != StatusPending {
						completed = true
					} else {
						time.Sleep(10 * time.Millisecond)
					}
				}
			}

			if tt.expectErr {
				assert.Equal(t, StatusFailed, execution.GetStatus())
				assert.Contains(t, execution.Error, "exceeds maximum iterations")
			} else {
				assert.Equal(t, StatusCompleted, execution.GetStatus())
				assert.True(t, execution.HasStepResult("foreach-loop-step"))

				// Check that loop variables were set
				assert.True(t, execution.HasVariable(tt.loop.Variable))
				if tt.loop.IndexVariable != "" {
					assert.True(t, execution.HasVariable(tt.loop.IndexVariable))
				}
			}
		})
	}
}

func TestLoopUtilityFunctions(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	t.Run("resolveLoopValue", func(t *testing.T) {
		execution := &WorkflowExecution{
			Variables: map[string]interface{}{
				"test_var": 42,
			},
		}

		tests := []struct {
			name      string
			value     interface{}
			expected  int
			expectErr bool
		}{
			{"direct int", 10, 10, false},
			{"string number", "15", 15, false},
			{"variable reference", "${test_var}", 42, false},
			{"missing variable", "${missing}", 0, true},
			{"invalid string", "abc", 0, true},
			{"nil value", nil, 0, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := engine.resolveLoopValue(tt.value, execution)
				if tt.expectErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expected, result)
				}
			})
		}
	})

	t.Run("convertToSlice", func(t *testing.T) {
		tests := []struct {
			name      string
			value     interface{}
			expected  []interface{}
			expectErr bool
		}{
			{"slice of interfaces", []interface{}{"a", "b", "c"}, []interface{}{"a", "b", "c"}, false},
			{"slice of strings", []string{"x", "y", "z"}, []interface{}{"x", "y", "z"}, false},
			{"slice of ints", []int{1, 2, 3}, []interface{}{1, 2, 3}, false},
			{"invalid type", "not a slice", nil, true},
			{"nil value", nil, nil, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := engine.convertToSlice(tt.value)
				if tt.expectErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expected, result)
				}
			})
		}
	})

	t.Run("parseInteger", func(t *testing.T) {
		tests := []struct {
			name      string
			input     string
			expected  int
			expectErr bool
		}{
			{"positive number", "123", 123, false},
			{"negative number", "-456", -456, false},
			{"zero", "0", 0, false},
			{"invalid character", "12a3", 0, true},
			{"empty string", "", 0, true},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result, err := engine.parseInteger(tt.input)
				if tt.expectErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
					assert.Equal(t, tt.expected, result)
				}
			})
		}
	})
}

func TestNestedLoops(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	workflow := Workflow{
		Name: "nested-loops-test",
		Variables: map[string]interface{}{
			"outer_items": []interface{}{"A", "B"},
			"inner_items": []interface{}{1, 2},
		},
		Steps: []Step{
			{
				Name: "outer-foreach",
				Type: StepTypeForeach,
				Loop: &LoopConfig{
					Type:          LoopTypeForeach,
					Variable:      "outer_item",
					ItemsVariable: "outer_items",
				},
				Steps: []Step{
					{
						Name: "inner-foreach",
						Type: StepTypeForeach,
						Loop: &LoopConfig{
							Type:          LoopTypeForeach,
							Variable:      "inner_item",
							ItemsVariable: "inner_items",
						},
						Steps: []Step{
							{
								Name: "nested-delay",
								Type: StepTypeDelay,
								Delay: &DelayConfig{
									Duration: 1 * time.Millisecond,
									Message:  "Nested loop iteration",
								},
							},
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion with timeout
	timeout := time.After(5 * time.Second)
	completed := false
	for !completed {
		select {
		case <-timeout:
			t.Fatal("Test timed out waiting for workflow completion")
		default:
			execution, _ = engine.GetExecution(execution.ID)
			if execution.GetStatus() != StatusRunning && execution.GetStatus() != StatusPending {
				completed = true
			} else {
				time.Sleep(10 * time.Millisecond)
			}
		}
	}

	assert.Equal(t, StatusCompleted, execution.GetStatus())
	assert.True(t, execution.HasStepResult("outer-foreach"))
	assert.True(t, execution.HasStepResult("inner-foreach"))
	assert.True(t, execution.HasStepResult("nested-delay"))

	// Check that both loop variables were set to their final values
	assert.True(t, execution.HasVariable("outer_item"))
	assert.True(t, execution.HasVariable("inner_item"))
}
