// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func TestWorkflowConditionalLogic(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	tests := []struct {
		name      string
		condition *Condition
		variables map[string]interface{}
		expected  bool
		expectErr bool
	}{
		{
			name: "simple variable equality - true",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "status",
				Operator: OperatorEqual,
				Value:    "active",
			},
			variables: map[string]interface{}{
				"status": "active",
			},
			expected: true,
		},
		{
			name: "simple variable equality - false",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "status",
				Operator: OperatorEqual,
				Value:    "active",
			},
			variables: map[string]interface{}{
				"status": "inactive",
			},
			expected: false,
		},
		{
			name: "variable not equal - true",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "status",
				Operator: OperatorNotEqual,
				Value:    "active",
			},
			variables: map[string]interface{}{
				"status": "inactive",
			},
			expected: true,
		},
		{
			name: "numeric greater than - true",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "count",
				Operator: OperatorGreaterThan,
				Value:    5,
			},
			variables: map[string]interface{}{
				"count": 10,
			},
			expected: true,
		},
		{
			name: "numeric greater than - false",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "count",
				Operator: OperatorGreaterThan,
				Value:    15,
			},
			variables: map[string]interface{}{
				"count": 10,
			},
			expected: false,
		},
		{
			name: "numeric less than - true",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "count",
				Operator: OperatorLessThan,
				Value:    15,
			},
			variables: map[string]interface{}{
				"count": 10,
			},
			expected: true,
		},
		{
			name: "string contains - true",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "message",
				Operator: OperatorContains,
				Value:    "error",
			},
			variables: map[string]interface{}{
				"message": "This is an error message",
			},
			expected: true,
		},
		{
			name: "string contains - false",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "message",
				Operator: OperatorContains,
				Value:    "success",
			},
			variables: map[string]interface{}{
				"message": "This is an error message",
			},
			expected: false,
		},
		{
			name: "variable exists - true",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "status",
				Operator: OperatorExists,
			},
			variables: map[string]interface{}{
				"status": "active",
			},
			expected: true,
		},
		{
			name: "variable exists - false",
			condition: &Condition{
				Type:     ConditionTypeVariable,
				Variable: "missing",
				Operator: OperatorExists,
			},
			variables: map[string]interface{}{
				"status": "active",
			},
			expected: false,
		},
		{
			name: "nested AND conditions - all true",
			condition: &Condition{
				Type: ConditionTypeAnd,
				And: []*Condition{
					{
						Type:     ConditionTypeVariable,
						Variable: "status",
						Operator: OperatorEqual,
						Value:    "active",
					},
					{
						Type:     ConditionTypeVariable,
						Variable: "count",
						Operator: OperatorGreaterThan,
						Value:    5,
					},
				},
			},
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: true,
		},
		{
			name: "nested AND conditions - one false",
			condition: &Condition{
				Type: ConditionTypeAnd,
				And: []*Condition{
					{
						Type:     ConditionTypeVariable,
						Variable: "status",
						Operator: OperatorEqual,
						Value:    "active",
					},
					{
						Type:     ConditionTypeVariable,
						Variable: "count",
						Operator: OperatorGreaterThan,
						Value:    15,
					},
				},
			},
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: false,
		},
		{
			name: "nested OR conditions - one true",
			condition: &Condition{
				Type: ConditionTypeOr,
				Or: []*Condition{
					{
						Type:     ConditionTypeVariable,
						Variable: "status",
						Operator: OperatorEqual,
						Value:    "inactive",
					},
					{
						Type:     ConditionTypeVariable,
						Variable: "count",
						Operator: OperatorGreaterThan,
						Value:    5,
					},
				},
			},
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: true,
		},
		{
			name: "nested OR conditions - all false",
			condition: &Condition{
				Type: ConditionTypeOr,
				Or: []*Condition{
					{
						Type:     ConditionTypeVariable,
						Variable: "status",
						Operator: OperatorEqual,
						Value:    "inactive",
					},
					{
						Type:     ConditionTypeVariable,
						Variable: "count",
						Operator: OperatorLessThan,
						Value:    5,
					},
				},
			},
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: false,
		},
		{
			name: "NOT condition - true",
			condition: &Condition{
				Type: ConditionTypeNot,
				Not: &Condition{
					Type:     ConditionTypeVariable,
					Variable: "status",
					Operator: OperatorEqual,
					Value:    "inactive",
				},
			},
			variables: map[string]interface{}{
				"status": "active",
			},
			expected: true,
		},
		{
			name: "NOT condition - false",
			condition: &Condition{
				Type: ConditionTypeNot,
				Not: &Condition{
					Type:     ConditionTypeVariable,
					Variable: "status",
					Operator: OperatorEqual,
					Value:    "active",
				},
			},
			variables: map[string]interface{}{
				"status": "active",
			},
			expected: false,
		},
		{
			name: "complex nested condition - 3 levels deep",
			condition: &Condition{
				Type: ConditionTypeAnd,
				And: []*Condition{
					{
						Type:     ConditionTypeVariable,
						Variable: "environment",
						Operator: OperatorEqual,
						Value:    "production",
					},
					{
						Type: ConditionTypeOr,
						Or: []*Condition{
							{
								Type:     ConditionTypeVariable,
								Variable: "priority",
								Operator: OperatorEqual,
								Value:    "high",
							},
							{
								Type: ConditionTypeAnd,
								And: []*Condition{
									{
										Type:     ConditionTypeVariable,
										Variable: "priority",
										Operator: OperatorEqual,
										Value:    "medium",
									},
									{
										Type:     ConditionTypeVariable,
										Variable: "urgent",
										Operator: OperatorEqual,
										Value:    true,
									},
								},
							},
						},
					},
				},
			},
			variables: map[string]interface{}{
				"environment": "production",
				"priority":    "medium",
				"urgent":      true,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.evaluateCondition(tt.condition, tt.variables)

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWorkflowExpressionConditions(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	tests := []struct {
		name       string
		expression string
		variables  map[string]interface{}
		expected   bool
		expectErr  bool
	}{
		{
			name:       "simple boolean true",
			expression: "true",
			variables:  map[string]interface{}{},
			expected:   true,
		},
		{
			name:       "simple boolean false",
			expression: "false",
			variables:  map[string]interface{}{},
			expected:   false,
		},
		{
			name:       "variable replacement and equality",
			expression: "${status} == 'active'",
			variables: map[string]interface{}{
				"status": "active",
			},
			expected: true,
		},
		{
			name:       "numeric comparison with variables",
			expression: "${count} > 5",
			variables: map[string]interface{}{
				"count": 10,
			},
			expected: true,
		},
		{
			name:       "AND expression - both true",
			expression: "${status} == 'active' && ${count} > 5",
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: true,
		},
		{
			name:       "AND expression - one false",
			expression: "${status} == 'active' && ${count} > 15",
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: false,
		},
		{
			name:       "OR expression - one true",
			expression: "${status} == 'inactive' || ${count} > 5",
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: true,
		},
		{
			name:       "OR expression - both false",
			expression: "${status} == 'inactive' || ${count} < 5",
			variables: map[string]interface{}{
				"status": "active",
				"count":  10,
			},
			expected: false,
		},
		{
			name:       "NOT expression - true",
			expression: "!${disabled}",
			variables: map[string]interface{}{
				"disabled": false,
			},
			expected: true,
		},
		{
			name:       "string contains in expression",
			expression: "${message} contains 'error'",
			variables: map[string]interface{}{
				"message": "This is an error message",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := &Condition{
				Type:       ConditionTypeExpression,
				Expression: tt.expression,
			}

			result, err := engine.evaluateCondition(condition, tt.variables)

			if tt.expectErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWorkflowConditionalExecution(t *testing.T) {
	logger := logging.NewLogger("info")
	engine := NewEngine(nil, logger)

	workflow := Workflow{
		Name: "conditional-test",
		Variables: map[string]interface{}{
			"environment":     "production",
			"feature_enabled": true,
		},
		Steps: []Step{
			{
				Name: "conditional-step",
				Type: StepTypeConditional,
				Condition: &Condition{
					Type: ConditionTypeAnd,
					And: []*Condition{
						{
							Type:     ConditionTypeVariable,
							Variable: "environment",
							Operator: OperatorEqual,
							Value:    "production",
						},
						{
							Type:     ConditionTypeVariable,
							Variable: "feature_enabled",
							Operator: OperatorEqual,
							Value:    true,
						},
					},
				},
				Steps: []Step{
					{
						Name: "inner-step",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 100 * 1000000, // 100ms in nanoseconds
							Message:  "Feature enabled in production",
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

	// Wait for completion
	for execution.GetStatus() == StatusRunning || execution.GetStatus() == StatusPending {
		// Small delay to allow workflow to complete
		time.Sleep(10 * time.Millisecond)
		execution, _ = engine.GetExecution(execution.ID)
	}

	// Additional wait for async goroutines to complete logging (Windows CI timing)
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, StatusCompleted, execution.GetStatus())
	assert.True(t, execution.HasStepResult("conditional-step"))
	assert.True(t, execution.HasStepResult("inner-step"))
}
