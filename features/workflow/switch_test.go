// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package workflow

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestSwitchStep_BasicFunctionality(t *testing.T) {
	tests := []struct {
		name           string
		switchValue    interface{}
		cases          []SwitchCase
		expectedStep   string
		expectedOutput map[string]interface{}
	}{
		{
			name:        "string_match_first_case",
			switchValue: "prod",
			cases: []SwitchCase{
				{
					Value: "prod",
					Steps: []Step{
						{
							Name: "production-setup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "Production environment setup",
							},
						},
					},
				},
				{
					Value: "staging",
					Steps: []Step{
						{
							Name: "staging-setup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "Staging environment setup",
							},
						},
					},
				},
			},
			expectedStep: "production-setup",
			expectedOutput: map[string]interface{}{
				"message": "Production environment setup",
			},
		},
		{
			name:        "numeric_match",
			switchValue: 42,
			cases: []SwitchCase{
				{
					Value: 42,
					Steps: []Step{
						{
							Name: "answer-found",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "The answer to everything",
							},
						},
					},
				},
				{
					Value: 0,
					Steps: []Step{
						{
							Name: "zero-case",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "Zero value",
							},
						},
					},
				},
			},
			expectedStep: "answer-found",
			expectedOutput: map[string]interface{}{
				"message": "The answer to everything",
			},
		},
		{
			name:        "boolean_match",
			switchValue: true,
			cases: []SwitchCase{
				{
					Value: true,
					Steps: []Step{
						{
							Name: "true-case",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "Boolean true matched",
							},
						},
					},
				},
				{
					Value: false,
					Steps: []Step{
						{
							Name: "false-case",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "Boolean false matched",
							},
						},
					},
				},
			},
			expectedStep: "true-case",
			expectedOutput: map[string]interface{}{
				"message": "Boolean true matched",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create workflow with switch step
			workflow := Workflow{
				Name: "switch-test",
				Variables: map[string]interface{}{
					"switch_value": tt.switchValue,
				},
				Steps: []Step{
					{
						Name: "switch-step",
						Type: StepTypeSwitch,
						Switch: &SwitchConfig{
							Variable: "switch_value",
							Cases:    tt.cases,
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

			// Verify the correct step was executed
			stepResults := execution.GetStepResults()
			assert.Contains(t, stepResults, tt.expectedStep)

			result := stepResults[tt.expectedStep]
			assert.Equal(t, StatusCompleted, result.Status)

			// Verify output if specified
			if tt.expectedOutput != nil {
				for key, expectedValue := range tt.expectedOutput {
					assert.Equal(t, expectedValue, result.Output[key])
				}
			}
		})
	}
}

func TestSwitchStep_DefaultCase(t *testing.T) {
	workflow := Workflow{
		Name: "switch-default-test",
		Variables: map[string]interface{}{
			"env": "unknown",
		},
		Steps: []Step{
			{
				Name: "switch-with-default",
				Type: StepTypeSwitch,
				Switch: &SwitchConfig{
					Variable: "env",
					Cases: []SwitchCase{
						{
							Value: "prod",
							Steps: []Step{
								{
									Name:  "prod-step",
									Type:  StepTypeDelay,
									Delay: &DelayConfig{Duration: 10 * time.Millisecond},
								},
							},
						},
						{
							Value: "staging",
							Steps: []Step{
								{
									Name:  "staging-step",
									Type:  StepTypeDelay,
									Delay: &DelayConfig{Duration: 10 * time.Millisecond},
								},
							},
						},
					},
					Default: []Step{
						{
							Name: "default-step",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 10 * time.Millisecond,
								Message:  "Default case executed",
							},
						},
					},
				},
			},
		},
	}

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

	// Verify default step was executed
	stepResults := execution.GetStepResults()
	assert.Contains(t, stepResults, "default-step")

	result := stepResults["default-step"]
	assert.Equal(t, StatusCompleted, result.Status)
	assert.Equal(t, "Default case executed", result.Output["message"])
}

func TestSwitchStep_NoMatchNoDefault(t *testing.T) {
	workflow := Workflow{
		Name: "switch-no-match-test",
		Variables: map[string]interface{}{
			"env": "unknown",
		},
		Steps: []Step{
			{
				Name: "switch-no-default",
				Type: StepTypeSwitch,
				Switch: &SwitchConfig{
					Variable: "env",
					Cases: []SwitchCase{
						{
							Value: "prod",
							Steps: []Step{
								{
									Name:  "prod-step",
									Type:  StepTypeDelay,
									Delay: &DelayConfig{Duration: 10 * time.Millisecond},
								},
							},
						},
					},
					// No default case
				},
			},
		},
	}

	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution completed successfully (no match is valid)
	assert.Equal(t, StatusCompleted, execution.GetStatus())

	// Verify no steps were executed for the switch
	stepResults := execution.GetStepResults()
	assert.NotContains(t, stepResults, "prod-step")
}

func TestSwitchStep_ExpressionBasedSwitch(t *testing.T) {
	workflow := Workflow{
		Name: "switch-expression-test",
		Variables: map[string]interface{}{
			"cpu_usage":    85,
			"memory_usage": 60,
		},
		Steps: []Step{
			{
				Name: "resource-switch",
				Type: StepTypeSwitch,
				Switch: &SwitchConfig{
					Expression: "${cpu_usage > 80 ? 'high_cpu' : (memory_usage > 70 ? 'high_memory' : 'normal')}",
					Cases: []SwitchCase{
						{
							Value: "high_cpu",
							Steps: []Step{
								{
									Name: "scale-cpu",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 10 * time.Millisecond,
										Message:  "Scaling up CPU resources",
									},
								},
							},
						},
						{
							Value: "high_memory",
							Steps: []Step{
								{
									Name: "scale-memory",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 10 * time.Millisecond,
										Message:  "Scaling up memory resources",
									},
								},
							},
						},
						{
							Value: "normal",
							Steps: []Step{
								{
									Name: "normal-operation",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 10 * time.Millisecond,
										Message:  "Normal operation",
									},
								},
							},
						},
					},
				},
			},
		},
	}

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

	// Verify high CPU case was executed (cpu_usage = 85 > 80)
	stepResults := execution.GetStepResults()
	assert.Contains(t, stepResults, "scale-cpu")

	result := stepResults["scale-cpu"]
	assert.Equal(t, StatusCompleted, result.Status)
	assert.Equal(t, "Scaling up CPU resources", result.Output["message"])
}

func TestSwitchStep_VariableResolutionError(t *testing.T) {
	workflow := Workflow{
		Name: "switch-error-test",
		Steps: []Step{
			{
				Name: "switch-missing-var",
				Type: StepTypeSwitch,
				Switch: &SwitchConfig{
					Variable: "nonexistent_var",
					Cases: []SwitchCase{
						{
							Value: "test",
							Steps: []Step{
								{
									Name:  "test-step",
									Type:  StepTypeDelay,
									Delay: &DelayConfig{Duration: 10 * time.Millisecond},
								},
							},
						},
					},
				},
			},
		},
	}

	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)
	ctx := context.Background()

	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	require.NotNil(t, execution)

	// Wait for completion
	time.Sleep(100 * time.Millisecond)

	// Verify execution failed due to missing variable
	assert.Equal(t, StatusFailed, execution.GetStatus())

	errorDetails := execution.GetErrorDetails()
	require.NotNil(t, errorDetails)
	assert.Equal(t, ErrorCodeVariableResolution, errorDetails.Code)
}

func TestSwitchStep_NestedSwitchStatements(t *testing.T) {
	workflow := Workflow{
		Name: "nested-switch-test",
		Variables: map[string]interface{}{
			"environment": "prod",
			"region":      "us-east",
		},
		Steps: []Step{
			{
				Name: "env-switch",
				Type: StepTypeSwitch,
				Switch: &SwitchConfig{
					Variable: "environment",
					Cases: []SwitchCase{
						{
							Value: "prod",
							Steps: []Step{
								{
									Name: "region-switch",
									Type: StepTypeSwitch,
									Switch: &SwitchConfig{
										Variable: "region",
										Cases: []SwitchCase{
											{
												Value: "us-east",
												Steps: []Step{
													{
														Name: "us-east-prod",
														Type: StepTypeDelay,
														Delay: &DelayConfig{
															Duration: 10 * time.Millisecond,
															Message:  "US East Production deployment",
														},
													},
												},
											},
											{
												Value: "eu-west",
												Steps: []Step{
													{
														Name: "eu-west-prod",
														Type: StepTypeDelay,
														Delay: &DelayConfig{
															Duration: 10 * time.Millisecond,
															Message:  "EU West Production deployment",
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

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

	// Verify nested switch executed correctly
	stepResults := execution.GetStepResults()
	assert.Contains(t, stepResults, "us-east-prod")

	result := stepResults["us-east-prod"]
	assert.Equal(t, StatusCompleted, result.Status)
	assert.Equal(t, "US East Production deployment", result.Output["message"])
}
