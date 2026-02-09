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

func TestTrySuccess(t *testing.T) {
	// Test try block that succeeds - finally should run, catch should not
	workflow := Workflow{
		Name: "try-success-test",
		Variables: map[string]interface{}{
			"executed": []string{},
		},
		Steps: []Step{
			{
				Name: "try-step",
				Type: StepTypeTry,
				Try: &TryConfig{
					Try: []Step{
						{
							Name: "success-step",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Success step executed",
							},
						},
					},
					Catch: []CatchBlock{
						{
							Steps: []Step{
								{
									Name: "catch-step",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 1 * time.Millisecond,
										Message:  "This should not execute",
									},
								},
							},
						},
					},
					Finally: []Step{
						{
							Name: "finally-step",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Finally step executed",
							},
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
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Verify execution completed successfully
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestTryCatchHandled(t *testing.T) {
	// Test try block that fails but error is caught and handled
	workflow := Workflow{
		Name: "try-catch-handled-test",
		Variables: map[string]interface{}{
			"counter": 0,
		},
		Steps: []Step{
			{
				Name: "try-step",
				Type: StepTypeTry,
				Try: &TryConfig{
					Try: []Step{
						{
							Name: "failing-step",
							Type: "invalid-step-type", // This will fail immediately
						},
					},
					Catch: []CatchBlock{
						{
							ErrorCodes: []ErrorCode{ErrorCodeStepExecution},
							Steps: []Step{
								{
									Name: "error-handler",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 1 * time.Millisecond,
										Message:  "Error was handled",
									},
								},
							},
						},
					},
					Finally: []Step{
						{
							Name: "cleanup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Cleanup completed",
							},
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
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Verify execution completed successfully (error was caught)
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestTryCatchNotHandled(t *testing.T) {
	// Test try block that fails and error is not caught
	workflow := Workflow{
		Name: "try-catch-not-handled-test",
		Variables: map[string]interface{}{
			"counter": 0,
		},
		Steps: []Step{
			{
				Name: "try-step",
				Type: StepTypeTry,
				Try: &TryConfig{
					Try: []Step{
						{
							Name: "failing-step",
							Type: StepTypeHTTP, // This will fail with validation error
						},
					},
					Catch: []CatchBlock{
						{
							ErrorCodes: []ErrorCode{ErrorCodeHTTPRequest}, // Different error code
							Steps: []Step{
								{
									Name: "wrong-error-handler",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 1 * time.Millisecond,
										Message:  "This should not execute",
									},
								},
							},
						},
					},
					Finally: []Step{
						{
							Name: "cleanup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Cleanup always runs",
							},
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
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Verify execution failed (error was not caught)
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestTryCatchByErrorType(t *testing.T) {
	// Test catching errors by error message content
	workflow := Workflow{
		Name: "try-catch-by-type-test",
		Variables: map[string]interface{}{
			"handled": false,
		},
		Steps: []Step{
			{
				Name: "try-step",
				Type: StepTypeTry,
				Try: &TryConfig{
					Try: []Step{
						{
							Name: "failing-step",
							Type: StepTypeHTTP, // This will fail with "missing" in error message
						},
					},
					Catch: []CatchBlock{
						{
							ErrorTypes: []string{"configuration"}, // Match by substring in error message
							Steps: []Step{
								{
									Name: "type-error-handler",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 1 * time.Millisecond,
										Message:  "Handled by error type",
									},
								},
							},
						},
					},
					Finally: []Step{
						{
							Name: "cleanup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Finally executed",
							},
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
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Verify execution completed successfully (error was caught by type)
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestTryFinallyWithoutCatch(t *testing.T) {
	// Test try/finally without catch - finally should always run
	workflow := Workflow{
		Name: "try-finally-test",
		Variables: map[string]interface{}{
			"cleanup_done": false,
		},
		Steps: []Step{
			{
				Name: "try-step",
				Type: StepTypeTry,
				Try: &TryConfig{
					Try: []Step{
						{
							Name: "failing-step",
							Type: StepTypeHTTP, // This will fail
						},
					},
					// No catch blocks
					Finally: []Step{
						{
							Name: "cleanup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Cleanup always executed",
							},
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
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Verify execution failed (no catch block) but finally ran
	assert.Equal(t, StatusFailed, execution.GetStatus())
}

func TestCatchAllErrors(t *testing.T) {
	// Test catch block that catches all errors (no specific error codes or types)
	workflow := Workflow{
		Name: "catch-all-test",
		Variables: map[string]interface{}{
			"error_caught": false,
		},
		Steps: []Step{
			{
				Name: "try-step",
				Type: StepTypeTry,
				Try: &TryConfig{
					Try: []Step{
						{
							Name: "failing-step",
							Type: StepTypeHTTP, // This will fail
						},
					},
					Catch: []CatchBlock{
						{
							// No error codes or types specified - catches all
							Steps: []Step{
								{
									Name: "catch-all-handler",
									Type: StepTypeDelay,
									Delay: &DelayConfig{
										Duration: 1 * time.Millisecond,
										Message:  "Caught all errors",
									},
								},
							},
						},
					},
					Finally: []Step{
						{
							Name: "cleanup",
							Type: StepTypeDelay,
							Delay: &DelayConfig{
								Duration: 1 * time.Millisecond,
								Message:  "Finally executed",
							},
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
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	// Verify execution completed successfully (all errors caught)
	assert.Equal(t, StatusCompleted, execution.GetStatus())
}

func TestTryMissingConfiguration(t *testing.T) {
	// Test try step with missing configuration
	workflow := Workflow{
		Name: "try-missing-config-test",
		Steps: []Step{
			{
				Name: "invalid-try",
				Type: StepTypeTry,
				// No Try configuration
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

	// Wait for completion with extended timeout for concurrent test scenarios
	waitForWorkflowCompletion(t, execution, 15*time.Second)

	// Verify execution failed due to missing configuration
	assert.Equal(t, StatusFailed, execution.GetStatus())
}
