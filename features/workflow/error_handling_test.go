package workflow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWorkflowError(t *testing.T) {
	t.Run("NewWorkflowError creates comprehensive error", func(t *testing.T) {
		originalErr := errors.New("original error")
		stepName := "test-step"
		stepType := StepTypeTask
		
		wfErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"step failed",
			stepName,
			stepType,
			originalErr,
		)
		
		assert.Equal(t, ErrorCodeStepExecution, wfErr.Code)
		assert.Equal(t, "step failed", wfErr.Message)
		assert.Equal(t, stepName, wfErr.StepName)
		assert.Equal(t, stepType, wfErr.StepType)
		assert.Equal(t, originalErr, wfErr.Cause)
		assert.Equal(t, "original error", wfErr.CauseMessage)
		assert.Equal(t, 0, wfErr.RetryAttempt)
		assert.True(t, wfErr.Recoverable) // StepExecution is recoverable
		assert.NotEmpty(t, wfErr.StackTrace)
		assert.NotZero(t, wfErr.Timestamp)
	})

	t.Run("WithDetails adds debugging information", func(t *testing.T) {
		wfErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"step failed",
			"test-step",
			StepTypeTask,
			nil,
		).WithDetails("module", "file").WithDetails("path", "/tmp/test")
		
		assert.Equal(t, "file", wfErr.Details["module"])
		assert.Equal(t, "/tmp/test", wfErr.Details["path"])
	})

	t.Run("WithVariableState captures current state", func(t *testing.T) {
		variables := map[string]interface{}{
			"test_var": "test_value",
			"count":    42,
		}
		
		wfErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"step failed",
			"test-step",
			StepTypeTask,
			nil,
		).WithVariableState(variables)
		
		assert.Equal(t, "test_value", wfErr.VariableState["test_var"])
		assert.Equal(t, 42, wfErr.VariableState["count"])
	})

	t.Run("WithExecutionPath tracks workflow path", func(t *testing.T) {
		path := []string{"root", "parallel-1", "sequential-2", "task-3"}
		
		wfErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"step failed",
			"test-step",
			StepTypeTask,
			nil,
		).WithExecutionPath(path)
		
		assert.Equal(t, path, wfErr.ExecutionPath)
	})

	t.Run("Error returns formatted error message", func(t *testing.T) {
		wfErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"step failed",
			"test-step",
			StepTypeTask,
			errors.New("original error"),
		).WithRetryAttempt(2)
		
		errorMsg := wfErr.Error()
		assert.Contains(t, errorMsg, "STEP_EXECUTION_FAILED")
		assert.Contains(t, errorMsg, "step failed")
		assert.Contains(t, errorMsg, "step: test-step")
		assert.Contains(t, errorMsg, "retry: 2")
		assert.Contains(t, errorMsg, "cause: original error")
	})

	t.Run("FullError returns comprehensive debugging information", func(t *testing.T) {
		variables := map[string]interface{}{
			"test_var": "test_value",
		}
		path := []string{"root", "task"}
		
		wfErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"step failed",
			"test-step",
			StepTypeTask,
			errors.New("original error"),
		).WithVariableState(variables).WithExecutionPath(path).WithDetails("module", "file")
		
		fullError := wfErr.FullError()
		assert.Contains(t, fullError, "WorkflowError:")
		assert.Contains(t, fullError, "Code: STEP_EXECUTION_FAILED")
		assert.Contains(t, fullError, "Step: test-step (task)")
		assert.Contains(t, fullError, "Execution Path: root -> task")
		assert.Contains(t, fullError, "Variable State:")
		assert.Contains(t, fullError, "test_var: test_value")
		assert.Contains(t, fullError, "Details:")
		assert.Contains(t, fullError, "module: file")
		assert.Contains(t, fullError, "Stack Trace:")
	})

	t.Run("AddChildError supports nested errors", func(t *testing.T) {
		parentErr := NewWorkflowError(
			ErrorCodeStepExecution,
			"parallel step failed",
			"parallel-step",
			StepTypeParallel,
			nil,
		)
		
		childErr1 := NewWorkflowError(
			ErrorCodeStepExecution,
			"child 1 failed",
			"child-1",
			StepTypeTask,
			errors.New("child error 1"),
		)
		
		childErr2 := NewWorkflowError(
			ErrorCodeTimeout,
			"child 2 timed out",
			"child-2",
			StepTypeTask,
			errors.New("timeout error"),
		)
		
		parentErr.AddChildError(childErr1)
		parentErr.AddChildError(childErr2)
		
		assert.Len(t, parentErr.ChildErrors, 2)
		assert.Equal(t, "child 1 failed", parentErr.ChildErrors[0].Message)
		assert.Equal(t, "child 2 timed out", parentErr.ChildErrors[1].Message)
		
		fullError := parentErr.FullError()
		assert.Contains(t, fullError, "Child Errors:")
		assert.Contains(t, fullError, "[1]")
		assert.Contains(t, fullError, "[2]")
	})
}

func TestDefaultErrorHandler(t *testing.T) {
	handler := NewDefaultErrorHandler()
	
	t.Run("HandleError returns appropriate decisions", func(t *testing.T) {
		execution := &WorkflowExecution{
			ID:        "test-execution",
			Variables: make(map[string]interface{}),
		}
		ctx := context.Background()
		
		// Test cancellation error
		cancelErr := NewWorkflowError(
			ErrorCodeCancellation,
			"workflow cancelled",
			"test-step",
			StepTypeTask,
			context.Canceled,
		)
		
		decision := handler.HandleError(ctx, cancelErr, execution)
		assert.Equal(t, ErrorActionStop, decision.Action)
		assert.Contains(t, decision.Message, "cancelled")
		
		// Test recoverable error with retry
		recoverableErr := NewWorkflowError(
			ErrorCodeHTTPRequest,
			"HTTP request failed",
			"http-step",
			StepTypeHTTP,
			errors.New("connection refused"),
		).WithRetryAttempt(1)
		
		decision = handler.HandleError(ctx, recoverableErr, execution)
		assert.Equal(t, ErrorActionRetry, decision.Action)
		assert.Greater(t, decision.RetryDelay, time.Duration(0))
		assert.Contains(t, decision.Message, "Retrying")
		
		// Test validation error
		validationErr := NewWorkflowError(
			ErrorCodeValidation,
			"invalid configuration",
			"config-step",
			StepTypeTask,
			errors.New("required field missing"),
		)
		
		decision = handler.HandleError(ctx, validationErr, execution)
		assert.Equal(t, ErrorActionStop, decision.Action)
		assert.Contains(t, decision.Message, "configuration error")
		
		// Test infinite loop error
		loopErr := NewWorkflowError(
			ErrorCodeInfiniteLoop,
			"loop exceeded maximum iterations",
			"while-step",
			StepTypeWhile,
			errors.New("infinite loop detected"),
		)
		
		decision = handler.HandleError(ctx, loopErr, execution)
		assert.Equal(t, ErrorActionStop, decision.Action)
		assert.Contains(t, decision.Message, "infinite loop")
	})
	
	t.Run("ShouldRetry respects retry limits", func(t *testing.T) {
		recoverableErr := NewWorkflowError(
			ErrorCodeHTTPRequest,
			"HTTP request failed",
			"http-step",
			StepTypeHTTP,
			errors.New("connection refused"),
		)
		
		// Should retry within limits
		assert.True(t, handler.ShouldRetry(recoverableErr, 0, nil))
		assert.True(t, handler.ShouldRetry(recoverableErr, 2, nil))
		
		// Should not retry beyond limits
		assert.False(t, handler.ShouldRetry(recoverableErr, 3, nil))
		assert.False(t, handler.ShouldRetry(recoverableErr, 5, nil))
		
		// Should not retry non-recoverable errors
		nonRecoverableErr := NewWorkflowError(
			ErrorCodeValidation,
			"validation failed",
			"validation-step",
			StepTypeTask,
			errors.New("invalid input"),
		)
		
		assert.False(t, handler.ShouldRetry(nonRecoverableErr, 0, nil))
	})
	
	t.Run("CalculateRetryDelay implements exponential backoff", func(t *testing.T) {
		// Test default exponential backoff
		delay0 := handler.CalculateRetryDelay(0, nil)
		delay1 := handler.CalculateRetryDelay(1, nil)
		delay2 := handler.CalculateRetryDelay(2, nil)
		
		assert.Equal(t, handler.BaseDelay, delay0)
		assert.Equal(t, handler.BaseDelay*2, delay1)
		assert.Equal(t, handler.BaseDelay*4, delay2)
		
		// Test with retry config
		retryConfig := &RetryConfig{
			MaxAttempts:       5,
			InitialDelay:      500 * time.Millisecond,
			MaxDelay:          10 * time.Second,
			BackoffMultiplier: 3.0,
		}
		
		configDelay0 := handler.CalculateRetryDelay(0, retryConfig)
		configDelay1 := handler.CalculateRetryDelay(1, retryConfig)
		
		assert.Equal(t, retryConfig.InitialDelay, configDelay0)
		assert.Equal(t, time.Duration(float64(retryConfig.InitialDelay)*3.0), configDelay1)
		
		// Test max delay cap
		highDelayConfig := &RetryConfig{
			InitialDelay:      1 * time.Second,
			MaxDelay:          2 * time.Second,
			BackoffMultiplier: 10.0,
		}
		
		cappedDelay := handler.CalculateRetryDelay(5, highDelayConfig) // Should be capped
		assert.Equal(t, highDelayConfig.MaxDelay, cappedDelay)
	})
}

func TestErrorHandlingIntegration(t *testing.T) {
	t.Skip("Skipping integration test - requires module factory setup")
	
	t.Run("Workflow handles step errors appropriately", func(t *testing.T) {
		// Test is skipped - would require proper module factory setup
		// This test would create a workflow with a failing step and verify
		// that error handling works correctly throughout the execution chain
	})
}

func TestExecutionTrace(t *testing.T) {
	execution := &WorkflowExecution{
		Variables: map[string]interface{}{
			"test_var": "test_value",
		},
	}
	
	// Add execution trace entries
	AddExecutionTrace(execution, "step1", StepTypeTask, StatusCompleted, 100*time.Millisecond, execution.GetVariables(), "", 0)
	AddExecutionTrace(execution, "step2", StepTypeDelay, StatusFailed, 50*time.Millisecond, execution.GetVariables(), "step1", 0)
	AddExecutionTrace(execution, "step3", StepTypeTask, StatusCompleted, 75*time.Millisecond, execution.GetVariables(), "step2", 2)
	
	executionTrace := execution.GetExecutionTrace()
	require.Len(t, executionTrace, 3)
	
	// Verify first trace entry
	trace1 := executionTrace[0]
	assert.Equal(t, "step1", trace1.StepName)
	assert.Equal(t, StepTypeTask, trace1.StepType)
	assert.Equal(t, StatusCompleted, trace1.Status)
	assert.Equal(t, 100*time.Millisecond, trace1.Duration)
	assert.Equal(t, "", trace1.ParentStep)
	assert.Equal(t, 0, trace1.LoopIteration)
	assert.NotEmpty(t, trace1.Variables)
	
	// Verify second trace entry
	trace2 := executionTrace[1]
	assert.Equal(t, "step2", trace2.StepName)
	assert.Equal(t, StatusFailed, trace2.Status)
	assert.Equal(t, "step1", trace2.ParentStep)
	
	// Verify third trace entry
	trace3 := executionTrace[2]
	assert.Equal(t, "step3", trace3.StepName)
	assert.Equal(t, 2, trace3.LoopIteration)
}

func TestRetryAttempts(t *testing.T) {
	result := &StepResult{}
	variables := map[string]interface{}{
		"retry_var": "retry_value",
	}
	
	err1 := NewWorkflowError(
		ErrorCodeHTTPRequest,
		"first attempt failed",
		"http-step",
		StepTypeHTTP,
		errors.New("connection refused"),
	)
	
	err2 := NewWorkflowError(
		ErrorCodeHTTPRequest,
		"second attempt failed",
		"http-step",
		StepTypeHTTP,
		errors.New("timeout"),
	)
	
	// Record retry attempts
	RecordRetryAttempt(result, 1, err1, 1*time.Second, variables)
	RecordRetryAttempt(result, 2, err2, 2*time.Second, variables)
	
	require.Len(t, result.RetryAttempts, 2)
	
	// Verify first retry attempt
	retry1 := result.RetryAttempts[0]
	assert.Equal(t, 1, retry1.AttemptNumber)
	assert.Equal(t, 1*time.Second, retry1.Delay)
	assert.Equal(t, "first attempt failed", retry1.Error.Message)
	assert.Equal(t, "retry_value", retry1.Variables["retry_var"])
	
	// Verify second retry attempt
	retry2 := result.RetryAttempts[1]
	assert.Equal(t, 2, retry2.AttemptNumber)
	assert.Equal(t, 2*time.Second, retry2.Delay)
	assert.Equal(t, "second attempt failed", retry2.Error.Message)
}

func TestStackTraceCapture(t *testing.T) {
	err := NewWorkflowError(
		ErrorCodeStepExecution,
		"test error with stack trace",
		"test-step",
		StepTypeTask,
		nil,
	)
	
	// Verify stack trace was captured
	assert.NotEmpty(t, err.StackTrace)
	
	// Verify stack frames contain expected information
	found := false
	for _, frame := range err.StackTrace {
		if strings.Contains(frame.Function, "TestStackTraceCapture") {
			found = true
			assert.Contains(t, frame.File, "error_handling_test.go")
			assert.Greater(t, frame.Line, 0)
			break
		}
	}
	assert.True(t, found, "Expected to find test function in stack trace")
}

func TestBuildExecutionPath(t *testing.T) {
	// Test building execution path
	path1 := BuildExecutionPath("step1", nil)
	assert.Equal(t, []string{"step1"}, path1)
	
	path2 := BuildExecutionPath("step2", []string{"root"})
	assert.Equal(t, []string{"root", "step2"}, path2)
	
	path3 := BuildExecutionPath("step3", []string{"root", "parallel", "sequential"})
	assert.Equal(t, []string{"root", "parallel", "sequential", "step3"}, path3)
}

func TestIsRecoverableErrorCode(t *testing.T) {
	// Test recoverable error codes
	assert.True(t, isRecoverableErrorCode(ErrorCodeTimeout))
	assert.True(t, isRecoverableErrorCode(ErrorCodeHTTPRequest))
	assert.True(t, isRecoverableErrorCode(ErrorCodeAPIRequest))
	assert.True(t, isRecoverableErrorCode(ErrorCodeWebhookDelivery))
	assert.True(t, isRecoverableErrorCode(ErrorCodeRateLimitExceeded))
	assert.True(t, isRecoverableErrorCode(ErrorCodeModuleExecution))
	
	// Test non-recoverable error codes
	assert.False(t, isRecoverableErrorCode(ErrorCodeValidation))
	assert.False(t, isRecoverableErrorCode(ErrorCodeConditionEvaluation))
	assert.False(t, isRecoverableErrorCode(ErrorCodeVariableResolution))
	assert.False(t, isRecoverableErrorCode(ErrorCodeInfiniteLoop))
	assert.False(t, isRecoverableErrorCode(ErrorCodeCancellation))
	assert.False(t, isRecoverableErrorCode(ErrorCodeUnknown))
}