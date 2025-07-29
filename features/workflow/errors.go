package workflow

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// NewWorkflowError creates a new WorkflowError with comprehensive debugging information
func NewWorkflowError(code ErrorCode, message string, stepName string, stepType StepType, cause error) *WorkflowError {
	err := &WorkflowError{
		Code:         code,
		Message:      message,
		Timestamp:    time.Now(),
		StepName:     stepName,
		StepType:     stepType,
		Cause:        cause,
		RetryAttempt: 0,
		Recoverable:  isRecoverableErrorCode(code),
		Details:      make(map[string]interface{}),
	}

	if cause != nil {
		err.CauseMessage = cause.Error()
	}

	// Capture stack trace
	err.StackTrace = captureStackTrace(3) // Skip NewWorkflowError, caller, and runtime frames

	return err
}

// WithDetails adds additional details to the error for debugging
func (e *WorkflowError) WithDetails(key string, value interface{}) *WorkflowError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// WithExecutionPath sets the execution path for the error
func (e *WorkflowError) WithExecutionPath(path []string) *WorkflowError {
	e.ExecutionPath = path
	return e
}

// WithVariableState captures the current variable state
func (e *WorkflowError) WithVariableState(variables map[string]interface{}) *WorkflowError {
	// Deep copy variables to prevent modification
	e.VariableState = make(map[string]interface{})
	for k, v := range variables {
		e.VariableState[k] = v
	}
	return e
}

// WithRetryAttempt sets the retry attempt number
func (e *WorkflowError) WithRetryAttempt(attemptNumber int) *WorkflowError {
	e.RetryAttempt = attemptNumber
	return e
}

// AddChildError adds a child error (useful for parallel/sequential step errors)
func (e *WorkflowError) AddChildError(childErr *WorkflowError) {
	if e.ChildErrors == nil {
		e.ChildErrors = make([]*WorkflowError, 0)
	}
	e.ChildErrors = append(e.ChildErrors, childErr)
}

// Error implements the error interface
func (e *WorkflowError) Error() string {
	var parts []string
	
	parts = append(parts, fmt.Sprintf("[%s] %s", e.Code, e.Message))
	
	if e.StepName != "" {
		parts = append(parts, fmt.Sprintf("step: %s", e.StepName))
	}
	
	if e.RetryAttempt > 0 {
		parts = append(parts, fmt.Sprintf("retry: %d", e.RetryAttempt))
	}
	
	if e.CauseMessage != "" {
		parts = append(parts, fmt.Sprintf("cause: %s", e.CauseMessage))
	}
	
	return strings.Join(parts, ", ")
}

// FullError returns a comprehensive error string with all debugging information
func (e *WorkflowError) FullError() string {
	var builder strings.Builder
	
	builder.WriteString(fmt.Sprintf("WorkflowError: %s\n", e.Error()))
	builder.WriteString(fmt.Sprintf("  Code: %s\n", e.Code))
	builder.WriteString(fmt.Sprintf("  Message: %s\n", e.Message))
	builder.WriteString(fmt.Sprintf("  Timestamp: %s\n", e.Timestamp.Format(time.RFC3339)))
	builder.WriteString(fmt.Sprintf("  Step: %s (%s)\n", e.StepName, e.StepType))
	builder.WriteString(fmt.Sprintf("  Recoverable: %t\n", e.Recoverable))
	builder.WriteString(fmt.Sprintf("  Retry Attempt: %d\n", e.RetryAttempt))
	
	if len(e.ExecutionPath) > 0 {
		builder.WriteString(fmt.Sprintf("  Execution Path: %s\n", strings.Join(e.ExecutionPath, " -> ")))
	}
	
	if len(e.VariableState) > 0 {
		builder.WriteString("  Variable State:\n")
		for k, v := range e.VariableState {
			builder.WriteString(fmt.Sprintf("    %s: %v\n", k, v))
		}
	}
	
	if len(e.Details) > 0 {
		builder.WriteString("  Details:\n")
		for k, v := range e.Details {
			builder.WriteString(fmt.Sprintf("    %s: %v\n", k, v))
		}
	}
	
	if len(e.StackTrace) > 0 {
		builder.WriteString("  Stack Trace:\n")
		for _, frame := range e.StackTrace {
			builder.WriteString(fmt.Sprintf("    %s:%d in %s()\n", frame.File, frame.Line, frame.Function))
		}
	}
	
	if len(e.ChildErrors) > 0 {
		builder.WriteString("  Child Errors:\n")
		for i, childErr := range e.ChildErrors {
			lines := strings.Split(childErr.FullError(), "\n")
			for j, line := range lines {
				if j == 0 {
					builder.WriteString(fmt.Sprintf("    [%d] %s\n", i+1, line))
				} else if line != "" {
					builder.WriteString(fmt.Sprintf("      %s\n", line))
				}
			}
		}
	}
	
	return builder.String()
}

// captureStackTrace captures the current stack trace
func captureStackTrace(skip int) []StackFrame {
	const maxFrames = 32
	frames := make([]StackFrame, 0, maxFrames)
	
	pcs := make([]uintptr, maxFrames)
	n := runtime.Callers(skip, pcs)
	
	if n == 0 {
		return frames
	}
	
	runtimeFrames := runtime.CallersFrames(pcs[:n])
	
	for {
		frame, more := runtimeFrames.Next()
		
		// Skip runtime and testing frames for cleaner stack traces
		if !strings.Contains(frame.Function, "runtime.") && 
		   !strings.Contains(frame.Function, "testing.") {
			frames = append(frames, StackFrame{
				Function: frame.Function,
				File:     frame.File,
				Line:     frame.Line,
			})
		}
		
		if !more {
			break
		}
	}
	
	return frames
}

// isRecoverableErrorCode determines if an error code represents a recoverable error
func isRecoverableErrorCode(code ErrorCode) bool {
	recoverableErrors := map[ErrorCode]bool{
		ErrorCodeStepExecution:        true, // Many step execution errors are recoverable
		ErrorCodeTimeout:              true,
		ErrorCodeHTTPRequest:          true,
		ErrorCodeAPIRequest:           true,
		ErrorCodeWebhookDelivery:      true,
		ErrorCodeRateLimitExceeded:    true,
		ErrorCodeModuleExecution:      true, // May be recoverable depending on the specific error
		ErrorCodeAuthenticationFailure: true, // May be temporary auth issues
	}
	
	return recoverableErrors[code]
}

// DefaultErrorHandler provides a default implementation of ErrorHandler
type DefaultErrorHandler struct {
	// MaxRetries is the default maximum number of retries
	MaxRetries int
	
	// BaseDelay is the base delay for exponential backoff
	BaseDelay time.Duration
	
	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration
	
	// BackoffMultiplier is the multiplier for exponential backoff
	BackoffMultiplier float64
}

// NewDefaultErrorHandler creates a new default error handler
func NewDefaultErrorHandler() *DefaultErrorHandler {
	return &DefaultErrorHandler{
		MaxRetries:        3,
		BaseDelay:         1 * time.Second,
		MaxDelay:          30 * time.Second,
		BackoffMultiplier: 2.0,
	}
}

// HandleError implements the ErrorHandler interface
func (h *DefaultErrorHandler) HandleError(ctx context.Context, err *WorkflowError, execution *WorkflowExecution) ErrorHandlingDecision {
	// Check if the error should be ignored
	if err.Code == ErrorCodeCancellation {
		return ErrorHandlingDecision{
			Action:  ErrorActionStop,
			Message: "Workflow was cancelled",
		}
	}
	
	// Check if error is recoverable and should be retried
	if err.Recoverable && err.RetryAttempt < h.MaxRetries {
		delay := h.CalculateRetryDelay(err.RetryAttempt, nil)
		return ErrorHandlingDecision{
			Action:     ErrorActionRetry,
			Message:    fmt.Sprintf("Retrying step after recoverable error (attempt %d/%d)", err.RetryAttempt+1, h.MaxRetries),
			RetryDelay: delay,
		}
	}
	
	// For non-recoverable errors or exhausted retries, check error type
	switch err.Code {
	case ErrorCodeValidation, ErrorCodeConditionEvaluation, ErrorCodeVariableResolution:
		// These are typically configuration errors that won't be fixed by retrying
		return ErrorHandlingDecision{
			Action:  ErrorActionStop,
			Message: "Stopping workflow due to configuration error",
		}
	case ErrorCodeInfiniteLoop:
		// Infinite loop detection should stop the workflow
		return ErrorHandlingDecision{
			Action:  ErrorActionStop,
			Message: "Stopping workflow due to infinite loop detection",
		}
	default:
		// For other errors, continue with next step if possible
		return ErrorHandlingDecision{
			Action:  ErrorActionContinue,
			Message: "Continuing with next step after error",
		}
	}
}

// ShouldRetry implements the ErrorHandler interface
func (h *DefaultErrorHandler) ShouldRetry(err *WorkflowError, retryCount int, config *RetryConfig) bool {
	if config != nil {
		return retryCount < config.MaxAttempts && err.Recoverable
	}
	return retryCount < h.MaxRetries && err.Recoverable
}

// CalculateRetryDelay implements the ErrorHandler interface
func (h *DefaultErrorHandler) CalculateRetryDelay(retryCount int, config *RetryConfig) time.Duration {
	if config != nil {
		delay := config.InitialDelay
		for i := 0; i < retryCount; i++ {
			delay = time.Duration(float64(delay) * config.BackoffMultiplier)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
				break
			}
		}
		return delay
	}
	
	// Use default exponential backoff
	delay := h.BaseDelay
	for i := 0; i < retryCount; i++ {
		delay = time.Duration(float64(delay) * h.BackoffMultiplier)
		if delay > h.MaxDelay {
			delay = h.MaxDelay
			break
		}
	}
	return delay
}

// BuildExecutionPath builds the execution path for error context
func BuildExecutionPath(currentStep string, parentPath []string) []string {
	if len(parentPath) == 0 {
		return []string{currentStep}
	}
	
	path := make([]string, len(parentPath)+1)
	copy(path, parentPath)
	path[len(parentPath)] = currentStep
	return path
}

// RecordRetryAttempt records a retry attempt for debugging
func RecordRetryAttempt(result *StepResult, attemptNumber int, err *WorkflowError, delay time.Duration, variables map[string]interface{}) {
	if result.RetryAttempts == nil {
		result.RetryAttempts = make([]RetryAttempt, 0)
	}
	
	attempt := RetryAttempt{
		AttemptNumber: attemptNumber,
		Timestamp:     time.Now(),
		Error:         err,
		Delay:         delay,
	}
	
	// Copy variables
	if variables != nil {
		attempt.Variables = make(map[string]interface{})
		for k, v := range variables {
			attempt.Variables[k] = v
		}
	}
	
	result.RetryAttempts = append(result.RetryAttempts, attempt)
}

// AddExecutionTrace adds a step to the execution trace
func AddExecutionTrace(execution *WorkflowExecution, stepName string, stepType StepType, status ExecutionStatus, duration time.Duration, variables map[string]interface{}, parentStep string, loopIteration int) {
	if execution.ExecutionTrace == nil {
		execution.ExecutionTrace = make([]ExecutionStep, 0)
	}
	
	step := ExecutionStep{
		StepName:      stepName,
		StepType:      stepType,
		Timestamp:     time.Now(),
		Duration:      duration,
		Status:        status,
		ParentStep:    parentStep,
		LoopIteration: loopIteration,
	}
	
	// Copy variables
	if variables != nil {
		step.Variables = make(map[string]interface{})
		for k, v := range variables {
			step.Variables[k] = v
		}
	}
	
	execution.ExecutionTrace = append(execution.ExecutionTrace, step)
}