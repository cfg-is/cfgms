// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

// executionIDCounter ensures unique IDs even when time.Now().UnixNano() returns
// the same value (Windows has ~15.6ms clock granularity).
var executionIDCounter atomic.Uint64

// Engine implements the WorkflowEngine interface
type Engine struct {
	moduleFactory    *factory.ModuleFactory
	logger           *logging.ModuleLogger
	executions       map[string]*WorkflowExecution
	mutex            sync.RWMutex
	httpClient       *HTTPClient
	providerRegistry *ProviderRegistry
	errorHandler     ErrorHandler
	syncManager      *SyncManager
	debugEngine      *DebugEngineImpl
}

// NewEngine creates a new workflow engine instance
func NewEngine(moduleFactory *factory.ModuleFactory, logger logging.Logger) *Engine {
	// Create module logger for structured workflow logging
	workflowLogger := logging.ForModule("workflow").WithField("component", "engine")

	// Create HTTP client with default configuration
	httpClient := NewHTTPClient(HTTPClientConfig{
		Timeout: 30 * time.Second,
		DefaultRetryConfig: &RetryConfig{
			MaxAttempts:       3,
			InitialDelay:      time.Second,
			MaxDelay:          30 * time.Second,
			BackoffMultiplier: 2.0,
		},
	})

	// Create provider registry with workflow logger for consistency
	// Note: ProviderRegistry will need updating to accept ModuleLogger
	providerRegistry := NewProviderRegistry(logger) // Keep legacy for now

	engine := &Engine{
		moduleFactory:    moduleFactory,
		logger:           workflowLogger,
		executions:       make(map[string]*WorkflowExecution),
		httpClient:       httpClient,
		providerRegistry: providerRegistry,
		errorHandler:     NewDefaultErrorHandler(),
		syncManager:      NewSyncManager(),
	}

	// Initialize debug engine
	engine.debugEngine = NewDebugEngine(engine, logger)

	return engine
}

// ExecuteWorkflow starts execution of a workflow
func (e *Engine) ExecuteWorkflow(ctx context.Context, workflow Workflow, variables map[string]interface{}) (*WorkflowExecution, error) {
	executionID := generateExecutionID()

	// Create execution context with timeout if specified
	var execCtx context.Context
	var cancel context.CancelFunc
	if workflow.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, workflow.Timeout)
	} else {
		execCtx, cancel = context.WithCancel(ctx)
	}

	// Merge workflow variables with provided variables
	mergedVars := make(map[string]interface{})
	for k, v := range workflow.Variables {
		mergedVars[k] = v
	}
	for k, v := range variables {
		mergedVars[k] = v
	}

	execution := &WorkflowExecution{
		ID:           executionID,
		WorkflowName: workflow.Name,
		Status:       StatusPending,
		StartTime:    time.Now(),
		StepResults:  make(map[string]StepResult),
		Variables:    mergedVars,
		Context:      execCtx,
		Cancel:       cancel,
		Done:         make(chan struct{}),
	}

	// Store execution
	e.mutex.Lock()
	e.executions[executionID] = execution
	e.mutex.Unlock()

	// Extract tenant context for structured logging
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := e.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting workflow execution",
		"operation", "workflow_execute",
		"execution_id", executionID,
		"workflow", workflow.Name,
		"step_count", len(workflow.Steps))

	// Start execution in goroutine
	go e.executeWorkflowAsync(execution, workflow)

	return execution, nil
}

// executeWorkflowAsync executes the workflow asynchronously
func (e *Engine) executeWorkflowAsync(execution *WorkflowExecution, workflow Workflow) {
	// Close Done channel after all work (including logging) completes.
	// This is the first defer so it runs last (LIFO), after the panic recovery
	// defer below finishes its logging.
	defer close(execution.Done)

	execution.SetStatus(StatusRunning)

	defer func() {
		if r := recover(); r != nil {
			panicErr := NewWorkflowError(
				ErrorCodeUnknown,
				fmt.Sprintf("workflow panicked: %v", r),
				"",
				"",
				fmt.Errorf("%v", r),
			).WithVariableState(execution.Variables)

			execution.SetError(panicErr.Error())
			execution.SetErrorDetails(panicErr)
			endTime := time.Now()
			execution.SetEndTime(&endTime)
			execution.SetStatus(StatusFailed)
			e.logger.Error("Workflow execution panicked",
				"execution_id", execution.ID,
				"error", panicErr.FullError())
		}
	}()

	// Execute all root steps
	err := e.executeSteps(execution.Context, workflow.Steps, execution)

	endTime := time.Now()
	execution.SetEndTime(&endTime)
	e.mutex.Lock()

	if err != nil {
		// Handle workflow-level error
		var workflowErr *WorkflowError
		if wfErr, ok := err.(*WorkflowError); ok {
			workflowErr = wfErr
		} else {
			workflowErr = NewWorkflowError(
				ErrorCodeStepExecution,
				err.Error(),
				execution.GetCurrentStep(),
				"",
				err,
			).WithVariableState(execution.Variables)
		}

		execution.SetError(workflowErr.Error())
		execution.SetErrorDetails(workflowErr)
		e.mutex.Unlock()
		execution.SetStatus(StatusFailed)
		e.logger.Error("Workflow execution failed",
			"execution_id", execution.ID,
			"error", workflowErr.FullError())
	} else {
		e.mutex.Unlock()
		execution.SetStatus(StatusCompleted)
		e.logger.Info("Workflow execution completed",
			"execution_id", execution.ID,
			"duration", endTime.Sub(execution.StartTime))
	}
}

// executeSteps executes a list of steps based on their type
func (e *Engine) executeSteps(ctx context.Context, steps []Step, execution *WorkflowExecution) error {
	return e.executeStepsWithRetry(ctx, steps, execution, true)
}

func (e *Engine) executeStepsWithRetry(ctx context.Context, steps []Step, execution *WorkflowExecution, enableRetry bool) error {
	for _, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := e.executeStep(ctx, step, execution); err != nil {
				// Check if it's a loop control error (break/continue)
				if _, isLoopControl := err.(*LoopControlError); isLoopControl {
					// Propagate loop control errors without handling
					return err
				}

				// Convert error to WorkflowError if needed
				var workflowErr *WorkflowError
				if wfErr, ok := err.(*WorkflowError); ok {
					workflowErr = wfErr
				} else {
					workflowErr = NewWorkflowError(
						ErrorCodeStepExecution,
						err.Error(),
						step.Name,
						step.Type,
						err,
					).WithVariableState(execution.Variables)
				}

				// Handle error using the error handler only if retry is enabled
				if enableRetry {
					decision := e.errorHandler.HandleError(ctx, workflowErr, execution)

					switch decision.Action {
					case ErrorActionStop:
						e.logger.Error("Stopping workflow execution due to error",
							"step", step.Name,
							"error", workflowErr.FullError(),
							"decision", decision.Message)
						return workflowErr
					case ErrorActionContinue:
						e.logger.Warn("Continuing workflow execution after error",
							"step", step.Name,
							"error", workflowErr.Error(),
							"decision", decision.Message)
						continue
					case ErrorActionRetry:
						// Implement retry with backoff
						if decision.RetryDelay > 0 {
							e.logger.Info("Retrying step after delay",
								"step", step.Name,
								"delay", decision.RetryDelay,
								"decision", decision.Message)
							select {
							case <-ctx.Done():
								return ctx.Err()
							case <-time.After(decision.RetryDelay):
							}
						}
						// Retry the step (this would need more sophisticated retry tracking)
						e.logger.Info("Retrying failed step",
							"step", step.Name,
							"decision", decision.Message)
						if retryErr := e.executeStep(ctx, step, execution); retryErr != nil {
							return workflowErr // Return original error if retry fails
						}
					default:
						return workflowErr
					}
				} else {
					// When retry is disabled (e.g., in try/catch blocks), return error immediately
					return workflowErr
				}
			}
		}
	}
	return nil
}

// executeStep executes a single step based on its type
func (e *Engine) executeStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	execution.SetCurrentStep(step.Name)

	e.logger.Info("Executing step",
		"execution_id", execution.ID,
		"step", step.Name,
		"type", step.Type)

	// Check for pause status before executing step
	if execution.GetStatus() == StatusPaused {
		// Wait for resume signal
		for execution.GetStatus() == StatusPaused {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
				// Check again
			}
		}
	}

	// Check for debug sessions and breakpoints
	e.checkDebugBreakpoints(execution, step.Name)

	startTime := time.Now()
	result := StepResult{
		Status:    StatusRunning,
		StartTime: startTime,
	}

	// Store initial result safely
	execution.SetStepResult(step.Name, result)

	var err error
	switch step.Type {
	case StepTypeTask:
		err = e.executeTaskStep(ctx, step, execution)
	case StepTypeSequential:
		err = e.executeSequentialStep(ctx, step, execution)
	case StepTypeParallel:
		err = e.executeParallelStep(ctx, step, execution)
	case StepTypeConditional:
		err = e.executeConditionalStep(ctx, step, execution)
	case StepTypeHTTP:
		err = e.executeHTTPStep(ctx, step, execution)
	case StepTypeAPI:
		err = e.executeAPIStep(ctx, step, execution)
	case StepTypeWebhook:
		err = e.executeWebhookStep(ctx, step, execution)
	case StepTypeDelay:
		err = e.executeDelayStep(ctx, step, execution)
	case StepTypeFor:
		err = e.executeForStep(ctx, step, execution)
	case StepTypeWhile:
		err = e.executeWhileStep(ctx, step, execution)
	case StepTypeForeach:
		err = e.executeForeachStep(ctx, step, execution)
	case StepTypeSwitch:
		err = e.executeSwitchStep(ctx, step, execution)
	case StepTypeTry:
		err = e.executeTryStep(ctx, step, execution)
	case StepTypeWorkflow:
		err = e.executeWorkflowStep(ctx, step, execution)
	case StepTypeBreak:
		err = NewBreakError(step.Name)
	case StepTypeContinue:
		err = NewContinueError(step.Name)
	case StepTypeBarrier:
		err = e.executeBarrierStep(ctx, step, execution)
	case StepTypeSemaphore:
		err = e.executeSemaphoreStep(ctx, step, execution)
	case StepTypeLock:
		err = e.executeLockStep(ctx, step, execution)
	case StepTypeWaitGroup:
		err = e.executeWaitGroupStep(ctx, step, execution)
	case StepTypeFanOut:
		err = e.executeFanOutStep(ctx, step, execution)
	case StepTypeFanIn:
		err = e.executeFanInStep(ctx, step, execution)
	case StepTypeErrorWorkflow:
		err = e.executeErrorWorkflowStep(ctx, step, execution)
	case StepTypeComposite:
		err = e.executeCompositeStep(ctx, step, execution)
	default:
		err = fmt.Errorf("unknown step type: %s", step.Type)
	}

	// Get the current result (which may have been updated by the step execution)
	currentResult, exists := execution.GetStepResult(step.Name)
	if exists {
		result = currentResult
	}

	// Update result safely
	endTime := time.Now()
	result.EndTime = &endTime
	result.Duration = endTime.Sub(startTime)

	if err != nil {
		result.Status = StatusFailed
		result.Error = err.Error()

		// Store detailed error information
		var workflowErr *WorkflowError
		if wfErr, ok := err.(*WorkflowError); ok {
			workflowErr = wfErr
		} else {
			workflowErr = NewWorkflowError(
				ErrorCodeStepExecution,
				err.Error(),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.Variables)
		}
		result.ErrorDetails = workflowErr
	} else {
		result.Status = StatusCompleted
	}

	// Add execution trace entry
	AddExecutionTrace(execution, step.Name, step.Type, result.Status, result.Duration, execution.Variables, "", 0)

	execution.SetStepResult(step.Name, result)
	return err
}

// executeTaskStep executes a module task
func (e *Engine) executeTaskStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Module == "" {
		return NewWorkflowError(
			ErrorCodeValidation,
			"module is required for task steps",
			step.Name,
			step.Type,
			nil,
		).WithVariableState(execution.Variables)
	}

	// Create module instance
	var module modules.Module
	module, err := e.moduleFactory.CreateModuleInstance(step.Module)
	if err != nil {
		return NewWorkflowError(
			ErrorCodeModuleExecution,
			"failed to create module instance",
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.Variables).WithDetails("module", step.Module)
	}

	// Create resource ID from step name
	resourceID := step.Name

	// Create config state from step config
	var configState modules.ConfigState = &genericConfigState{data: step.Config}

	// Execute the module
	_, err = module.Get(ctx, resourceID)
	if err != nil {
		// If resource doesn't exist, proceed with Set
		e.logger.Info("Resource not found, creating new",
			"step", step.Name,
			"resource", resourceID)
	}

	// Apply configuration
	if err := module.Set(ctx, resourceID, configState); err != nil {
		return NewWorkflowError(
			ErrorCodeModuleExecution,
			"failed to apply module configuration",
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.Variables).WithDetails("module", step.Module).WithDetails("resource_id", resourceID)
	}

	// Verify by getting current state
	finalState, err := module.Get(ctx, resourceID)
	if err != nil {
		e.logger.Warn("Failed to verify final state",
			"step", step.Name,
			"error", err)
	} else {
		// Store output in variables safely
		if finalState != nil {
			e.mutex.Lock()
			execution.SetVariable(step.Name+"_result", finalState.AsMap())
			e.mutex.Unlock()
		}
	}

	return nil
}

// executeSequentialStep executes child steps sequentially
func (e *Engine) executeSequentialStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	return e.executeSteps(ctx, step.Steps, execution)
}

// executeParallelStep executes child steps in parallel
func (e *Engine) executeParallelStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(step.Steps))

	for _, childStep := range step.Steps {
		wg.Add(1)
		go func(s Step) {
			defer wg.Done()
			if err := e.executeStep(ctx, s, execution); err != nil {
				errChan <- fmt.Errorf("parallel step %s failed: %w", s.Name, err)
			}
		}(childStep)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return fmt.Errorf("parallel execution failed with %d errors: %v", len(errors), errors[0])
	}

	return nil
}

// executeConditionalStep executes child steps based on condition
func (e *Engine) executeConditionalStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Condition == nil {
		return fmt.Errorf("condition is required for conditional steps")
	}

	// Get variables safely
	e.mutex.Lock()
	variablesCopy := make(map[string]interface{})
	for k, v := range execution.Variables {
		variablesCopy[k] = v
	}
	e.mutex.Unlock()

	shouldExecute, err := e.evaluateCondition(step.Condition, variablesCopy)
	if err != nil {
		return fmt.Errorf("failed to evaluate condition: %w", err)
	}

	if !shouldExecute {
		e.logger.Info("Condition not met, skipping conditional step",
			"step", step.Name)
		return nil
	}

	return e.executeSteps(ctx, step.Steps, execution)
}

// GetExecution returns the status of a workflow execution
func (e *Engine) GetExecution(executionID string) (*WorkflowExecution, error) {
	e.mutex.RLock()
	execution, exists := e.executions[executionID]
	e.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	// Return a copy to avoid race conditions - use thread-safe methods
	executionCopy := WorkflowExecution{
		ID:             execution.ID,
		WorkflowName:   execution.WorkflowName,
		Status:         execution.GetStatus(),
		StartTime:      execution.StartTime,
		EndTime:        execution.GetEndTime(),
		CurrentStep:    execution.GetCurrentStep(),
		StepResults:    execution.GetStepResults(),
		Variables:      execution.GetVariables(),
		ExecutionTrace: execution.GetExecutionTrace(),
		Error:          execution.GetError(),
		ErrorDetails:   execution.GetErrorDetails(),
		Context:        execution.Context,
		Cancel:         execution.Cancel,
	}

	// Copy EndTime if it exists (GetEndTime returns the pointer, so copy the value)
	if executionCopy.EndTime != nil {
		endTimeCopy := *executionCopy.EndTime
		executionCopy.EndTime = &endTimeCopy
	}

	return &executionCopy, nil
}

// ListExecutions returns all workflow executions
func (e *Engine) ListExecutions() ([]*WorkflowExecution, error) {
	e.mutex.RLock()
	defer e.mutex.RUnlock()

	executions := make([]*WorkflowExecution, 0, len(e.executions))
	for _, execution := range e.executions {
		executions = append(executions, execution)
	}

	return executions, nil
}

// CancelExecution cancels a running workflow execution
func (e *Engine) CancelExecution(executionID string) error {
	e.mutex.RLock()
	execution, exists := e.executions[executionID]
	e.mutex.RUnlock()

	if !exists {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	if execution.Cancel != nil {
		execution.Cancel()
		e.mutex.Lock()
		endTime := time.Now()
		execution.SetEndTime(&endTime)
		e.mutex.Unlock()
		execution.SetStatus(StatusCancelled)
	}

	return nil
}

// PauseExecution pauses a running workflow execution
func (e *Engine) PauseExecution(executionID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	execution, exists := e.executions[executionID]
	if !exists {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	currentStatus := execution.GetStatus()
	if currentStatus != StatusRunning {
		return fmt.Errorf("cannot pause execution in status: %s", currentStatus)
	}

	// Set execution status to paused
	execution.SetStatus(StatusPaused)

	e.logger.Info("Paused workflow execution",
		"execution_id", executionID,
		"workflow", execution.WorkflowName)

	return nil
}

// ResumeExecution resumes a paused workflow execution
func (e *Engine) ResumeExecution(executionID string) error {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	execution, exists := e.executions[executionID]
	if !exists {
		return fmt.Errorf("execution not found: %s", executionID)
	}

	currentStatus := execution.GetStatus()
	if currentStatus != StatusPaused {
		return fmt.Errorf("cannot resume execution in status: %s", currentStatus)
	}

	// Set execution status back to running
	execution.SetStatus(StatusRunning)

	e.logger.Info("Resumed workflow execution",
		"execution_id", executionID,
		"workflow", execution.WorkflowName)

	return nil
}

// GetDebugEngine returns the debug engine for this workflow engine
func (e *Engine) GetDebugEngine() DebugEngine {
	return e.debugEngine
}

// checkDebugBreakpoints checks if execution should pause at a breakpoint
func (e *Engine) checkDebugBreakpoints(execution *WorkflowExecution, stepName string) {
	// Find any debug sessions for this execution
	if e.debugEngine != nil {
		sessions, err := e.debugEngine.ListDebugSessions()
		if err != nil {
			return
		}

		for _, session := range sessions {
			if session.ExecutionID == execution.ID {
				// Check if there's a breakpoint for this step
				if breakpoint, shouldBreak := e.debugEngine.checkBreakpoint(session, stepName, execution.GetVariables()); shouldBreak {
					e.logger.Info("Breakpoint hit",
						"execution_id", execution.ID,
						"step", stepName,
						"breakpoint_id", breakpoint.ID)

					// Pause execution
					execution.SetStatus(StatusPaused)

					// Update debug session status
					session.mutex.Lock()
					session.Status = DebugStatusBreakpoint
					session.CurrentStep = stepName
					session.mutex.Unlock()

					// Wait for debug commands
					e.waitForDebugCommands(session, execution)
				}
			}
		}
	}
}

// waitForDebugCommands waits for debug commands while paused at a breakpoint
func (e *Engine) waitForDebugCommands(session *DebugSession, execution *WorkflowExecution) {
	for {
		select {
		case command := <-session.stepChan:
			switch command.Action {
			case DebugActionContinue:
				// Resume normal execution
				execution.SetStatus(StatusRunning)
				session.mutex.Lock()
				session.Status = DebugStatusActive
				session.mutex.Unlock()
				return
			case DebugActionStep:
				// Execute next step and pause again
				execution.SetStatus(StatusRunning)
				session.mutex.Lock()
				session.Status = DebugStatusStepping
				session.mutex.Unlock()
				return
			case DebugActionStop:
				// Stop execution
				execution.Cancel()
				return
			case DebugActionUpdateVariables:
				// Apply variable updates
				if command.VariableUpdates != nil {
					for varName, value := range command.VariableUpdates {
						execution.SetVariable(varName, value)
					}
				}
			}
		case <-session.Context.Done():
			return
		case <-time.After(100 * time.Millisecond):
			// Check if execution status changed externally
			if execution.GetStatus() == StatusRunning {
				return
			}
		}
	}
}

// generateExecutionID generates a unique execution ID.
// Uses an atomic counter to guarantee uniqueness even on Windows
// where time.Now().UnixNano() has ~15.6ms granularity.
func generateExecutionID() string {
	return fmt.Sprintf("exec_%d_%d", time.Now().UnixNano(), executionIDCounter.Add(1))
}

// genericConfigState implements modules.ConfigState for workflow tasks
type genericConfigState struct {
	data map[string]interface{}
}

func (g *genericConfigState) AsMap() map[string]interface{} {
	return g.data
}

func (g *genericConfigState) ToYAML() ([]byte, error) {
	// This would use yaml.Marshal in a real implementation
	return []byte("workflow yaml"), nil
}

func (g *genericConfigState) FromYAML(data []byte) error {
	// This would use yaml.Unmarshal in a real implementation
	return nil
}

func (g *genericConfigState) Validate() error {
	return nil
}

func (g *genericConfigState) GetManagedFields() []string {
	fields := make([]string, 0, len(g.data))
	for key := range g.data {
		fields = append(fields, key)
	}
	return fields
}

// executeTryStep executes a try/catch/finally step with error handling
func (e *Engine) executeTryStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Try == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"try step missing try configuration",
			step.Name,
			step.Type,
			fmt.Errorf("try configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	tryConfig := step.Try
	logger := e.logger.WithField("step", step.Name).WithField("step_type", "try")

	var tryErr error
	var finallyErr error
	var errorHandled bool

	// Execute try block
	logger.InfoCtx(ctx, "Executing try block",
		"operation", "try_execute",
		"step_count", len(tryConfig.Try))

	tryErr = e.executeStepsWithRetry(ctx, tryConfig.Try, execution, false)

	// Handle errors if any occurred in the try block
	if tryErr != nil {
		logger.Debug("Try block failed, checking catch blocks",
			"error", tryErr.Error(),
			"catch_blocks_count", len(tryConfig.Catch))

		// Try to handle the error with catch blocks
		for _, catchBlock := range tryConfig.Catch {
			if e.shouldHandleError(tryErr, catchBlock) {
				logger.InfoCtx(ctx, "Executing catch block",
					"operation", "catch_execute",
					"step_count", len(catchBlock.Steps),
					"error", tryErr.Error())

				catchErr := e.executeSteps(ctx, catchBlock.Steps, execution)
				if catchErr != nil {
					// If catch block fails, return both errors
					logger.Error("Catch block execution failed",
						"catch_error", catchErr.Error(),
						"original_error", tryErr.Error())

					// Wrap the catch error with context about the original error
					if workflowErr, ok := catchErr.(*WorkflowError); ok {
						_ = workflowErr.WithDetails("original_try_error", tryErr.Error())
						tryErr = workflowErr
					} else {
						tryErr = NewWorkflowError(
							ErrorCodeStepExecution,
							fmt.Sprintf("catch block failed: %v (original error: %v)", catchErr, tryErr),
							step.Name,
							step.Type,
							catchErr,
						).WithVariableState(execution.GetVariables()).WithDetails("original_try_error", tryErr.Error())
					}
				} else {
					// Error was handled successfully
					logger.Debug("Error handled by catch block")
					errorHandled = true
					tryErr = nil
				}
				break // Only execute the first matching catch block
			}
		}

		// If no catch block handled the error, the error will propagate
		if !errorHandled {
			logger.Debug("No catch block handled the error")
		}
	} else {
		logger.Debug("Try block completed successfully")
	}

	// Always execute finally block if present
	if len(tryConfig.Finally) > 0 {
		logger.InfoCtx(ctx, "Executing finally block",
			"operation", "finally_execute",
			"step_count", len(tryConfig.Finally))

		finallyErr = e.executeSteps(ctx, tryConfig.Finally, execution)
		if finallyErr != nil {
			logger.Error("Finally block execution failed",
				"finally_error", finallyErr.Error())

			// If both try/catch and finally failed, combine the errors
			if tryErr != nil {
				if workflowErr, ok := finallyErr.(*WorkflowError); ok {
					_ = workflowErr.WithDetails("try_catch_error", tryErr.Error())
					return workflowErr
				} else {
					return NewWorkflowError(
						ErrorCodeStepExecution,
						fmt.Sprintf("finally block failed: %v (try/catch error: %v)", finallyErr, tryErr),
						step.Name,
						step.Type,
						finallyErr,
					).WithVariableState(execution.GetVariables()).WithDetails("try_catch_error", tryErr.Error())
				}
			} else {
				// Only finally failed
				return finallyErr
			}
		} else {
			logger.Debug("Finally block completed successfully")
		}
	}

	// Return the try/catch error if it wasn't handled, otherwise return nil
	// Mark unhandled errors as non-recoverable to prevent retry of the entire try/catch step
	if tryErr != nil {
		if workflowErr, ok := tryErr.(*WorkflowError); ok {
			// Convert to validation error to ensure workflow stops for unhandled errors
			unhandledErr := NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("unhandled error in try/catch: %s", workflowErr.Message),
				step.Name,
				step.Type,
				workflowErr,
			).WithVariableState(execution.GetVariables()).WithDetails("original_error_code", workflowErr.Code)
			unhandledErr.Recoverable = false
			return unhandledErr
		}
		// For non-WorkflowError, wrap it with validation error code to stop execution
		wrappedErr := NewWorkflowError(
			ErrorCodeValidation, // Use validation error to ensure workflow stops
			fmt.Sprintf("unhandled error in try/catch: %v", tryErr),
			step.Name,
			step.Type,
			tryErr,
		).WithVariableState(execution.GetVariables())
		wrappedErr.Recoverable = false
		return wrappedErr
	}
	return nil
}

// shouldHandleError determines if a catch block should handle the given error
func (e *Engine) shouldHandleError(err error, catchBlock CatchBlock) bool {
	// Convert error to WorkflowError if possible for better error matching
	var workflowErr *WorkflowError
	if we, ok := err.(*WorkflowError); ok {
		workflowErr = we
	} else {
		// For non-WorkflowError, we can only match by error message
		if len(catchBlock.ErrorTypes) > 0 {
			errMsg := err.Error()
			for _, errorType := range catchBlock.ErrorTypes {
				if contains(errMsg, errorType) {
					return true
				}
			}
		}
		return len(catchBlock.ErrorCodes) == 0 && len(catchBlock.ErrorTypes) == 0 // Match all if no specific criteria
	}

	// Match by error codes
	if len(catchBlock.ErrorCodes) > 0 {
		for _, errorCode := range catchBlock.ErrorCodes {
			if workflowErr.Code == errorCode {
				return true
			}
		}
	}

	// Match by error types (string matching in error message)
	if len(catchBlock.ErrorTypes) > 0 {
		errMsg := workflowErr.Error()
		for _, errorType := range catchBlock.ErrorTypes {
			if contains(errMsg, errorType) {
				return true
			}
		}
	}

	// If no specific error codes or types are specified, catch all errors
	return len(catchBlock.ErrorCodes) == 0 && len(catchBlock.ErrorTypes) == 0
}

// contains checks if a string contains a substring (case-insensitive)
func contains(str, substr string) bool {
	// Simple case-insensitive substring matching
	str = strings.ToLower(str)
	substr = strings.ToLower(substr)
	return strings.Contains(str, substr)
}

// executeFanOutStep executes a fan-out step that distributes work across multiple parallel branches
func (e *Engine) executeFanOutStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.FanOut == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"fan-out configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("fan-out configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	config := step.FanOut

	// Get the data source
	dataSource, exists := execution.GetVariable(config.DataSource)
	if !exists {
		return fmt.Errorf("step %s: data source variable '%s' not found", step.Name, config.DataSource)
	}

	// Convert data source to slice for iteration
	dataSlice, ok := dataSource.([]interface{})
	if !ok {
		return fmt.Errorf("step %s: data source must be an array, got %T", step.Name, dataSource)
	}

	if len(dataSlice) == 0 {
		e.logger.Info("Fan-out with empty data source", "step", step.Name)
		return nil
	}

	e.logger.Info("Starting fan-out", "step", step.Name, "items", len(dataSlice), "max_concurrency", config.MaxConcurrency)

	// Create semaphore for concurrency control if specified
	var semaphore chan struct{}
	if config.MaxConcurrency > 0 {
		semaphore = make(chan struct{}, config.MaxConcurrency)
		for i := 0; i < config.MaxConcurrency; i++ {
			semaphore <- struct{}{}
		}
	}

	// Create context with timeout if specified
	workCtx := ctx
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		workCtx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	// Channel to collect results
	resultsChan := make(chan fanOutResult, len(dataSlice))
	var wg sync.WaitGroup

	// Execute worker for each data item
	for i, item := range dataSlice {
		wg.Add(1)
		go func(index int, dataItem interface{}) {
			defer wg.Done()

			// Acquire semaphore if concurrency is limited
			if semaphore != nil {
				select {
				case <-semaphore:
				case <-workCtx.Done():
					resultsChan <- fanOutResult{Index: index, Error: workCtx.Err()}
					return
				}
				defer func() { semaphore <- struct{}{} }()
			}

			// Create a copy of the worker template
			workerStep := config.WorkerTemplate
			workerStep.Name = fmt.Sprintf("%s_worker_%d", step.Name, index)

			// Create new execution context for the worker
			workerExecution := &WorkflowExecution{
				ID:           fmt.Sprintf("%s_worker_%d", execution.ID, index),
				WorkflowName: fmt.Sprintf("%s_worker_%d", execution.WorkflowName, index),
				Status:       StatusPending,
				StartTime:    time.Now(),
				StepResults:  make(map[string]StepResult),
				Variables:    execution.GetVariables(),
				Context:      workCtx,
			}

			// Set the current data item in a variable (default name is "item")
			itemVarName := "item"
			if config.ResultVariable != "" {
				itemVarName = config.ResultVariable + "_item"
			}
			workerExecution.SetVariable(itemVarName, dataItem)
			workerExecution.SetVariable("index", index)

			// Process step variables
			for varName, varValue := range workerStep.Variables {
				workerExecution.SetVariable(varName, varValue)
			}

			// Execute the worker step
			err := e.executeStep(workCtx, workerStep, workerExecution)

			result := fanOutResult{Index: index}
			if err != nil {
				result.Error = err
			} else {
				// Get the result from the worker execution
				if config.ResultVariable != "" {
					if value, exists := workerExecution.GetVariable(config.ResultVariable); exists {
						result.Value = value
					}
				}
				// Also capture step result
				if stepResult, exists := workerExecution.GetStepResult(workerStep.Name); exists {
					result.StepResult = stepResult
				}
			}

			resultsChan <- result
		}(i, item)
	}

	// Wait for all workers to complete
	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	// Collect results
	results := make([]fanOutResult, len(dataSlice))
	for result := range resultsChan {
		results[result.Index] = result
	}

	// Check for errors
	var workerErrors []error
	var successfulResults []interface{}
	var stepResults []interface{}

	for _, result := range results {
		if result.Error != nil {
			workerErrors = append(workerErrors, result.Error)
		} else {
			if result.Value != nil {
				successfulResults = append(successfulResults, result.Value)
			}
			if result.StepResult != nil {
				stepResults = append(stepResults, result.StepResult)
			}
		}
	}

	// Store results in execution context
	if config.ResultVariable != "" {
		execution.SetVariable(config.ResultVariable, successfulResults)
	}
	execution.SetVariable(step.Name+"_results", stepResults)
	execution.SetVariable(step.Name+"_errors", workerErrors)

	e.logger.Info("Fan-out completed", "step", step.Name, "successful", len(successfulResults), "errors", len(workerErrors))

	// Return error if any workers failed
	if len(workerErrors) > 0 {
		return fmt.Errorf("step %s: %d workers failed: %v", step.Name, len(workerErrors), workerErrors[0])
	}

	return nil
}

// fanOutResult holds the result of a single fan-out worker
type fanOutResult struct {
	Index      int
	Value      interface{}
	StepResult interface{}
	Error      error
}
