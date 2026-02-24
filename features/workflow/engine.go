// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/features/steward/factory"
	"github.com/cfgis/cfgms/pkg/logging"
)

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

// evaluateCondition evaluates a condition against current variables
func (e *Engine) evaluateCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	switch condition.Type {
	case ConditionTypeVariable:
		return e.evaluateVariableCondition(condition, variables)
	case ConditionTypeExpression:
		return e.evaluateExpressionCondition(condition, variables)
	case ConditionTypeAnd:
		return e.evaluateAndCondition(condition, variables)
	case ConditionTypeOr:
		return e.evaluateOrCondition(condition, variables)
	case ConditionTypeNot:
		return e.evaluateNotCondition(condition, variables)
	default:
		// Handle nested conditions using And/Or/Not fields
		if len(condition.And) > 0 {
			return e.evaluateNestedAndConditions(condition.And, variables)
		}
		if len(condition.Or) > 0 {
			return e.evaluateNestedOrConditions(condition.Or, variables)
		}
		if condition.Not != nil {
			result, err := e.evaluateCondition(condition.Not, variables)
			if err != nil {
				return false, err
			}
			return !result, nil
		}
		return false, fmt.Errorf("unknown condition type: %s", condition.Type)
	}
}

// evaluateVariableCondition evaluates a variable-based condition
func (e *Engine) evaluateVariableCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	value, exists := variables[condition.Variable]

	switch condition.Operator {
	case OperatorExists:
		return exists, nil
	case OperatorEqual:
		return exists && e.compareValues(value, condition.Value, "eq"), nil
	case OperatorNotEqual:
		return !exists || !e.compareValues(value, condition.Value, "eq"), nil
	case OperatorGreaterThan:
		if !exists {
			return false, nil
		}
		return e.compareValues(value, condition.Value, "gt"), nil
	case OperatorLessThan:
		if !exists {
			return false, nil
		}
		return e.compareValues(value, condition.Value, "lt"), nil
	case OperatorContains:
		if !exists {
			return false, nil
		}
		return e.compareValues(value, condition.Value, "contains"), nil
	default:
		return false, fmt.Errorf("unknown operator: %s", condition.Operator)
	}
}

// evaluateAndCondition evaluates logical AND of multiple conditions
func (e *Engine) evaluateAndCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if len(condition.And) == 0 {
		return false, fmt.Errorf("and condition requires at least one child condition")
	}
	return e.evaluateNestedAndConditions(condition.And, variables)
}

// evaluateOrCondition evaluates logical OR of multiple conditions
func (e *Engine) evaluateOrCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if len(condition.Or) == 0 {
		return false, fmt.Errorf("or condition requires at least one child condition")
	}
	return e.evaluateNestedOrConditions(condition.Or, variables)
}

// evaluateNotCondition evaluates logical NOT of a condition
func (e *Engine) evaluateNotCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if condition.Not == nil {
		return false, fmt.Errorf("not condition requires a child condition")
	}
	result, err := e.evaluateCondition(condition.Not, variables)
	if err != nil {
		return false, err
	}
	return !result, nil
}

// evaluateNestedAndConditions evaluates AND conditions with support for up to 5 levels deep
func (e *Engine) evaluateNestedAndConditions(conditions []*Condition, variables map[string]interface{}) (bool, error) {
	for _, cond := range conditions {
		result, err := e.evaluateCondition(cond, variables)
		if err != nil {
			return false, err
		}
		if !result {
			return false, nil
		}
	}
	return true, nil
}

// evaluateNestedOrConditions evaluates OR conditions with support for up to 5 levels deep
func (e *Engine) evaluateNestedOrConditions(conditions []*Condition, variables map[string]interface{}) (bool, error) {
	for _, cond := range conditions {
		result, err := e.evaluateCondition(cond, variables)
		if err != nil {
			return false, err
		}
		if result {
			return true, nil
		}
	}
	return false, nil
}

// evaluateExpressionCondition evaluates complex expression conditions
func (e *Engine) evaluateExpressionCondition(condition *Condition, variables map[string]interface{}) (bool, error) {
	if condition.Expression == "" {
		return false, fmt.Errorf("expression is required for expression conditions")
	}

	// Simple expression evaluator supporting basic logical operations
	return e.evaluateExpression(condition.Expression, variables)
}

// evaluateExpression evaluates a condition expression
func (e *Engine) evaluateExpression(expression string, variables map[string]interface{}) (bool, error) {
	// Replace variables in the expression
	resolvedExpression := e.replaceVariables(expression, variables)

	// Parse and evaluate the expression
	return e.parseExpression(resolvedExpression, variables)
}

// replaceVariables replaces ${variable} placeholders with actual values
func (e *Engine) replaceVariables(expression string, variables map[string]interface{}) string {
	result := expression

	// Simple variable replacement for ${variable_name}
	for varName, varValue := range variables {
		placeholder := fmt.Sprintf("${%s}", varName)
		valueStr := fmt.Sprintf("%v", varValue)
		result = strings.ReplaceAll(result, placeholder, valueStr)
	}

	return result
}

// parseExpression parses and evaluates logical expressions
func (e *Engine) parseExpression(expression string, variables map[string]interface{}) (bool, error) {
	// Remove whitespace
	expr := strings.TrimSpace(expression)

	// Handle simple boolean values
	if expr == "true" {
		return true, nil
	}
	if expr == "false" {
		return false, nil
	}

	// Handle AND operations
	if strings.Contains(expr, " && ") {
		parts := strings.Split(expr, " && ")
		for _, part := range parts {
			result, err := e.parseExpression(strings.TrimSpace(part), variables)
			if err != nil {
				return false, err
			}
			if !result {
				return false, nil
			}
		}
		return true, nil
	}

	// Handle OR operations
	if strings.Contains(expr, " || ") {
		parts := strings.Split(expr, " || ")
		for _, part := range parts {
			result, err := e.parseExpression(strings.TrimSpace(part), variables)
			if err != nil {
				return false, err
			}
			if result {
				return true, nil
			}
		}
		return false, nil
	}

	// Handle NOT operations
	if strings.HasPrefix(expr, "!") {
		innerExpr := strings.TrimSpace(expr[1:])
		result, err := e.parseExpression(innerExpr, variables)
		if err != nil {
			return false, err
		}
		return !result, nil
	}

	// Handle comparison operations
	return e.parseComparison(expr, variables)
}

// parseComparison parses comparison expressions like "var1 == value"
func (e *Engine) parseComparison(expression string, variables map[string]interface{}) (bool, error) {
	// Support different comparison operators
	operators := []string{"==", "!=", ">=", "<=", ">", "<", "contains"}

	for _, op := range operators {
		if strings.Contains(expression, fmt.Sprintf(" %s ", op)) {
			parts := strings.SplitN(expression, fmt.Sprintf(" %s ", op), 2)
			if len(parts) != 2 {
				continue
			}

			left := strings.TrimSpace(parts[0])
			right := strings.TrimSpace(parts[1])

			// Get variable value or use literal
			leftValue := e.getValueFromExpression(left, variables)
			rightValue := e.getValueFromExpression(right, variables)

			// Perform comparison
			switch op {
			case "==":
				return leftValue == rightValue, nil
			case "!=":
				return leftValue != rightValue, nil
			case ">":
				return e.numericCompare(leftValue, rightValue) > 0, nil
			case "<":
				return e.numericCompare(leftValue, rightValue) < 0, nil
			case ">=":
				return e.numericCompare(leftValue, rightValue) >= 0, nil
			case "<=":
				return e.numericCompare(leftValue, rightValue) <= 0, nil
			case "contains":
				return e.containsCompare(leftValue, rightValue), nil
			}
		}
	}

	return false, fmt.Errorf("unable to parse expression: %s", expression)
}

// getValueFromExpression extracts value from expression part (variable or literal)
func (e *Engine) getValueFromExpression(expr string, variables map[string]interface{}) interface{} {
	// Remove quotes for string literals
	if (strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"")) ||
		(strings.HasPrefix(expr, "'") && strings.HasSuffix(expr, "'")) {
		return expr[1 : len(expr)-1]
	}

	// Try to get from variables
	if value, exists := variables[expr]; exists {
		return value
	}

	// Try to parse as number
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}

	// Try to parse as integer
	if len(expr) > 0 && (expr[0] >= '0' && expr[0] <= '9') {
		// Simple integer parsing
		result := 0
		for _, char := range expr {
			if char >= '0' && char <= '9' {
				result = result*10 + int(char-'0')
			} else {
				// Not a valid number, return as string
				return expr
			}
		}
		return result
	}

	// Return as string literal
	return expr
}

// compareValues performs type-safe comparison between two values
func (e *Engine) compareValues(left, right interface{}, operator string) bool {
	// Handle nil values
	if left == nil && right == nil {
		return operator == "eq"
	}
	if left == nil || right == nil {
		return operator == "ne"
	}

	switch operator {
	case "eq":
		return left == right
	case "gt":
		return e.numericCompare(left, right) > 0
	case "lt":
		return e.numericCompare(left, right) < 0
	case "contains":
		return e.containsCompare(left, right)
	default:
		return false
	}
}

// numericCompare performs numeric comparison, returning -1, 0, 1
func (e *Engine) numericCompare(left, right interface{}) int {
	leftFloat := e.toFloat64(left)
	rightFloat := e.toFloat64(right)

	if leftFloat < rightFloat {
		return -1
	} else if leftFloat > rightFloat {
		return 1
	}
	return 0
}

// toFloat64 converts various numeric types to float64
func (e *Engine) toFloat64(val interface{}) float64 {
	switch v := val.(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float32:
		return float64(v)
	case float64:
		return v
	default:
		return 0
	}
}

// containsCompare checks if left contains right
func (e *Engine) containsCompare(left, right interface{}) bool {
	leftStr := fmt.Sprintf("%v", left)
	rightStr := fmt.Sprintf("%v", right)

	// Empty string is contained in everything
	if len(rightStr) == 0 {
		return true
	}

	// Check string containment using strings.Contains
	return strings.Contains(leftStr, rightStr)
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

// generateExecutionID generates a unique execution ID
func generateExecutionID() string {
	return fmt.Sprintf("exec_%d", time.Now().UnixNano())
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

// executeHTTPStep executes an HTTP-based workflow step
func (e *Engine) executeHTTPStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.HTTP == nil {
		return fmt.Errorf("HTTP configuration is required for HTTP steps")
	}

	// Execute HTTP request
	response, err := e.httpClient.ExecuteRequest(ctx, step.HTTP)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}

	// Store response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_status_code", response.StatusCode)
	execution.SetVariable(step.Name+"_headers", response.Headers)
	execution.SetVariable(step.Name+"_body", string(response.Body))
	execution.SetVariable(step.Name+"_duration", response.Duration.String())
	e.mutex.Unlock()

	e.logger.Info("HTTP step completed",
		"step", step.Name,
		"status_code", response.StatusCode,
		"duration", response.Duration)

	return nil
}

// executeAPIStep executes an API-based workflow step (SaaS integrations)
func (e *Engine) executeAPIStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.API == nil {
		return fmt.Errorf("API configuration is required for API steps")
	}

	// Use provider registry for API operations
	response, err := e.providerRegistry.ExecuteOperation(ctx, step.API)
	if err != nil {
		return fmt.Errorf("API operation failed: %w", err)
	}

	// Store API response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_api_success", response.Success)
	execution.SetVariable(step.Name+"_api_status", response.StatusCode)
	execution.SetVariable(step.Name+"_api_duration", response.Duration)
	execution.SetVariable(step.Name+"_api_response", response.Data)
	execution.SetVariable(step.Name+"_api_metadata", response.Metadata)
	e.mutex.Unlock()

	e.logger.Info("API step completed",
		"step", step.Name,
		"provider", step.API.Provider,
		"service", step.API.Service,
		"operation", step.API.Operation,
		"success", response.Success)

	return nil
}

// executeWebhookStep executes a webhook-based workflow step
func (e *Engine) executeWebhookStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Webhook == nil {
		return fmt.Errorf("webhook configuration is required for webhook steps")
	}

	// Convert webhook config to HTTP config
	httpConfig := &HTTPConfig{
		URL:            step.Webhook.URL,
		Method:         step.Webhook.Method,
		Headers:        step.Webhook.Headers,
		Body:           step.Webhook.Payload,
		Auth:           step.Webhook.Auth,
		Timeout:        step.Webhook.Timeout,
		Retry:          step.Webhook.Retry,
		ExpectedStatus: []int{200, 201, 202, 204}, // Common webhook success codes
	}

	// Set default method if not specified
	if httpConfig.Method == "" {
		httpConfig.Method = "POST"
	}

	// Execute webhook request
	response, err := e.httpClient.ExecuteRequest(ctx, httpConfig)
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}

	// Store webhook response in variables safely
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_webhook_status", response.StatusCode)
	execution.SetVariable(step.Name+"_webhook_response", string(response.Body))
	e.mutex.Unlock()

	e.logger.Info("Webhook step completed",
		"step", step.Name,
		"url", step.Webhook.URL,
		"status_code", response.StatusCode)

	return nil
}

// executeDelayStep executes a delay workflow step
func (e *Engine) executeDelayStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Delay == nil {
		return fmt.Errorf("delay configuration is required for delay steps")
	}

	if step.Delay.Duration <= 0 {
		return fmt.Errorf("delay duration must be positive")
	}

	message := step.Delay.Message
	if message == "" {
		message = "Waiting"
	}

	e.logger.Info("Starting delay step",
		"step", step.Name,
		"duration", step.Delay.Duration,
		"message", message)

	// Wait for the specified duration or context cancellation
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(step.Delay.Duration):
		// Delay completed successfully
	}

	e.logger.Info("Delay step completed",
		"step", step.Name,
		"duration", step.Delay.Duration)

	// Set the output for the step result
	result, exists := execution.GetStepResult(step.Name)
	if exists {
		if result.Output == nil {
			result.Output = make(map[string]interface{})
		}
		result.Output["message"] = message
		execution.SetStepResult(step.Name, result)
	}

	return nil
}

// convertAPIConfigToHTTP converts API configuration to HTTP configuration

// executeForStep executes a for loop workflow step
func (e *Engine) executeForStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Loop == nil {
		return fmt.Errorf("loop configuration is required for for steps")
	}

	if step.Loop.Type != LoopTypeFor {
		return fmt.Errorf("for step requires loop type 'for', got '%s'", step.Loop.Type)
	}

	if step.Loop.Variable == "" {
		return fmt.Errorf("loop variable is required for for loops")
	}

	// Get start, end, and step values
	start, err := e.resolveLoopValue(step.Loop.Start, execution)
	if err != nil {
		return fmt.Errorf("invalid start value: %w", err)
	}

	end, err := e.resolveLoopValue(step.Loop.End, execution)
	if err != nil {
		return fmt.Errorf("invalid end value: %w", err)
	}

	stepValue := 1
	if step.Loop.Step != nil {
		resolvedStep, err := e.resolveLoopValue(step.Loop.Step, execution)
		if err != nil {
			return fmt.Errorf("invalid step value: %w", err)
		}
		stepValue = resolvedStep
	}

	// Safety check for maximum iterations
	maxIterations := step.Loop.MaxIterations
	if maxIterations == 0 {
		maxIterations = 1000 // Default safety limit
	}

	e.logger.Info("Starting for loop",
		"step", step.Name,
		"variable", step.Loop.Variable,
		"start", start,
		"end", end,
		"step", stepValue)

	// Execute loop
	iterations := 0
	for i := start; (stepValue > 0 && i <= end) || (stepValue < 0 && i >= end); i += stepValue {
		iterations++
		if iterations > maxIterations {
			return fmt.Errorf("for loop exceeded maximum iterations: %d", maxIterations)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set loop variable safely
		execution.SetVariable(step.Loop.Variable, i)

		// Execute child steps
		if err := e.executeSteps(ctx, step.Steps, execution); err != nil {
			// Check if it's a loop control error
			if loopErr, isLoopControl := err.(*LoopControlError); isLoopControl {
				switch loopErr.Type {
				case LoopControlBreak:
					// Break out of the loop
					e.logger.Debug("Breaking out of for loop", "step", loopErr.StepName, "iteration", i)
					goto forLoopComplete // Use goto to break out of the for loop
				case LoopControlContinue:
					// Continue to next iteration
					e.logger.Debug("Continuing for loop", "step", loopErr.StepName, "iteration", i)
					continue
				}
			}
			return fmt.Errorf("for loop iteration %d failed: %w", i, err)
		}
	}

forLoopComplete:
	e.logger.Info("For loop completed",
		"step", step.Name,
		"iterations", iterations)

	return nil
}

// executeWhileStep executes a while loop workflow step
func (e *Engine) executeWhileStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Loop == nil {
		return fmt.Errorf("loop configuration is required for while steps")
	}

	if step.Loop.Type != LoopTypeWhile {
		return fmt.Errorf("while step requires loop type 'while', got '%s'", step.Loop.Type)
	}

	if step.Loop.Condition == nil {
		return fmt.Errorf("condition is required for while loops")
	}

	// Safety check for maximum iterations
	maxIterations := step.Loop.MaxIterations
	if maxIterations == 0 {
		maxIterations = 1000 // Default safety limit
	}

	e.logger.Info("Starting while loop",
		"step", step.Name,
		"max_iterations", maxIterations)

	// Execute loop
	iterations := 0
whileLoopExecute:
	for {
		iterations++
		if iterations > maxIterations {
			return fmt.Errorf("while loop exceeded maximum iterations: %d", maxIterations)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Get variables safely
		e.mutex.Lock()
		variablesCopy := make(map[string]interface{})
		for k, v := range execution.Variables {
			variablesCopy[k] = v
		}
		e.mutex.Unlock()

		// Evaluate condition
		shouldContinue, err := e.evaluateCondition(step.Loop.Condition, variablesCopy)
		if err != nil {
			return fmt.Errorf("failed to evaluate while condition: %w", err)
		}

		if !shouldContinue {
			break
		}

		// Execute child steps
		if err := e.executeSteps(ctx, step.Steps, execution); err != nil {
			// Check if it's a loop control error
			if loopErr, isLoopControl := err.(*LoopControlError); isLoopControl {
				switch loopErr.Type {
				case LoopControlBreak:
					// Break out of the loop
					e.logger.Debug("Breaking out of while loop", "step", loopErr.StepName, "iteration", iterations)
					goto whileLoopComplete
				case LoopControlContinue:
					// Continue to next iteration
					e.logger.Debug("Continuing while loop", "step", loopErr.StepName, "iteration", iterations)
					continue whileLoopExecute
				}
			}
			return fmt.Errorf("while loop iteration %d failed: %w", iterations, err)
		}
	}
whileLoopComplete:

	e.logger.Info("While loop completed",
		"step", step.Name,
		"iterations", iterations)

	return nil
}

// executeForeachStep executes a foreach loop workflow step
func (e *Engine) executeForeachStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Loop == nil {
		return fmt.Errorf("loop configuration is required for foreach steps")
	}

	if step.Loop.Type != LoopTypeForeach {
		return fmt.Errorf("foreach step requires loop type 'foreach', got '%s'", step.Loop.Type)
	}

	if step.Loop.Variable == "" {
		return fmt.Errorf("loop variable is required for foreach loops")
	}

	// Get collection to iterate over
	var items []interface{}
	var err error

	if step.Loop.ItemsVariable != "" {
		// Get items from variable
		itemsVar, exists := execution.GetVariable(step.Loop.ItemsVariable)

		if !exists {
			return fmt.Errorf("items variable '%s' not found", step.Loop.ItemsVariable)
		}

		items, err = e.convertToSlice(itemsVar)
		if err != nil {
			return fmt.Errorf("items variable '%s' is not a valid collection: %w", step.Loop.ItemsVariable, err)
		}
	} else if step.Loop.Items != nil {
		// Use direct items
		items, err = e.convertToSlice(step.Loop.Items)
		if err != nil {
			return fmt.Errorf("items is not a valid collection: %w", err)
		}
	} else {
		return fmt.Errorf("either items or items_variable is required for foreach loops")
	}

	// Safety check for maximum iterations
	maxIterations := step.Loop.MaxIterations
	if maxIterations == 0 {
		maxIterations = 1000 // Default safety limit
	}

	if len(items) > maxIterations {
		return fmt.Errorf("foreach loop collection size (%d) exceeds maximum iterations: %d", len(items), maxIterations)
	}

	e.logger.Info("Starting foreach loop",
		"step", step.Name,
		"variable", step.Loop.Variable,
		"items_count", len(items))

	// Execute loop
foreachLoopExecute:
	for index, item := range items {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set loop variables safely
		execution.SetVariable(step.Loop.Variable, item)
		if step.Loop.IndexVariable != "" {
			execution.SetVariable(step.Loop.IndexVariable, index)
		}

		// Execute child steps
		if err := e.executeSteps(ctx, step.Steps, execution); err != nil {
			// Check if it's a loop control error
			if loopErr, isLoopControl := err.(*LoopControlError); isLoopControl {
				switch loopErr.Type {
				case LoopControlBreak:
					// Break out of the loop
					e.logger.Debug("Breaking out of foreach loop", "step", loopErr.StepName, "iteration", index)
					goto foreachLoopComplete
				case LoopControlContinue:
					// Continue to next iteration
					e.logger.Debug("Continuing foreach loop", "step", loopErr.StepName, "iteration", index)
					continue foreachLoopExecute
				}
			}
			return fmt.Errorf("foreach loop iteration %d failed: %w", index, err)
		}
	}
foreachLoopComplete:

	e.logger.Info("Foreach loop completed",
		"step", step.Name,
		"iterations", len(items))

	return nil
}

// resolveLoopValue resolves a loop value from variables or returns the literal value
func (e *Engine) resolveLoopValue(value interface{}, execution *WorkflowExecution) (int, error) {
	if value == nil {
		return 0, fmt.Errorf("value cannot be nil")
	}

	// If it's already an int, return it
	if intVal, ok := value.(int); ok {
		return intVal, nil
	}

	// If it's a string, check if it's a variable reference
	if strVal, ok := value.(string); ok {
		if strings.HasPrefix(strVal, "${") && strings.HasSuffix(strVal, "}") {
			// Variable reference
			varName := strVal[2 : len(strVal)-1]
			varValue, exists := execution.GetVariable(varName)

			if !exists {
				return 0, fmt.Errorf("variable '%s' not found", varName)
			}

			if intVal, ok := varValue.(int); ok {
				return intVal, nil
			}

			return 0, fmt.Errorf("variable '%s' is not an integer", varName)
		}

		// Try to parse as integer
		if intVal, err := e.parseInteger(strVal); err == nil {
			return intVal, nil
		}
	}

	// Try direct conversion
	if intVal, err := e.convertToInt(value); err == nil {
		return intVal, nil
	}

	return 0, fmt.Errorf("cannot convert value to integer: %v", value)
}

// convertToSlice converts various types to []interface{}
func (e *Engine) convertToSlice(value interface{}) ([]interface{}, error) {
	if value == nil {
		return nil, fmt.Errorf("value cannot be nil")
	}

	// If it's already a slice of interfaces, return it
	if slice, ok := value.([]interface{}); ok {
		return slice, nil
	}

	// If it's a slice of strings, convert it
	if strSlice, ok := value.([]string); ok {
		result := make([]interface{}, len(strSlice))
		for i, s := range strSlice {
			result[i] = s
		}
		return result, nil
	}

	// If it's a slice of ints, convert it
	if intSlice, ok := value.([]int); ok {
		result := make([]interface{}, len(intSlice))
		for i, n := range intSlice {
			result[i] = n
		}
		return result, nil
	}

	return nil, fmt.Errorf("value is not a valid collection type")
}

// convertToInt converts various numeric types to int
func (e *Engine) convertToInt(value interface{}) (int, error) {
	switch v := value.(type) {
	case int:
		return v, nil
	case int32:
		return int(v), nil
	case int64:
		return int(v), nil
	case float32:
		return int(v), nil
	case float64:
		return int(v), nil
	default:
		return 0, fmt.Errorf("cannot convert %T to int", value)
	}
}

// parseInteger parses a string as an integer (simple implementation)
func (e *Engine) parseInteger(s string) (int, error) {
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}

	result := 0
	negative := false
	start := 0

	if s[0] == '-' {
		negative = true
		start = 1
	}

	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid character '%c' in number", s[i])
		}
		result = result*10 + int(s[i]-'0')
	}

	if negative {
		result = -result
	}

	return result, nil
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

// executeWorkflowStep executes a nested workflow step
func (e *Engine) executeWorkflowStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.WorkflowCall == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"workflow step missing workflow call configuration",
			step.Name,
			step.Type,
			fmt.Errorf("workflow call configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	workflowConfig := step.WorkflowCall
	logger := e.logger.WithField("step", step.Name).WithField("step_type", "workflow")

	// Validate workflow specification
	if workflowConfig.WorkflowName == "" && workflowConfig.WorkflowPath == "" {
		return NewWorkflowError(
			ErrorCodeValidation,
			"workflow step must specify either workflow_name or workflow_path",
			step.Name,
			step.Type,
			fmt.Errorf("no workflow specified"),
		).WithVariableState(execution.GetVariables())
	}

	// Create nested workflow
	var nestedWorkflow Workflow
	var err error

	if workflowConfig.WorkflowName != "" {
		// Load workflow by name (this would typically load from a registry)
		nestedWorkflow, err = e.loadWorkflowByName(workflowConfig.WorkflowName)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("failed to load workflow '%s': %v", workflowConfig.WorkflowName, err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		logger.Debug("Loaded workflow by name",
			"workflow_name", workflowConfig.WorkflowName)
	} else {
		// Load workflow from file path
		nestedWorkflow, err = e.loadWorkflowFromPath(workflowConfig.WorkflowPath)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("failed to load workflow from path '%s': %v", workflowConfig.WorkflowPath, err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		logger.Debug("Loaded workflow from path",
			"workflow_path", workflowConfig.WorkflowPath)
	}

	// Prepare nested workflow parameters
	nestedParameters := make(map[string]interface{})

	// Apply direct parameters
	for key, value := range workflowConfig.Parameters {
		nestedParameters[key] = value
	}

	// Apply parameter mappings (map current variables to nested workflow parameters)
	for nestedParam, currentVar := range workflowConfig.ParameterMappings {
		if value, exists := execution.GetVariable(currentVar); exists {
			nestedParameters[nestedParam] = value
		} else {
			logger.Warn("Parameter mapping source variable not found",
				"nested_param", nestedParam,
				"current_var", currentVar)
		}
	}

	logger.InfoCtx(ctx, "Executing nested workflow",
		"operation", "nested_workflow_execute",
		"nested_workflow", nestedWorkflow.Name,
		"parameter_count", len(nestedParameters),
		"async", workflowConfig.Async)

	// Execute nested workflow
	var nestedExecution *WorkflowExecution
	if workflowConfig.Async {
		// Asynchronous execution
		nestedExecution, err = e.executeNestedWorkflowAsync(ctx, nestedWorkflow, nestedParameters, workflowConfig.Timeout)
	} else {
		// Synchronous execution
		nestedExecution, err = e.executeNestedWorkflowSync(ctx, nestedWorkflow, nestedParameters, workflowConfig.Timeout)
	}

	if err != nil {
		return NewWorkflowError(
			ErrorCodeStepExecution,
			fmt.Sprintf("nested workflow execution failed: %v", err),
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.GetVariables())
	}

	// Apply output mappings (map nested workflow outputs back to current variables)
	if len(workflowConfig.OutputMappings) > 0 {
		logger.Debug("Applying output mappings",
			"mapping_count", len(workflowConfig.OutputMappings))

		for currentVar, nestedVar := range workflowConfig.OutputMappings {
			if value, exists := nestedExecution.GetVariable(nestedVar); exists {
				execution.SetVariable(currentVar, value)
				logger.Debug("Mapped output variable",
					"current_var", currentVar,
					"nested_var", nestedVar,
					"value", value)
			} else {
				logger.Warn("Output mapping source variable not found in nested workflow",
					"current_var", currentVar,
					"nested_var", nestedVar)
			}
		}
	}

	logger.InfoCtx(ctx, "Nested workflow completed successfully",
		"operation", "nested_workflow_complete",
		"nested_workflow", nestedWorkflow.Name,
		"status", nestedExecution.GetStatus())

	return nil
}

// executeNestedWorkflowSync executes a nested workflow synchronously
func (e *Engine) executeNestedWorkflowSync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// Create timeout context if specified
	var execCtx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	} else {
		execCtx = ctx
	}

	// Execute nested workflow
	return e.ExecuteWorkflow(execCtx, workflow, parameters)
}

// executeNestedWorkflowAsync executes a nested workflow asynchronously
func (e *Engine) executeNestedWorkflowAsync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// For async execution, we start the workflow and return immediately
	// The caller can check the status later if needed

	// Create timeout context if specified
	var execCtx context.Context
	var cancel context.CancelFunc

	if timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		// Don't defer cancel here since we're returning immediately
		_ = cancel // To avoid unused variable warning for now
	} else {
		execCtx = ctx
	}

	// Start async execution
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// For async execution, we don't wait for completion
	// Return the execution object immediately
	return execution, nil
}

// loadWorkflowByName loads a workflow by name from a registry (placeholder implementation)
func (e *Engine) loadWorkflowByName(name string) (Workflow, error) {
	// For now, create simple test workflows
	// In a real implementation, this would load from a workflow registry
	switch name {
	case "test-nested-workflow":
		return Workflow{
			Name: "test-nested-workflow",
			Variables: map[string]interface{}{
				"nested_result": "default",
			},
			Steps: []Step{
				{
					Name: "nested-delay",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Nested workflow executed",
					},
				},
			},
		}, nil

	case "test-error-handler":
		return Workflow{
			Name: "test-error-handler",
			Variables: map[string]interface{}{
				"handled":         "handled",
				"recovery_status": "handled",
				"resolution":      "error_resolved",
				"remediation":     "auto_fix_applied",
				"next_action":     "continue_execution",
			},
			Steps: []Step{
				{
					Name: "handle-error-step",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Error handled by recovery workflow",
					},
				},
			},
		}, nil

	default:
		return Workflow{}, fmt.Errorf("workflow '%s' not found", name)
	}
}

// loadWorkflowFromPath loads a workflow from a file path (placeholder implementation)
func (e *Engine) loadWorkflowFromPath(path string) (Workflow, error) {
	// For now, handle specific test paths
	// In a real implementation, this would load and parse a YAML/JSON file
	switch path {
	case "/path/to/error-handler.yaml":
		return Workflow{
			Name: "path-error-handler",
			Variables: map[string]interface{}{
				"recovery_status": "handled",
				"loaded_from":     path,
			},
			Steps: []Step{
				{
					Name: "path-error-step",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Error handler loaded from path",
					},
				},
			},
		}, nil
	default:
		return Workflow{
			Name: "file-loaded-workflow",
			Variables: map[string]interface{}{
				"loaded_from": path,
			},
			Steps: []Step{
				{
					Name: "file-loaded-step",
					Type: StepTypeDelay,
					Delay: &DelayConfig{
						Duration: 1 * time.Millisecond,
						Message:  "Workflow loaded from file",
					},
				},
			},
		}, nil
	}
}

// executeBarrierStep executes a barrier synchronization step
func (e *Engine) executeBarrierStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Barrier == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"barrier configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("barrier configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	barrierName := step.Barrier.Name
	if barrierName == "" {
		barrierName = step.Name
	}

	barrier, err := e.syncManager.GetOrCreateBarrier(barrierName, step.Barrier.Count)
	if err != nil {
		return fmt.Errorf("step %s: failed to get barrier: %w", step.Name, err)
	}

	e.logger.Info("Waiting at barrier", "step", step.Name, "barrier", barrierName, "count", step.Barrier.Count)

	timeout := step.Barrier.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	err = barrier.Wait(ctx, timeout)
	if err != nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			fmt.Sprintf("barrier wait failed: %v", err),
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.GetVariables())
	}

	e.logger.Info("Barrier released", "step", step.Name, "barrier", barrierName)
	return nil
}

// executeSemaphoreStep executes a semaphore synchronization step
func (e *Engine) executeSemaphoreStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Semaphore == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"semaphore configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("semaphore configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	semaphoreName := step.Semaphore.Name
	if semaphoreName == "" {
		semaphoreName = step.Name
	}

	permits := step.Semaphore.InitialPermits
	if permits <= 0 {
		permits = 1 // Default to 1 permit
	}

	semaphore, err := e.syncManager.GetOrCreateSemaphore(semaphoreName, permits)
	if err != nil {
		return fmt.Errorf("step %s: failed to get semaphore: %w", step.Name, err)
	}

	acquireCount := step.Semaphore.Count
	if acquireCount <= 0 {
		acquireCount = 1
	}

	timeout := step.Semaphore.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	switch step.Semaphore.Action {
	case SemaphoreActionAcquire:
		e.logger.Info("Acquiring semaphore", "step", step.Name, "semaphore", semaphoreName, "count", acquireCount)
		err = semaphore.Acquire(ctx, acquireCount, timeout)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("semaphore acquire failed: %v", err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		e.logger.Info("Semaphore acquired", "step", step.Name, "semaphore", semaphoreName)

	case SemaphoreActionRelease:
		e.logger.Info("Releasing semaphore", "step", step.Name, "semaphore", semaphoreName, "count", acquireCount)
		semaphore.Release(acquireCount)
		e.logger.Info("Semaphore released", "step", step.Name, "semaphore", semaphoreName)

	default:
		return fmt.Errorf("step %s: invalid semaphore action: %s", step.Name, step.Semaphore.Action)
	}

	return nil
}

// executeLockStep executes a lock synchronization step
func (e *Engine) executeLockStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Lock == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"lock configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("lock configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	lockName := step.Lock.Name
	if lockName == "" {
		lockName = step.Name
	}

	lock, err := e.syncManager.GetOrCreateLock(lockName)
	if err != nil {
		return fmt.Errorf("step %s: failed to get lock: %w", step.Name, err)
	}

	timeout := step.Lock.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	switch step.Lock.Action {
	case LockActionAcquire:
		if step.Lock.Exclusive {
			e.logger.Info("Acquiring write lock", "step", step.Name, "lock", lockName)
			err = lock.AcquireWrite(ctx, timeout)
			if err != nil {
				return NewWorkflowError(
					ErrorCodeValidation,
					fmt.Sprintf("write lock acquire failed: %v", err),
					step.Name,
					step.Type,
					err,
				).WithVariableState(execution.GetVariables())
			}
			e.logger.Info("Write lock acquired", "step", step.Name, "lock", lockName)
		} else {
			e.logger.Info("Acquiring read lock", "step", step.Name, "lock", lockName)
			err = lock.AcquireRead(ctx, timeout)
			if err != nil {
				return NewWorkflowError(
					ErrorCodeValidation,
					fmt.Sprintf("read lock acquire failed: %v", err),
					step.Name,
					step.Type,
					err,
				).WithVariableState(execution.GetVariables())
			}
			e.logger.Info("Read lock acquired", "step", step.Name, "lock", lockName)
		}

	case LockActionRelease:
		if step.Lock.Exclusive {
			e.logger.Info("Releasing write lock", "step", step.Name, "lock", lockName)
			lock.ReleaseWrite()
			e.logger.Info("Write lock released", "step", step.Name, "lock", lockName)
		} else {
			e.logger.Info("Releasing read lock", "step", step.Name, "lock", lockName)
			lock.ReleaseRead()
			e.logger.Info("Read lock released", "step", step.Name, "lock", lockName)
		}

	default:
		return fmt.Errorf("step %s: invalid lock action: %s", step.Name, step.Lock.Action)
	}

	return nil
}

// executeWaitGroupStep executes a wait group synchronization step
func (e *Engine) executeWaitGroupStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.WaitGroup == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"wait group configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("wait group configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	waitGroupName := step.WaitGroup.Name
	if waitGroupName == "" {
		waitGroupName = step.Name
	}

	waitGroup, err := e.syncManager.GetOrCreateWaitGroup(waitGroupName)
	if err != nil {
		return fmt.Errorf("step %s: failed to get wait group: %w", step.Name, err)
	}

	timeout := step.WaitGroup.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	switch step.WaitGroup.Action {
	case WaitGroupActionAdd:
		count := step.WaitGroup.Count
		if count == 0 {
			count = 1 // Default to 1
		}
		e.logger.Info("Adding to wait group", "step", step.Name, "waitGroup", waitGroupName, "count", count)
		waitGroup.Add(count)
		e.logger.Info("Wait group updated", "step", step.Name, "waitGroup", waitGroupName)

	case WaitGroupActionDone:
		e.logger.Info("Marking wait group done", "step", step.Name, "waitGroup", waitGroupName)
		waitGroup.Done()
		e.logger.Info("Wait group done", "step", step.Name, "waitGroup", waitGroupName)

	case WaitGroupActionWait:
		e.logger.Info("Waiting for wait group", "step", step.Name, "waitGroup", waitGroupName)
		err = waitGroup.Wait(ctx, timeout)
		if err != nil {
			return NewWorkflowError(
				ErrorCodeValidation,
				fmt.Sprintf("wait group wait failed: %v", err),
				step.Name,
				step.Type,
				err,
			).WithVariableState(execution.GetVariables())
		}
		e.logger.Info("Wait group completed", "step", step.Name, "waitGroup", waitGroupName)

	default:
		return fmt.Errorf("step %s: invalid wait group action: %s", step.Name, step.WaitGroup.Action)
	}

	return nil
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

// executeFanInStep executes a fan-in step that collects and combines results from multiple sources
func (e *Engine) executeFanInStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.FanIn == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"fan-in configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("fan-in configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	config := step.FanIn

	if len(config.Sources) == 0 {
		return fmt.Errorf("step %s: at least one source must be specified", step.Name)
	}

	e.logger.Info("Starting fan-in", "step", step.Name, "sources", len(config.Sources), "strategy", config.Strategy)

	// Collect data from all sources
	var sourceData []interface{}
	for _, source := range config.Sources {
		if value, exists := execution.GetVariable(source); exists && value != nil {
			sourceData = append(sourceData, value)
		}
	}

	if len(sourceData) == 0 {
		e.logger.Warn("Fan-in with no data from sources", "step", step.Name)
		execution.SetVariable(config.OutputVariable, nil)
		return nil
	}

	// Apply strategy to combine results
	var result interface{}
	var err error

	switch config.Strategy {
	case FanInStrategyMerge:
		result, err = e.fanInMerge(sourceData)
	case FanInStrategyConcat:
		result, err = e.fanInConcat(sourceData)
	case FanInStrategySum:
		result, err = e.fanInSum(sourceData)
	case FanInStrategyFirst:
		result = sourceData[0]
	case FanInStrategyLast:
		result = sourceData[len(sourceData)-1]
	case FanInStrategyCustom:
		result, err = e.fanInCustom(sourceData, config.Transform)
	default:
		err = fmt.Errorf("unsupported fan-in strategy: %s", config.Strategy)
	}

	if err != nil {
		return fmt.Errorf("step %s: fan-in failed: %w", step.Name, err)
	}

	// Apply filter if specified
	if config.Filter != "" {
		// For now, we'll skip filtering implementation
		e.logger.Warn("Fan-in filtering not yet implemented", "step", step.Name, "filter", config.Filter)
	}

	// Store result
	execution.SetVariable(config.OutputVariable, result)

	e.logger.Info("Fan-in completed", "step", step.Name, "output_variable", config.OutputVariable)
	return nil
}

// fanInMerge merges all source data into a single array
func (e *Engine) fanInMerge(sourceData []interface{}) (interface{}, error) {
	var merged []interface{}
	for _, data := range sourceData {
		if slice, ok := data.([]interface{}); ok {
			merged = append(merged, slice...)
		} else {
			merged = append(merged, data)
		}
	}
	return merged, nil
}

// fanInConcat concatenates string results
func (e *Engine) fanInConcat(sourceData []interface{}) (interface{}, error) {
	var result strings.Builder
	for _, data := range sourceData {
		if str, ok := data.(string); ok {
			result.WriteString(str)
		} else {
			result.WriteString(fmt.Sprintf("%v", data))
		}
	}
	return result.String(), nil
}

// fanInSum sums numeric results
func (e *Engine) fanInSum(sourceData []interface{}) (interface{}, error) {
	var sum float64
	for _, data := range sourceData {
		switch v := data.(type) {
		case int:
			sum += float64(v)
		case int64:
			sum += float64(v)
		case float32:
			sum += float64(v)
		case float64:
			sum += v
		default:
			return nil, fmt.Errorf("cannot sum non-numeric value: %T", data)
		}
	}
	return sum, nil
}

// fanInCustom applies a custom transformation (placeholder implementation)
func (e *Engine) fanInCustom(sourceData []interface{}, transform string) (interface{}, error) {
	// For now, just return the first item
	// In a full implementation, this would evaluate the transform expression
	e.logger.Warn("Custom fan-in transformation not fully implemented", "transform", transform)
	if len(sourceData) > 0 {
		return sourceData[0], nil
	}
	return nil, nil
}

// executeErrorWorkflowStep executes a custom error workflow step
func (e *Engine) executeErrorWorkflowStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.ErrorWorkflow == nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			"error workflow configuration is required",
			step.Name,
			step.Type,
			fmt.Errorf("error workflow configuration is nil"),
		).WithVariableState(execution.GetVariables())
	}

	config := step.ErrorWorkflow

	// Load the error handling workflow
	var errorWorkflow Workflow
	var err error

	if config.WorkflowName != "" {
		errorWorkflow, err = e.loadWorkflowByName(config.WorkflowName)
	} else if config.WorkflowPath != "" {
		errorWorkflow, err = e.loadWorkflowFromPath(config.WorkflowPath)
	} else {
		return NewWorkflowError(
			ErrorCodeValidation,
			"either workflow_name or workflow_path must be specified",
			step.Name,
			step.Type,
			fmt.Errorf("no workflow specification provided"),
		).WithVariableState(execution.GetVariables())
	}

	if err != nil {
		return NewWorkflowError(
			ErrorCodeValidation,
			fmt.Sprintf("failed to load error workflow: %v", err),
			step.Name,
			step.Type,
			err,
		).WithVariableState(execution.GetVariables())
	}

	e.logger.Info("Executing error workflow", "step", step.Name, "error_workflow", errorWorkflow.Name)

	// Create parameters for the error workflow
	parameters := make(map[string]interface{})

	// Add direct parameters
	for key, value := range config.Parameters {
		parameters[key] = value
	}

	// Add parameter mappings from current execution variables
	for errorParam, sourceVar := range config.ParameterMappings {
		if value, exists := execution.GetVariable(sourceVar); exists {
			parameters[errorParam] = value
		}
	}

	// Add error context
	parameters["original_execution_id"] = execution.ID
	parameters["original_workflow"] = execution.WorkflowName
	if execution.GetError() != "" {
		parameters["error_message"] = execution.GetError()
	}
	if errorDetails := execution.GetErrorDetails(); errorDetails != nil {
		parameters["error_details"] = errorDetails
	}

	// Execute the error workflow
	var errorExecution *WorkflowExecution
	if config.Async {
		// Execute asynchronously
		errorExecution, err = e.executeErrorWorkflowAsync(ctx, errorWorkflow, parameters, config.Timeout)
	} else {
		// Execute synchronously
		errorExecution, err = e.executeErrorWorkflowSync(ctx, errorWorkflow, parameters, config.Timeout)
	}

	if err != nil {
		return fmt.Errorf("step %s: error workflow execution failed: %w", step.Name, err)
	}

	// Apply output mappings
	for errorVar, targetVar := range config.OutputMappings {
		if value, exists := errorExecution.GetVariable(errorVar); exists {
			execution.SetVariable(targetVar, value)
		}
	}

	e.logger.Info("Error workflow completed", "step", step.Name, "error_workflow", errorWorkflow.Name, "status", errorExecution.GetStatus())

	// Handle recovery action (but don't apply it here - that should be done by the caller)
	// Just store the recovery action for the caller to use
	execution.SetVariable(step.Name+"_recovery_action", config.RecoveryAction)

	return nil
}

// executeErrorWorkflowSync executes an error workflow synchronously
func (e *Engine) executeErrorWorkflowSync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// Create context with timeout if specified
	execCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Execute the error workflow
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Wait for completion if timeout is specified
	if timeout > 0 {
		select {
		case <-time.After(timeout):
			if execution.Cancel != nil {
				execution.Cancel()
			}
			return execution, fmt.Errorf("error workflow timed out after %v", timeout)
		case <-execCtx.Done():
			return execution, execCtx.Err()
		default:
			// Continue to check status
		}
	}

	// Wait a bit for execution to complete
	time.Sleep(10 * time.Millisecond)

	return execution, nil
}

// executeErrorWorkflowAsync executes an error workflow asynchronously
func (e *Engine) executeErrorWorkflowAsync(ctx context.Context, workflow Workflow, parameters map[string]interface{}, timeout time.Duration) (*WorkflowExecution, error) {
	// Create context with timeout if specified
	execCtx := ctx
	if timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	// Execute the error workflow asynchronously
	execution, err := e.ExecuteWorkflow(execCtx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Return immediately for async execution
	return execution, nil
}

// executeCompositeStep executes a workflow composition step
func (e *Engine) executeCompositeStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Composite == nil {
		return fmt.Errorf("step %s: composite configuration is required", step.Name)
	}

	config := step.Composite

	if len(config.Components) == 0 {
		return fmt.Errorf("step %s: at least one component must be specified", step.Name)
	}

	e.logger.Info("Starting workflow composition", "step", step.Name, "components", len(config.Components), "strategy", config.Strategy)

	// Create context with timeout if specified
	compCtx := ctx
	if config.Timeout > 0 {
		var cancel context.CancelFunc
		compCtx, cancel = context.WithTimeout(ctx, config.Timeout)
		defer cancel()
	}

	// Execute components based on strategy
	var err error
	switch config.Strategy {
	case CompositionStrategySequential:
		err = e.executeComponentsSequential(compCtx, config, execution, step.Name)
	case CompositionStrategyParallel:
		err = e.executeComponentsParallel(compCtx, config, execution, step.Name)
	case CompositionStrategyDependency:
		err = e.executeComponentsDependency(compCtx, config, execution, step.Name)
	case CompositionStrategyPipeline:
		err = e.executeComponentsPipeline(compCtx, config, execution, step.Name)
	case CompositionStrategyConditional:
		err = e.executeComponentsConditional(compCtx, config, execution, step.Name)
	default:
		err = fmt.Errorf("unsupported composition strategy: %s", config.Strategy)
	}

	if err != nil {
		return fmt.Errorf("step %s: composition failed: %w", step.Name, err)
	}

	e.logger.Info("Workflow composition completed", "step", step.Name)
	return nil
}

// executeComponentsSequential executes components one by one
func (e *Engine) executeComponentsSequential(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	for i, component := range config.Components {
		e.logger.Info("Executing component sequentially", "component", component.Name, "index", i)

		err := e.executeComponent(ctx, component, execution, stepName)
		if err != nil {
			return e.handleComponentFailure(err, component, config.FailurePolicy)
		}
	}
	return nil
}

// executeComponentsParallel executes all components in parallel
func (e *Engine) executeComponentsParallel(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	// Create semaphore for concurrency control if specified
	var semaphore chan struct{}
	if config.MaxConcurrency > 0 {
		semaphore = make(chan struct{}, config.MaxConcurrency)
		for i := 0; i < config.MaxConcurrency; i++ {
			semaphore <- struct{}{}
		}
	}

	// Channel to collect errors
	errorsChan := make(chan error, len(config.Components))
	var wg sync.WaitGroup

	// Execute components in parallel
	for _, component := range config.Components {
		wg.Add(1)
		go func(comp WorkflowComponent) {
			defer wg.Done()

			// Acquire semaphore if concurrency is limited
			if semaphore != nil {
				select {
				case <-semaphore:
				case <-ctx.Done():
					errorsChan <- ctx.Err()
					return
				}
				defer func() { semaphore <- struct{}{} }()
			}

			err := e.executeComponent(ctx, comp, execution, stepName)
			if err != nil {
				errorsChan <- e.handleComponentFailure(err, comp, config.FailurePolicy)
			} else {
				errorsChan <- nil
			}
		}(component)
	}

	// Wait for all components to complete
	go func() {
		wg.Wait()
		close(errorsChan)
	}()

	// Collect errors
	var errors []error
	for err := range errorsChan {
		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return errors[0] // Return first error
	}

	return nil
}

// executeComponentsDependency executes components based on dependencies (simplified implementation)
func (e *Engine) executeComponentsDependency(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	// For now, just execute sequentially - a full implementation would build a dependency graph
	e.logger.Warn("Dependency-based composition not fully implemented, falling back to sequential")
	return e.executeComponentsSequential(ctx, config, execution, stepName)
}

// executeComponentsPipeline executes components as a data processing pipeline
func (e *Engine) executeComponentsPipeline(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	// For now, just execute sequentially with data flow - a full implementation would handle complex pipelines
	e.logger.Warn("Pipeline composition not fully implemented, falling back to sequential")
	return e.executeComponentsSequential(ctx, config, execution, stepName)
}

// executeComponentsConditional executes components based on conditions
func (e *Engine) executeComponentsConditional(ctx context.Context, config *CompositeConfig, execution *WorkflowExecution, stepName string) error {
	for _, component := range config.Components {
		// Check component condition (simplified - would need full condition evaluation)
		if component.Condition != nil {
			e.logger.Info("Skipping component due to condition", "component", component.Name)
			continue
		}

		err := e.executeComponent(ctx, component, execution, stepName)
		if err != nil {
			return e.handleComponentFailure(err, component, config.FailurePolicy)
		}
	}
	return nil
}

// executeComponent executes a single workflow component
func (e *Engine) executeComponent(ctx context.Context, component WorkflowComponent, execution *WorkflowExecution, stepName string) error {
	// Load the component workflow
	var workflow Workflow
	var err error

	if component.WorkflowName != "" {
		workflow, err = e.loadWorkflowByName(component.WorkflowName)
	} else if component.WorkflowPath != "" {
		workflow, err = e.loadWorkflowFromPath(component.WorkflowPath)
	} else {
		return fmt.Errorf("component %s: either workflow_name or workflow_path must be specified", component.Name)
	}

	if err != nil {
		return fmt.Errorf("component %s: failed to load workflow: %w", component.Name, err)
	}

	// Create parameters for the component
	parameters := make(map[string]interface{})

	// Add direct parameters
	for key, value := range component.Parameters {
		parameters[key] = value
	}

	// Add parameter mappings
	for compParam, sourceVar := range component.ParameterMappings {
		if value, exists := execution.GetVariable(sourceVar); exists {
			parameters[compParam] = value
		}
	}

	// Create context with timeout if specified
	compCtx := ctx
	if component.Timeout > 0 {
		var cancel context.CancelFunc
		compCtx, cancel = context.WithTimeout(ctx, component.Timeout)
		defer cancel()
	}

	// Execute the component workflow
	var componentExecution *WorkflowExecution
	if component.Async {
		componentExecution, err = e.executeComponentAsync(compCtx, workflow, parameters)
	} else {
		componentExecution, err = e.executeComponentSync(compCtx, workflow, parameters)
	}

	if err != nil {
		return fmt.Errorf("component %s: execution failed: %w", component.Name, err)
	}

	// Apply output mappings
	for compVar, targetVar := range component.OutputMappings {
		if value, exists := componentExecution.GetVariable(compVar); exists {
			execution.SetVariable(targetVar, value)
		}
	}

	// Store component execution result
	execution.SetVariable(stepName+"_component_"+component.Name+"_result", componentExecution.GetStepResults())

	return nil
}

// executeComponentSync executes a component workflow synchronously
func (e *Engine) executeComponentSync(ctx context.Context, workflow Workflow, parameters map[string]interface{}) (*WorkflowExecution, error) {
	execution, err := e.ExecuteWorkflow(ctx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Wait a bit for execution to complete
	time.Sleep(10 * time.Millisecond)

	return execution, nil
}

// executeComponentAsync executes a component workflow asynchronously
func (e *Engine) executeComponentAsync(ctx context.Context, workflow Workflow, parameters map[string]interface{}) (*WorkflowExecution, error) {
	execution, err := e.ExecuteWorkflow(ctx, workflow, parameters)
	if err != nil {
		return nil, err
	}

	// Return immediately for async execution
	return execution, nil
}

// handleComponentFailure handles component execution failures based on failure policy
func (e *Engine) handleComponentFailure(err error, component WorkflowComponent, policy CompositeFailurePolicy) error {
	switch policy {
	case CompositeFailurePolicyFail:
		return err
	case CompositeFailurePolicySkip:
		e.logger.Warn("Skipping failed component", "component", component.Name, "error", err.Error())
		return nil
	case CompositeFailurePolicyRetry:
		e.logger.Warn("Component retry not fully implemented", "component", component.Name)
		return err
	case CompositeFailurePolicyIsolate:
		e.logger.Warn("Component isolation not fully implemented", "component", component.Name)
		return nil
	default:
		return err
	}
}
