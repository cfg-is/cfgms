package workflow

import (
	"context"
	"encoding/json"
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
	logger           logging.Logger
	executions       map[string]*WorkflowExecution
	mutex            sync.RWMutex
	httpClient       *HTTPClient
	providerRegistry *ProviderRegistry
	errorHandler     ErrorHandler
}

// NewEngine creates a new workflow engine instance
func NewEngine(moduleFactory *factory.ModuleFactory, logger logging.Logger) *Engine {
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

	// Create provider registry
	providerRegistry := NewProviderRegistry(logger)

	return &Engine{
		moduleFactory:    moduleFactory,
		logger:           logger,
		executions:       make(map[string]*WorkflowExecution),
		httpClient:       httpClient,
		providerRegistry: providerRegistry,
		errorHandler:     NewDefaultErrorHandler(),
	}
}

// ExecuteWorkflow starts execution of a workflow
func (e *Engine) ExecuteWorkflow(ctx context.Context, workflow Workflow, variables map[string]interface{}) (*WorkflowExecution, error) {
	executionID := generateExecutionID()
	
	// Create execution context with timeout if specified
	execCtx := ctx
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
	}

	// Store execution
	e.mutex.Lock()
	e.executions[executionID] = execution
	e.mutex.Unlock()

	e.logger.Info("Starting workflow execution",
		"execution_id", executionID,
		"workflow", workflow.Name)

	// Start execution in goroutine
	go e.executeWorkflowAsync(execution, workflow)

	return execution, nil
}

// executeWorkflowAsync executes the workflow asynchronously
func (e *Engine) executeWorkflowAsync(execution *WorkflowExecution, workflow Workflow) {
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
	for _, step := range steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := e.executeStep(ctx, step, execution); err != nil {
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

				// Handle error using the error handler
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
	default:
		err = fmt.Errorf("unknown step type: %s", step.Type)
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
		var result int = 0
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
	// TODO: Implement pause functionality
	return fmt.Errorf("pause functionality not yet implemented")
}

// ResumeExecution resumes a paused workflow execution
func (e *Engine) ResumeExecution(executionID string) error {
	// TODO: Implement resume functionality
	return fmt.Errorf("resume functionality not yet implemented")
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

	return nil
}

// convertAPIConfigToHTTP converts API configuration to HTTP configuration
func (e *Engine) convertAPIConfigToHTTP(apiConfig *APIConfig, execution *WorkflowExecution) (*HTTPConfig, error) {
	// This is a simplified implementation
	// In a real system, this would have provider-specific logic for different APIs
	// (Microsoft Graph, Google Admin SDK, Salesforce, etc.)

	var url string
	var method string
	var body interface{}

	// Provider-specific URL and method determination
	switch apiConfig.Provider {
	case "microsoft":
		url, method, body = e.buildMicrosoftGraphRequest(apiConfig)
	case "google":
		url, method, body = e.buildGoogleAPIRequest(apiConfig)
	case "salesforce":
		url, method, body = e.buildSalesforceAPIRequest(apiConfig)
	default:
		return nil, fmt.Errorf("unsupported API provider: %s", apiConfig.Provider)
	}

	httpConfig := &HTTPConfig{
		URL:       url,
		Method:    method,
		Body:      body,
		Auth:      apiConfig.Auth,
		Timeout:   apiConfig.Timeout,
		Retry:     apiConfig.Retry,
		Headers:   make(map[string]string),
	}

	// Set default headers
	if method == "POST" || method == "PUT" || method == "PATCH" {
		httpConfig.Headers["Content-Type"] = "application/json"
	}

	return httpConfig, nil
}

// buildMicrosoftGraphRequest builds Microsoft Graph API requests
func (e *Engine) buildMicrosoftGraphRequest(apiConfig *APIConfig) (string, string, interface{}) {
	baseURL := "https://graph.microsoft.com/v1.0"
	
	switch apiConfig.Service {
	case "users":
		switch apiConfig.Operation {
		case "list":
			return baseURL + "/users", "GET", nil
		case "create":
			return baseURL + "/users", "POST", apiConfig.Parameters
		case "get":
			userID := apiConfig.Parameters["user_id"]
			return fmt.Sprintf("%s/users/%v", baseURL, userID), "GET", nil
		case "update":
			userID := apiConfig.Parameters["user_id"]
			return fmt.Sprintf("%s/users/%v", baseURL, userID), "PATCH", apiConfig.Parameters
		case "delete":
			userID := apiConfig.Parameters["user_id"]
			return fmt.Sprintf("%s/users/%v", baseURL, userID), "DELETE", nil
		}
	case "groups":
		switch apiConfig.Operation {
		case "list":
			return baseURL + "/groups", "GET", nil
		case "create":
			return baseURL + "/groups", "POST", apiConfig.Parameters
		}
	}

	// Default fallback
	return baseURL, "GET", nil
}

// buildGoogleAPIRequest builds Google API requests
func (e *Engine) buildGoogleAPIRequest(apiConfig *APIConfig) (string, string, interface{}) {
	// Simplified implementation for Google APIs
	baseURL := "https://www.googleapis.com"
	
	switch apiConfig.Service {
	case "admin":
		switch apiConfig.Operation {
		case "list_users":
			return baseURL + "/admin/directory/v1/users", "GET", nil
		case "create_user":
			return baseURL + "/admin/directory/v1/users", "POST", apiConfig.Parameters
		}
	}

	return baseURL, "GET", nil
}

// buildSalesforceAPIRequest builds Salesforce API requests
func (e *Engine) buildSalesforceAPIRequest(apiConfig *APIConfig) (string, string, interface{}) {
	// Simplified implementation for Salesforce APIs
	// Note: Real implementation would need instance URL from authentication
	baseURL := "https://your-instance.salesforce.com/services/data/v57.0"
	
	switch apiConfig.Service {
	case "sobjects":
		switch apiConfig.Operation {
		case "query":
			return baseURL + "/query", "GET", nil
		case "create":
			objectType := apiConfig.Parameters["object_type"]
			return fmt.Sprintf("%s/sobjects/%v", baseURL, objectType), "POST", apiConfig.Parameters
		}
	}

	return baseURL, "GET", nil
}

// parseAPIResponse parses API responses and stores relevant data in execution variables
func (e *Engine) parseAPIResponse(step Step, response *HTTPResponse, execution *WorkflowExecution) error {
	// Store common response data
	e.mutex.Lock()
	execution.SetVariable(step.Name+"_api_status", response.StatusCode)
	execution.SetVariable(step.Name+"_api_duration", response.Duration.String())
	e.mutex.Unlock()

	// Try to parse JSON response
	if len(response.Body) > 0 {
		var responseData interface{}
		if err := json.Unmarshal(response.Body, &responseData); err == nil {
			e.mutex.Lock()
			execution.SetVariable(step.Name+"_api_response", responseData)
			e.mutex.Unlock()
		} else {
			// Store as string if JSON parsing fails
			e.mutex.Lock()
			execution.SetVariable(step.Name+"_api_response", string(response.Body))
			e.mutex.Unlock()
		}
	}

	return nil
}

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
			return fmt.Errorf("for loop iteration %d failed: %w", i, err)
		}
	}

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
			return fmt.Errorf("while loop iteration %d failed: %w", iterations, err)
		}
	}

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
			return fmt.Errorf("foreach loop iteration %d failed: %w", index, err)
		}
	}

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