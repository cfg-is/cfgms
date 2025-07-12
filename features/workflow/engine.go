package workflow

import (
	"context"
	"encoding/json"
	"fmt"
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
	e.mutex.Lock()
	execution.Status = StatusRunning
	e.mutex.Unlock()

	defer func() {
		if r := recover(); r != nil {
			e.mutex.Lock()
			execution.Status = StatusFailed
			execution.Error = fmt.Sprintf("workflow panicked: %v", r)
			endTime := time.Now()
			execution.EndTime = &endTime
			e.mutex.Unlock()
			e.logger.Error("Workflow execution panicked",
				"execution_id", execution.ID,
				"error", r)
		}
	}()

	// Execute all root steps
	err := e.executeSteps(execution.Context, workflow.Steps, execution)
	
	endTime := time.Now()
	e.mutex.Lock()
	execution.EndTime = &endTime

	if err != nil {
		execution.Status = StatusFailed
		execution.Error = err.Error()
		e.mutex.Unlock()
		e.logger.Error("Workflow execution failed",
			"execution_id", execution.ID,
			"error", err)
	} else {
		execution.Status = StatusCompleted
		e.mutex.Unlock()
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
				// Handle failure based on step or workflow policy
				failureAction := step.OnFailure
				if failureAction == "" {
					// Use default action
					failureAction = ActionStop
				}

				switch failureAction {
				case ActionStop:
					return fmt.Errorf("step %s failed: %w", step.Name, err)
				case ActionContinue:
					e.logger.Warn("Step failed but continuing",
						"step", step.Name,
						"error", err)
					continue
				case ActionRetry:
					// TODO: Implement retry logic with backoff
					e.logger.Warn("Step failed, retry not yet implemented",
						"step", step.Name,
						"error", err)
					return fmt.Errorf("step %s failed: %w", step.Name, err)
				}
			}
		}
	}
	return nil
}

// executeStep executes a single step based on its type
func (e *Engine) executeStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	e.mutex.Lock()
	execution.CurrentStep = step.Name
	e.mutex.Unlock()
	
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
	e.mutex.Lock()
	execution.StepResults[step.Name] = result
	e.mutex.Unlock()

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
	} else {
		result.Status = StatusCompleted
	}

	e.mutex.Lock()
	execution.StepResults[step.Name] = result
	e.mutex.Unlock()
	return err
}

// executeTaskStep executes a module task
func (e *Engine) executeTaskStep(ctx context.Context, step Step, execution *WorkflowExecution) error {
	if step.Module == "" {
		return fmt.Errorf("module is required for task steps")
	}

	// Create module instance
	var module modules.Module
	module, err := e.moduleFactory.CreateModuleInstance(step.Module)
	if err != nil {
		return fmt.Errorf("failed to create module instance: %w", err)
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
		return fmt.Errorf("failed to apply module configuration: %w", err)
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
			execution.Variables[step.Name+"_result"] = finalState.AsMap()
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
		// TODO: Implement expression evaluation
		return false, fmt.Errorf("expression conditions not yet implemented")
	default:
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
		return exists && value == condition.Value, nil
	case OperatorNotEqual:
		return !exists || value != condition.Value, nil
	// TODO: Implement other operators
	default:
		return false, fmt.Errorf("operator %s not yet implemented", condition.Operator)
	}
}

// GetExecution returns the status of a workflow execution
func (e *Engine) GetExecution(executionID string) (*WorkflowExecution, error) {
	e.mutex.RLock()
	execution, exists := e.executions[executionID]
	e.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("execution not found: %s", executionID)
	}

	// Return a copy to avoid race conditions
	e.mutex.RLock()
	executionCopy := *execution
	
	// Deep copy maps
	executionCopy.StepResults = make(map[string]StepResult)
	for k, v := range execution.StepResults {
		executionCopy.StepResults[k] = v
	}
	
	executionCopy.Variables = make(map[string]interface{})
	for k, v := range execution.Variables {
		executionCopy.Variables[k] = v
	}
	e.mutex.RUnlock()

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
		execution.Status = StatusCancelled
		endTime := time.Now()
		execution.EndTime = &endTime
		e.mutex.Unlock()
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
	execution.Variables[step.Name+"_status_code"] = response.StatusCode
	execution.Variables[step.Name+"_headers"] = response.Headers
	execution.Variables[step.Name+"_body"] = string(response.Body)
	execution.Variables[step.Name+"_duration"] = response.Duration.String()
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
	execution.Variables[step.Name+"_api_success"] = response.Success
	execution.Variables[step.Name+"_api_status"] = response.StatusCode
	execution.Variables[step.Name+"_api_duration"] = response.Duration
	execution.Variables[step.Name+"_api_response"] = response.Data
	execution.Variables[step.Name+"_api_metadata"] = response.Metadata
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
	execution.Variables[step.Name+"_webhook_status"] = response.StatusCode
	execution.Variables[step.Name+"_webhook_response"] = string(response.Body)
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
	execution.Variables[step.Name+"_api_status"] = response.StatusCode
	execution.Variables[step.Name+"_api_duration"] = response.Duration.String()
	e.mutex.Unlock()

	// Try to parse JSON response
	if len(response.Body) > 0 {
		var responseData interface{}
		if err := json.Unmarshal(response.Body, &responseData); err == nil {
			e.mutex.Lock()
			execution.Variables[step.Name+"_api_response"] = responseData
			e.mutex.Unlock()
		} else {
			// Store as string if JSON parsing fails
			e.mutex.Lock()
			execution.Variables[step.Name+"_api_response"] = string(response.Body)
			e.mutex.Unlock()
		}
	}

	return nil
}