// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package workflow provides basic workflow engine capabilities for the CFGMS system.
//
// This package implements a basic workflow engine that supports sequential,
// parallel, and conditional execution of tasks. Workflows are defined using
// YAML configuration and can orchestrate multiple module operations.
//
// Basic workflow primitives:
//   - Sequential: Execute steps one after another
//   - Parallel: Execute multiple steps simultaneously
//   - Conditional: Execute steps based on conditions
//
// Example workflow definition:
//
//	workflow:
//	  name: "deploy-application"
//	  steps:
//	    - type: sequential
//	      steps:
//	        - name: "create-directory"
//	          module: "directory"
//	          config:
//	            path: "/opt/app"
//	            permissions: "755"
//	        - type: parallel
//	          steps:
//	            - name: "install-package"
//	              module: "package"
//	              config:
//	                name: "nginx"
//	                state: "present"
//	            - name: "configure-firewall"
//	              module: "firewall"
//	              config:
//	                port: 80
//	                action: "allow"
//
// The workflow engine integrates with the existing module system and provides
// state management, monitoring, and error handling capabilities.
package workflow

import (
	"context"
	"sync"
	"time"
)

// Workflow defines a complete workflow with metadata and execution steps
type Workflow struct {
	// Name is the unique identifier for this workflow
	Name string `yaml:"name" json:"name"`

	// Description provides human-readable documentation
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Version for workflow versioning support
	Version string `yaml:"version,omitempty" json:"version,omitempty"`

	// Variables define workflow-level variables that can be used in steps
	Variables map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`

	// Steps define the execution flow of the workflow
	Steps []Step `yaml:"steps" json:"steps"`

	// Timeout defines maximum execution time for the entire workflow
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// OnFailure defines what to do when a step fails
	OnFailure FailureAction `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`

	// ErrorWorkflows define custom error handling workflows
	ErrorWorkflows []ErrorWorkflowConfig `yaml:"error_workflows,omitempty" json:"error_workflows,omitempty"`
}

// Step represents a single execution unit in a workflow
type Step struct {
	// Name is the unique identifier for this step within the workflow
	Name string `yaml:"name" json:"name"`

	// Type defines the step execution type (task, sequential, parallel, conditional)
	Type StepType `yaml:"type" json:"type"`

	// Module is the name of the module to execute (for task steps)
	Module string `yaml:"module,omitempty" json:"module,omitempty"`

	// Config contains module-specific configuration (for task steps)
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`

	// Steps contains child steps (for sequential, parallel, conditional steps)
	Steps []Step `yaml:"steps,omitempty" json:"steps,omitempty"`

	// Condition defines when this step should execute (for conditional steps)
	Condition *Condition `yaml:"condition,omitempty" json:"condition,omitempty"`

	// Timeout defines maximum execution time for this step
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// OnFailure defines what to do when this step fails
	OnFailure FailureAction `yaml:"on_failure,omitempty" json:"on_failure,omitempty"`

	// Variables define step-level variables
	Variables map[string]interface{} `yaml:"variables,omitempty" json:"variables,omitempty"`

	// HTTP configuration for HTTP steps
	HTTP *HTTPConfig `yaml:"http,omitempty" json:"http,omitempty"`

	// API configuration for API steps
	API *APIConfig `yaml:"api,omitempty" json:"api,omitempty"`

	// Webhook configuration for webhook steps
	Webhook *WebhookConfig `yaml:"webhook,omitempty" json:"webhook,omitempty"`

	// Delay configuration for delay steps
	Delay *DelayConfig `yaml:"delay,omitempty" json:"delay,omitempty"`

	// Loop configuration for loop steps (for, while, foreach)
	Loop *LoopConfig `yaml:"loop,omitempty" json:"loop,omitempty"`

	// Switch configuration for switch steps
	Switch *SwitchConfig `yaml:"switch,omitempty" json:"switch,omitempty"`

	// Try configuration for try/catch/finally steps
	Try *TryConfig `yaml:"try,omitempty" json:"try,omitempty"`

	// Workflow configuration for nested workflow steps
	WorkflowCall *WorkflowCallConfig `yaml:"workflow_call,omitempty" json:"workflow_call,omitempty"`

	// ErrorHandling defines error handling configuration for this step
	ErrorHandling *ErrorHandlingConfig `yaml:"error_handling,omitempty" json:"error_handling,omitempty"`
	// Barrier configuration for barrier synchronization steps
	Barrier *BarrierConfig `yaml:"barrier,omitempty" json:"barrier,omitempty"`
	// Semaphore configuration for semaphore steps
	Semaphore *SemaphoreConfig `yaml:"semaphore,omitempty" json:"semaphore,omitempty"`
	// Lock configuration for lock steps
	Lock *LockConfig `yaml:"lock,omitempty" json:"lock,omitempty"`
	// WaitGroup configuration for wait group steps
	WaitGroup *WaitGroupConfig `yaml:"waitgroup,omitempty" json:"waitgroup,omitempty"`
	// FanOut configuration for fan-out steps
	FanOut *FanOutConfig `yaml:"fanout,omitempty" json:"fanout,omitempty"`
	// FanIn configuration for fan-in steps
	FanIn *FanInConfig `yaml:"fanin,omitempty" json:"fanin,omitempty"`
	// ErrorWorkflow configuration for custom error workflow steps
	ErrorWorkflow *ErrorWorkflowConfig `yaml:"error_workflow,omitempty" json:"error_workflow,omitempty"`
	// Composite configuration for workflow composition steps
	Composite *CompositeConfig `yaml:"composite,omitempty" json:"composite,omitempty"`
	// Transform configuration for data transformation steps
	Transform map[string]interface{} `yaml:"transform,omitempty" json:"transform,omitempty"`
}

// StepType defines the type of workflow step
type StepType string

const (
	// StepTypeTask executes a single module operation
	StepTypeTask StepType = "task"

	// StepTypeSequential executes child steps one after another
	StepTypeSequential StepType = "sequential"

	// StepTypeParallel executes child steps simultaneously
	StepTypeParallel StepType = "parallel"

	// StepTypeConditional executes child steps based on a condition
	StepTypeConditional StepType = "conditional"

	// StepTypeHTTP executes HTTP API calls
	StepTypeHTTP StepType = "http"

	// StepTypeAPI executes API-based operations (SaaS integrations)
	StepTypeAPI StepType = "api"

	// StepTypeWebhook handles webhook-based operations
	StepTypeWebhook StepType = "webhook"

	// StepTypeDelay introduces delays in workflow execution
	StepTypeDelay StepType = "delay"

	// StepTypeFor executes child steps in a for loop
	StepTypeFor StepType = "for"

	// StepTypeWhile executes child steps in a while loop
	StepTypeWhile StepType = "while"

	// StepTypeForeach executes child steps for each item in a collection
	StepTypeForeach StepType = "foreach"

	// StepTypeSwitch executes child steps based on switch/case logic
	StepTypeSwitch StepType = "switch"

	// StepTypeTry executes child steps with try/catch/finally error handling
	StepTypeTry StepType = "try"

	// StepTypeWorkflow executes a nested workflow
	StepTypeWorkflow StepType = "workflow"

	// StepTypeBreak breaks out of the current loop
	StepTypeBreak StepType = "break"

	// StepTypeContinue continues to the next iteration of the current loop
	StepTypeContinue StepType = "continue"

	// StepTypeBarrier waits for all parallel executions to reach the barrier
	StepTypeBarrier StepType = "barrier"

	// StepTypeSemaphore acquires or releases a semaphore
	StepTypeSemaphore StepType = "semaphore"

	// StepTypeLock acquires or releases a named lock
	StepTypeLock StepType = "lock"

	// StepTypeWaitGroup waits for a group of operations to complete
	StepTypeWaitGroup StepType = "waitgroup"

	// StepTypeFanOut distributes work across multiple parallel branches
	StepTypeFanOut StepType = "fanout"

	// StepTypeFanIn collects and combines results from multiple parallel branches
	StepTypeFanIn StepType = "fanin"

	// StepTypeErrorWorkflow executes a custom error handling workflow
	StepTypeErrorWorkflow StepType = "error_workflow"

	// StepTypeComposite executes a composed workflow from multiple components
	StepTypeComposite StepType = "composite"

	// StepTypeTransform executes data transformation operations
	StepTypeTransform StepType = "transform"
)

// Condition defines execution conditions for conditional steps
type Condition struct {
	// Type defines the condition type
	Type ConditionType `yaml:"type" json:"type"`

	// Variable is the variable name to evaluate
	Variable string `yaml:"variable,omitempty" json:"variable,omitempty"`

	// Operator defines the comparison operator
	Operator ComparisonOperator `yaml:"operator,omitempty" json:"operator,omitempty"`

	// Value is the value to compare against
	Value interface{} `yaml:"value,omitempty" json:"value,omitempty"`

	// Expression allows for complex condition expressions
	Expression string `yaml:"expression,omitempty" json:"expression,omitempty"`

	// And allows for logical AND combinations of conditions
	And []*Condition `yaml:"and,omitempty" json:"and,omitempty"`

	// Or allows for logical OR combinations of conditions
	Or []*Condition `yaml:"or,omitempty" json:"or,omitempty"`

	// Not allows for logical NOT of a condition
	Not *Condition `yaml:"not,omitempty" json:"not,omitempty"`
}

// ConditionType defines the type of condition
type ConditionType string

const (
	// ConditionTypeVariable evaluates a variable against a value
	ConditionTypeVariable ConditionType = "variable"

	// ConditionTypeExpression evaluates a complex expression
	ConditionTypeExpression ConditionType = "expression"

	// ConditionTypeAnd evaluates logical AND of multiple conditions
	ConditionTypeAnd ConditionType = "and"

	// ConditionTypeOr evaluates logical OR of multiple conditions
	ConditionTypeOr ConditionType = "or"

	// ConditionTypeNot evaluates logical NOT of a condition
	ConditionTypeNot ConditionType = "not"
)

// ComparisonOperator defines comparison operators for conditions
type ComparisonOperator string

const (
	// OperatorEqual checks if values are equal
	OperatorEqual ComparisonOperator = "eq"

	// OperatorNotEqual checks if values are not equal
	OperatorNotEqual ComparisonOperator = "ne"

	// OperatorGreaterThan checks if left > right
	OperatorGreaterThan ComparisonOperator = "gt"

	// OperatorGreaterThanOrEqual checks if left >= right
	OperatorGreaterThanOrEqual ComparisonOperator = "gte"

	// OperatorLessThan checks if left < right
	OperatorLessThan ComparisonOperator = "lt"

	// OperatorLessThanOrEqual checks if left <= right
	OperatorLessThanOrEqual ComparisonOperator = "lte"

	// OperatorContains checks if left contains right
	OperatorContains ComparisonOperator = "contains"

	// OperatorExists checks if variable exists
	OperatorExists ComparisonOperator = "exists"
)

// FailureAction defines what to do when a step fails
type FailureAction string

const (
	// ActionStop stops the entire workflow on failure
	ActionStop FailureAction = "stop"

	// ActionContinue continues with the next step on failure
	ActionContinue FailureAction = "continue"

	// ActionRetry retries the failed step
	ActionRetry FailureAction = "retry"
)

// WorkflowExecution represents a running workflow instance
type WorkflowExecution struct {
	// ID is the unique identifier for this execution
	ID string `json:"id"`

	// WorkflowName is the name of the workflow being executed
	WorkflowName string `json:"workflow_name"`

	// Status is the current execution status
	Status ExecutionStatus `json:"status"`

	// StartTime is when the execution started
	StartTime time.Time `json:"start_time"`

	// EndTime is when the execution completed (if finished)
	EndTime *time.Time `json:"end_time,omitempty"`

	// CurrentStep is the currently executing step
	CurrentStep string `json:"current_step,omitempty"`

	// StepResults contains the results of completed steps
	StepResults map[string]StepResult `json:"step_results"`

	// Variables contains the current variable values
	Variables map[string]interface{} `json:"variables"`

	// ExecutionTrace contains the execution path for debugging
	ExecutionTrace []ExecutionStep `json:"execution_trace,omitempty"`

	// Error contains basic error message if the execution failed (deprecated, use ErrorDetails)
	Error string `json:"error,omitempty"`

	// ErrorDetails contains comprehensive error information for debugging
	ErrorDetails *WorkflowError `json:"error_details,omitempty"`

	// Context for cancellation
	Context context.Context `json:"-"`

	// Cancel function for stopping execution
	Cancel context.CancelFunc `json:"-"`

	// mutex protects concurrent access to Variables, StepResults, and ExecutionTrace
	mutex sync.RWMutex `json:"-"`

	// Done is closed when executeWorkflowAsync fully completes (including all logging).
	// Tests wait on this channel instead of polling status to avoid race conditions
	// where goroutines are still writing logs after status reaches a terminal state.
	Done chan struct{} `json:"-"`
}

// Thread-safe methods for WorkflowExecution

// SetVariable safely sets a variable value
func (we *WorkflowExecution) SetVariable(key string, value interface{}) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	if we.Variables == nil {
		we.Variables = make(map[string]interface{})
	}
	we.Variables[key] = value
}

// GetVariable safely gets a variable value
func (we *WorkflowExecution) GetVariable(key string) (interface{}, bool) {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	if we.Variables == nil {
		return nil, false
	}
	value, exists := we.Variables[key]
	return value, exists
}

// GetVariables safely returns a copy of all variables
func (we *WorkflowExecution) GetVariables() map[string]interface{} {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	if we.Variables == nil {
		return make(map[string]interface{})
	}
	// Return a copy to prevent external modification
	result := make(map[string]interface{})
	for k, v := range we.Variables {
		result[k] = v
	}
	return result
}

// SetStepResult safely sets a step result
func (we *WorkflowExecution) SetStepResult(stepName string, result StepResult) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	if we.StepResults == nil {
		we.StepResults = make(map[string]StepResult)
	}
	we.StepResults[stepName] = result
}

// GetStepResult safely gets a step result
func (we *WorkflowExecution) GetStepResult(stepName string) (StepResult, bool) {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	if we.StepResults == nil {
		return StepResult{}, false
	}
	result, exists := we.StepResults[stepName]
	return result, exists
}

// AddExecutionTrace safely adds an execution trace entry
func (we *WorkflowExecution) AddExecutionTrace(step ExecutionStep) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	we.ExecutionTrace = append(we.ExecutionTrace, step)
}

// GetExecutionTrace safely returns a copy of the execution trace
func (we *WorkflowExecution) GetExecutionTrace() []ExecutionStep {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	// Return a copy to prevent external modification
	result := make([]ExecutionStep, len(we.ExecutionTrace))
	copy(result, we.ExecutionTrace)
	return result
}

// SetStatus safely sets the execution status
func (we *WorkflowExecution) SetStatus(status ExecutionStatus) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	we.Status = status
}

// GetStatus safely gets the execution status
func (we *WorkflowExecution) GetStatus() ExecutionStatus {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	return we.Status
}

// GetStepResults safely returns a copy of all step results
func (we *WorkflowExecution) GetStepResults() map[string]StepResult {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	if we.StepResults == nil {
		return make(map[string]StepResult)
	}
	// Return a copy to prevent external modification
	result := make(map[string]StepResult)
	for k, v := range we.StepResults {
		result[k] = v
	}
	return result
}

// HasStepResult safely checks if a step result exists
func (we *WorkflowExecution) HasStepResult(stepName string) bool {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	if we.StepResults == nil {
		return false
	}
	_, exists := we.StepResults[stepName]
	return exists
}

// HasVariable safely checks if a variable exists
func (we *WorkflowExecution) HasVariable(varName string) bool {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	if we.Variables == nil {
		return false
	}
	_, exists := we.Variables[varName]
	return exists
}

// SetCurrentStep safely sets the current step
func (we *WorkflowExecution) SetCurrentStep(stepName string) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	we.CurrentStep = stepName
}

// GetCurrentStep safely gets the current step
func (we *WorkflowExecution) GetCurrentStep() string {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	return we.CurrentStep
}

// SetError safely sets the error message
func (we *WorkflowExecution) SetError(errorMsg string) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	we.Error = errorMsg
}

// GetError safely gets the error message
func (we *WorkflowExecution) GetError() string {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	return we.Error
}

// SetErrorDetails safely sets the error details
func (we *WorkflowExecution) SetErrorDetails(errorDetails *WorkflowError) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	we.ErrorDetails = errorDetails
}

// GetErrorDetails safely gets the error details
func (we *WorkflowExecution) GetErrorDetails() *WorkflowError {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	return we.ErrorDetails
}

// SetEndTime safely sets the end time
func (we *WorkflowExecution) SetEndTime(endTime *time.Time) {
	we.mutex.Lock()
	defer we.mutex.Unlock()
	we.EndTime = endTime
}

// GetEndTime safely gets the end time
func (we *WorkflowExecution) GetEndTime() *time.Time {
	we.mutex.RLock()
	defer we.mutex.RUnlock()
	return we.EndTime
}

// ExecutionStatus represents the status of a workflow execution
type ExecutionStatus string

const (
	// StatusPending indicates the workflow is waiting to start
	StatusPending ExecutionStatus = "pending"

	// StatusRunning indicates the workflow is currently executing
	StatusRunning ExecutionStatus = "running"

	// StatusCompleted indicates the workflow completed successfully
	StatusCompleted ExecutionStatus = "completed"

	// StatusFailed indicates the workflow failed
	StatusFailed ExecutionStatus = "failed"

	// StatusCancelled indicates the workflow was cancelled
	StatusCancelled ExecutionStatus = "cancelled"

	// StatusPaused indicates the workflow is paused
	StatusPaused ExecutionStatus = "paused"
)

// StepResult contains the result of a step execution
type StepResult struct {
	// Status is the execution status of the step
	Status ExecutionStatus `json:"status"`

	// StartTime is when the step started
	StartTime time.Time `json:"start_time"`

	// EndTime is when the step completed
	EndTime *time.Time `json:"end_time,omitempty"`

	// Duration is how long the step took to execute
	Duration time.Duration `json:"duration"`

	// Output contains any output from the step
	Output map[string]interface{} `json:"output,omitempty"`

	// Error contains basic error message if the step failed (deprecated, use ErrorDetails)
	Error string `json:"error,omitempty"`

	// ErrorDetails contains comprehensive error information for debugging
	ErrorDetails *WorkflowError `json:"error_details,omitempty"`

	// RetryCount tracks how many times this step has been retried
	RetryCount int `json:"retry_count"`

	// RetryAttempts contains details of each retry attempt
	RetryAttempts []RetryAttempt `json:"retry_attempts,omitempty"`
}

// WorkflowEngine defines the interface for workflow execution
type WorkflowEngine interface {
	// ExecuteWorkflow starts execution of a workflow
	ExecuteWorkflow(ctx context.Context, workflow Workflow, variables map[string]interface{}) (*WorkflowExecution, error)

	// GetExecution returns the status of a workflow execution
	GetExecution(executionID string) (*WorkflowExecution, error)

	// ListExecutions returns all workflow executions
	ListExecutions() ([]*WorkflowExecution, error)

	// CancelExecution cancels a running workflow execution
	CancelExecution(executionID string) error

	// PauseExecution pauses a running workflow execution
	PauseExecution(executionID string) error

	// ResumeExecution resumes a paused workflow execution
	ResumeExecution(executionID string) error
}

// StepExecutor defines the interface for executing individual steps
type StepExecutor interface {
	// ExecuteStep executes a single workflow step
	ExecuteStep(ctx context.Context, step Step, variables map[string]interface{}) (StepResult, error)
}

// HTTPConfig defines configuration for HTTP-based workflow steps
type HTTPConfig struct {
	// URL is the target URL for the HTTP request
	URL string `yaml:"url" json:"url"`

	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.)
	Method string `yaml:"method" json:"method"`

	// Headers contains HTTP headers to send with the request
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Body contains the request body (for POST/PUT requests)
	Body interface{} `yaml:"body,omitempty" json:"body,omitempty"`

	// Authentication configuration
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`

	// Timeout for the HTTP request
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retry configuration
	Retry *RetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`

	// ExpectedStatus defines expected HTTP status codes (default: 200-299)
	ExpectedStatus []int `yaml:"expected_status,omitempty" json:"expected_status,omitempty"`

	// RateLimit configuration for this specific request
	RateLimit *RateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// APIConfig defines configuration for API-based workflow steps (SaaS integrations)
type APIConfig struct {
	// Provider specifies the API provider (e.g., "microsoft", "google", "salesforce")
	Provider string `yaml:"provider" json:"provider"`

	// Service specifies the specific service within the provider (e.g., "graph", "admin")
	Service string `yaml:"service" json:"service"`

	// Operation specifies the API operation to perform
	Operation string `yaml:"operation" json:"operation"`

	// Parameters contains operation-specific parameters
	Parameters map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`

	// Authentication configuration
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`

	// Timeout for the API request
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retry configuration
	Retry *RetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`

	// RateLimit configuration
	RateLimit *RateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`
}

// WebhookConfig defines configuration for webhook-based workflow steps
type WebhookConfig struct {
	// URL is the webhook endpoint URL
	URL string `yaml:"url" json:"url"`

	// Method is the HTTP method for the webhook (default: POST)
	Method string `yaml:"method,omitempty" json:"method,omitempty"`

	// Headers contains HTTP headers to send with the webhook
	Headers map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`

	// Payload contains the webhook payload
	Payload interface{} `yaml:"payload,omitempty" json:"payload,omitempty"`

	// Authentication configuration
	Auth *AuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`

	// Timeout for the webhook request
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Retry configuration
	Retry *RetryConfig `yaml:"retry,omitempty" json:"retry,omitempty"`
}

// DelayConfig defines configuration for delay workflow steps
type DelayConfig struct {
	// Duration specifies how long to wait
	Duration time.Duration `yaml:"duration" json:"duration"`

	// Message provides a description of why the delay is happening
	Message string `yaml:"message,omitempty" json:"message,omitempty"`
}

// AuthConfig defines authentication configuration for API requests
type AuthConfig struct {
	// Type specifies the authentication type
	Type AuthType `yaml:"type" json:"type"`

	// Bearer token for Bearer authentication
	BearerToken string `yaml:"bearer_token,omitempty" json:"bearer_token,omitempty"`

	// API key for API key authentication
	APIKey string `yaml:"api_key,omitempty" json:"api_key,omitempty"`

	// API key header name (default: "X-API-Key")
	APIKeyHeader string `yaml:"api_key_header,omitempty" json:"api_key_header,omitempty"`

	// Basic authentication username
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Basic authentication password
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// OAuth2 configuration
	OAuth2 *OAuth2Config `yaml:"oauth2,omitempty" json:"oauth2,omitempty"`

	// Custom headers for authentication
	CustomHeaders map[string]string `yaml:"custom_headers,omitempty" json:"custom_headers,omitempty"`
}

// AuthType defines supported authentication types
type AuthType string

const (
	// AuthTypeBearer uses Bearer token authentication
	AuthTypeBearer AuthType = "bearer"

	// AuthTypeAPIKey uses API key authentication
	AuthTypeAPIKey AuthType = "api_key"

	// AuthTypeBasic uses HTTP Basic authentication
	AuthTypeBasic AuthType = "basic"

	// AuthTypeOAuth2 uses OAuth2 authentication
	AuthTypeOAuth2 AuthType = "oauth2"

	// AuthTypeCustom uses custom authentication headers
	AuthTypeCustom AuthType = "custom"

	// AuthTypeNone uses no authentication
	AuthTypeNone AuthType = "none"
)

// OAuth2Config defines OAuth2 authentication configuration
type OAuth2Config struct {
	// ClientID for OAuth2
	ClientID string `yaml:"client_id" json:"client_id"`

	// ClientSecret for OAuth2
	ClientSecret string `yaml:"client_secret" json:"client_secret"`

	// TokenURL for obtaining access tokens
	TokenURL string `yaml:"token_url" json:"token_url"`

	// Scopes for OAuth2 authorization
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// GrantType for OAuth2 (default: "client_credentials")
	GrantType string `yaml:"grant_type,omitempty" json:"grant_type,omitempty"`
}

// RetryConfig defines retry configuration for HTTP/API requests
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int `yaml:"max_attempts" json:"max_attempts"`

	// InitialDelay is the initial delay between retries
	InitialDelay time.Duration `yaml:"initial_delay" json:"initial_delay"`

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration `yaml:"max_delay" json:"max_delay"`

	// BackoffMultiplier for exponential backoff
	BackoffMultiplier float64 `yaml:"backoff_multiplier" json:"backoff_multiplier"`

	// RetryableStatusCodes defines which HTTP status codes should trigger retries
	RetryableStatusCodes []int `yaml:"retryable_status_codes,omitempty" json:"retryable_status_codes,omitempty"`
}

// RateLimitConfig defines rate limiting configuration for API requests
type RateLimitConfig struct {
	// RequestsPerSecond limits the number of requests per second
	RequestsPerSecond float64 `yaml:"requests_per_second" json:"requests_per_second"`

	// BurstSize allows for burst requests above the rate limit
	BurstSize int `yaml:"burst_size" json:"burst_size"`

	// WaitOnLimit determines whether to wait or fail when rate limit is exceeded
	WaitOnLimit bool `yaml:"wait_on_limit" json:"wait_on_limit"`
}

// LoopConfig defines configuration for loop workflow steps
type LoopConfig struct {
	// Type specifies the type of loop (for, while, foreach)
	Type LoopType `yaml:"type" json:"type"`

	// Variable is the loop variable name (for for and foreach loops)
	Variable string `yaml:"variable,omitempty" json:"variable,omitempty"`

	// Start is the starting value for for loops
	Start interface{} `yaml:"start,omitempty" json:"start,omitempty"`

	// End is the ending value for for loops
	End interface{} `yaml:"end,omitempty" json:"end,omitempty"`

	// Step is the increment value for for loops (default: 1)
	Step interface{} `yaml:"step,omitempty" json:"step,omitempty"`

	// Condition is the condition to evaluate for while loops
	Condition *Condition `yaml:"condition,omitempty" json:"condition,omitempty"`

	// Items is the collection to iterate over for foreach loops
	Items interface{} `yaml:"items,omitempty" json:"items,omitempty"`

	// ItemsVariable is the variable name containing the collection for foreach loops
	ItemsVariable string `yaml:"items_variable,omitempty" json:"items_variable,omitempty"`

	// IndexVariable is the variable name for the current index (optional)
	IndexVariable string `yaml:"index_variable,omitempty" json:"index_variable,omitempty"`

	// MaxIterations is a safety limit to prevent infinite loops
	MaxIterations int `yaml:"max_iterations,omitempty" json:"max_iterations,omitempty"`
}

// LoopType defines the type of loop
type LoopType string

const (
	// LoopTypeFor executes a counted loop
	LoopTypeFor LoopType = "for"

	// LoopTypeWhile executes a conditional loop
	LoopTypeWhile LoopType = "while"

	// LoopTypeForeach executes a loop over a collection
	LoopTypeForeach LoopType = "foreach"
)

// WorkflowError provides comprehensive error information for debugging
type WorkflowError struct {
	// Code is a unique error code for programmatic handling
	Code ErrorCode `json:"code"`

	// Message is the human-readable error message
	Message string `json:"message"`

	// Details provides additional context about the error
	Details map[string]interface{} `json:"details,omitempty"`

	// Timestamp is when the error occurred
	Timestamp time.Time `json:"timestamp"`

	// StepName is the name of the step where the error occurred
	StepName string `json:"step_name"`

	// StepType is the type of step where the error occurred
	StepType StepType `json:"step_type"`

	// ExecutionPath shows the path through the workflow to this error
	ExecutionPath []string `json:"execution_path"`

	// VariableState captures the variable state at the time of error
	VariableState map[string]interface{} `json:"variable_state"`

	// StackTrace provides the Go stack trace for debugging
	StackTrace []StackFrame `json:"stack_trace,omitempty"`

	// Cause is the underlying error that caused this workflow error
	Cause error `json:"-"`

	// CauseMessage is the string representation of the underlying error
	CauseMessage string `json:"cause_message,omitempty"`

	// RetryAttempt indicates which retry attempt this error occurred on (0 = first attempt)
	RetryAttempt int `json:"retry_attempt"`

	// Recoverable indicates whether this error can be recovered from
	Recoverable bool `json:"recoverable"`

	// ChildErrors contains errors from child steps (for parallel/sequential steps)
	ChildErrors []*WorkflowError `json:"child_errors,omitempty"`
}

// ErrorCode defines specific error types for programmatic handling
type ErrorCode string

const (
	// ErrorCodeStepExecution indicates a step failed during execution
	ErrorCodeStepExecution ErrorCode = "STEP_EXECUTION_FAILED"

	// ErrorCodeTimeout indicates a step or workflow timed out
	ErrorCodeTimeout ErrorCode = "TIMEOUT"

	// ErrorCodeValidation indicates a validation error
	ErrorCodeValidation ErrorCode = "VALIDATION_ERROR"

	// ErrorCodeConditionEvaluation indicates a condition evaluation error
	ErrorCodeConditionEvaluation ErrorCode = "CONDITION_EVALUATION_ERROR"

	// ErrorCodeVariableResolution indicates a variable resolution error
	ErrorCodeVariableResolution ErrorCode = "VARIABLE_RESOLUTION_ERROR"

	// ErrorCodeLoopExecution indicates a loop execution error
	ErrorCodeLoopExecution ErrorCode = "LOOP_EXECUTION_ERROR"

	// ErrorCodeInfiniteLoop indicates a loop exceeded maximum iterations
	ErrorCodeInfiniteLoop ErrorCode = "INFINITE_LOOP_DETECTED"

	// ErrorCodeModuleExecution indicates a module execution error
	ErrorCodeModuleExecution ErrorCode = "MODULE_EXECUTION_FAILED"

	// ErrorCodeHTTPRequest indicates an HTTP request error
	ErrorCodeHTTPRequest ErrorCode = "HTTP_REQUEST_FAILED"

	// ErrorCodeAPIRequest indicates an API request error
	ErrorCodeAPIRequest ErrorCode = "API_REQUEST_FAILED"

	// ErrorCodeWebhookDelivery indicates a webhook delivery error
	ErrorCodeWebhookDelivery ErrorCode = "WEBHOOK_DELIVERY_FAILED"

	// ErrorCodeAuthenticationFailure indicates an authentication error
	ErrorCodeAuthenticationFailure ErrorCode = "AUTHENTICATION_FAILED"

	// ErrorCodeRateLimitExceeded indicates a rate limit was exceeded
	ErrorCodeRateLimitExceeded ErrorCode = "RATE_LIMIT_EXCEEDED"

	// ErrorCodeCancellation indicates the workflow was cancelled
	ErrorCodeCancellation ErrorCode = "WORKFLOW_CANCELLED"

	// ErrorCodeUnknown indicates an unknown error occurred
	ErrorCodeUnknown ErrorCode = "UNKNOWN_ERROR"
)

// StackFrame represents a single frame in a stack trace
type StackFrame struct {
	// Function is the function name
	Function string `json:"function"`

	// File is the source file path
	File string `json:"file"`

	// Line is the line number in the source file
	Line int `json:"line"`
}

// ExecutionStep represents a step in the execution trace
type ExecutionStep struct {
	// StepName is the name of the executed step
	StepName string `json:"step_name"`

	// StepType is the type of step
	StepType StepType `json:"step_type"`

	// Timestamp is when this step was executed
	Timestamp time.Time `json:"timestamp"`

	// Duration is how long this step took
	Duration time.Duration `json:"duration"`

	// Status is the result status of this step
	Status ExecutionStatus `json:"status"`

	// Variables contains the variable state when this step started
	Variables map[string]interface{} `json:"variables,omitempty"`

	// ParentStep is the name of the parent step (for nested steps)
	ParentStep string `json:"parent_step,omitempty"`

	// LoopIteration indicates the loop iteration number (if in a loop)
	LoopIteration int `json:"loop_iteration,omitempty"`
}

// RetryAttempt contains details about a retry attempt
type RetryAttempt struct {
	// AttemptNumber is the retry attempt number (1-based)
	AttemptNumber int `json:"attempt_number"`

	// Timestamp is when this retry attempt was made
	Timestamp time.Time `json:"timestamp"`

	// Error is the error that occurred during this attempt
	Error *WorkflowError `json:"error,omitempty"`

	// Delay is how long we waited before this retry
	Delay time.Duration `json:"delay"`

	// Variables contains the variable state at retry time
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// ErrorHandler defines the interface for handling workflow errors
type ErrorHandler interface {
	// HandleError processes a workflow error and returns recovery actions
	HandleError(ctx context.Context, err *WorkflowError, execution *WorkflowExecution) ErrorHandlingDecision

	// ShouldRetry determines if a step should be retried based on the error
	ShouldRetry(err *WorkflowError, retryCount int, config *RetryConfig) bool

	// CalculateRetryDelay calculates the delay before the next retry attempt
	CalculateRetryDelay(retryCount int, config *RetryConfig) time.Duration
}

// ErrorHandlingDecision represents the decision made by an error handler
type ErrorHandlingDecision struct {
	// Action is the action to take
	Action ErrorAction `json:"action"`

	// Message provides context for the decision
	Message string `json:"message,omitempty"`

	// RetryDelay specifies how long to wait before retry (if Action is Retry)
	RetryDelay time.Duration `json:"retry_delay,omitempty"`

	// ContinueWith specifies which step to continue with (if Action is ContinueWith)
	ContinueWith string `json:"continue_with,omitempty"`

	// Variables contains any variable updates to apply
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// ErrorAction defines the possible actions to take when handling an error
type ErrorAction string

const (
	// ErrorActionStop stops the workflow execution
	ErrorActionStop ErrorAction = "stop"

	// ErrorActionContinue continues with the next step
	ErrorActionContinue ErrorAction = "continue"

	// ErrorActionRetry retries the failed step
	ErrorActionRetry ErrorAction = "retry"

	// ErrorActionContinueWith continues execution from a specific step
	ErrorActionContinueWith ErrorAction = "continue_with"

	// ErrorActionFallback executes a fallback step or workflow
	ErrorActionFallback ErrorAction = "fallback"
)

// Step error handling configuration
type ErrorHandlingConfig struct {
	// IgnoreErrors defines which error codes to ignore and continue
	IgnoreErrors []ErrorCode `yaml:"ignore_errors,omitempty" json:"ignore_errors,omitempty"`

	// RetryOnErrors defines which error codes should trigger retries
	RetryOnErrors []ErrorCode `yaml:"retry_on_errors,omitempty" json:"retry_on_errors,omitempty"`

	// FallbackStep defines a step to execute if this step fails
	FallbackStep *Step `yaml:"fallback_step,omitempty" json:"fallback_step,omitempty"`

	// ContinueOnErrors defines which error codes allow continuing to next step
	ContinueOnErrors []ErrorCode `yaml:"continue_on_errors,omitempty" json:"continue_on_errors,omitempty"`

	// StopOnErrors defines which error codes should stop the workflow
	StopOnErrors []ErrorCode `yaml:"stop_on_errors,omitempty" json:"stop_on_errors,omitempty"`

	// CustomHandler allows specifying a custom error handler function name
	CustomHandler string `yaml:"custom_handler,omitempty" json:"custom_handler,omitempty"`
}

// Node represents a workflow node interface
type Node interface {
	// Execute runs the node with given inputs and returns outputs
	Execute(ctx context.Context, inputs NodeInput) (NodeOutput, error)

	// GetID returns the unique identifier for this node
	GetID() string

	// GetType returns the node type
	GetType() string
}

// BaseNode provides common functionality for workflow nodes
type BaseNode struct {
	// ID is the unique identifier for this node
	ID string `yaml:"id" json:"id"`

	// Type specifies the node type
	Type string `yaml:"type" json:"type"`

	// Name is a human-readable name for the node
	Name string `yaml:"name" json:"name"`

	// Description provides additional context about the node
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// GetID returns the node's unique identifier
func (bn *BaseNode) GetID() string {
	return bn.ID
}

// GetType returns the node's type
func (bn *BaseNode) GetType() string {
	return bn.Type
}

// NodeInput represents input data for a workflow node
type NodeInput struct {
	// Data contains the input data as key-value pairs
	Data map[string]interface{} `json:"data"`

	// Context provides additional context information
	Context map[string]interface{} `json:"context,omitempty"`
}

// NodeOutput represents output data from a workflow node
type NodeOutput struct {
	// Data contains the output data as key-value pairs
	Data map[string]interface{} `json:"data"`

	// Success indicates whether the node executed successfully
	Success bool `json:"success"`

	// Error contains error information if execution failed
	Error string `json:"error,omitempty"`

	// Metadata provides additional information about the execution
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// SwitchConfig defines configuration for switch workflow steps
type SwitchConfig struct {
	// Variable is the variable name to evaluate for switch logic
	Variable string `yaml:"variable,omitempty" json:"variable,omitempty"`

	// Expression allows for complex expression evaluation (alternative to Variable)
	Expression string `yaml:"expression,omitempty" json:"expression,omitempty"`

	// Cases define the different case branches
	Cases []SwitchCase `yaml:"cases" json:"cases"`

	// Default defines the default steps to execute if no case matches
	Default []Step `yaml:"default,omitempty" json:"default,omitempty"`
}

// SwitchCase represents a single case in a switch statement
type SwitchCase struct {
	// Value is the value to match against the switch variable/expression
	Value interface{} `yaml:"value" json:"value"`

	// Steps define the steps to execute if this case matches
	Steps []Step `yaml:"steps" json:"steps"`

	// Condition allows for more complex matching logic (alternative to Value)
	Condition *Condition `yaml:"condition,omitempty" json:"condition,omitempty"`
}

// TryConfig defines configuration for try/catch/finally workflow steps
type TryConfig struct {
	// Try defines the steps to execute in the try block
	Try []Step `yaml:"try" json:"try"`

	// Catch defines the error handling steps
	Catch []CatchBlock `yaml:"catch,omitempty" json:"catch,omitempty"`

	// Finally defines steps that always execute after try/catch
	Finally []Step `yaml:"finally,omitempty" json:"finally,omitempty"`
}

// CatchBlock represents a catch block for specific error types
type CatchBlock struct {
	// ErrorCodes define which error codes this catch block handles
	ErrorCodes []ErrorCode `yaml:"error_codes,omitempty" json:"error_codes,omitempty"`

	// ErrorTypes define which error types this catch block handles (for string matching)
	ErrorTypes []string `yaml:"error_types,omitempty" json:"error_types,omitempty"`

	// Steps define the error handling steps
	Steps []Step `yaml:"steps" json:"steps"`

	// RethrowAfter determines if the error should be rethrown after handling
	RethrowAfter bool `yaml:"rethrow_after,omitempty" json:"rethrow_after,omitempty"`
}

// WorkflowCallConfig defines configuration for nested workflow execution
type WorkflowCallConfig struct {
	// WorkflowName is the name of the workflow to execute
	WorkflowName string `yaml:"workflow_name" json:"workflow_name"`

	// WorkflowPath is the path to the workflow file (alternative to WorkflowName)
	WorkflowPath string `yaml:"workflow_path,omitempty" json:"workflow_path,omitempty"`

	// Parameters define input parameters to pass to the nested workflow
	Parameters map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`

	// ParameterMappings define how to map current variables to nested workflow parameters
	ParameterMappings map[string]string `yaml:"parameter_mappings,omitempty" json:"parameter_mappings,omitempty"`

	// OutputMappings define how to map nested workflow outputs back to current variables
	OutputMappings map[string]string `yaml:"output_mappings,omitempty" json:"output_mappings,omitempty"`

	// Timeout defines maximum execution time for the nested workflow
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Async determines if the nested workflow should run asynchronously
	Async bool `yaml:"async,omitempty" json:"async,omitempty"`

	// WaitForCompletion determines if we should wait for async workflows to complete
	WaitForCompletion bool `yaml:"wait_for_completion,omitempty" json:"wait_for_completion,omitempty"`
}

// BarrierConfig defines configuration for barrier synchronization
type BarrierConfig struct {
	// Name is the unique identifier for this barrier
	Name string `yaml:"name" json:"name"`
	// Count is the number of workflows/steps that must reach the barrier
	Count int `yaml:"count" json:"count"`
	// Timeout defines maximum time to wait for all participants
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// SemaphoreConfig defines configuration for semaphore operations
type SemaphoreConfig struct {
	// Name is the unique identifier for this semaphore
	Name string `yaml:"name" json:"name"`
	// Action defines the operation: "acquire" or "release"
	Action SemaphoreAction `yaml:"action" json:"action"`
	// Count is the number of permits to acquire/release (default: 1)
	Count int `yaml:"count,omitempty" json:"count,omitempty"`
	// Timeout defines maximum time to wait for acquisition
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// InitialPermits defines initial permits when creating the semaphore
	InitialPermits int `yaml:"initial_permits,omitempty" json:"initial_permits,omitempty"`
}

// SemaphoreAction defines the type of semaphore operation
type SemaphoreAction string

const (
	SemaphoreActionAcquire SemaphoreAction = "acquire"
	SemaphoreActionRelease SemaphoreAction = "release"
)

// LockConfig defines configuration for lock operations
type LockConfig struct {
	// Name is the unique identifier for this lock
	Name string `yaml:"name" json:"name"`
	// Action defines the operation: "acquire" or "release"
	Action LockAction `yaml:"action" json:"action"`
	// Timeout defines maximum time to wait for acquisition
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Exclusive determines if this is an exclusive (write) lock or shared (read) lock
	Exclusive bool `yaml:"exclusive,omitempty" json:"exclusive,omitempty"`
}

// LockAction defines the type of lock operation
type LockAction string

const (
	LockActionAcquire LockAction = "acquire"
	LockActionRelease LockAction = "release"
)

// WaitGroupConfig defines configuration for wait group operations
type WaitGroupConfig struct {
	// Name is the unique identifier for this wait group
	Name string `yaml:"name" json:"name"`
	// Action defines the operation: "add", "done", or "wait"
	Action WaitGroupAction `yaml:"action" json:"action"`
	// Count is the number to add to the wait group (for "add" action)
	Count int `yaml:"count,omitempty" json:"count,omitempty"`
	// Timeout defines maximum time to wait for completion
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// WaitGroupAction defines the type of wait group operation
type WaitGroupAction string

const (
	WaitGroupActionAdd  WaitGroupAction = "add"
	WaitGroupActionDone WaitGroupAction = "done"
	WaitGroupActionWait WaitGroupAction = "wait"
)

// FanOutConfig defines configuration for fan-out operations
type FanOutConfig struct {
	// DataSource defines the variable containing data to distribute
	DataSource string `yaml:"data_source" json:"data_source"`
	// WorkerTemplate defines the step template to execute for each data item
	WorkerTemplate Step `yaml:"worker_template" json:"worker_template"`
	// MaxConcurrency limits the number of concurrent workers (0 = unlimited)
	MaxConcurrency int `yaml:"max_concurrency,omitempty" json:"max_concurrency,omitempty"`
	// ResultVariable defines where to store individual worker results
	ResultVariable string `yaml:"result_variable,omitempty" json:"result_variable,omitempty"`
	// Timeout defines maximum time to wait for all workers to complete
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// FanInConfig defines configuration for fan-in operations
type FanInConfig struct {
	// Sources defines the variables to collect from
	Sources []string `yaml:"sources" json:"sources"`
	// Strategy defines how to combine the results
	Strategy FanInStrategy `yaml:"strategy" json:"strategy"`
	// OutputVariable defines where to store the combined result
	OutputVariable string `yaml:"output_variable" json:"output_variable"`
	// Filter defines optional filtering expression for results
	Filter string `yaml:"filter,omitempty" json:"filter,omitempty"`
	// Transform defines optional transformation expression for results
	Transform string `yaml:"transform,omitempty" json:"transform,omitempty"`
}

// FanInStrategy defines how to combine fan-in results
type FanInStrategy string

const (
	// FanInStrategyMerge merges all results into a single array
	FanInStrategyMerge FanInStrategy = "merge"
	// FanInStrategyConcat concatenates string results
	FanInStrategyConcat FanInStrategy = "concat"
	// FanInStrategySum sums numeric results
	FanInStrategySum FanInStrategy = "sum"
	// FanInStrategyFirst takes the first non-nil result
	FanInStrategyFirst FanInStrategy = "first"
	// FanInStrategyLast takes the last non-nil result
	FanInStrategyLast FanInStrategy = "last"
	// FanInStrategyCustom applies a custom aggregation function
	FanInStrategyCustom FanInStrategy = "custom"
)

// ErrorWorkflowConfig defines configuration for custom error workflow execution
type ErrorWorkflowConfig struct {
	// WorkflowName is the name of the error handling workflow to execute
	WorkflowName string `yaml:"workflow_name,omitempty" json:"workflow_name,omitempty"`
	// WorkflowPath is the file path to the error handling workflow
	WorkflowPath string `yaml:"workflow_path,omitempty" json:"workflow_path,omitempty"`
	// ErrorCodes specifies which error codes this workflow should handle
	ErrorCodes []ErrorCode `yaml:"error_codes,omitempty" json:"error_codes,omitempty"`
	// ErrorTypes specifies which error types (by message content) to handle
	ErrorTypes []string `yaml:"error_types,omitempty" json:"error_types,omitempty"`
	// Priority determines the order of error workflow execution (higher = first)
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`
	// Parameters to pass to the error handling workflow
	Parameters map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	// ParameterMappings maps variables from the current workflow to error workflow parameters
	ParameterMappings map[string]string `yaml:"parameter_mappings,omitempty" json:"parameter_mappings,omitempty"`
	// OutputMappings maps variables from the error workflow back to the current workflow
	OutputMappings map[string]string `yaml:"output_mappings,omitempty" json:"output_mappings,omitempty"`
	// RecoveryAction defines what to do after the error workflow completes
	RecoveryAction RecoveryAction `yaml:"recovery_action,omitempty" json:"recovery_action,omitempty"`
	// Timeout defines maximum time to wait for error workflow completion
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Async determines if the error workflow should run asynchronously
	Async bool `yaml:"async,omitempty" json:"async,omitempty"`
}

// RecoveryAction defines what to do after an error workflow completes
type RecoveryAction string

const (
	// RecoveryActionContinue continues normal workflow execution
	RecoveryActionContinue RecoveryAction = "continue"
	// RecoveryActionRetry retries the failed step
	RecoveryActionRetry RecoveryAction = "retry"
	// RecoveryActionSkip skips the failed step and continues
	RecoveryActionSkip RecoveryAction = "skip"
	// RecoveryActionFail fails the workflow (default behavior)
	RecoveryActionFail RecoveryAction = "fail"
	// RecoveryActionAbort immediately stops workflow execution
	RecoveryActionAbort RecoveryAction = "abort"
)

// CompositeConfig defines configuration for workflow composition
type CompositeConfig struct {
	// Components defines the workflow components to compose
	Components []WorkflowComponent `yaml:"components" json:"components"`
	// Strategy defines how to compose the components
	Strategy CompositionStrategy `yaml:"strategy" json:"strategy"`
	// DataFlow defines how data flows between components
	DataFlow []DataFlowMapping `yaml:"data_flow,omitempty" json:"data_flow,omitempty"`
	// FailurePolicy defines how to handle component failures
	FailurePolicy CompositeFailurePolicy `yaml:"failure_policy,omitempty" json:"failure_policy,omitempty"`
	// Timeout defines maximum time for the entire composition
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// MaxConcurrency limits concurrent component execution
	MaxConcurrency int `yaml:"max_concurrency,omitempty" json:"max_concurrency,omitempty"`
}

// WorkflowComponent defines a single component in a workflow composition
type WorkflowComponent struct {
	// Name is the unique identifier for this component
	Name string `yaml:"name" json:"name"`
	// WorkflowName is the name of the workflow to execute
	WorkflowName string `yaml:"workflow_name,omitempty" json:"workflow_name,omitempty"`
	// WorkflowPath is the file path to the workflow
	WorkflowPath string `yaml:"workflow_path,omitempty" json:"workflow_path,omitempty"`
	// Parameters to pass to the component workflow
	Parameters map[string]interface{} `yaml:"parameters,omitempty" json:"parameters,omitempty"`
	// ParameterMappings maps variables to component parameters
	ParameterMappings map[string]string `yaml:"parameter_mappings,omitempty" json:"parameter_mappings,omitempty"`
	// OutputMappings maps component outputs back to variables
	OutputMappings map[string]string `yaml:"output_mappings,omitempty" json:"output_mappings,omitempty"`
	// DependsOn defines component dependencies
	DependsOn []string `yaml:"depends_on,omitempty" json:"depends_on,omitempty"`
	// Condition defines when this component should execute
	Condition *Condition `yaml:"condition,omitempty" json:"condition,omitempty"`
	// Timeout defines maximum time for this component
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	// Async determines if this component runs asynchronously
	Async bool `yaml:"async,omitempty" json:"async,omitempty"`
	// RetryPolicy defines retry behavior for this component
	RetryPolicy *RetryPolicy `yaml:"retry_policy,omitempty" json:"retry_policy,omitempty"`
}

// CompositionStrategy defines how workflow components are composed
type CompositionStrategy string

const (
	// CompositionStrategySequential executes components one by one
	CompositionStrategySequential CompositionStrategy = "sequential"
	// CompositionStrategyParallel executes all components in parallel
	CompositionStrategyParallel CompositionStrategy = "parallel"
	// CompositionStrategyDependency executes components based on dependencies
	CompositionStrategyDependency CompositionStrategy = "dependency"
	// CompositionStrategyPipeline creates a data processing pipeline
	CompositionStrategyPipeline CompositionStrategy = "pipeline"
	// CompositionStrategyConditional executes components based on conditions
	CompositionStrategyConditional CompositionStrategy = "conditional"
)

// DataFlowMapping defines how data flows between workflow components
type DataFlowMapping struct {
	// FromComponent is the source component name
	FromComponent string `yaml:"from_component" json:"from_component"`
	// FromVariable is the source variable name
	FromVariable string `yaml:"from_variable" json:"from_variable"`
	// ToComponent is the target component name
	ToComponent string `yaml:"to_component" json:"to_component"`
	// ToVariable is the target variable name
	ToVariable string `yaml:"to_variable" json:"to_variable"`
	// Transform defines optional data transformation
	Transform string `yaml:"transform,omitempty" json:"transform,omitempty"`
	// Condition defines when this mapping should apply
	Condition *Condition `yaml:"condition,omitempty" json:"condition,omitempty"`
}

// CompositeFailurePolicy defines how to handle failures in workflow composition
type CompositeFailurePolicy string

const (
	// CompositeFailurePolicyFail fails the entire composition on any component failure
	CompositeFailurePolicyFail CompositeFailurePolicy = "fail"
	// CompositeFailurePolicySkip skips failed components and continues
	CompositeFailurePolicySkip CompositeFailurePolicy = "skip"
	// CompositeFailurePolicyRetry retries failed components
	CompositeFailurePolicyRetry CompositeFailurePolicy = "retry"
	// CompositeFailurePolicyIsolate isolates failed components from affecting others
	CompositeFailurePolicyIsolate CompositeFailurePolicy = "isolate"
)

// RetryPolicy defines retry behavior for workflow components
type RetryPolicy struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int `yaml:"max_attempts" json:"max_attempts"`
	// Delay is the initial delay between retries
	Delay time.Duration `yaml:"delay" json:"delay"`
	// BackoffMultiplier increases delay between attempts
	BackoffMultiplier float64 `yaml:"backoff_multiplier,omitempty" json:"backoff_multiplier,omitempty"`
	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration `yaml:"max_delay,omitempty" json:"max_delay,omitempty"`
	// RetryableErrors defines which errors should trigger retries
	RetryableErrors []string `yaml:"retryable_errors,omitempty" json:"retryable_errors,omitempty"`
}
