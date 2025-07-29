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

	// ErrorHandling defines error handling configuration for this step
	ErrorHandling *ErrorHandlingConfig `yaml:"error_handling,omitempty" json:"error_handling,omitempty"`
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

	// OperatorLessThan checks if left < right
	OperatorLessThan ComparisonOperator = "lt"

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