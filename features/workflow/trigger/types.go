// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package trigger

import (
	"context"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// TenantIDContextKey is the key for tenant ID in context
	TenantIDContextKey contextKey = "tenant_id"
)

// TriggerType defines the type of workflow trigger
type TriggerType string

const (
	// TriggerTypeSchedule executes workflows on a scheduled basis
	TriggerTypeSchedule TriggerType = "schedule"

	// TriggerTypeWebhook executes workflows in response to webhook calls
	TriggerTypeWebhook TriggerType = "webhook"

	// TriggerTypeSIEM executes workflows based on SIEM log analysis
	TriggerTypeSIEM TriggerType = "siem"

	// TriggerTypeManual executes workflows manually (on-demand)
	TriggerTypeManual TriggerType = "manual"
)

// TriggerStatus represents the current status of a trigger
type TriggerStatus string

const (
	// TriggerStatusActive indicates the trigger is active and ready to fire
	TriggerStatusActive TriggerStatus = "active"

	// TriggerStatusInactive indicates the trigger is temporarily disabled
	TriggerStatusInactive TriggerStatus = "inactive"

	// TriggerStatusPaused indicates the trigger is paused
	TriggerStatusPaused TriggerStatus = "paused"

	// TriggerStatusError indicates the trigger has an error condition
	TriggerStatusError TriggerStatus = "error"

	// TriggerStatusDeleted indicates the trigger has been deleted
	TriggerStatusDeleted TriggerStatus = "deleted"
)

// Trigger defines a workflow trigger configuration
type Trigger struct {
	// ID is the unique identifier for this trigger
	ID string `json:"id" yaml:"id"`

	// Name is a human-readable name for the trigger
	Name string `json:"name" yaml:"name"`

	// Description provides additional context about the trigger
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Type specifies the trigger type
	Type TriggerType `json:"type" yaml:"type"`

	// Status indicates the current trigger status
	Status TriggerStatus `json:"status" yaml:"status"`

	// TenantID for multi-tenant isolation
	TenantID string `json:"tenant_id" yaml:"tenant_id"`

	// WorkflowName is the name of the workflow to execute
	WorkflowName string `json:"workflow_name" yaml:"workflow_name"`

	// WorkflowPath is the optional path to the workflow file
	WorkflowPath string `json:"workflow_path,omitempty" yaml:"workflow_path,omitempty"`

	// Variables contains default variables to pass to the workflow
	Variables map[string]interface{} `json:"variables,omitempty" yaml:"variables,omitempty"`

	// Schedule configuration for schedule-based triggers
	Schedule *ScheduleConfig `json:"schedule,omitempty" yaml:"schedule,omitempty"`

	// Webhook configuration for webhook-based triggers
	Webhook *WebhookConfig `json:"webhook,omitempty" yaml:"webhook,omitempty"`

	// SIEM configuration for SIEM-based triggers
	SIEM *SIEMConfig `json:"siem,omitempty" yaml:"siem,omitempty"`

	// Timeout defines maximum execution time for triggered workflows
	Timeout time.Duration `json:"timeout,omitempty" yaml:"timeout,omitempty"`

	// Concurrency controls concurrent workflow executions
	Concurrency *ConcurrencyConfig `json:"concurrency,omitempty" yaml:"concurrency,omitempty"`

	// Conditions define when the trigger should fire
	Conditions []*TriggerCondition `json:"conditions,omitempty" yaml:"conditions,omitempty"`

	// ErrorHandling defines error handling behavior
	ErrorHandling *TriggerErrorHandling `json:"error_handling,omitempty" yaml:"error_handling,omitempty"`

	// Monitoring configuration for trigger metrics and alerts
	Monitoring *TriggerMonitoring `json:"monitoring,omitempty" yaml:"monitoring,omitempty"`

	// CreatedAt is when the trigger was created
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`

	// UpdatedAt is when the trigger was last updated
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`

	// CreatedBy is who created the trigger
	CreatedBy string `json:"created_by,omitempty" yaml:"created_by,omitempty"`

	// Tags for trigger organization and filtering
	Tags []string `json:"tags,omitempty" yaml:"tags,omitempty"`
}

// ScheduleConfig defines configuration for schedule-based triggers
type ScheduleConfig struct {
	// CronExpression in standard cron format (supports seconds field)
	CronExpression string `json:"cron_expression" yaml:"cron_expression"`

	// Timezone for schedule evaluation (defaults to UTC)
	Timezone string `json:"timezone,omitempty" yaml:"timezone,omitempty"`

	// StartTime defines when the schedule becomes active
	StartTime *time.Time `json:"start_time,omitempty" yaml:"start_time,omitempty"`

	// EndTime defines when the schedule expires
	EndTime *time.Time `json:"end_time,omitempty" yaml:"end_time,omitempty"`

	// MaxRuns limits the total number of executions (0 = unlimited)
	MaxRuns int `json:"max_runs,omitempty" yaml:"max_runs,omitempty"`

	// CurrentRuns tracks the number of executions so far
	CurrentRuns int `json:"current_runs,omitempty" yaml:"current_runs,omitempty"`

	// Enabled allows temporarily disabling the schedule
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Jitter adds randomness to execution time (in seconds)
	Jitter int `json:"jitter,omitempty" yaml:"jitter,omitempty"`

	// LastExecution records the last execution time
	LastExecution *time.Time `json:"last_execution,omitempty" yaml:"last_execution,omitempty"`

	// NextExecution predicts the next execution time
	NextExecution *time.Time `json:"next_execution,omitempty" yaml:"next_execution,omitempty"`
}

// WebhookConfig defines configuration for webhook-based triggers
type WebhookConfig struct {
	// Path is the webhook endpoint path (e.g., "/triggers/webhook/{id}")
	Path string `json:"path" yaml:"path"`

	// Method specifies allowed HTTP methods (defaults to POST)
	Method []string `json:"method,omitempty" yaml:"method,omitempty"`

	// Authentication configuration
	Authentication *WebhookAuth `json:"authentication,omitempty" yaml:"authentication,omitempty"`

	// Headers defines required/expected headers
	Headers map[string]string `json:"headers,omitempty" yaml:"headers,omitempty"`

	// ContentType specifies expected content type (defaults to "application/json")
	ContentType string `json:"content_type,omitempty" yaml:"content_type,omitempty"`

	// PayloadMapping maps webhook payload to workflow variables
	PayloadMapping map[string]string `json:"payload_mapping,omitempty" yaml:"payload_mapping,omitempty"`

	// PayloadValidation defines payload validation rules
	PayloadValidation *PayloadValidation `json:"payload_validation,omitempty" yaml:"payload_validation,omitempty"`

	// RateLimit defines rate limiting for webhook calls
	RateLimit *WebhookRateLimit `json:"rate_limit,omitempty" yaml:"rate_limit,omitempty"`

	// AllowedIPs restricts webhook access to specific IP addresses/ranges
	AllowedIPs []string `json:"allowed_ips,omitempty" yaml:"allowed_ips,omitempty"`

	// Enabled allows temporarily disabling the webhook
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Statistics tracks webhook usage
	Statistics *WebhookStatistics `json:"statistics,omitempty" yaml:"statistics,omitempty"`
}

// SIEMConfig defines configuration for SIEM-based triggers
type SIEMConfig struct {
	// EventTypes defines which log events trigger workflows
	EventTypes []string `json:"event_types" yaml:"event_types"`

	// Conditions define log analysis conditions
	Conditions []*SIEMCondition `json:"conditions" yaml:"conditions"`

	// Aggregation defines log aggregation rules
	Aggregation *SIEMAggregation `json:"aggregation,omitempty" yaml:"aggregation,omitempty"`

	// Threshold defines trigger thresholds
	Threshold *SIEMThreshold `json:"threshold,omitempty" yaml:"threshold,omitempty"`

	// WindowSize defines the time window for log analysis
	WindowSize time.Duration `json:"window_size" yaml:"window_size"`

	// Enabled allows temporarily disabling SIEM triggers
	Enabled bool `json:"enabled" yaml:"enabled"`

	// Priority defines trigger priority (higher = more important)
	Priority int `json:"priority,omitempty" yaml:"priority,omitempty"`
}

// WebhookAuth defines authentication configuration for webhooks
type WebhookAuth struct {
	// Type specifies the authentication type
	Type WebhookAuthType `json:"type" yaml:"type"`

	// Secret for HMAC signature validation
	Secret string `json:"secret,omitempty" yaml:"secret,omitempty"`

	// SignatureHeader specifies where to find the signature
	SignatureHeader string `json:"signature_header,omitempty" yaml:"signature_header,omitempty"`

	// APIKey for API key authentication
	APIKey string `json:"api_key,omitempty" yaml:"api_key,omitempty"`

	// APIKeyHeader specifies where to find the API key
	APIKeyHeader string `json:"api_key_header,omitempty" yaml:"api_key_header,omitempty"`

	// Bearer token for Bearer authentication
	BearerToken string `json:"bearer_token,omitempty" yaml:"bearer_token,omitempty"`

	// BasicAuth for HTTP Basic authentication
	BasicAuth *BasicAuth `json:"basic_auth,omitempty" yaml:"basic_auth,omitempty"`
}

// WebhookAuthType defines supported webhook authentication types
type WebhookAuthType string

const (
	// WebhookAuthNone requires no authentication
	WebhookAuthNone WebhookAuthType = "none"

	// WebhookAuthHMAC uses HMAC signature validation
	WebhookAuthHMAC WebhookAuthType = "hmac"

	// WebhookAuthAPIKey uses API key authentication
	WebhookAuthAPIKey WebhookAuthType = "api_key"

	// WebhookAuthBearer uses Bearer token authentication
	WebhookAuthBearer WebhookAuthType = "bearer"

	// WebhookAuthBasic uses HTTP Basic authentication
	WebhookAuthBasic WebhookAuthType = "basic"
)

// BasicAuth defines HTTP Basic authentication credentials
type BasicAuth struct {
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
}

// PayloadValidation defines webhook payload validation rules
type PayloadValidation struct {
	// JSONSchema for JSON payload validation
	JSONSchema string `json:"json_schema,omitempty" yaml:"json_schema,omitempty"`

	// RequiredFields defines required payload fields
	RequiredFields []string `json:"required_fields,omitempty" yaml:"required_fields,omitempty"`

	// MaxSize defines maximum payload size in bytes
	MaxSize int64 `json:"max_size,omitempty" yaml:"max_size,omitempty"`
}

// WebhookRateLimit defines rate limiting for webhook endpoints
type WebhookRateLimit struct {
	// RequestsPerMinute limits requests per minute
	RequestsPerMinute int `json:"requests_per_minute" yaml:"requests_per_minute"`

	// BurstSize allows burst requests above the rate limit
	BurstSize int `json:"burst_size,omitempty" yaml:"burst_size,omitempty"`

	// WindowSize defines the time window for rate limiting
	WindowSize time.Duration `json:"window_size,omitempty" yaml:"window_size,omitempty"`
}

// WebhookStatistics tracks webhook usage and performance
type WebhookStatistics struct {
	// TotalCalls is the total number of webhook calls
	TotalCalls int64 `json:"total_calls" yaml:"total_calls"`

	// SuccessfulCalls is the number of successful webhook calls
	SuccessfulCalls int64 `json:"successful_calls" yaml:"successful_calls"`

	// FailedCalls is the number of failed webhook calls
	FailedCalls int64 `json:"failed_calls" yaml:"failed_calls"`

	// LastCall is the timestamp of the last webhook call
	LastCall *time.Time `json:"last_call,omitempty" yaml:"last_call,omitempty"`

	// AverageResponseTime is the average webhook response time
	AverageResponseTime time.Duration `json:"average_response_time,omitempty" yaml:"average_response_time,omitempty"`
}

// SIEMCondition defines a condition for SIEM log analysis
type SIEMCondition struct {
	// Field is the log field to evaluate
	Field string `json:"field" yaml:"field"`

	// Operator defines the comparison operator
	Operator SIEMOperator `json:"operator" yaml:"operator"`

	// Value is the value to compare against
	Value interface{} `json:"value" yaml:"value"`

	// CaseSensitive determines if string comparisons are case-sensitive
	CaseSensitive bool `json:"case_sensitive,omitempty" yaml:"case_sensitive,omitempty"`
}

// SIEMOperator defines comparison operators for SIEM conditions
type SIEMOperator string

const (
	SIEMOperatorEquals      SIEMOperator = "equals"
	SIEMOperatorNotEquals   SIEMOperator = "not_equals"
	SIEMOperatorContains    SIEMOperator = "contains"
	SIEMOperatorNotContains SIEMOperator = "not_contains"
	SIEMOperatorStartsWith  SIEMOperator = "starts_with"
	SIEMOperatorEndsWith    SIEMOperator = "ends_with"
	SIEMOperatorRegex       SIEMOperator = "regex"
	SIEMOperatorGreaterThan SIEMOperator = "greater_than"
	SIEMOperatorLessThan    SIEMOperator = "less_than"
	SIEMOperatorExists      SIEMOperator = "exists"
	SIEMOperatorNotExists   SIEMOperator = "not_exists"
)

// SIEMAggregation defines log aggregation rules
type SIEMAggregation struct {
	// GroupBy defines fields to group log entries by
	GroupBy []string `json:"group_by" yaml:"group_by"`

	// CountBy defines fields to count occurrences
	CountBy string `json:"count_by,omitempty" yaml:"count_by,omitempty"`

	// SumBy defines numeric fields to sum
	SumBy []string `json:"sum_by,omitempty" yaml:"sum_by,omitempty"`

	// AverageBy defines numeric fields to average
	AverageBy []string `json:"average_by,omitempty" yaml:"average_by,omitempty"`
}

// SIEMThreshold defines trigger thresholds for SIEM analysis
type SIEMThreshold struct {
	// Count threshold for log entry count
	Count int `json:"count,omitempty" yaml:"count,omitempty"`

	// Rate threshold for log entry rate (per minute)
	Rate float64 `json:"rate,omitempty" yaml:"rate,omitempty"`

	// Sum threshold for numeric field sums
	Sum float64 `json:"sum,omitempty" yaml:"sum,omitempty"`

	// Average threshold for numeric field averages
	Average float64 `json:"average,omitempty" yaml:"average,omitempty"`
}

// ConcurrencyConfig defines concurrency control for triggered workflows
type ConcurrencyConfig struct {
	// MaxConcurrent limits the number of concurrent workflow executions
	MaxConcurrent int `json:"max_concurrent" yaml:"max_concurrent"`

	// QueueSize defines the maximum number of queued executions
	QueueSize int `json:"queue_size,omitempty" yaml:"queue_size,omitempty"`

	// Strategy defines what to do when limits are exceeded
	Strategy ConcurrencyStrategy `json:"strategy" yaml:"strategy"`

	// CurrentExecutions tracks currently running executions
	CurrentExecutions int `json:"current_executions,omitempty" yaml:"current_executions,omitempty"`

	// QueuedExecutions tracks queued executions
	QueuedExecutions int `json:"queued_executions,omitempty" yaml:"queued_executions,omitempty"`
}

// ConcurrencyStrategy defines strategies for handling concurrency limits
type ConcurrencyStrategy string

const (
	// ConcurrencyStrategyQueue queues executions when limit is reached
	ConcurrencyStrategyQueue ConcurrencyStrategy = "queue"

	// ConcurrencyStrategyDrop drops new executions when limit is reached
	ConcurrencyStrategyDrop ConcurrencyStrategy = "drop"

	// ConcurrencyStrategyReplace replaces oldest execution with new one
	ConcurrencyStrategyReplace ConcurrencyStrategy = "replace"
)

// TriggerCondition defines when a trigger should fire
type TriggerCondition struct {
	// Type specifies the condition type
	Type TriggerConditionType `json:"type" yaml:"type"`

	// Expression defines the condition expression
	Expression string `json:"expression,omitempty" yaml:"expression,omitempty"`

	// Field defines the field to evaluate
	Field string `json:"field,omitempty" yaml:"field,omitempty"`

	// Operator defines the comparison operator
	Operator string `json:"operator,omitempty" yaml:"operator,omitempty"`

	// Value defines the value to compare against
	Value interface{} `json:"value,omitempty" yaml:"value,omitempty"`
}

// TriggerConditionType defines types of trigger conditions
type TriggerConditionType string

const (
	// TriggerConditionExpression evaluates a complex expression
	TriggerConditionExpression TriggerConditionType = "expression"

	// TriggerConditionField evaluates a specific field
	TriggerConditionField TriggerConditionType = "field"

	// TriggerConditionTime evaluates time-based conditions
	TriggerConditionTime TriggerConditionType = "time"
)

// TriggerErrorHandling defines error handling behavior for triggers
type TriggerErrorHandling struct {
	// RetryPolicy defines retry behavior for failed triggers
	RetryPolicy *TriggerRetryPolicy `json:"retry_policy,omitempty" yaml:"retry_policy,omitempty"`

	// OnError defines actions to take on trigger errors
	OnError TriggerErrorAction `json:"on_error" yaml:"on_error"`

	// NotificationChannels defines where to send error notifications
	NotificationChannels []string `json:"notification_channels,omitempty" yaml:"notification_channels,omitempty"`

	// MaxConsecutiveFailures defines when to disable the trigger
	MaxConsecutiveFailures int `json:"max_consecutive_failures,omitempty" yaml:"max_consecutive_failures,omitempty"`

	// CurrentConsecutiveFailures tracks current consecutive failures
	CurrentConsecutiveFailures int `json:"current_consecutive_failures,omitempty" yaml:"current_consecutive_failures,omitempty"`
}

// TriggerRetryPolicy defines retry behavior for failed triggers
type TriggerRetryPolicy struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int `json:"max_attempts" yaml:"max_attempts"`

	// InitialDelay is the initial delay between retries
	InitialDelay time.Duration `json:"initial_delay" yaml:"initial_delay"`

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration `json:"max_delay" yaml:"max_delay"`

	// BackoffMultiplier for exponential backoff
	BackoffMultiplier float64 `json:"backoff_multiplier" yaml:"backoff_multiplier"`
}

// TriggerErrorAction defines actions to take on trigger errors
type TriggerErrorAction string

const (
	// TriggerErrorActionContinue continues normal trigger operation
	TriggerErrorActionContinue TriggerErrorAction = "continue"

	// TriggerErrorActionPause pauses the trigger temporarily
	TriggerErrorActionPause TriggerErrorAction = "pause"

	// TriggerErrorActionDisable disables the trigger permanently
	TriggerErrorActionDisable TriggerErrorAction = "disable"

	// TriggerErrorActionNotify sends notifications but continues
	TriggerErrorActionNotify TriggerErrorAction = "notify"
)

// TriggerMonitoring defines monitoring configuration for triggers
type TriggerMonitoring struct {
	// Metrics defines which metrics to collect
	Metrics []TriggerMetric `json:"metrics,omitempty" yaml:"metrics,omitempty"`

	// Alerts defines alert conditions
	Alerts []*TriggerAlert `json:"alerts,omitempty" yaml:"alerts,omitempty"`

	// LogLevel defines the logging level for trigger events
	LogLevel string `json:"log_level,omitempty" yaml:"log_level,omitempty"`

	// Enabled allows disabling monitoring for this trigger
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// TriggerMetric defines a metric to collect for triggers
type TriggerMetric string

const (
	// TriggerMetricExecutionCount counts workflow executions
	TriggerMetricExecutionCount TriggerMetric = "execution_count"

	// TriggerMetricExecutionDuration measures workflow execution time
	TriggerMetricExecutionDuration TriggerMetric = "execution_duration"

	// TriggerMetricSuccessRate measures success rate
	TriggerMetricSuccessRate TriggerMetric = "success_rate"

	// TriggerMetricErrorRate measures error rate
	TriggerMetricErrorRate TriggerMetric = "error_rate"

	// TriggerMetricTriggerLatency measures trigger response time
	TriggerMetricTriggerLatency TriggerMetric = "trigger_latency"
)

// TriggerAlert defines an alert condition for triggers
type TriggerAlert struct {
	// Name is the alert name
	Name string `json:"name" yaml:"name"`

	// Condition defines when the alert should fire
	Condition string `json:"condition" yaml:"condition"`

	// Threshold defines the alert threshold
	Threshold float64 `json:"threshold" yaml:"threshold"`

	// Window defines the time window for alert evaluation
	Window time.Duration `json:"window" yaml:"window"`

	// Actions defines actions to take when alert fires
	Actions []string `json:"actions,omitempty" yaml:"actions,omitempty"`

	// Enabled allows disabling specific alerts
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// TriggerExecution represents a single trigger execution
type TriggerExecution struct {
	// ID is the unique identifier for this execution
	ID string `json:"id"`

	// TriggerID is the ID of the trigger that fired
	TriggerID string `json:"trigger_id"`

	// WorkflowExecutionID is the ID of the resulting workflow execution
	WorkflowExecutionID string `json:"workflow_execution_id,omitempty"`

	// Status is the execution status
	Status TriggerExecutionStatus `json:"status"`

	// StartTime is when the trigger fired
	StartTime time.Time `json:"start_time"`

	// EndTime is when the execution completed
	EndTime *time.Time `json:"end_time,omitempty"`

	// Duration is how long the execution took
	Duration time.Duration `json:"duration,omitempty"`

	// TriggerData contains the data that triggered the execution
	TriggerData map[string]interface{} `json:"trigger_data,omitempty"`

	// Error contains error information if execution failed
	Error string `json:"error,omitempty"`

	// Metadata contains additional execution metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// TriggerExecutionStatus represents the status of a trigger execution
type TriggerExecutionStatus string

const (
	// TriggerExecutionStatusPending indicates execution is pending
	TriggerExecutionStatusPending TriggerExecutionStatus = "pending"

	// TriggerExecutionStatusRunning indicates execution is in progress
	TriggerExecutionStatusRunning TriggerExecutionStatus = "running"

	// TriggerExecutionStatusSuccess indicates execution completed successfully
	TriggerExecutionStatusSuccess TriggerExecutionStatus = "success"

	// TriggerExecutionStatusFailed indicates execution failed
	TriggerExecutionStatusFailed TriggerExecutionStatus = "failed"

	// TriggerExecutionStatusSkipped indicates execution was skipped
	TriggerExecutionStatusSkipped TriggerExecutionStatus = "skipped"
)

// TriggerManager defines the interface for managing workflow triggers
type TriggerManager interface {
	// CreateTrigger creates a new trigger
	CreateTrigger(ctx context.Context, trigger *Trigger) error

	// UpdateTrigger updates an existing trigger
	UpdateTrigger(ctx context.Context, trigger *Trigger) error

	// DeleteTrigger deletes a trigger
	DeleteTrigger(ctx context.Context, triggerID string) error

	// GetTrigger retrieves a trigger by ID
	GetTrigger(ctx context.Context, triggerID string) (*Trigger, error)

	// ListTriggers lists triggers with optional filtering
	ListTriggers(ctx context.Context, filter *TriggerFilter) ([]*Trigger, error)

	// EnableTrigger enables a disabled trigger
	EnableTrigger(ctx context.Context, triggerID string) error

	// DisableTrigger disables an active trigger
	DisableTrigger(ctx context.Context, triggerID string) error

	// ExecuteTrigger manually executes a trigger
	ExecuteTrigger(ctx context.Context, triggerID string, data map[string]interface{}) (*TriggerExecution, error)

	// GetTriggerExecutions retrieves execution history for a trigger
	GetTriggerExecutions(ctx context.Context, triggerID string, limit int) ([]*TriggerExecution, error)

	// Start starts the trigger manager
	Start(ctx context.Context) error

	// Stop stops the trigger manager
	Stop(ctx context.Context) error
}

// TriggerFilter defines filtering options for listing triggers
type TriggerFilter struct {
	// TenantID filters by tenant
	TenantID string `json:"tenant_id,omitempty"`

	// Type filters by trigger type
	Type TriggerType `json:"type,omitempty"`

	// Status filters by trigger status
	Status TriggerStatus `json:"status,omitempty"`

	// Tags filters by tags
	Tags []string `json:"tags,omitempty"`

	// CreatedAfter filters by creation date
	CreatedAfter *time.Time `json:"created_after,omitempty"`

	// CreatedBefore filters by creation date
	CreatedBefore *time.Time `json:"created_before,omitempty"`

	// Limit limits the number of results
	Limit int `json:"limit,omitempty"`

	// Offset specifies the result offset
	Offset int `json:"offset,omitempty"`
}

// Scheduler defines the interface for scheduling workflow executions
type Scheduler interface {
	// ScheduleWorkflow schedules a workflow execution
	ScheduleWorkflow(ctx context.Context, trigger *Trigger) error

	// UnscheduleWorkflow removes a scheduled workflow
	UnscheduleWorkflow(ctx context.Context, triggerID string) error

	// Start starts the scheduler
	Start(ctx context.Context) error

	// Stop stops the scheduler
	Stop(ctx context.Context) error
}

// WebhookHandler defines the interface for handling webhook triggers
type WebhookHandler interface {
	// RegisterWebhook registers a webhook endpoint
	RegisterWebhook(ctx context.Context, trigger *Trigger) error

	// UnregisterWebhook removes a webhook endpoint
	UnregisterWebhook(ctx context.Context, triggerID string) error

	// HandleWebhook processes an incoming webhook request
	HandleWebhook(ctx context.Context, triggerID string, payload []byte, headers map[string]string) (*TriggerExecution, error)

	// Start starts the webhook handler
	Start(ctx context.Context) error

	// Stop stops the webhook handler
	Stop(ctx context.Context) error
}

// SIEMIntegration defines the interface for SIEM-based triggers
type SIEMIntegration interface {
	// RegisterSIEMTrigger registers a SIEM-based trigger
	RegisterSIEMTrigger(ctx context.Context, trigger *Trigger) error

	// UnregisterSIEMTrigger removes a SIEM-based trigger
	UnregisterSIEMTrigger(ctx context.Context, triggerID string) error

	// ProcessLogEntry processes a log entry for SIEM triggers
	ProcessLogEntry(ctx context.Context, logEntry map[string]interface{}) error

	// Start starts the SIEM integration
	Start(ctx context.Context) error

	// Stop stops the SIEM integration
	Stop(ctx context.Context) error
}

// WorkflowExecution represents a workflow execution result
type WorkflowExecution struct {
	ID           string    `json:"id"`
	WorkflowName string    `json:"workflow_name"`
	Status       string    `json:"status"`
	StartTime    time.Time `json:"start_time"`
}

// WorkflowTrigger defines the interface for triggering workflow executions
type WorkflowTrigger interface {
	// TriggerWorkflow triggers a workflow execution
	TriggerWorkflow(ctx context.Context, trigger *Trigger, data map[string]interface{}) (*WorkflowExecution, error)

	// ValidateTrigger validates a trigger configuration
	ValidateTrigger(ctx context.Context, trigger *Trigger) error
}
