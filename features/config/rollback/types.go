// Package rollback provides configuration rollback capabilities for CFGMS.
// It integrates with the Git backend to enable safe, auditable rollback
// of configurations at various levels (device, group, client, MSP).
package rollback

import (
	"context"
	"time"
)

// RollbackType defines the type of rollback operation
type RollbackType string

const (
	// RollbackTypeFull rolls back entire configuration
	RollbackTypeFull RollbackType = "full"
	
	// RollbackTypePartial rolls back specific configuration files
	RollbackTypePartial RollbackType = "partial"
	
	// RollbackTypeModule rolls back individual module configurations
	RollbackTypeModule RollbackType = "module"
	
	// RollbackTypeEmergency performs immediate rollback without approval
	RollbackTypeEmergency RollbackType = "emergency"
)

// TargetType defines what entity is being rolled back
type TargetType string

const (
	// TargetTypeDevice rolls back a single device
	TargetTypeDevice TargetType = "device"
	
	// TargetTypeGroup rolls back a device group
	TargetTypeGroup TargetType = "group"
	
	// TargetTypeClient rolls back an entire client
	TargetTypeClient TargetType = "client"
	
	// TargetTypeMSP rolls back MSP-level configurations
	TargetTypeMSP TargetType = "msp"
)

// RollbackStatus represents the status of a rollback operation
type RollbackStatus string

const (
	// RollbackStatusPending waiting to start
	RollbackStatusPending RollbackStatus = "pending"
	
	// RollbackStatusValidating performing validation
	RollbackStatusValidating RollbackStatus = "validating"
	
	// RollbackStatusApprovalRequired waiting for approval
	RollbackStatusApprovalRequired RollbackStatus = "approval_required"
	
	// RollbackStatusInProgress actively rolling back
	RollbackStatusInProgress RollbackStatus = "in_progress"
	
	// RollbackStatusCompleted successfully completed
	RollbackStatusCompleted RollbackStatus = "completed"
	
	// RollbackStatusFailed rollback failed
	RollbackStatusFailed RollbackStatus = "failed"
	
	// RollbackStatusCancelled rollback was cancelled
	RollbackStatusCancelled RollbackStatus = "cancelled"
)

// RiskLevel indicates the risk level of a rollback
type RiskLevel string

const (
	// RiskLevelLow minimal risk rollback
	RiskLevelLow RiskLevel = "low"
	
	// RiskLevelMedium moderate risk rollback
	RiskLevelMedium RiskLevel = "medium"
	
	// RiskLevelHigh high risk rollback
	RiskLevelHigh RiskLevel = "high"
	
	// RiskLevelCritical critical risk rollback
	RiskLevelCritical RiskLevel = "critical"
)

// RollbackPoint represents a point in time that can be rolled back to
type RollbackPoint struct {
	// CommitSHA is the Git commit hash
	CommitSHA string `json:"commit_sha"`
	
	// Timestamp when the commit was made
	Timestamp time.Time `json:"timestamp"`
	
	// Author who made the commit
	Author string `json:"author"`
	
	// Message is the commit message
	Message string `json:"message"`
	
	// Configurations affected by this commit
	Configurations []string `json:"configurations"`
	
	// RiskLevel of rolling back to this point
	RiskLevel RiskLevel `json:"risk_level"`
	
	// CanRollback indicates if rollback is possible
	CanRollback bool `json:"can_rollback"`
	
	// Metadata contains additional information
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// RollbackRequest represents a request to perform a rollback
type RollbackRequest struct {
	// TargetType is what type of entity to rollback
	TargetType TargetType `json:"target_type"`
	
	// TargetID is the ID of the entity to rollback
	TargetID string `json:"target_id"`
	
	// RollbackType is the type of rollback to perform
	RollbackType RollbackType `json:"rollback_type"`
	
	// RollbackTo is the commit SHA to rollback to
	RollbackTo string `json:"rollback_to"`
	
	// Configurations to rollback (for partial rollback)
	Configurations []string `json:"configurations,omitempty"`
	
	// Modules to rollback (for module rollback)
	Modules []string `json:"modules,omitempty"`
	
	// Reason for the rollback
	Reason string `json:"reason"`
	
	// Emergency indicates if this is an emergency rollback
	Emergency bool `json:"emergency"`
	
	// ApprovalID if approval was obtained
	ApprovalID string `json:"approval_id,omitempty"`
	
	// DryRun performs validation without executing
	DryRun bool `json:"dry_run"`
	
	// Options for the rollback
	Options RollbackOptions `json:"options,omitempty"`
}

// RollbackOptions contains additional options for rollback
type RollbackOptions struct {
	// SkipValidation bypasses validation checks
	SkipValidation bool `json:"skip_validation"`
	
	// Force forces rollback even with warnings
	Force bool `json:"force"`
	
	// Progressive performs progressive/canary rollback
	Progressive bool `json:"progressive"`
	
	// ProgressivePercent percentage for progressive rollback
	ProgressivePercent int `json:"progressive_percent,omitempty"`
	
	// NotifyUsers sends notifications about rollback
	NotifyUsers bool `json:"notify_users"`
	
	// PreserveUserData preserves user-specific data
	PreserveUserData bool `json:"preserve_user_data"`
}

// RollbackPreview shows what will change in a rollback
type RollbackPreview struct {
	// Changes that will be made
	Changes []ConfigurationChange `json:"changes"`
	
	// AffectedModules that will be impacted
	AffectedModules []string `json:"affected_modules"`
	
	// ValidationResults from pre-rollback checks
	ValidationResults ValidationResults `json:"validation_results"`
	
	// EstimatedDuration for the rollback
	EstimatedDuration time.Duration `json:"estimated_duration"`
	
	// RequiresApproval indicates if approval is needed
	RequiresApproval bool `json:"requires_approval"`
	
	// RiskAssessment for this rollback
	RiskAssessment RiskAssessment `json:"risk_assessment"`
}

// ConfigurationChange represents a single configuration change
type ConfigurationChange struct {
	// Path to the configuration file
	Path string `json:"path"`
	
	// CurrentVersion commit SHA
	CurrentVersion string `json:"current_version"`
	
	// RollbackVersion commit SHA
	RollbackVersion string `json:"rollback_version"`
	
	// Diff between versions
	Diff string `json:"diff"`
	
	// Risk level of this change
	Risk RiskLevel `json:"risk"`
	
	// Module affected by this change
	Module string `json:"module,omitempty"`
}

// ValidationResults contains results of rollback validation
type ValidationResults struct {
	// Passed indicates if all validations passed
	Passed bool `json:"passed"`
	
	// Warnings that don't block rollback
	Warnings []ValidationIssue `json:"warnings"`
	
	// Errors that block rollback
	Errors []ValidationIssue `json:"errors"`
	
	// Metadata about validation
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// ValidationIssue represents a validation warning or error
type ValidationIssue struct {
	// Type of issue
	Type string `json:"type"`
	
	// Severity of the issue
	Severity string `json:"severity"`
	
	// Message describing the issue
	Message string `json:"message"`
	
	// Details with additional information
	Details map[string]interface{} `json:"details,omitempty"`
	
	// Resolvable indicates if issue can be resolved
	Resolvable bool `json:"resolvable"`
	
	// Resolution steps if resolvable
	Resolution string `json:"resolution,omitempty"`
}

// RiskAssessment evaluates the risk of a rollback
type RiskAssessment struct {
	// OverallRisk level
	OverallRisk RiskLevel `json:"overall_risk"`
	
	// ServiceImpact on running services
	ServiceImpact string `json:"service_impact"`
	
	// DataLossRisk of losing data
	DataLossRisk bool `json:"data_loss_risk"`
	
	// DowntimeEstimate expected downtime
	DowntimeEstimate time.Duration `json:"downtime_estimate"`
	
	// AffectedUsers count
	AffectedUsers int `json:"affected_users"`
	
	// RiskFactors contributing to risk
	RiskFactors []RiskFactor `json:"risk_factors"`
}

// RiskFactor represents a factor contributing to rollback risk
type RiskFactor struct {
	// Factor name
	Factor string `json:"factor"`
	
	// Description of the risk
	Description string `json:"description"`
	
	// Impact level
	Impact RiskLevel `json:"impact"`
	
	// Mitigation steps available
	Mitigation string `json:"mitigation,omitempty"`
}

// RollbackOperation represents an active or completed rollback
type RollbackOperation struct {
	// ID unique identifier
	ID string `json:"id"`
	
	// Request that initiated this rollback
	Request RollbackRequest `json:"request"`
	
	// Status of the rollback
	Status RollbackStatus `json:"status"`
	
	// InitiatedBy user who initiated
	InitiatedBy string `json:"initiated_by"`
	
	// InitiatedAt timestamp
	InitiatedAt time.Time `json:"initiated_at"`
	
	// CompletedAt timestamp
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	
	// Progress information
	Progress RollbackProgress `json:"progress"`
	
	// Result of the rollback
	Result *RollbackResult `json:"result,omitempty"`
	
	// AuditTrail of all actions
	AuditTrail []AuditEntry `json:"audit_trail"`
}

// RollbackProgress tracks progress of a rollback
type RollbackProgress struct {
	// Stage current stage
	Stage string `json:"stage"`
	
	// Percentage complete (0-100)
	Percentage int `json:"percentage"`
	
	// CurrentAction being performed
	CurrentAction string `json:"current_action"`
	
	// ItemsProcessed count
	ItemsProcessed int `json:"items_processed"`
	
	// ItemsTotal count
	ItemsTotal int `json:"items_total"`
	
	// StartedAt for current stage
	StartedAt time.Time `json:"started_at"`
	
	// EstimatedCompletion time
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
}

// RollbackResult contains the result of a rollback operation
type RollbackResult struct {
	// Success indicates if rollback succeeded
	Success bool `json:"success"`
	
	// ConfigurationsRolledBack count
	ConfigurationsRolledBack int `json:"configurations_rolled_back"`
	
	// DevicesAffected count
	DevicesAffected int `json:"devices_affected"`
	
	// PartialSuccess for partial failures
	PartialSuccess bool `json:"partial_success,omitempty"`
	
	// Failures that occurred
	Failures []RollbackFailure `json:"failures,omitempty"`
	
	// Metrics about the rollback
	Metrics RollbackMetrics `json:"metrics"`
}

// RollbackFailure represents a failure during rollback
type RollbackFailure struct {
	// Component that failed
	Component string `json:"component"`
	
	// Error message
	Error string `json:"error"`
	
	// Timestamp of failure
	Timestamp time.Time `json:"timestamp"`
	
	// Recoverable indicates if failure is recoverable
	Recoverable bool `json:"recoverable"`
	
	// RetryCount attempts made
	RetryCount int `json:"retry_count"`
}

// RollbackMetrics contains metrics about a rollback
type RollbackMetrics struct {
	// Duration of the rollback
	Duration time.Duration `json:"duration"`
	
	// ConfigurationSizeBytes rolled back
	ConfigurationSizeBytes int64 `json:"configuration_size_bytes"`
	
	// NetworkBytesTransferred
	NetworkBytesTransferred int64 `json:"network_bytes_transferred"`
	
	// ValidationDuration time spent validating
	ValidationDuration time.Duration `json:"validation_duration"`
	
	// DeploymentDuration time spent deploying
	DeploymentDuration time.Duration `json:"deployment_duration"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	// Timestamp of the event
	Timestamp time.Time `json:"timestamp"`
	
	// EventType that occurred
	EventType string `json:"event_type"`
	
	// Actor who performed the action
	Actor string `json:"actor"`
	
	// Action that was taken
	Action string `json:"action"`
	
	// Details of the event
	Details map[string]interface{} `json:"details,omitempty"`
	
	// Result of the action
	Result string `json:"result"`
}

// RollbackManager orchestrates rollback operations
type RollbackManager interface {
	// ListRollbackPoints returns available rollback points
	ListRollbackPoints(ctx context.Context, targetType TargetType, targetID string, limit int) ([]RollbackPoint, error)
	
	// PreviewRollback shows what will change
	PreviewRollback(ctx context.Context, request RollbackRequest) (*RollbackPreview, error)
	
	// ExecuteRollback performs the rollback
	ExecuteRollback(ctx context.Context, request RollbackRequest) (*RollbackOperation, error)
	
	// GetRollbackStatus returns current status
	GetRollbackStatus(ctx context.Context, rollbackID string) (*RollbackOperation, error)
	
	// CancelRollback cancels an in-progress rollback
	CancelRollback(ctx context.Context, rollbackID string, reason string) error
	
	// ListRollbackHistory returns past rollbacks
	ListRollbackHistory(ctx context.Context, targetType TargetType, targetID string, limit int) ([]RollbackOperation, error)
}

// RollbackValidator validates rollback safety
type RollbackValidator interface {
	// ValidateRollback checks if rollback is safe
	ValidateRollback(ctx context.Context, request RollbackRequest, preview *RollbackPreview) (*ValidationResults, error)
	
	// AssessRisk evaluates rollback risk
	AssessRisk(ctx context.Context, request RollbackRequest, changes []ConfigurationChange) (*RiskAssessment, error)
	
	// CheckDependencies validates module dependencies
	CheckDependencies(ctx context.Context, targetType TargetType, targetID string, changes []ConfigurationChange) error
	
	// ValidateModuleCompatibility checks module versions
	ValidateModuleCompatibility(ctx context.Context, modules []string, targetVersion string) error
}

// RollbackNotifier handles rollback notifications
type RollbackNotifier interface {
	// NotifyRollbackStarted sends start notification
	NotifyRollbackStarted(ctx context.Context, operation *RollbackOperation) error
	
	// NotifyRollbackProgress sends progress updates
	NotifyRollbackProgress(ctx context.Context, operation *RollbackOperation) error
	
	// NotifyRollbackCompleted sends completion notification
	NotifyRollbackCompleted(ctx context.Context, operation *RollbackOperation) error
	
	// NotifyRollbackFailed sends failure notification
	NotifyRollbackFailed(ctx context.Context, operation *RollbackOperation, err error) error
}

// RollbackStore persists rollback operations
type RollbackStore interface {
	// SaveOperation saves a rollback operation
	SaveOperation(ctx context.Context, operation *RollbackOperation) error
	
	// GetOperation retrieves an operation by ID
	GetOperation(ctx context.Context, id string) (*RollbackOperation, error)
	
	// ListOperations lists operations with filters
	ListOperations(ctx context.Context, filters RollbackFilters) ([]RollbackOperation, error)
	
	// UpdateOperation updates an existing operation
	UpdateOperation(ctx context.Context, operation *RollbackOperation) error
	
	// AddAuditEntry adds an audit log entry
	AddAuditEntry(ctx context.Context, operationID string, entry AuditEntry) error
}

// RollbackFilters for querying rollback operations
type RollbackFilters struct {
	// TargetType filter
	TargetType TargetType
	
	// TargetID filter
	TargetID string
	
	// Status filter
	Status RollbackStatus
	
	// InitiatedBy filter
	InitiatedBy string
	
	// StartTime filter
	StartTime *time.Time
	
	// EndTime filter
	EndTime *time.Time
	
	// Limit results
	Limit int
}

// RollbackError represents a rollback-specific error
type RollbackError struct {
	Code    string
	Message string
	Details map[string]interface{}
}

func (e *RollbackError) Error() string {
	return e.Message
}

// Common rollback errors
var (
	// ErrRollbackValidationFailed validation failed
	ErrRollbackValidationFailed = &RollbackError{
		Code:    "ROLLBACK_VALIDATION_FAILED",
		Message: "Rollback validation failed",
	}
	
	// ErrRollbackNotFound rollback operation not found
	ErrRollbackNotFound = &RollbackError{
		Code:    "ROLLBACK_NOT_FOUND",
		Message: "Rollback operation not found",
	}
	
	// ErrRollbackInProgress another rollback is in progress
	ErrRollbackInProgress = &RollbackError{
		Code:    "ROLLBACK_IN_PROGRESS",
		Message: "Another rollback is already in progress",
	}
	
	// ErrRollbackPermissionDenied insufficient permissions
	ErrRollbackPermissionDenied = &RollbackError{
		Code:    "ROLLBACK_PERMISSION_DENIED",
		Message: "Permission denied for rollback operation",
	}
)