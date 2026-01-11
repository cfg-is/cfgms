// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package interfaces defines global storage contracts used by all CFGMS modules
package interfaces

import (
	"context"
	"time"
)

// AuditStore defines storage interface for all CFGMS audit and compliance data
// This interface handles immutable audit logs, security events, and compliance records
type AuditStore interface {
	// Audit entry operations (immutable - no updates or deletes)
	StoreAuditEntry(ctx context.Context, entry *AuditEntry) error
	GetAuditEntry(ctx context.Context, id string) (*AuditEntry, error)
	ListAuditEntries(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error)

	// Batch operations for performance
	StoreAuditBatch(ctx context.Context, entries []*AuditEntry) error

	// Compliance and reporting queries
	GetAuditsByUser(ctx context.Context, userID string, timeRange *TimeRange) ([]*AuditEntry, error)
	GetAuditsByResource(ctx context.Context, resourceType, resourceID string, timeRange *TimeRange) ([]*AuditEntry, error)
	GetAuditsByAction(ctx context.Context, action string, timeRange *TimeRange) ([]*AuditEntry, error)

	// Security monitoring
	GetFailedActions(ctx context.Context, timeRange *TimeRange, limit int) ([]*AuditEntry, error)
	GetSuspiciousActivity(ctx context.Context, tenantID string, timeRange *TimeRange) ([]*AuditEntry, error)

	// Statistics and health
	GetAuditStats(ctx context.Context) (*AuditStats, error)

	// Retention and archival (implementation dependent)
	ArchiveAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error)
	PurgeAuditEntries(ctx context.Context, beforeDate time.Time) (int64, error)
}

// AuditEntry represents an immutable audit log entry
type AuditEntry struct {
	ID        string         `json:"id"`                   // Unique identifier (UUID)
	TenantID  string         `json:"tenant_id"`            // Multi-tenant isolation
	Timestamp time.Time      `json:"timestamp"`            // When the event occurred
	EventType AuditEventType `json:"event_type"`           // Type of audit event
	Action    string         `json:"action"`               // Action performed (create, update, delete, access, etc.)
	UserID    string         `json:"user_id"`              // User who performed the action
	UserType  AuditUserType  `json:"user_type"`            // Human, system, service, etc.
	SessionID string         `json:"session_id,omitempty"` // Session identifier if applicable

	// Resource information
	ResourceType string `json:"resource_type"`           // Type of resource (config, user, certificate, etc.)
	ResourceID   string `json:"resource_id"`             // Identifier of the resource
	ResourceName string `json:"resource_name,omitempty"` // Human-readable name

	// Result and context
	Result       AuditResult `json:"result"`                  // Success, failure, error
	ErrorCode    string      `json:"error_code,omitempty"`    // Error code if failed
	ErrorMessage string      `json:"error_message,omitempty"` // Error message if failed

	// Request details
	RequestID string `json:"request_id,omitempty"` // Trace requests across systems
	IPAddress string `json:"ip_address,omitempty"` // Client IP address
	UserAgent string `json:"user_agent,omitempty"` // Client user agent
	Method    string `json:"method,omitempty"`     // HTTP method or action method
	Path      string `json:"path,omitempty"`       // API path or resource path

	// Additional context
	Details  map[string]interface{} `json:"details,omitempty"` // Additional event-specific data
	Changes  *AuditChanges          `json:"changes,omitempty"` // Before/after for modifications
	Tags     []string               `json:"tags,omitempty"`    // Tags for categorization
	Severity AuditSeverity          `json:"severity"`          // Event severity level

	// System metadata
	Source   string `json:"source"`            // Component that generated the audit
	Version  string `json:"version,omitempty"` // Schema version
	Checksum string `json:"checksum"`          // SHA256 for integrity
}

// AuditEventType categorizes types of audit events
type AuditEventType string

const (
	AuditEventAuthentication   AuditEventType = "authentication"    // Login, logout, auth failures
	AuditEventAuthorization    AuditEventType = "authorization"     // Permission checks, access denials
	AuditEventConfiguration    AuditEventType = "configuration"     // Config changes, template updates
	AuditEventUserManagement   AuditEventType = "user_management"   // User CRUD, role assignments
	AuditEventSystemAccess     AuditEventType = "system_access"     // Terminal sessions, API access
	AuditEventDataAccess       AuditEventType = "data_access"       // Data reads, exports, queries
	AuditEventDataModification AuditEventType = "data_modification" // Data writes, updates, deletes
	AuditEventSecurityEvent    AuditEventType = "security_event"    // Security incidents, violations
	AuditEventSystemEvent      AuditEventType = "system_event"      // System startup, shutdown, errors
	AuditEventCompliance       AuditEventType = "compliance"        // Compliance-related events
)

// AuditUserType identifies the type of actor performing the action
type AuditUserType string

const (
	AuditUserTypeHuman    AuditUserType = "human"    // Human user
	AuditUserTypeSystem   AuditUserType = "system"   // System process
	AuditUserTypeService  AuditUserType = "service"  // Service account
	AuditUserTypeWorkflow AuditUserType = "workflow" // Workflow engine
	AuditUserTypeAPI      AuditUserType = "api"      // API client
)

// AuditResult indicates the outcome of the audited action
type AuditResult string

const (
	AuditResultSuccess AuditResult = "success" // Action completed successfully
	AuditResultFailure AuditResult = "failure" // Action failed due to business logic
	AuditResultError   AuditResult = "error"   // Action failed due to system error
	AuditResultDenied  AuditResult = "denied"  // Action denied by authorization
)

// AuditSeverity indicates the severity level of the audit event
type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "low"      // Routine operations
	AuditSeverityMedium   AuditSeverity = "medium"   // Important operations
	AuditSeverityHigh     AuditSeverity = "high"     // Sensitive operations
	AuditSeverityCritical AuditSeverity = "critical" // Security-critical operations
)

// AuditChanges captures before/after state for modifications
type AuditChanges struct {
	Before map[string]interface{} `json:"before,omitempty"` // State before change
	After  map[string]interface{} `json:"after,omitempty"`  // State after change
	Fields []string               `json:"fields,omitempty"` // List of changed fields
}

// AuditFilter defines criteria for querying audit entries
type AuditFilter struct {
	TenantID   string           `json:"tenant_id,omitempty"`
	EventTypes []AuditEventType `json:"event_types,omitempty"`
	Actions    []string         `json:"actions,omitempty"`
	UserIDs    []string         `json:"user_ids,omitempty"`
	UserTypes  []AuditUserType  `json:"user_types,omitempty"`
	Results    []AuditResult    `json:"results,omitempty"`
	Severities []AuditSeverity  `json:"severities,omitempty"`

	// Resource filtering
	ResourceTypes []string `json:"resource_types,omitempty"`
	ResourceIDs   []string `json:"resource_ids,omitempty"`

	// Time-based filtering
	TimeRange *TimeRange `json:"time_range,omitempty"`

	// Text search
	SearchQuery string   `json:"search_query,omitempty"` // Full-text search in details
	Tags        []string `json:"tags,omitempty"`         // Filter by tags

	// Pagination and sorting
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
	SortBy string `json:"sort_by,omitempty"` // "timestamp", "severity", "user_id"
	Order  string `json:"order,omitempty"`   // "asc", "desc" (default: "desc")
}

// TimeRange defines a time range for queries
type TimeRange struct {
	Start *time.Time `json:"start,omitempty"` // Start time (inclusive)
	End   *time.Time `json:"end,omitempty"`   // End time (inclusive)
}

// AuditStats provides statistics about stored audit entries
type AuditStats struct {
	TotalEntries      int64            `json:"total_entries"`
	TotalSize         int64            `json:"total_size"` // Total storage size in bytes
	EntriesByTenant   map[string]int64 `json:"entries_by_tenant"`
	EntriesByType     map[string]int64 `json:"entries_by_type"`     // By event type
	EntriesByResult   map[string]int64 `json:"entries_by_result"`   // Success, failure, error, denied
	EntriesBySeverity map[string]int64 `json:"entries_by_severity"` // By severity level

	// Time-based statistics
	OldestEntry    *time.Time `json:"oldest_entry,omitempty"`
	NewestEntry    *time.Time `json:"newest_entry,omitempty"`
	EntriesLast24h int64      `json:"entries_last_24h"`
	EntriesLast7d  int64      `json:"entries_last_7d"`
	EntriesLast30d int64      `json:"entries_last_30d"`

	// Security statistics
	FailedActionsLast24h    int64      `json:"failed_actions_last_24h"`
	SuspiciousActivityCount int64      `json:"suspicious_activity_count"`
	LastSecurityIncident    *time.Time `json:"last_security_incident,omitempty"`

	// Performance metrics
	AverageSize int64     `json:"average_size"` // Average entry size
	LastUpdated time.Time `json:"last_updated"` // When stats were computed
}

// Common audit errors
var (
	ErrAuditNotFound        = &AuditValidationError{Field: "id", Message: "audit entry not found", Code: "AUDIT_NOT_FOUND"}
	ErrInvalidTimeRange     = &AuditValidationError{Field: "time_range", Message: "invalid time range", Code: "INVALID_TIME_RANGE"}
	ErrTenantIDRequired     = &AuditValidationError{Field: "tenant_id", Message: "tenant ID is required", Code: "TENANT_REQUIRED"}
	ErrUserIDRequired       = &AuditValidationError{Field: "user_id", Message: "user ID is required", Code: "USER_REQUIRED"}
	ErrActionRequired       = &AuditValidationError{Field: "action", Message: "action is required", Code: "ACTION_REQUIRED"}
	ErrResourceTypeRequired = &AuditValidationError{Field: "resource_type", Message: "resource type is required", Code: "RESOURCE_TYPE_REQUIRED"}
	ErrResourceIDRequired   = &AuditValidationError{Field: "resource_id", Message: "resource ID is required", Code: "RESOURCE_ID_REQUIRED"}
)

// AuditValidationError represents validation errors for audit operations
type AuditValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

func (e *AuditValidationError) Error() string {
	return e.Field + ": " + e.Message
}
