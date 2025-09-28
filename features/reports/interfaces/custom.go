// Package interfaces provides custom report generation interfaces for Story #174.
// This extends the existing reporting framework to support user-defined custom reports
// with parameters, validation, template sharing, and large dataset handling.
package interfaces

import (
	"context"
	"time"
)

// CustomReportBuilder defines the interface for building custom reports
type CustomReportBuilder interface {
	// CreateCustomReport creates a new custom report from a request
	CreateCustomReport(ctx context.Context, req CustomReportRequest) (*CustomReport, error)

	// GenerateReport generates a report from a custom report request
	GenerateReport(ctx context.Context, req CustomReportRequest) (*CustomReport, error)

	// ValidateParameters validates user-provided parameters against template requirements
	ValidateParameters(template *CustomReportTemplate, params map[string]interface{}) error

	// BuildQuery builds a data query from custom query specification
	BuildQuery(query CustomQuery) (*ProcessedQuery, error)

	// GetReportData retrieves paginated report data for streaming
	GetReportData(ctx context.Context, pagination PaginationRequest) ([]byte, bool, error)
}

// CustomTemplateManager defines the interface for managing custom report templates
type CustomTemplateManager interface {
	// SaveTemplate saves a custom report template
	SaveTemplate(ctx context.Context, template *CustomReportTemplate) (*CustomReportTemplate, error)

	// GetTemplate retrieves a template by ID with tenant access validation
	GetTemplate(ctx context.Context, templateID, tenantID string) (*CustomReportTemplate, error)

	// GetAccessibleTemplates returns all templates accessible to a tenant
	GetAccessibleTemplates(ctx context.Context, tenantID string) ([]*CustomReportTemplate, error)

	// ShareTemplate shares a template with other tenants
	ShareTemplate(ctx context.Context, req ShareTemplateRequest) error

	// DeleteTemplate deletes a template (only by owner)
	DeleteTemplate(ctx context.Context, templateID, tenantID string) error
}

// CustomTemplateStore defines the interface for storing custom report templates
type CustomTemplateStore interface {
	// Save saves a custom report template
	Save(ctx context.Context, template *CustomReportTemplate) (*CustomReportTemplate, error)

	// GetByID retrieves a template by ID
	GetByID(ctx context.Context, id string) (*CustomReportTemplate, error)

	// GetByTenant retrieves templates owned by a tenant
	GetByTenant(ctx context.Context, tenantID string) ([]*CustomReportTemplate, error)

	// GetSharedTemplates retrieves templates shared with a tenant
	GetSharedTemplates(ctx context.Context, tenantID string) ([]*CustomReportTemplate, error)

	// Delete deletes a template
	Delete(ctx context.Context, id string, tenantID string) error

	// UpdateSharing updates the sharing configuration of a template
	UpdateSharing(ctx context.Context, templateID string, shares []TemplateShare) error
}

// ScheduledReportManager defines the interface for scheduled report generation
type ScheduledReportManager interface {
	// ScheduleReport schedules a custom report for automatic generation
	ScheduleReport(ctx context.Context, req ScheduleReportRequest) (*ScheduledReport, error)

	// UpdateSchedule updates an existing scheduled report
	UpdateSchedule(ctx context.Context, scheduleID string, req ScheduleReportRequest) error

	// DeleteSchedule deletes a scheduled report
	DeleteSchedule(ctx context.Context, scheduleID, tenantID string) error

	// GetScheduledReports retrieves all scheduled reports for a tenant
	GetScheduledReports(ctx context.Context, tenantID string) ([]*ScheduledReport, error)

	// ExecuteScheduledReport executes a scheduled report immediately
	ExecuteScheduledReport(ctx context.Context, scheduleID string) (*CustomReport, error)
}

// ScheduledReportStore defines the interface for storing scheduled reports
type ScheduledReportStore interface {
	// Save saves a scheduled report
	Save(ctx context.Context, schedule *ScheduledReport) (*ScheduledReport, error)

	// GetByID retrieves a scheduled report by ID
	GetByID(ctx context.Context, id string) (*ScheduledReport, error)

	// GetByTenant retrieves scheduled reports for a tenant
	GetByTenant(ctx context.Context, tenantID string) ([]*ScheduledReport, error)

	// GetDueReports retrieves reports that are due for execution
	GetDueReports(ctx context.Context, before time.Time) ([]*ScheduledReport, error)

	// Delete deletes a scheduled report
	Delete(ctx context.Context, id string) error
}

// Custom report request and response types

// CustomReportRequest represents a request to create/generate a custom report
type CustomReportRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Query       CustomQuery            `json:"query"`
	Parameters  []CustomParameter      `json:"parameters,omitempty"`
	Format      ExportFormat           `json:"format"`
	TenantID    string                 `json:"tenant_id"`
	CreatedBy   string                 `json:"created_by"`
	UserParams  map[string]interface{} `json:"user_params,omitempty"`
}

// CustomQuery defines a custom data query specification
type CustomQuery struct {
	DataSources  []string               `json:"data_sources"`  // "dna", "audit", "compliance", etc.
	Filters      map[string]interface{} `json:"filters"`
	Aggregations []QueryAggregation     `json:"aggregations,omitempty"`
	Sorting      []QuerySort            `json:"sorting,omitempty"`
	TimeRange    TimeRange              `json:"time_range"`
	Pagination   *PaginationConfig      `json:"pagination,omitempty"`
}

// QueryAggregation defines an aggregation operation
type QueryAggregation struct {
	Field     string   `json:"field"`
	Operation string   `json:"operation"` // sum, avg, count, min, max, distinct
	GroupBy   []string `json:"group_by,omitempty"`
	Having    string   `json:"having,omitempty"`
}

// QuerySort defines sorting criteria
type QuerySort struct {
	Field     string `json:"field"`
	Direction string `json:"direction"` // asc, desc
}

// PaginationConfig defines pagination settings for large datasets
type PaginationConfig struct {
	PageSize   int  `json:"page_size"`   // Number of records per page
	MaxPages   int  `json:"max_pages"`   // Maximum pages to generate
	StreamMode bool `json:"stream_mode"` // Use streaming for very large datasets
}

// CustomParameter defines a parameter that can be provided by users
type CustomParameter struct {
	Name         string      `json:"name"`
	Type         string      `json:"type"`         // string, number, boolean, date, array
	Description  string      `json:"description"`
	Required     bool        `json:"required"`
	Default      interface{} `json:"default,omitempty"`
	Options      []string    `json:"options,omitempty"`      // For enum-type parameters
	MinValue     *float64    `json:"min_value,omitempty"`    // For numeric parameters
	MaxValue     *float64    `json:"max_value,omitempty"`    // For numeric parameters
	Pattern      string      `json:"pattern,omitempty"`      // Regex pattern for string validation
	MinLength    *int        `json:"min_length,omitempty"`   // For string parameters
	MaxLength    *int        `json:"max_length,omitempty"`   // For string parameters
}

// CustomReport represents a generated custom report
type CustomReport struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	TenantID    string                 `json:"tenant_id"`
	CreatedBy   string                 `json:"created_by"`
	CreatedAt   time.Time              `json:"created_at"`
	Query       CustomQuery            `json:"query"`
	Parameters  []CustomParameter      `json:"parameters,omitempty"`
	UserParams  map[string]interface{} `json:"user_params,omitempty"`

	// Report data
	Data        interface{}   `json:"data"`
	Summary     ReportSummary `json:"summary"`
	Charts      []ChartData   `json:"charts,omitempty"`

	// Generation metadata
	GeneratedAt   time.Time      `json:"generated_at"`
	GenerationMS  int64          `json:"generation_ms"`
	DataPoints    int            `json:"data_points"`
	Format        ExportFormat   `json:"format"`

	// Streaming support for large datasets
	IsStreamed  bool   `json:"is_streamed"`
	StreamToken string `json:"stream_token,omitempty"`
	TotalPages  int    `json:"total_pages,omitempty"`
}

// CustomReportTemplate represents a reusable custom report template
type CustomReportTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Query       CustomQuery       `json:"query"`
	Parameters  []CustomParameter `json:"parameters"`

	// Ownership and sharing
	TenantID   string          `json:"tenant_id"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	IsShared   bool            `json:"is_shared"`
	SharedWith []TemplateShare `json:"shared_with,omitempty"`

	// Template metadata
	Tags        []string `json:"tags,omitempty"`
	Category    string   `json:"category,omitempty"`
	Version     string   `json:"version,omitempty"`
	UsageCount  int      `json:"usage_count"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
}

// TemplateShare defines sharing permissions for a template
type TemplateShare struct {
	TenantID    string    `json:"tenant_id"`
	SharedBy    string    `json:"shared_by"`
	SharedAt    time.Time `json:"shared_at"`
	Permissions []string  `json:"permissions"` // read, execute, modify
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// ShareTemplateRequest represents a request to share a template
type ShareTemplateRequest struct {
	TemplateID        string     `json:"template_id"`
	SharedWithTenants []string   `json:"shared_with_tenants"`
	Permissions       []string   `json:"permissions"`
	SharedBy          string     `json:"shared_by"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
}

// ProcessedQuery represents a processed and validated query
type ProcessedQuery struct {
	DataSources  []string               `json:"data_sources"`
	Filters      map[string]interface{} `json:"filters"`
	Aggregations []QueryAggregation     `json:"aggregations"`
	Sorting      []QuerySort            `json:"sorting"`
	TimeRange    TimeRange              `json:"time_range"`
	Pagination   *PaginationConfig      `json:"pagination"`

	// Processing metadata
	EstimatedRows int           `json:"estimated_rows"`
	Complexity    string        `json:"complexity"` // low, medium, high
	CacheKey      string        `json:"cache_key"`
	Timeout       time.Duration `json:"timeout"`
}

// PaginationRequest represents a request for paginated data
type PaginationRequest struct {
	StreamToken string `json:"stream_token"`
	Page        int    `json:"page"`
	PageSize    int    `json:"page_size"`
}

// Scheduled report types

// ScheduleReportRequest represents a request to schedule a report
type ScheduleReportRequest struct {
	Name         string                 `json:"name"`
	TemplateID   string                 `json:"template_id"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	Schedule     ReportSchedule         `json:"schedule"`
	Format       ExportFormat           `json:"format"`
	DeliveryMode DeliveryMode           `json:"delivery_mode"`
	Recipients   []ReportRecipient      `json:"recipients,omitempty"`
	TenantID     string                 `json:"tenant_id"`
	CreatedBy    string                 `json:"created_by"`
}

// ReportSchedule defines when and how often to generate a report
type ReportSchedule struct {
	Type       ScheduleType `json:"type"`        // cron, interval
	Expression string       `json:"expression"`  // cron expression or interval duration
	Timezone   string       `json:"timezone"`
	StartDate  *time.Time   `json:"start_date,omitempty"`
	EndDate    *time.Time   `json:"end_date,omitempty"`
}

// ScheduleType defines the type of schedule
type ScheduleType string

const (
	ScheduleTypeCron     ScheduleType = "cron"
	ScheduleTypeInterval ScheduleType = "interval"
)

// DeliveryMode defines how scheduled reports are delivered
type DeliveryMode string

const (
	DeliveryModeEmail  DeliveryMode = "email"
	DeliveryModeWebhook DeliveryMode = "webhook"
	DeliveryModeStorage DeliveryMode = "storage"
)

// ReportRecipient defines a recipient for scheduled reports
type ReportRecipient struct {
	Type    string `json:"type"`    // email, webhook, storage_path
	Address string `json:"address"` // email address, webhook URL, or storage path
	Name    string `json:"name,omitempty"`
}

// ScheduledReport represents a scheduled report configuration
type ScheduledReport struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	TemplateID   string                 `json:"template_id"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	Schedule     ReportSchedule         `json:"schedule"`
	Format       ExportFormat           `json:"format"`
	DeliveryMode DeliveryMode           `json:"delivery_mode"`
	Recipients   []ReportRecipient      `json:"recipients,omitempty"`

	// Ownership and status
	TenantID  string    `json:"tenant_id"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	IsActive  bool      `json:"is_active"`

	// Execution tracking
	LastRun       *time.Time `json:"last_run,omitempty"`
	NextRun       *time.Time `json:"next_run,omitempty"`
	RunCount      int        `json:"run_count"`
	FailureCount  int        `json:"failure_count"`
	LastError     string     `json:"last_error,omitempty"`
}

// Report builder configuration

// CustomReportConfig contains configuration for custom report generation
type CustomReportConfig struct {
	MaxDataSources   int           `json:"max_data_sources"`
	MaxParameters    int           `json:"max_parameters"`
	MaxFilters       int           `json:"max_filters"`
	MaxAggregations  int           `json:"max_aggregations"`
	DefaultPageSize  int           `json:"default_page_size"`
	MaxPageSize      int           `json:"max_page_size"`
	DefaultTimeout   time.Duration `json:"default_timeout"`
	MaxTimeout       time.Duration `json:"max_timeout"`
	EnableStreaming  bool          `json:"enable_streaming"`
	StreamThreshold  int           `json:"stream_threshold"` // Records threshold for streaming
	CacheEnabled     bool          `json:"cache_enabled"`
	CacheTTL         time.Duration `json:"cache_ttl"`
}

// DefaultCustomReportConfig returns default configuration
func DefaultCustomReportConfig() CustomReportConfig {
	return CustomReportConfig{
		MaxDataSources:  5,
		MaxParameters:   20,
		MaxFilters:      10,
		MaxAggregations: 5,
		DefaultPageSize: 100,
		MaxPageSize:     1000,
		DefaultTimeout:  5 * time.Minute,
		MaxTimeout:      15 * time.Minute,
		EnableStreaming: true,
		StreamThreshold: 10000, // Use streaming for >10k records
		CacheEnabled:    true,
		CacheTTL:        time.Hour,
	}
}

// Parameter validation types

// ParameterValidationRule defines validation rules for custom parameters
type ParameterValidationRule struct {
	Type        string                 `json:"type"`
	Required    bool                   `json:"required"`
	Options     []string               `json:"options,omitempty"`
	MinValue    *float64               `json:"min_value,omitempty"`
	MaxValue    *float64               `json:"max_value,omitempty"`
	Pattern     string                 `json:"pattern,omitempty"`
	MinLength   *int                   `json:"min_length,omitempty"`
	MaxLength   *int                   `json:"max_length,omitempty"`
	CustomRules map[string]interface{} `json:"custom_rules,omitempty"`
}

// ParameterValidationResult represents the result of parameter validation
type ParameterValidationResult struct {
	Valid   bool     `json:"valid"`
	Errors  []string `json:"errors,omitempty"`
	Value   interface{} `json:"value,omitempty"`
}