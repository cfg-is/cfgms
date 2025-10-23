// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package interfaces provides advanced reporting interfaces for Story #173.
// This extends the existing DNA-focused reporting system to include audit data
// and comprehensive multi-tenant reporting capabilities.
package interfaces

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// AdvancedDataProvider extends DataProvider to include audit data integration
type AdvancedDataProvider interface {
	DataProvider // Embed existing DNA-focused provider

	// Audit data integration
	GetAuditData(ctx context.Context, query AuditDataQuery) ([]interfaces.AuditEntry, error)
	GetComplianceData(ctx context.Context, query ComplianceDataQuery) (*ComplianceData, error)
	GetSecurityEvents(ctx context.Context, query SecurityEventQuery) ([]SecurityEvent, error)
	GetUserActivity(ctx context.Context, query UserActivityQuery) ([]UserActivity, error)

	// Cross-system aggregation
	GetCrossSystemMetrics(ctx context.Context, query CrossSystemQuery) (*CrossSystemMetrics, error)
	GetTenantSummary(ctx context.Context, tenantID string, timeRange TimeRange) (*TenantSummary, error)
	GetMultiTenantAggregation(ctx context.Context, tenantIDs []string, timeRange TimeRange) (*MultiTenantAggregation, error)
}

// AdvancedReportEngine extends ReportEngine with audit integration and enhanced capabilities
type AdvancedReportEngine interface {
	ReportEngine // Embed existing engine

	// Advanced report generation
	GenerateAdvancedReport(ctx context.Context, req AdvancedReportRequest) (*AdvancedReport, error)
	GenerateComplianceReport(ctx context.Context, req ComplianceReportRequest) (*ComplianceReport, error)
	GenerateSecurityReport(ctx context.Context, req SecurityReportRequest) (*SecurityReport, error)
	GenerateExecutiveReport(ctx context.Context, req ExecutiveReportRequest) (*ExecutiveReport, error)

	// Multi-tenant capabilities
	GenerateMultiTenantReport(ctx context.Context, req MultiTenantReportRequest) (*MultiTenantReport, error)
	ValidateMultiTenantAccess(ctx context.Context, userID string, tenantIDs []string) error

	// Template management
	GetAdvancedTemplates() []AdvancedTemplateInfo
	ValidateAdvancedTemplate(template string, reportType AdvancedReportType) error
}

// AdvancedReportType extends ReportType with new audit-integrated types
type AdvancedReportType string

const (
	// Existing types are still supported
	AdvancedReportTypeCompliance  AdvancedReportType = "compliance"
	AdvancedReportTypeExecutive   AdvancedReportType = "executive"
	AdvancedReportTypeDrift       AdvancedReportType = "drift"
	AdvancedReportTypeOperational AdvancedReportType = "operational"

	// New advanced types
	AdvancedReportTypeSecurity    AdvancedReportType = "security"
	AdvancedReportTypeAudit       AdvancedReportType = "audit"
	AdvancedReportTypeGovernance  AdvancedReportType = "governance"
	AdvancedReportTypeRisk        AdvancedReportType = "risk"
	AdvancedReportTypeMultiTenant AdvancedReportType = "multi_tenant"
)

// AuditDataQuery specifies parameters for querying audit data
type AuditDataQuery struct {
	TimeRange    TimeRange
	TenantIDs    []string
	UserIDs      []string
	EventTypes   []interfaces.AuditEventType
	Actions      []string
	Results      []interfaces.AuditResult
	Severities   []interfaces.AuditSeverity
	ResourceType string
	ResourceIDs  []string
	Limit        int
	Offset       int
}

// ComplianceDataQuery specifies parameters for compliance-focused queries
type ComplianceDataQuery struct {
	TimeRange            TimeRange
	TenantIDs            []string
	ComplianceFrameworks []string // CIS, HIPAA, PCI-DSS, etc.
	RiskLevels           []RiskLevel
	IncludeBaselines     bool
	IncludeExceptions    bool
}

// SecurityEventQuery specifies parameters for security event queries
type SecurityEventQuery struct {
	TimeRange       TimeRange
	TenantIDs       []string
	Severities      []interfaces.AuditSeverity
	EventTypes      []SecurityEventType
	IncludeResolved bool
}

// UserActivityQuery specifies parameters for user activity queries
type UserActivityQuery struct {
	TimeRange       TimeRange
	TenantIDs       []string
	UserIDs         []string
	UserTypes       []interfaces.AuditUserType
	Actions         []string
	IncludeFailures bool
}

// CrossSystemQuery enables querying across DNA and audit data
type CrossSystemQuery struct {
	TimeRange          TimeRange
	TenantIDs          []string
	DeviceIDs          []string
	UserIDs            []string
	CorrelationMetrics []string // "drift_vs_changes", "access_vs_events", etc.
}

// SecurityEventType categorizes security events
type SecurityEventType string

const (
	SecurityEventTypeAuthentication SecurityEventType = "authentication"
	SecurityEventTypeAuthorization  SecurityEventType = "authorization"
	SecurityEventTypeAccess         SecurityEventType = "access"
	SecurityEventTypeBreach         SecurityEventType = "breach"
	SecurityEventTypeFailure        SecurityEventType = "failure"
	SecurityEventTypeAnomaly        SecurityEventType = "anomaly"
)

// ComplianceData represents compliance assessment results
type ComplianceData struct {
	Framework    string                `json:"framework"`
	Score        float64               `json:"score"`
	Controls     []ComplianceControl   `json:"controls"`
	Violations   []ComplianceViolation `json:"violations"`
	Exceptions   []ComplianceException `json:"exceptions"`
	LastAssessed time.Time             `json:"last_assessed"`
	TrendData    []ComplianceTrend     `json:"trend_data"`
}

// ComplianceControl represents a compliance control assessment
type ComplianceControl struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Status      string   `json:"status"` // "compliant", "non_compliant", "not_applicable"
	Score       float64  `json:"score"`
	Evidence    []string `json:"evidence"`
	Remediation string   `json:"remediation,omitempty"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ControlID    string     `json:"control_id"`
	DeviceID     string     `json:"device_id"`
	Severity     string     `json:"severity"`
	Description  string     `json:"description"`
	DetectedAt   time.Time  `json:"detected_at"`
	Remediated   bool       `json:"remediated"`
	RemediatedAt *time.Time `json:"remediated_at,omitempty"`
}

// ComplianceException represents an approved compliance exception
type ComplianceException struct {
	ID            string     `json:"id"`
	ControlID     string     `json:"control_id"`
	DeviceID      string     `json:"device_id"`
	Justification string     `json:"justification"`
	ApprovedBy    string     `json:"approved_by"`
	ApprovedAt    time.Time  `json:"approved_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

// ComplianceTrend represents compliance score over time
type ComplianceTrend struct {
	Timestamp time.Time `json:"timestamp"`
	Score     float64   `json:"score"`
	Framework string    `json:"framework"`
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	ID          string                   `json:"id"`
	Type        SecurityEventType        `json:"type"`
	Severity    interfaces.AuditSeverity `json:"severity"`
	Description string                   `json:"description"`
	DeviceID    string                   `json:"device_id,omitempty"`
	UserID      string                   `json:"user_id"`
	TenantID    string                   `json:"tenant_id"`
	Timestamp   time.Time                `json:"timestamp"`
	Source      string                   `json:"source"`
	Resolved    bool                     `json:"resolved"`
	ResolvedAt  *time.Time               `json:"resolved_at,omitempty"`
	ResolvedBy  string                   `json:"resolved_by,omitempty"`
	Context     map[string]interface{}   `json:"context,omitempty"`
}

// UserActivity represents user activity summary
type UserActivity struct {
	UserID       string               `json:"user_id"`
	TenantID     string               `json:"tenant_id"`
	ActionCount  int                  `json:"action_count"`
	FailureCount int                  `json:"failure_count"`
	LastActivity time.Time            `json:"last_activity"`
	RiskScore    float64              `json:"risk_score"`
	Activities   []UserActivityDetail `json:"activities"`
}

// UserActivityDetail represents detailed user activity
type UserActivityDetail struct {
	Action       string                 `json:"action"`
	ResourceType string                 `json:"resource_type"`
	ResourceID   string                 `json:"resource_id"`
	Timestamp    time.Time              `json:"timestamp"`
	Result       interfaces.AuditResult `json:"result"`
	IPAddress    string                 `json:"ip_address,omitempty"`
}

// CrossSystemMetrics represents metrics across DNA and audit systems
type CrossSystemMetrics struct {
	TenantID     string              `json:"tenant_id"`
	TimeRange    TimeRange           `json:"time_range"`
	DNAMetrics   DNASystemMetrics    `json:"dna_metrics"`
	AuditMetrics AuditSystemMetrics  `json:"audit_metrics"`
	Correlations []SystemCorrelation `json:"correlations"`
}

// DNASystemMetrics represents DNA system metrics
type DNASystemMetrics struct {
	DeviceCount     int     `json:"device_count"`
	RecordCount     int     `json:"record_count"`
	DriftEventCount int     `json:"drift_event_count"`
	ComplianceScore float64 `json:"compliance_score"`
	HealthScore     float64 `json:"health_score"`
}

// AuditSystemMetrics represents audit system metrics
type AuditSystemMetrics struct {
	EventCount     int     `json:"event_count"`
	UserCount      int     `json:"user_count"`
	FailureRate    float64 `json:"failure_rate"`
	SecurityEvents int     `json:"security_events"`
	CriticalEvents int     `json:"critical_events"`
}

// SystemCorrelation represents correlation between DNA and audit data
type SystemCorrelation struct {
	Metric      string  `json:"metric"`
	Correlation float64 `json:"correlation"`
	Confidence  float64 `json:"confidence"`
	Description string  `json:"description"`
}

// TenantSummary represents summary metrics for a single tenant
type TenantSummary struct {
	TenantID        string             `json:"tenant_id"`
	TimeRange       TimeRange          `json:"time_range"`
	DeviceCount     int                `json:"device_count"`
	UserCount       int                `json:"user_count"`
	ComplianceScore float64            `json:"compliance_score"`
	SecurityScore   float64            `json:"security_score"`
	RiskLevel       RiskLevel          `json:"risk_level"`
	KeyMetrics      map[string]float64 `json:"key_metrics"`
	Alerts          []TenantAlert      `json:"alerts"`
}

// TenantAlert represents an alert for a tenant
type TenantAlert struct {
	ID          string                   `json:"id"`
	Type        string                   `json:"type"`
	Severity    interfaces.AuditSeverity `json:"severity"`
	Description string                   `json:"description"`
	Timestamp   time.Time                `json:"timestamp"`
	Resolved    bool                     `json:"resolved"`
}

// MultiTenantAggregation represents aggregated metrics across multiple tenants
type MultiTenantAggregation struct {
	TenantIDs         []string                 `json:"tenant_ids"`
	TimeRange         TimeRange                `json:"time_range"`
	TotalDevices      int                      `json:"total_devices"`
	TotalUsers        int                      `json:"total_users"`
	AverageCompliance float64                  `json:"average_compliance"`
	AverageSecurity   float64                  `json:"average_security"`
	TenantSummaries   map[string]TenantSummary `json:"tenant_summaries"`
	Trends            []MultiTenantTrend       `json:"trends"`
}

// MultiTenantTrend represents trends across multiple tenants
type MultiTenantTrend struct {
	Timestamp         time.Time `json:"timestamp"`
	AverageCompliance float64   `json:"average_compliance"`
	AverageSecurity   float64   `json:"average_security"`
	TotalAlerts       int       `json:"total_alerts"`
}

// Advanced request types

// AdvancedReportRequest extends ReportRequest with advanced capabilities
type AdvancedReportRequest struct {
	ReportRequest            // Embed base request
	IncludeAuditData    bool `json:"include_audit_data"`
	IncludeCompliance   bool `json:"include_compliance"`
	IncludeSecurity     bool `json:"include_security"`
	CorrelationAnalysis bool `json:"correlation_analysis"`
	RiskAssessment      bool `json:"risk_assessment"`
}

// ComplianceReportRequest specifies parameters for compliance reports
type ComplianceReportRequest struct {
	TimeRange         TimeRange    `json:"time_range"`
	TenantIDs         []string     `json:"tenant_ids"`
	DeviceIDs         []string     `json:"device_ids,omitempty"`
	Frameworks        []string     `json:"frameworks"` // CIS, HIPAA, etc.
	IncludeBaselines  bool         `json:"include_baselines"`
	IncludeExceptions bool         `json:"include_exceptions"`
	Format            ExportFormat `json:"format"`
	DetailLevel       string       `json:"detail_level"` // "summary", "detailed", "full"
}

// SecurityReportRequest specifies parameters for security reports
type SecurityReportRequest struct {
	TimeRange       TimeRange                  `json:"time_range"`
	TenantIDs       []string                   `json:"tenant_ids"`
	UserIDs         []string                   `json:"user_ids,omitempty"`
	Severities      []interfaces.AuditSeverity `json:"severities,omitempty"`
	EventTypes      []SecurityEventType        `json:"event_types,omitempty"`
	IncludeResolved bool                       `json:"include_resolved"`
	Format          ExportFormat               `json:"format"`
	AnalysisType    string                     `json:"analysis_type"` // "threat", "user_behavior", "access_patterns"
}

// ExecutiveReportRequest specifies parameters for executive reports
type ExecutiveReportRequest struct {
	TimeRange     TimeRange    `json:"time_range"`
	TenantIDs     []string     `json:"tenant_ids"`
	KPIs          []string     `json:"kpis"` // "compliance", "security", "drift", "availability"
	IncludeCharts bool         `json:"include_charts"`
	IncludeTrends bool         `json:"include_trends"`
	Format        ExportFormat `json:"format"`
	Audience      string       `json:"audience"` // "executive", "technical", "compliance"
}

// MultiTenantReportRequest specifies parameters for multi-tenant reports
type MultiTenantReportRequest struct {
	TimeRange       TimeRange          `json:"time_range"`
	TenantIDs       []string           `json:"tenant_ids"`
	ReportType      AdvancedReportType `json:"report_type"`
	AggregationType string             `json:"aggregation_type"` // "summary", "comparative", "drill_down"
	IncludeDetails  bool               `json:"include_details"`
	Format          ExportFormat       `json:"format"`
}

// Advanced response types

// AdvancedReport extends Report with additional audit and cross-system data
type AdvancedReport struct {
	Report                                     // Embed base report
	AuditData          []interfaces.AuditEntry `json:"audit_data,omitempty"`
	ComplianceData     *ComplianceData         `json:"compliance_data,omitempty"`
	SecurityEvents     []SecurityEvent         `json:"security_events,omitempty"`
	CrossSystemMetrics *CrossSystemMetrics     `json:"cross_system_metrics,omitempty"`
	RiskAssessment     *RiskAssessment         `json:"risk_assessment,omitempty"`
}

// ComplianceReport represents a compliance assessment report
type ComplianceReport struct {
	ID              string                `json:"id"`
	GeneratedAt     time.Time             `json:"generated_at"`
	TimeRange       TimeRange             `json:"time_range"`
	TenantIDs       []string              `json:"tenant_ids"`
	Frameworks      []string              `json:"frameworks"`
	OverallScore    float64               `json:"overall_score"`
	ComplianceData  []ComplianceData      `json:"compliance_data"`
	Violations      []ComplianceViolation `json:"violations"`
	Recommendations []string              `json:"recommendations"`
	Charts          []ChartData           `json:"charts,omitempty"`
}

// SecurityReport represents a security analysis report
type SecurityReport struct {
	ID              string            `json:"id"`
	GeneratedAt     time.Time         `json:"generated_at"`
	TimeRange       TimeRange         `json:"time_range"`
	TenantIDs       []string          `json:"tenant_ids"`
	SecurityScore   float64           `json:"security_score"`
	ThreatLevel     string            `json:"threat_level"`
	SecurityEvents  []SecurityEvent   `json:"security_events"`
	UserActivities  []UserActivity    `json:"user_activities"`
	Anomalies       []SecurityAnomaly `json:"anomalies"`
	Recommendations []string          `json:"recommendations"`
	Charts          []ChartData       `json:"charts,omitempty"`
}

// ExecutiveReport represents an executive-level summary report
type ExecutiveReport struct {
	ID               string             `json:"id"`
	GeneratedAt      time.Time          `json:"generated_at"`
	TimeRange        TimeRange          `json:"time_range"`
	TenantIDs        []string           `json:"tenant_ids"`
	ExecutiveSummary string             `json:"executive_summary"`
	KPIs             map[string]float64 `json:"kpis"`
	Trends           []ExecutiveTrend   `json:"trends"`
	RiskSummary      *RiskSummary       `json:"risk_summary"`
	ActionItems      []ActionItem       `json:"action_items"`
	Charts           []ChartData        `json:"charts,omitempty"`
}

// MultiTenantReport represents a multi-tenant analysis report
type MultiTenantReport struct {
	ID            string                  `json:"id"`
	GeneratedAt   time.Time               `json:"generated_at"`
	TimeRange     TimeRange               `json:"time_range"`
	TenantIDs     []string                `json:"tenant_ids"`
	Aggregation   *MultiTenantAggregation `json:"aggregation"`
	Comparisons   []TenantComparison      `json:"comparisons"`
	BestPractices []string                `json:"best_practices"`
	Charts        []ChartData             `json:"charts,omitempty"`
}

// Supporting types

// SecurityAnomaly represents a detected security anomaly
type SecurityAnomaly struct {
	ID          string                   `json:"id"`
	Type        string                   `json:"type"`
	Description string                   `json:"description"`
	Severity    interfaces.AuditSeverity `json:"severity"`
	Confidence  float64                  `json:"confidence"`
	DeviceID    string                   `json:"device_id,omitempty"`
	UserID      string                   `json:"user_id,omitempty"`
	DetectedAt  time.Time                `json:"detected_at"`
	Context     map[string]interface{}   `json:"context"`
}

// RiskAssessment represents overall risk assessment
type RiskAssessment struct {
	OverallRisk  RiskLevel    `json:"overall_risk"`
	RiskFactors  []RiskFactor `json:"risk_factors"`
	RiskScore    float64      `json:"risk_score"`
	Mitigation   []string     `json:"mitigation"`
	LastAssessed time.Time    `json:"last_assessed"`
}

// RiskFactor represents individual risk factors
type RiskFactor struct {
	Category    string    `json:"category"`
	Description string    `json:"description"`
	Impact      RiskLevel `json:"impact"`
	Likelihood  RiskLevel `json:"likelihood"`
	Score       float64   `json:"score"`
}

// RiskSummary represents high-level risk information
type RiskSummary struct {
	OverallRisk     RiskLevel      `json:"overall_risk"`
	HighRiskItems   int            `json:"high_risk_items"`
	MediumRiskItems int            `json:"medium_risk_items"`
	LowRiskItems    int            `json:"low_risk_items"`
	TrendDirection  TrendDirection `json:"trend_direction"`
}

// ExecutiveTrend represents trends for executive reporting
type ExecutiveTrend struct {
	Metric    string         `json:"metric"`
	Current   float64        `json:"current"`
	Previous  float64        `json:"previous"`
	Change    float64        `json:"change"`
	Direction TrendDirection `json:"direction"`
	Period    string         `json:"period"`
}

// ActionItem represents recommended actions
type ActionItem struct {
	ID          string     `json:"id"`
	Priority    string     `json:"priority"` // "high", "medium", "low"
	Category    string     `json:"category"`
	Description string     `json:"description"`
	Owner       string     `json:"owner,omitempty"`
	DueDate     *time.Time `json:"due_date,omitempty"`
	Status      string     `json:"status"` // "open", "in_progress", "completed"
}

// TenantComparison represents comparison between tenants
type TenantComparison struct {
	TenantID        string             `json:"tenant_id"`
	ComplianceScore float64            `json:"compliance_score"`
	SecurityScore   float64            `json:"security_score"`
	RiskLevel       RiskLevel          `json:"risk_level"`
	Ranking         int                `json:"ranking"`
	Metrics         map[string]float64 `json:"metrics"`
}

// AdvancedTemplateInfo extends TemplateInfo with advanced capabilities
type AdvancedTemplateInfo struct {
	TemplateInfo                        // Embed base template info
	RequiresAuditData    bool           `json:"requires_audit_data"`
	RequiresCompliance   bool           `json:"requires_compliance"`
	SupportedTenantTypes []string       `json:"supported_tenant_types"`
	DataSources          []string       `json:"data_sources"`
	OutputFormats        []ExportFormat `json:"output_formats"`
}
