// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package reports provides advanced reporting capabilities for Story #173.
// This extends the existing DNA-focused reporting system to include audit data integration,
// comprehensive multi-tenant reporting, and advanced analytics.
//
// Key Features:
//   - Audit data integration with DNA monitoring data
//   - Multi-tenant reporting with RBAC validation
//   - Compliance reporting across multiple frameworks
//   - Security analysis with anomaly detection
//   - Executive dashboards with KPIs and trends
//   - Cross-system correlation analysis
//   - Risk assessment and mitigation recommendations
//
// Architecture:
//   - AdvancedEngine: Core advanced report generation with audit integration
//   - AdvancedProvider: Data provider integrating DNA and audit systems
//   - Advanced templates: Compliance, security, and executive report templates
//   - RBAC integration: Multi-tenant access control and validation
//   - Enhanced caching: Performance optimization for complex queries
//
// Usage Example:
//
//	// Create advanced service
//	advancedService := reports.NewAdvancedService(
//		storageManager, driftDetector, auditManager, auditStore,
//		rbacManager, cache, logger,
//	)
//
//	// Generate compliance report
//	complianceReq := interfaces.ComplianceReportRequest{
//		TimeRange:  interfaces.TimeRange{Start: start, End: end},
//		TenantIDs:  []string{"tenant1", "tenant2"},
//		Frameworks: []string{"CIS", "HIPAA"},
//		Format:     interfaces.FormatHTML,
//	}
//
//	complianceReport, err := advancedService.GenerateComplianceReport(ctx, complianceReq)
//	if err != nil {
//		return fmt.Errorf("failed to generate compliance report: %w", err)
//	}
//
// Integration:
// This package builds upon and extends:
//   - features/reports: Existing DNA monitoring reports (Story #81)
//   - pkg/audit: Comprehensive audit system
//   - features/rbac: Role-based access control
//   - pkg/storage/interfaces: Pluggable storage architecture
//
// The advanced reporting system provides:
//   - Unified view across DNA monitoring and audit data
//   - Enterprise-grade compliance and security reporting
//   - Multi-tenant analytics with proper access controls
//   - Executive-level dashboards and KPI tracking
//   - Automated risk assessment and recommendations
package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/rbac"
	reportcache "github.com/cfgis/cfgms/features/reports/cache"
	"github.com/cfgis/cfgms/features/reports/engine"
	"github.com/cfgis/cfgms/features/reports/exporters"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/reports/provider"
	"github.com/cfgis/cfgms/features/reports/templates"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// AdvancedService provides comprehensive reporting capabilities integrating DNA and audit data
type AdvancedService struct {
	*Service         // Embed existing service for backward compatibility
	advancedEngine   interfaces.AdvancedReportEngine
	advancedProvider interfaces.AdvancedDataProvider
	rbacManager      *rbac.Manager
	auditManager     *audit.Manager
	logger           logging.Logger
	config           AdvancedServiceConfig
}

// AdvancedServiceConfig contains configuration for the advanced reports service
type AdvancedServiceConfig struct {
	ServiceConfig                                           // Embed base config
	EnableAuditIntegration   bool                           `json:"enable_audit_integration"`
	EnableRBACValidation     bool                           `json:"enable_rbac_validation"`
	EnableCrossSystemMetrics bool                           `json:"enable_cross_system_metrics"`
	MaxTenantsPerReport      int                            `json:"max_tenants_per_report"`
	ComplianceFrameworks     []string                       `json:"compliance_frameworks"`
	SecurityEventRetention   time.Duration                  `json:"security_event_retention"`
	AdvancedCacheConfig      interfaces.AdvancedCacheConfig `json:"advanced_cache_config"`
}

// DefaultAdvancedServiceConfig returns default configuration for advanced reporting
func DefaultAdvancedServiceConfig() AdvancedServiceConfig {
	return AdvancedServiceConfig{
		ServiceConfig:            DefaultServiceConfig(),
		EnableAuditIntegration:   true,
		EnableRBACValidation:     true,
		EnableCrossSystemMetrics: true,
		MaxTenantsPerReport:      50,
		ComplianceFrameworks:     []string{"CIS", "HIPAA", "PCI-DSS"},
		SecurityEventRetention:   90 * 24 * time.Hour, // 90 days
		AdvancedCacheConfig:      interfaces.DefaultAdvancedCacheConfig(),
	}
}

// NewAdvancedService creates a new advanced reports service
func NewAdvancedService(
	storageManager *storage.Manager,
	driftDetector drift.Detector,
	auditManager *audit.Manager,
	auditStore business.AuditStore,
	rbacManager *rbac.Manager,
	cache interfaces.ReportCache,
	logger logging.Logger,
) *AdvancedService {
	// Create base service for backward compatibility
	baseService := NewService(storageManager, driftDetector, cache, logger)

	// Create advanced data provider
	advancedProvider := provider.NewAdvancedProvider(
		storageManager, driftDetector, auditManager, auditStore, logger,
	)

	// Create template processor
	templateProcessor := templates.New(logger)

	// Create exporter
	exporter := exporters.New(logger)

	// Create advanced engine
	advancedEngine := engine.NewAdvancedEngine(
		advancedProvider, templateProcessor, exporter, cache, rbacManager, logger,
	)

	return &AdvancedService{
		Service:          baseService,
		advancedEngine:   advancedEngine,
		advancedProvider: advancedProvider,
		rbacManager:      rbacManager,
		auditManager:     auditManager,
		logger:           logger,
		config:           DefaultAdvancedServiceConfig(),
	}
}

// NewAdvancedServiceWithConfig creates a new advanced reports service with custom configuration
func NewAdvancedServiceWithConfig(
	storageManager *storage.Manager,
	driftDetector drift.Detector,
	auditManager *audit.Manager,
	auditStore business.AuditStore,
	rbacManager *rbac.Manager,
	cache interfaces.ReportCache,
	config AdvancedServiceConfig,
	logger logging.Logger,
) *AdvancedService {
	// Create base service
	baseService := NewServiceWithConfig(storageManager, driftDetector, cache, config.ServiceConfig, logger)

	// Create advanced data provider
	advancedProvider := provider.NewAdvancedProvider(
		storageManager, driftDetector, auditManager, auditStore, logger,
	)

	// Create template processor
	templateProcessor := templates.New(logger)

	// Create exporter with config
	exporter := exporters.New(logger).WithConfig(config.ExportConfig)

	// Create advanced cache if enabled
	advancedCache := cache
	if config.AdvancedCacheConfig.EnableAdvancedCaching {
		advancedCache = reportcache.NewAdvancedCache(cache, config.AdvancedCacheConfig, logger)
	}

	// Create advanced engine with config
	engineConfig := engine.AdvancedConfig{
		Config:                   engine.DefaultConfig(),
		EnableAuditIntegration:   config.EnableAuditIntegration,
		EnableRBACValidation:     config.EnableRBACValidation,
		EnableCrossSystemMetrics: config.EnableCrossSystemMetrics,
		MaxTenantsPerReport:      config.MaxTenantsPerReport,
		ComplianceFrameworks:     config.ComplianceFrameworks,
		SecurityEventRetention:   config.SecurityEventRetention,
	}

	advancedEngine := engine.NewAdvancedEngine(
		advancedProvider, templateProcessor, exporter, advancedCache, rbacManager, logger,
	).WithAdvancedConfig(engineConfig)

	return &AdvancedService{
		Service:          baseService,
		advancedEngine:   advancedEngine,
		advancedProvider: advancedProvider,
		rbacManager:      rbacManager,
		auditManager:     auditManager,
		logger:           logger,
		config:           config,
	}
}

// RBAC and Tenant Isolation Helper Methods

// getUserIDFromContext extracts user ID from context for RBAC validation
func (s *AdvancedService) getUserIDFromContext(ctx context.Context) string {
	if userID, ok := ctx.Value(ctxkeys.UserIDKey).(string); ok && userID != "" {
		return userID
	}

	if claims, ok := ctx.Value(ctxkeys.AuthClaimsKey).(map[string]interface{}); ok {
		if sub, ok := claims["sub"].(string); ok {
			return sub
		}
	}

	// For testing/development - extract from tenant context
	if tenantID, ok := ctx.Value(ctxkeys.TenantID).(string); ok {
		return "system-user-" + tenantID
	}

	// Default fallback for system operations
	return "system-user"
}

// validateTenantAccess validates user access to specific tenants with detailed logging
func (s *AdvancedService) validateTenantAccess(ctx context.Context, tenantIDs []string, operation string) error {
	if !s.config.EnableRBACValidation || s.rbacManager == nil {
		s.logger.Debug("RBAC validation disabled or manager not available",
			"operation", operation,
			"tenant_count", len(tenantIDs))
		return nil
	}

	userID := s.getUserIDFromContext(ctx)
	s.logger.Debug("validating tenant access",
		"user_id", userID,
		"operation", operation,
		"tenant_ids", tenantIDs,
		"tenant_count", len(tenantIDs))

	// Validate access for each tenant
	if err := s.advancedEngine.ValidateMultiTenantAccess(ctx, userID, tenantIDs); err != nil {
		s.logger.Warn("tenant access validation failed",
			"user_id", userID,
			"operation", operation,
			"tenant_ids", tenantIDs,
			"error", err)
		return fmt.Errorf("access denied for %s: %w", operation, err)
	}

	s.logger.Debug("tenant access validation successful",
		"user_id", userID,
		"operation", operation,
		"tenant_count", len(tenantIDs))
	return nil
}

// validateSingleTenantAccess validates access to a single tenant
func (s *AdvancedService) validateSingleTenantAccess(ctx context.Context, tenantID string, operation string) error {
	return s.validateTenantAccess(ctx, []string{tenantID}, operation)
}

// extractTenantsFromRequest extracts tenant IDs from various request types for validation
func (s *AdvancedService) extractTenantsFromRequest(req interface{}) []string {
	switch r := req.(type) {
	case interfaces.ComplianceReportRequest:
		return r.TenantIDs
	case interfaces.SecurityReportRequest:
		return r.TenantIDs
	case interfaces.ExecutiveReportRequest:
		return r.TenantIDs
	case interfaces.MultiTenantReportRequest:
		return r.TenantIDs
	case interfaces.AdvancedReportRequest:
		// Extract from Parameters if present
		if tenantIDs, ok := r.Parameters["tenant_ids"].([]string); ok {
			return tenantIDs
		}
		// Fallback to single tenant if specified in parameters
		if tenantID, ok := r.Parameters["tenant_id"].(string); ok {
			return []string{tenantID}
		}
	}
	return []string{}
}

// extractTenantIDsFromQuery extracts tenant IDs from various query types for validation
func (s *AdvancedService) extractTenantIDsFromQuery(query interface{}) []string {
	// Use reflection-like approach to extract tenant IDs from query objects
	// This is a generic approach since query types may have different field names
	switch q := query.(type) {
	case interfaces.DataQuery:
		return q.TenantIDs
	default:
		// For unknown query types, check if they have a TenantIDs field using type assertion
		// This is safe and will return empty slice if field doesn't exist
		if hasField, ok := query.(interface{ GetTenantIDs() []string }); ok {
			return hasField.GetTenantIDs()
		}
		// Fallback to single tenant if available
		if hasField, ok := query.(interface{ GetTenantID() string }); ok {
			if tenantID := hasField.GetTenantID(); tenantID != "" {
				return []string{tenantID}
			}
		}
	}
	return []string{}
}

// Advanced Report Generation Methods

// GenerateAdvancedReport generates an advanced report with audit integration
func (s *AdvancedService) GenerateAdvancedReport(ctx context.Context, req interfaces.AdvancedReportRequest) (*interfaces.AdvancedReport, error) {
	// Validate tenant access
	tenantIDs := s.extractTenantsFromRequest(req)
	if len(tenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, tenantIDs, "generate_advanced_report"); err != nil {
			return nil, err
		}
	}

	return s.advancedEngine.GenerateAdvancedReport(ctx, req)
}

// GenerateComplianceReport generates a comprehensive compliance report
func (s *AdvancedService) GenerateComplianceReport(ctx context.Context, req interfaces.ComplianceReportRequest) (*interfaces.ComplianceReport, error) {
	// Validate tenant access
	if len(req.TenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, req.TenantIDs, "generate_compliance_report"); err != nil {
			return nil, err
		}
	}

	return s.advancedEngine.GenerateComplianceReport(ctx, req)
}

// GenerateSecurityReport generates a comprehensive security report
func (s *AdvancedService) GenerateSecurityReport(ctx context.Context, req interfaces.SecurityReportRequest) (*interfaces.SecurityReport, error) {
	// Validate tenant access
	if len(req.TenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, req.TenantIDs, "generate_security_report"); err != nil {
			return nil, err
		}
	}

	return s.advancedEngine.GenerateSecurityReport(ctx, req)
}

// GenerateExecutiveReport generates an executive-level summary report
func (s *AdvancedService) GenerateExecutiveReport(ctx context.Context, req interfaces.ExecutiveReportRequest) (*interfaces.ExecutiveReport, error) {
	// Validate tenant access
	if len(req.TenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, req.TenantIDs, "generate_executive_report"); err != nil {
			return nil, err
		}
	}

	return s.advancedEngine.GenerateExecutiveReport(ctx, req)
}

// GenerateMultiTenantReport generates a multi-tenant analysis report
func (s *AdvancedService) GenerateMultiTenantReport(ctx context.Context, req interfaces.MultiTenantReportRequest) (*interfaces.MultiTenantReport, error) {
	// Validate tenant access - this is critical for multi-tenant reports
	if len(req.TenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, req.TenantIDs, "generate_multi_tenant_report"); err != nil {
			return nil, err
		}
	}

	return s.advancedEngine.GenerateMultiTenantReport(ctx, req)
}

// Convenience Methods for Advanced Reporting

// GenerateComplianceAssessment is a convenience method for generating compliance assessments
func (s *AdvancedService) GenerateComplianceAssessment(
	ctx context.Context,
	tenantIDs []string,
	frameworks []string,
	timeRange interfaces.TimeRange,
	format interfaces.ExportFormat,
) ([]byte, error) {
	req := interfaces.ComplianceReportRequest{
		TimeRange:         timeRange,
		TenantIDs:         tenantIDs,
		Frameworks:        frameworks,
		IncludeBaselines:  true,
		IncludeExceptions: false,
		Format:            format,
		DetailLevel:       "detailed",
	}

	report, err := s.GenerateComplianceReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance assessment: %w", err)
	}

	// Convert report to the requested format
	return s.exportAdvancedReport(ctx, report, format)
}

// GenerateSecurityAnalysis is a convenience method for generating security analysis
func (s *AdvancedService) GenerateSecurityAnalysis(
	ctx context.Context,
	tenantIDs []string,
	timeRange interfaces.TimeRange,
	analysisType string,
	format interfaces.ExportFormat,
) ([]byte, error) {
	req := interfaces.SecurityReportRequest{
		TimeRange:       timeRange,
		TenantIDs:       tenantIDs,
		IncludeResolved: false,
		Format:          format,
		AnalysisType:    analysisType,
	}

	report, err := s.GenerateSecurityReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate security analysis: %w", err)
	}

	// Convert report to the requested format
	return s.exportAdvancedReport(ctx, report, format)
}

// GenerateExecutiveDashboard is a convenience method for generating executive dashboards
func (s *AdvancedService) GenerateExecutiveDashboard(
	ctx context.Context,
	tenantIDs []string,
	timeRange interfaces.TimeRange,
	audience string,
	format interfaces.ExportFormat,
) ([]byte, error) {
	req := interfaces.ExecutiveReportRequest{
		TimeRange:     timeRange,
		TenantIDs:     tenantIDs,
		KPIs:          []string{"compliance", "security", "availability", "drift"},
		IncludeCharts: format == interfaces.FormatHTML || format == interfaces.FormatJSON,
		IncludeTrends: true,
		Format:        format,
		Audience:      audience,
	}

	report, err := s.GenerateExecutiveReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate executive dashboard: %w", err)
	}

	// Convert report to the requested format
	return s.exportAdvancedReport(ctx, report, format)
}

// Multi-Tenant Analytics Methods

// GetTenantSummary returns comprehensive summary for a single tenant
func (s *AdvancedService) GetTenantSummary(ctx context.Context, tenantID string, timeRange interfaces.TimeRange) (*interfaces.TenantSummary, error) {
	// Validate single tenant access
	if err := s.validateSingleTenantAccess(ctx, tenantID, "get_tenant_summary"); err != nil {
		return nil, err
	}

	return s.advancedProvider.GetTenantSummary(ctx, tenantID, timeRange)
}

// GetMultiTenantAggregation returns aggregated metrics across multiple tenants
func (s *AdvancedService) GetMultiTenantAggregation(ctx context.Context, tenantIDs []string, timeRange interfaces.TimeRange) (*interfaces.MultiTenantAggregation, error) {
	// Validate tenant access - critical for multi-tenant aggregation
	if err := s.validateTenantAccess(ctx, tenantIDs, "get_multi_tenant_aggregation"); err != nil {
		return nil, err
	}

	return s.advancedProvider.GetMultiTenantAggregation(ctx, tenantIDs, timeRange)
}

// Data Access Methods

// GetComplianceData retrieves compliance assessment data
func (s *AdvancedService) GetComplianceData(ctx context.Context, query interfaces.ComplianceDataQuery) (*interfaces.ComplianceData, error) {
	// Validate tenant access if query contains tenant IDs
	if tenantIDs := s.extractTenantIDsFromQuery(query); len(tenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, tenantIDs, "get_compliance_data"); err != nil {
			return nil, err
		}
	}

	return s.advancedProvider.GetComplianceData(ctx, query)
}

// GetSecurityEvents retrieves security-related events
func (s *AdvancedService) GetSecurityEvents(ctx context.Context, query interfaces.SecurityEventQuery) ([]interfaces.SecurityEvent, error) {
	// Validate tenant access if query contains tenant IDs
	if tenantIDs := s.extractTenantIDsFromQuery(query); len(tenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, tenantIDs, "get_security_events"); err != nil {
			return nil, err
		}
	}

	return s.advancedProvider.GetSecurityEvents(ctx, query)
}

// GetUserActivity retrieves user activity summaries
func (s *AdvancedService) GetUserActivity(ctx context.Context, query interfaces.UserActivityQuery) ([]interfaces.UserActivity, error) {
	// Validate tenant access if query contains tenant IDs
	if tenantIDs := s.extractTenantIDsFromQuery(query); len(tenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, tenantIDs, "get_user_activity"); err != nil {
			return nil, err
		}
	}

	return s.advancedProvider.GetUserActivity(ctx, query)
}

// GetCrossSystemMetrics generates metrics that correlate DNA and audit data
func (s *AdvancedService) GetCrossSystemMetrics(ctx context.Context, query interfaces.CrossSystemQuery) (*interfaces.CrossSystemMetrics, error) {
	// Validate tenant access if query contains tenant IDs
	if tenantIDs := s.extractTenantIDsFromQuery(query); len(tenantIDs) > 0 {
		if err := s.validateTenantAccess(ctx, tenantIDs, "get_cross_system_metrics"); err != nil {
			return nil, err
		}
	}

	return s.advancedProvider.GetCrossSystemMetrics(ctx, query)
}

// Template and Configuration Methods

// GetAdvancedTemplates returns information about available advanced report templates
func (s *AdvancedService) GetAdvancedTemplates() []interfaces.AdvancedTemplateInfo {
	return s.advancedEngine.GetAdvancedTemplates()
}

// ValidateAdvancedTemplate validates an advanced template
func (s *AdvancedService) ValidateAdvancedTemplate(template string, reportType interfaces.AdvancedReportType) error {
	return s.advancedEngine.ValidateAdvancedTemplate(template, reportType)
}

// GetConfiguration returns the current service configuration
func (s *AdvancedService) GetConfiguration() AdvancedServiceConfig {
	return s.config
}

// UpdateConfiguration updates the service configuration
func (s *AdvancedService) UpdateConfiguration(config AdvancedServiceConfig) {
	s.config = config

	// Update engine configuration
	engineConfig := engine.AdvancedConfig{
		EnableAuditIntegration:   config.EnableAuditIntegration,
		EnableRBACValidation:     config.EnableRBACValidation,
		EnableCrossSystemMetrics: config.EnableCrossSystemMetrics,
		MaxTenantsPerReport:      config.MaxTenantsPerReport,
		ComplianceFrameworks:     config.ComplianceFrameworks,
		SecurityEventRetention:   config.SecurityEventRetention,
	}

	if advancedEngine, ok := s.advancedEngine.(*engine.AdvancedEngine); ok {
		advancedEngine.WithAdvancedConfig(engineConfig)
	}

	s.logger.Info("updated advanced service configuration",
		"audit_integration", config.EnableAuditIntegration,
		"rbac_validation", config.EnableRBACValidation,
		"max_tenants", config.MaxTenantsPerReport)
}

// Health and Monitoring Methods

// Health returns the health status of the advanced reports service
func (s *AdvancedService) Health(ctx context.Context) map[string]interface{} {
	health := s.Service.Health(ctx)

	// Add advanced service health information
	health["advanced_features"] = map[string]interface{}{
		"audit_integration":      s.config.EnableAuditIntegration,
		"rbac_validation":        s.config.EnableRBACValidation,
		"cross_system_metrics":   s.config.EnableCrossSystemMetrics,
		"compliance_frameworks":  len(s.config.ComplianceFrameworks),
		"max_tenants_per_report": s.config.MaxTenantsPerReport,
	}

	// Test advanced functionality
	advancedTemplates := s.GetAdvancedTemplates()
	health["advanced_templates_available"] = len(advancedTemplates)

	// Test RBAC connectivity
	if s.config.EnableRBACValidation && s.rbacManager != nil {
		health["rbac_status"] = "connected"
	} else {
		health["rbac_status"] = "disabled"
	}

	// Test audit connectivity
	if s.config.EnableAuditIntegration && s.auditManager != nil {
		health["audit_status"] = "connected"
	} else {
		health["audit_status"] = "disabled"
	}

	return health
}

// GetMetrics returns advanced reporting metrics
func (s *AdvancedService) GetMetrics(ctx context.Context) map[string]interface{} {
	metrics := map[string]interface{}{
		"service_type": "advanced_reporting",
		"features": map[string]bool{
			"audit_integration":    s.config.EnableAuditIntegration,
			"rbac_validation":      s.config.EnableRBACValidation,
			"cross_system_metrics": s.config.EnableCrossSystemMetrics,
		},
		"configuration": map[string]interface{}{
			"max_tenants_per_report":   s.config.MaxTenantsPerReport,
			"compliance_frameworks":    len(s.config.ComplianceFrameworks),
			"security_event_retention": s.config.SecurityEventRetention.String(),
			"advanced_caching_enabled": s.config.AdvancedCacheConfig.EnableAdvancedCaching,
		},
	}

	// Add cache metrics if enabled
	if s.config.AdvancedCacheConfig.CacheMetricsEnabled {
		metrics["cache"] = map[string]interface{}{
			"compliance_report_ttl":   s.config.AdvancedCacheConfig.ComplianceReportTTL.String(),
			"security_report_ttl":     s.config.AdvancedCacheConfig.SecurityReportTTL.String(),
			"executive_report_ttl":    s.config.AdvancedCacheConfig.ExecutiveReportTTL.String(),
			"multi_tenant_report_ttl": s.config.AdvancedCacheConfig.MultiTenantReportTTL.String(),
		}
	}

	return metrics
}

// Close performs cleanup when the service is shutting down
func (s *AdvancedService) Close() error {
	s.logger.Info("advanced reports service shutting down")

	// Close base service
	if err := s.Service.Close(); err != nil {
		s.logger.Warn("error closing base service", "error", err)
	}

	return nil
}

// Helper Methods

// exportAdvancedReport converts an advanced report to the requested format.
func (s *AdvancedService) exportAdvancedReport(_ context.Context, report interface{}, format interfaces.ExportFormat) ([]byte, error) {
	switch format {
	case interfaces.FormatJSON:
		data, err := json.Marshal(report)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize report to JSON: %w", err)
		}
		return data, nil
	case interfaces.FormatHTML:
		return renderAdvancedReportHTML(report)
	case interfaces.FormatPDF:
		return renderAdvancedReportPDF(report)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// advancedReportHTMLData holds values interpolated into the HTML export template.
type advancedReportHTMLData struct {
	ReportID    string
	GeneratedAt string
	JSONContent string // full report as indented JSON; html/template escapes it
}

// advancedHTMLTmpl is the html/template used for advanced report HTML export.
// html/template (not text/template) is required to prevent XSS in report content.
var advancedHTMLTmpl = htmltemplate.Must(htmltemplate.New("advanced-report").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CFGMS Report {{.ReportID}}</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:2em;color:#333}
h1{color:#007acc}pre{background:#f4f4f4;padding:1em;border-radius:4px;overflow:auto}
</style>
</head>
<body>
<h1>CFGMS Advanced Report</h1>
<p><strong>Report ID:</strong> {{.ReportID}}</p>
<p><strong>Generated At:</strong> {{.GeneratedAt}}</p>
<h2>Report Data</h2>
<pre>{{.JSONContent}}</pre>
</body>
</html>`))

// renderAdvancedReportHTML serialises report to a full HTML document.
func renderAdvancedReportHTML(report interface{}) ([]byte, error) {
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize report for HTML export: %w", err)
	}

	data := advancedReportHTMLData{
		ReportID:    extractAdvancedReportID(report),
		GeneratedAt: extractAdvancedReportGeneratedAt(report),
		JSONContent: string(raw),
	}

	var buf bytes.Buffer
	if err := advancedHTMLTmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to render HTML template: %w", err)
	}
	return buf.Bytes(), nil
}

// renderAdvancedReportPDF generates a minimal valid PDF-1.4 document with report content.
// Uses pure stdlib byte-stream construction — the PDF-1.4 text-object format is sufficient
// for single-page text summaries without requiring an external PDF library.
func renderAdvancedReportPDF(report interface{}) ([]byte, error) {
	id := extractAdvancedReportID(report)
	ts := extractAdvancedReportGeneratedAt(report)

	title := "CFGMS Advanced Report"
	body := "Report ID: " + id + "\nGenerated: " + ts

	stream := buildPDFContentStream(title, body)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")

	// Track byte offset of each object (1-indexed; index 0 unused).
	var offsets [5]int

	offsets[1] = buf.Len()
	fmt.Fprintf(&buf, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	offsets[2] = buf.Len()
	fmt.Fprintf(&buf, "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	offsets[3] = buf.Len()
	fmt.Fprintf(&buf, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"+
		" /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1"+
		" /BaseFont /Helvetica >> >> >> >>\nendobj\n")

	offsets[4] = buf.Len()
	fmt.Fprintf(&buf, "4 0 obj\n<< /Length %d >>\nstream\n%sendstream\nendobj\n",
		len(stream), stream)

	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 5\n")
	// Each xref entry must be exactly 20 bytes: 10-digit-offset SP 5-digit-gen SP n|f CR LF
	fmt.Fprintf(&buf, "0000000000 65535 f\r\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n\r\n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n", xrefOffset)
	buf.WriteString("%%EOF\n")

	return buf.Bytes(), nil
}

// buildPDFContentStream builds a BT…ET text block for a single PDF page.
func buildPDFContentStream(title, body string) string {
	var b strings.Builder
	b.WriteString("BT\n")
	fmt.Fprintf(&b, "/F1 14 Tf\n50 730 Td\n(%s) Tj\n", pdfEscapeString(title))
	fmt.Fprintf(&b, "/F1 10 Tf\n0 -25 Td\n(%s) Tj\n", pdfEscapeString(body))
	b.WriteString("ET\n")
	return b.String()
}

// pdfEscapeString escapes characters that are special inside PDF literal strings.
func pdfEscapeString(s string) string {
	var b strings.Builder
	for _, ch := range s {
		switch ch {
		case '\\':
			b.WriteString("\\\\")
		case '(':
			b.WriteString("\\(")
		case ')':
			b.WriteString("\\)")
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			if ch > 126 {
				b.WriteByte(' ') // Type1 fonts only cover printable ASCII
			} else {
				b.WriteRune(ch)
			}
		}
	}
	return b.String()
}

// extractAdvancedReportID returns the ID field from any known advanced report type.
func extractAdvancedReportID(report interface{}) string {
	switch r := report.(type) {
	case *interfaces.ComplianceReport:
		return r.ID
	case *interfaces.SecurityReport:
		return r.ID
	case *interfaces.ExecutiveReport:
		return r.ID
	case *interfaces.MultiTenantReport:
		return r.ID
	case *interfaces.AdvancedReport:
		return r.ID
	}
	return "unknown"
}

// extractAdvancedReportGeneratedAt returns the GeneratedAt timestamp from any known advanced report type.
func extractAdvancedReportGeneratedAt(report interface{}) string {
	switch r := report.(type) {
	case *interfaces.ComplianceReport:
		return r.GeneratedAt.Format(time.RFC3339)
	case *interfaces.SecurityReport:
		return r.GeneratedAt.Format(time.RFC3339)
	case *interfaces.ExecutiveReport:
		return r.GeneratedAt.Format(time.RFC3339)
	case *interfaces.MultiTenantReport:
		return r.GeneratedAt.Format(time.RFC3339)
	case *interfaces.AdvancedReport:
		return r.GeneratedAt.Format(time.RFC3339)
	}
	return time.Now().Format(time.RFC3339)
}
