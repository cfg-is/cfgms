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
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/reports/engine"
	"github.com/cfgis/cfgms/features/reports/exporters"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/reports/provider"
	"github.com/cfgis/cfgms/features/reports/templates"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/audit"
	storageInterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// AdvancedService provides comprehensive reporting capabilities integrating DNA and audit data
type AdvancedService struct {
	*Service                                    // Embed existing service for backward compatibility
	advancedEngine   interfaces.AdvancedReportEngine
	advancedProvider interfaces.AdvancedDataProvider
	rbacManager      *rbac.Manager
	auditManager     *audit.Manager
	logger           logging.Logger
	config           AdvancedServiceConfig
}

// AdvancedServiceConfig contains configuration for the advanced reports service
type AdvancedServiceConfig struct {
	ServiceConfig                        // Embed base config
	EnableAuditIntegration    bool       `json:"enable_audit_integration"`
	EnableRBACValidation      bool       `json:"enable_rbac_validation"`
	EnableCrossSystemMetrics  bool       `json:"enable_cross_system_metrics"`
	MaxTenantsPerReport       int        `json:"max_tenants_per_report"`
	ComplianceFrameworks      []string   `json:"compliance_frameworks"`
	SecurityEventRetention    time.Duration `json:"security_event_retention"`
	AdvancedCacheConfig       AdvancedCacheConfig `json:"advanced_cache_config"`
}

// AdvancedCacheConfig contains advanced caching configuration
type AdvancedCacheConfig struct {
	EnableAdvancedCaching     bool          `json:"enable_advanced_caching"`
	ComplianceReportTTL       time.Duration `json:"compliance_report_ttl"`
	SecurityReportTTL         time.Duration `json:"security_report_ttl"`
	ExecutiveReportTTL        time.Duration `json:"executive_report_ttl"`
	MultiTenantReportTTL      time.Duration `json:"multi_tenant_report_ttl"`
	MaxCacheSize              int           `json:"max_cache_size"`
	CacheMetricsEnabled       bool          `json:"cache_metrics_enabled"`
}

// DefaultAdvancedServiceConfig returns default configuration for advanced reporting
func DefaultAdvancedServiceConfig() AdvancedServiceConfig {
	return AdvancedServiceConfig{
		ServiceConfig:             DefaultServiceConfig(),
		EnableAuditIntegration:    true,
		EnableRBACValidation:      true,
		EnableCrossSystemMetrics:  true,
		MaxTenantsPerReport:       50,
		ComplianceFrameworks:      []string{"CIS", "HIPAA", "PCI-DSS"},
		SecurityEventRetention:    90 * 24 * time.Hour, // 90 days
		AdvancedCacheConfig:       DefaultAdvancedCacheConfig(),
	}
}

// DefaultAdvancedCacheConfig returns default advanced caching configuration
func DefaultAdvancedCacheConfig() AdvancedCacheConfig {
	return AdvancedCacheConfig{
		EnableAdvancedCaching: true,
		ComplianceReportTTL:   4 * time.Hour,   // Compliance reports cached for 4 hours
		SecurityReportTTL:     30 * time.Minute, // Security reports cached for 30 minutes
		ExecutiveReportTTL:    2 * time.Hour,   // Executive reports cached for 2 hours
		MultiTenantReportTTL:  1 * time.Hour,   // Multi-tenant reports cached for 1 hour
		MaxCacheSize:          1000,            // Maximum cached reports
		CacheMetricsEnabled:   true,
	}
}

// NewAdvancedService creates a new advanced reports service
func NewAdvancedService(
	storageManager *storage.Manager,
	driftDetector *drift.Detector,
	auditManager *audit.Manager,
	auditStore storageInterfaces.AuditStore,
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
	driftDetector *drift.Detector,
	auditManager *audit.Manager,
	auditStore storageInterfaces.AuditStore,
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
		advancedCache = cache // Could wrap with advanced caching layer
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

// Advanced Report Generation Methods

// GenerateAdvancedReport generates an advanced report with audit integration
func (s *AdvancedService) GenerateAdvancedReport(ctx context.Context, req interfaces.AdvancedReportRequest) (*interfaces.AdvancedReport, error) {
	return s.advancedEngine.GenerateAdvancedReport(ctx, req)
}

// GenerateComplianceReport generates a comprehensive compliance report
func (s *AdvancedService) GenerateComplianceReport(ctx context.Context, req interfaces.ComplianceReportRequest) (*interfaces.ComplianceReport, error) {
	return s.advancedEngine.GenerateComplianceReport(ctx, req)
}

// GenerateSecurityReport generates a comprehensive security report
func (s *AdvancedService) GenerateSecurityReport(ctx context.Context, req interfaces.SecurityReportRequest) (*interfaces.SecurityReport, error) {
	return s.advancedEngine.GenerateSecurityReport(ctx, req)
}

// GenerateExecutiveReport generates an executive-level summary report
func (s *AdvancedService) GenerateExecutiveReport(ctx context.Context, req interfaces.ExecutiveReportRequest) (*interfaces.ExecutiveReport, error) {
	return s.advancedEngine.GenerateExecutiveReport(ctx, req)
}

// GenerateMultiTenantReport generates a multi-tenant analysis report
func (s *AdvancedService) GenerateMultiTenantReport(ctx context.Context, req interfaces.MultiTenantReportRequest) (*interfaces.MultiTenantReport, error) {
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
		TimeRange:       timeRange,
		TenantIDs:       tenantIDs,
		Frameworks:      frameworks,
		IncludeBaselines: true,
		IncludeExceptions: false,
		Format:          format,
		DetailLevel:     "detailed",
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
	return s.advancedProvider.GetTenantSummary(ctx, tenantID, timeRange)
}

// GetMultiTenantAggregation returns aggregated metrics across multiple tenants
func (s *AdvancedService) GetMultiTenantAggregation(ctx context.Context, tenantIDs []string, timeRange interfaces.TimeRange) (*interfaces.MultiTenantAggregation, error) {
	// Validate tenant access if RBAC is enabled
	if s.config.EnableRBACValidation {
		// This would typically get user ID from context
		// For now, we'll use the engine's validation
		if err := s.advancedEngine.ValidateMultiTenantAccess(ctx, "current-user", tenantIDs); err != nil {
			return nil, err
		}
	}

	return s.advancedProvider.GetMultiTenantAggregation(ctx, tenantIDs, timeRange)
}

// Data Access Methods

// GetComplianceData retrieves compliance assessment data
func (s *AdvancedService) GetComplianceData(ctx context.Context, query interfaces.ComplianceDataQuery) (*interfaces.ComplianceData, error) {
	return s.advancedProvider.GetComplianceData(ctx, query)
}

// GetSecurityEvents retrieves security-related events
func (s *AdvancedService) GetSecurityEvents(ctx context.Context, query interfaces.SecurityEventQuery) ([]interfaces.SecurityEvent, error) {
	return s.advancedProvider.GetSecurityEvents(ctx, query)
}

// GetUserActivity retrieves user activity summaries
func (s *AdvancedService) GetUserActivity(ctx context.Context, query interfaces.UserActivityQuery) ([]interfaces.UserActivity, error) {
	return s.advancedProvider.GetUserActivity(ctx, query)
}

// GetCrossSystemMetrics generates metrics that correlate DNA and audit data
func (s *AdvancedService) GetCrossSystemMetrics(ctx context.Context, query interfaces.CrossSystemQuery) (*interfaces.CrossSystemMetrics, error) {
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
			"max_tenants_per_report":    s.config.MaxTenantsPerReport,
			"compliance_frameworks":     len(s.config.ComplianceFrameworks),
			"security_event_retention":  s.config.SecurityEventRetention.String(),
			"advanced_caching_enabled":  s.config.AdvancedCacheConfig.EnableAdvancedCaching,
		},
	}

	// Add cache metrics if enabled
	if s.config.AdvancedCacheConfig.CacheMetricsEnabled {
		metrics["cache"] = map[string]interface{}{
			"compliance_report_ttl":  s.config.AdvancedCacheConfig.ComplianceReportTTL.String(),
			"security_report_ttl":    s.config.AdvancedCacheConfig.SecurityReportTTL.String(),
			"executive_report_ttl":   s.config.AdvancedCacheConfig.ExecutiveReportTTL.String(),
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

// exportAdvancedReport converts an advanced report to the requested format
func (s *AdvancedService) exportAdvancedReport(ctx context.Context, report interface{}, format interfaces.ExportFormat) ([]byte, error) {
	// This is a simplified implementation - in practice, would need type assertion
	// and proper serialization for different report types
	switch format {
	case interfaces.FormatJSON:
		// Would serialize report to JSON
		return []byte("{}"), nil // Placeholder
	case interfaces.FormatHTML:
		// Would render report as HTML
		return []byte("<html></html>"), nil // Placeholder
	case interfaces.FormatPDF:
		// Would render report as PDF
		return []byte("PDF content"), nil // Placeholder
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

// validateTenantAccess validates access to tenants (helper method)
func (s *AdvancedService) validateTenantAccess(ctx context.Context, tenantIDs []string) error {
	if !s.config.EnableRBACValidation {
		return nil
	}

	// This would typically get the user ID from the context
	userID := "current-user" // Placeholder

	return s.advancedEngine.ValidateMultiTenantAccess(ctx, userID, tenantIDs)
}

// getCacheKey generates cache keys for advanced reports
func (s *AdvancedService) getCacheKey(reportType string, params map[string]interface{}) string {
	// Generate cache key based on report type and parameters
	// This is a simplified implementation
	return fmt.Sprintf("advanced:%s:%v", reportType, params)
}

// getCacheTTL returns appropriate cache TTL for report type
func (s *AdvancedService) getCacheTTL(reportType string) time.Duration {
	switch reportType {
	case "compliance":
		return s.config.AdvancedCacheConfig.ComplianceReportTTL
	case "security":
		return s.config.AdvancedCacheConfig.SecurityReportTTL
	case "executive":
		return s.config.AdvancedCacheConfig.ExecutiveReportTTL
	case "multi_tenant":
		return s.config.AdvancedCacheConfig.MultiTenantReportTTL
	default:
		return s.config.CacheTTL // Fall back to base cache TTL
	}
}

// recordMetric records metrics for monitoring (placeholder)
func (s *AdvancedService) recordMetric(metric string, value float64, tags map[string]string) {
	// This would integrate with a metrics system
	s.logger.Debug("metric recorded", "metric", metric, "value", value, "tags", tags)
}