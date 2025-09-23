// Package reports provides comprehensive DNA monitoring and reporting capabilities for CFGMS.
//
// This package implements Story #81: DNA Monitoring - Comprehensive Reporting System.
// It builds upon the existing DNA collection, storage, and drift detection infrastructure
// to provide executive dashboards, compliance reports, and detailed drift analysis.
//
// Key Features:
//   - Template-based report generation for multiple report types
//   - Multi-format export (JSON, CSV, HTML, PDF)
//   - Real-time dashboard APIs for monitoring systems
//   - Comprehensive compliance and drift analysis
//   - Chart data preparation for visualization
//   - Report caching for improved performance
//   - REST API endpoints for external integration
//
// Architecture:
//   - Engine: Core report generation logic with caching
//   - Templates: Built-in templates for compliance, executive, and drift reports
//   - interfaces.Exporters: Multi-format export capabilities
//   - DataProvider: Integration with existing DNA storage and drift detection
//   - API: REST endpoints for dashboard and report access
//
// Usage Example:
//
//	// Create components
//	dataProvider := provider.New(storageManager, driftDetector, logger)
//	templateProcessor := templates.New(logger)
//	exporter := exporters.New(logger)
//	cache := memory.NewCache() // or other cache implementation
//	
//	// Create report engine
//	engine := engine.New(dataProvider, templateProcessor, exporter, cache, logger)
//	
//	// Generate report
//	req := reports.interfaces.ReportRequest{
//		Type:      reports.interfaces.ReportTypeCompliance,
//		Template:  "compliance-summary",
//		interfaces.TimeRange: reports.interfaces.TimeRange{Start: start, End: end},
//		Format:    reports.interfaces.FormatJSON,
//	}
//	
//	report, err := engine.GenerateReport(ctx, req)
//	if err != nil {
//		return fmt.Errorf("failed to generate report: %w", err)
//	}
//
// Integration:
// This package integrates with existing CFGMS components:
//   - features/steward/dna/storage: DNA data storage and querying
//   - features/steward/dna/drift: Drift detection and event management
//   - features/templates: Template processing and rendering
//   - features/controller/api: REST API infrastructure
//
// The reporting system is designed to be:
//   - Performant: Leverages caching and efficient data queries
//   - Extensible: Template-based architecture for custom reports
//   - Scalable: Handles large datasets with pagination and filtering
//   - Secure: Integrates with existing RBAC and tenant isolation
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
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Service provides the main entry point for the reports subsystem
type Service struct {
	engine   interfaces.ReportEngine
	exporter interfaces.Exporter
	logger   logging.Logger
}

// ServiceConfig contains configuration for the reports service
type ServiceConfig struct {
	CacheEnabled     bool          `json:"cache_enabled"`
	CacheTTL         time.Duration `json:"cache_ttl"`
	MaxDevices       int           `json:"max_devices"`
	MaxTimeRange     time.Duration `json:"max_time_range"`
	TimeoutDuration  time.Duration `json:"timeout_duration"`
	ExportConfig     exporters.Config `json:"export_config"`
}

// DefaultServiceConfig returns default configuration for the reports service
func DefaultServiceConfig() ServiceConfig {
	return ServiceConfig{
		CacheEnabled:     true,
		CacheTTL:         time.Hour,
		MaxDevices:       1000,
		MaxTimeRange:     30 * 24 * time.Hour, // 30 days
		TimeoutDuration:  5 * time.Minute,
		ExportConfig:     exporters.DefaultConfig(),
	}
}

// NewService creates a new reports service with the provided dependencies
func NewService(
	storageManager *storage.Manager,
	driftDetector drift.Detector,
	cache interfaces.ReportCache,
	logger logging.Logger,
) *Service {
	// Create data provider
	dataProvider := provider.New(storageManager, driftDetector, logger)
	
	// Create template processor
	templateProcessor := templates.New(logger)
	
	// Create exporter
	exporter := exporters.New(logger)
	
	// Create engine with default config
	reportEngine := engine.New(dataProvider, templateProcessor, exporter, cache, logger)
	
	return &Service{
		engine:   reportEngine,
		exporter: exporter,
		logger:   logger,
	}
}

// NewServiceWithConfig creates a new reports service with custom configuration
func NewServiceWithConfig(
	storageManager *storage.Manager,
	driftDetector drift.Detector,
	cache interfaces.ReportCache,
	config ServiceConfig,
	logger logging.Logger,
) *Service {
	// Create data provider
	dataProvider := provider.New(storageManager, driftDetector, logger)
	
	// Create template processor
	templateProcessor := templates.New(logger)
	
	// Create exporter with config
	exporter := exporters.New(logger).WithConfig(config.ExportConfig)
	
	// Create engine with custom config
	engineConfig := engine.Config{
		CacheEnabled:    config.CacheEnabled,
		CacheTTL:        config.CacheTTL,
		MaxDevices:      config.MaxDevices,
		MaxTimeRange:    config.MaxTimeRange,
		TimeoutDuration: config.TimeoutDuration,
	}
	
	reportEngine := engine.New(dataProvider, templateProcessor, exporter, cache, logger).
		WithConfig(engineConfig)
	
	return &Service{
		engine:   reportEngine,
		exporter: exporter,
		logger:   logger,
	}
}

// GenerateReport generates a report based on the provided request
func (s *Service) GenerateReport(ctx context.Context, req interfaces.ReportRequest) (*interfaces.Report, error) {
	return s.engine.GenerateReport(ctx, req)
}

// GenerateAndExport generates a report and exports it in the specified format
func (s *Service) GenerateAndExport(ctx context.Context, req interfaces.ReportRequest) ([]byte, error) {
	// Generate the report
	report, err := s.engine.GenerateReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate report: %w", err)
	}

	// Export in the requested format
	exportData, err := s.exporter.Export(ctx, report, req.Format)
	if err != nil {
		return nil, fmt.Errorf("failed to export report: %w", err)
	}

	return exportData, nil
}

// GetAvailableTemplates returns information about available report templates
func (s *Service) GetAvailableTemplates() []interfaces.TemplateInfo {
	return s.engine.GetAvailableTemplates()
}

// ValidateRequest validates a report request
func (s *Service) ValidateRequest(req interfaces.ReportRequest) error {
	return s.engine.ValidateRequest(req)
}

// GetSupportedFormats returns the export formats supported by the service
func (s *Service) GetSupportedFormats() []interfaces.ExportFormat {
	return s.exporter.SupportedFormats()
}

// GenerateComplianceReport is a convenience method for generating compliance reports
func (s *Service) GenerateComplianceReport(ctx context.Context, timeRange interfaces.TimeRange, deviceIDs []string, format interfaces.ExportFormat) ([]byte, error) {
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeCompliance,
		Template:  "compliance-summary",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		Format:    format,
		Title:     "Compliance Summary Report",
		Parameters: map[string]any{
			"include_details": true,
		},
	}

	return s.GenerateAndExport(ctx, req)
}

// GenerateExecutiveDashboard is a convenience method for generating executive dashboards
func (s *Service) GenerateExecutiveDashboard(ctx context.Context, timeRange interfaces.TimeRange, format interfaces.ExportFormat) ([]byte, error) {
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeExecutive,
		Template:  "executive-dashboard",
		TimeRange: timeRange,
		Format:    format,
		Title:     "Executive Dashboard",
		Subtitle:  "Configuration Management Overview",
		Parameters: map[string]any{
			"include_charts": format == interfaces.FormatHTML || format == interfaces.FormatJSON,
		},
	}

	return s.GenerateAndExport(ctx, req)
}

// GenerateDriftAnalysis is a convenience method for generating drift analysis reports
func (s *Service) GenerateDriftAnalysis(ctx context.Context, timeRange interfaces.TimeRange, deviceIDs []string, format interfaces.ExportFormat) ([]byte, error) {
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeDrift,
		Template:  "drift-analysis",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		Format:    format,
		Title:     "Configuration Drift Analysis",
		Parameters: map[string]any{
			"group_by_device": len(deviceIDs) > 1,
		},
	}

	return s.GenerateAndExport(ctx, req)
}

// GetComplianceStatus returns current compliance status for dashboard APIs
func (s *Service) GetComplianceStatus(ctx context.Context, timeRange interfaces.TimeRange, deviceIDs []string) (*ComplianceStatus, error) {
	// Generate compliance report in JSON format
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeCompliance,
		Template:  "compliance-summary",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		Format:    interfaces.FormatJSON,
		Parameters: map[string]any{
			"include_details": false,
		},
	}

	report, err := s.engine.GenerateReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate compliance status: %w", err)
	}

	// Extract compliance information
	status := &ComplianceStatus{
		Score:            report.Summary.ComplianceScore,
		TrendDirection:   report.Summary.TrendDirection,
		CriticalIssues:   report.Summary.CriticalIssues,
		DevicesAnalyzed:  report.Summary.DevicesAnalyzed,
		TotalDriftEvents: report.Summary.DriftEventsTotal,
		TimeRange:        report.TimeRange,
		GeneratedAt:      report.GeneratedAt,
	}

	// Extract additional details from sections
	for _, section := range report.Sections {
		if section.ID == "compliance-overview" {
			if kpiData, ok := section.Content.(map[string]interface{}); ok {
				if rate, exists := kpiData["compliance_rate"]; exists {
					if r, ok := rate.(float64); ok {
						status.ComplianceRate = r
					}
				}
			}
		}
	}

	return status, nil
}

// GetDriftSummary returns current drift summary for dashboard APIs
func (s *Service) GetDriftSummary(ctx context.Context, timeRange interfaces.TimeRange, deviceIDs []string) (*DriftSummary, error) {
	// Generate drift report in JSON format
	req := interfaces.ReportRequest{
		Type:      interfaces.ReportTypeDrift,
		Template:  "drift-analysis",
		TimeRange: timeRange,
		DeviceIDs: deviceIDs,
		Format:    interfaces.FormatJSON,
	}

	report, err := s.engine.GenerateReport(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to generate drift summary: %w", err)
	}

	// Extract drift information
	summary := &DriftSummary{
		TotalEvents: report.Summary.DriftEventsTotal,
		TimeRange:   report.TimeRange,
		GeneratedAt: report.GeneratedAt,
		Charts:      report.Charts,
	}

	// Extract event breakdown from sections
	for _, section := range report.Sections {
		if section.ID == "drift-overview" {
			if kpiData, ok := section.Content.(map[string]interface{}); ok {
				if critical, exists := kpiData["critical_events"]; exists {
					if c, ok := critical.(int); ok {
						summary.CriticalEvents = c
					}
				}
				if warning, exists := kpiData["warning_events"]; exists {
					if w, ok := warning.(int); ok {
						summary.WarningEvents = w
					}
				}
				if info, exists := kpiData["info_events"]; exists {
					if i, ok := info.(int); ok {
						summary.InfoEvents = i
					}
				}
			}
		}
	}

	return summary, nil
}

// ComplianceStatus represents current compliance status for API responses
type ComplianceStatus struct {
	Score            float64        `json:"score"`
	ComplianceRate   float64        `json:"compliance_rate"`
	TrendDirection   interfaces.TrendDirection `json:"trend_direction"`
	CriticalIssues   int            `json:"critical_issues"`
	DevicesAnalyzed  int            `json:"devices_analyzed"`
	TotalDriftEvents int            `json:"total_drift_events"`
	TimeRange        interfaces.TimeRange      `json:"time_range"`
	GeneratedAt      time.Time      `json:"generated_at"`
}

// DriftSummary represents current drift summary for API responses
type DriftSummary struct {
	TotalEvents    int         `json:"total_events"`
	CriticalEvents int         `json:"critical_events"`
	WarningEvents  int         `json:"warning_events"`
	InfoEvents     int         `json:"info_events"`
	TimeRange      interfaces.TimeRange   `json:"time_range"`
	GeneratedAt    time.Time   `json:"generated_at"`
	Charts         []interfaces.ChartData `json:"charts,omitempty"`
}

// Health returns the health status of the reports service
func (s *Service) Health(ctx context.Context) map[string]interface{} {
	health := map[string]interface{}{
		"status": "healthy",
		"components": map[string]interface{}{
			"engine":   "healthy",
			"exporter": "healthy",
		},
	}

	// Test basic functionality
	templates := s.GetAvailableTemplates()
	health["templates_available"] = len(templates)

	formats := s.GetSupportedFormats()
	health["formats_supported"] = formats

	return health
}

// Close performs cleanup when the service is shutting down
func (s *Service) Close() error {
	s.logger.Info("reports service shutting down")
	return nil
}