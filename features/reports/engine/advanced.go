// Package engine implements advanced reporting engine for Story #173.
// This extends the existing DNA-focused engine to include audit data integration
// and comprehensive multi-tenant reporting capabilities.
package engine

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/rbac"
	storageInterfaces "github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/google/uuid"
)

// AdvancedEngine implements AdvancedReportEngine interface
type AdvancedEngine struct {
	*Engine                                    // Embed existing engine
	advancedProvider interfaces.AdvancedDataProvider
	rbacManager      *rbac.Manager            // RBAC integration for access control
	logger           logging.Logger
	config           AdvancedConfig
}

// AdvancedConfig contains configuration for advanced reporting
type AdvancedConfig struct {
	Config                               // Embed base config
	EnableAuditIntegration    bool       `json:"enable_audit_integration"`
	EnableRBACValidation      bool       `json:"enable_rbac_validation"`
	EnableCrossSystemMetrics  bool       `json:"enable_cross_system_metrics"`
	MaxTenantsPerReport       int        `json:"max_tenants_per_report"`
	ComplianceFrameworks      []string   `json:"compliance_frameworks"`
	SecurityEventRetention    time.Duration `json:"security_event_retention"`
}

// DefaultAdvancedConfig returns default configuration for advanced reporting
func DefaultAdvancedConfig() AdvancedConfig {
	return AdvancedConfig{
		Config:                   DefaultConfig(),
		EnableAuditIntegration:   true,
		EnableRBACValidation:     true,
		EnableCrossSystemMetrics: true,
		MaxTenantsPerReport:      50,
		ComplianceFrameworks:     []string{"CIS", "HIPAA", "PCI-DSS"},
		SecurityEventRetention:   90 * 24 * time.Hour, // 90 days
	}
}

// NewAdvancedEngine creates a new advanced reporting engine
func NewAdvancedEngine(
	advancedProvider interfaces.AdvancedDataProvider,
	templateProcessor interfaces.TemplateProcessor,
	exporter interfaces.Exporter,
	cache interfaces.ReportCache,
	rbacManager *rbac.Manager,
	logger logging.Logger,
) *AdvancedEngine {
	// Create base engine
	baseEngine := New(advancedProvider, templateProcessor, exporter, cache, logger)

	return &AdvancedEngine{
		Engine:           baseEngine,
		advancedProvider: advancedProvider,
		rbacManager:      rbacManager,
		logger:           logger,
		config:           DefaultAdvancedConfig(),
	}
}

// WithAdvancedConfig sets advanced configuration
func (e *AdvancedEngine) WithAdvancedConfig(config AdvancedConfig) *AdvancedEngine {
	e.config = config
	e.Engine = e.WithConfig(config.Config) // Update base config
	return e
}

// GenerateAdvancedReport generates an advanced report with audit integration
func (e *AdvancedEngine) GenerateAdvancedReport(ctx context.Context, req interfaces.AdvancedReportRequest) (*interfaces.AdvancedReport, error) {
	startTime := time.Now()

	// Validate request
	if err := e.ValidateAdvancedRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("request validation failed: %w", err)
	}

	// Generate base report
	baseReport, err := e.GenerateReport(ctx, req.ReportRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to generate base report: %w", err)
	}

	// Create advanced report
	advancedReport := &interfaces.AdvancedReport{
		Report: *baseReport,
	}

	// Add audit data if requested
	if req.IncludeAuditData && e.config.EnableAuditIntegration {
		auditData, err := e.getAuditDataForReport(ctx, req)
		if err != nil {
			e.logger.Warn("failed to get audit data", "error", err)
		} else {
			advancedReport.AuditData = auditData
		}
	}

	// Add compliance data if requested
	if req.IncludeCompliance && e.config.EnableAuditIntegration {
		complianceData, err := e.getComplianceDataForReport(ctx, req)
		if err != nil {
			e.logger.Warn("failed to get compliance data", "error", err)
		} else {
			advancedReport.ComplianceData = complianceData
		}
	}

	// Add security events if requested
	if req.IncludeSecurity {
		securityEvents, err := e.getSecurityEventsForReport(ctx, req)
		if err != nil {
			e.logger.Warn("failed to get security events", "error", err)
		} else {
			advancedReport.SecurityEvents = securityEvents
		}
	}

	// Add cross-system metrics if requested
	if req.CorrelationAnalysis && e.config.EnableCrossSystemMetrics {
		crossSystemMetrics, err := e.getCrossSystemMetricsForReport(ctx, req)
		if err != nil {
			e.logger.Warn("failed to get cross-system metrics", "error", err)
		} else {
			advancedReport.CrossSystemMetrics = crossSystemMetrics
		}
	}

	// Add risk assessment if requested
	if req.RiskAssessment {
		riskAssessment, err := e.generateRiskAssessment(ctx, advancedReport)
		if err != nil {
			e.logger.Warn("failed to generate risk assessment", "error", err)
		} else {
			advancedReport.RiskAssessment = riskAssessment
		}
	}

	// Update metadata
	advancedReport.Metadata.GenerationMS = time.Since(startTime).Milliseconds()

	e.logger.Info("generated advanced report",
		"report_id", advancedReport.ID,
		"type", req.Type,
		"generation_time_ms", advancedReport.Metadata.GenerationMS,
		"include_audit", req.IncludeAuditData,
		"include_compliance", req.IncludeCompliance,
		"include_security", req.IncludeSecurity)

	return advancedReport, nil
}

// GenerateComplianceReport generates a comprehensive compliance report
func (e *AdvancedEngine) GenerateComplianceReport(ctx context.Context, req interfaces.ComplianceReportRequest) (*interfaces.ComplianceReport, error) {
	startTime := time.Now()

	// Validate RBAC access
	if e.config.EnableRBACValidation {
		if err := e.validateTenantAccess(ctx, req.TenantIDs); err != nil {
			return nil, fmt.Errorf("access denied: %w", err)
		}
	}

	// Get compliance data for each framework
	complianceDataList := make([]interfaces.ComplianceData, 0, len(req.Frameworks))
	for _, framework := range req.Frameworks {
		query := interfaces.ComplianceDataQuery{
			TimeRange:            req.TimeRange,
			TenantIDs:            req.TenantIDs,
			ComplianceFrameworks: []string{framework},
			IncludeBaselines:     req.IncludeBaselines,
			IncludeExceptions:    req.IncludeExceptions,
		}

		complianceData, err := e.advancedProvider.GetComplianceData(ctx, query)
		if err != nil {
			e.logger.Warn("failed to get compliance data for framework", "framework", framework, "error", err)
			continue
		}
		complianceDataList = append(complianceDataList, *complianceData)
	}

	// Aggregate compliance violations
	violations := make([]interfaces.ComplianceViolation, 0)
	overallScore := 0.0
	for _, data := range complianceDataList {
		violations = append(violations, data.Violations...)
		overallScore += data.Score
	}
	if len(complianceDataList) > 0 {
		overallScore /= float64(len(complianceDataList))
	}

	// Generate recommendations
	recommendations := e.generateComplianceRecommendations(complianceDataList, violations)

	// Generate charts if requested
	var charts []interfaces.ChartData
	if req.Format == interfaces.FormatHTML || req.Format == interfaces.FormatJSON {
		charts = e.generateComplianceCharts(complianceDataList)
	}

	report := &interfaces.ComplianceReport{
		ID:              uuid.New().String(),
		GeneratedAt:     time.Now(),
		TimeRange:       req.TimeRange,
		TenantIDs:       req.TenantIDs,
		Frameworks:      req.Frameworks,
		OverallScore:    overallScore,
		ComplianceData:  complianceDataList,
		Violations:      violations,
		Recommendations: recommendations,
		Charts:          charts,
	}

	e.logger.Info("generated compliance report",
		"report_id", report.ID,
		"frameworks", len(req.Frameworks),
		"tenants", len(req.TenantIDs),
		"overall_score", overallScore,
		"violations", len(violations),
		"generation_time_ms", time.Since(startTime).Milliseconds())

	return report, nil
}

// GenerateSecurityReport generates a comprehensive security report
func (e *AdvancedEngine) GenerateSecurityReport(ctx context.Context, req interfaces.SecurityReportRequest) (*interfaces.SecurityReport, error) {
	startTime := time.Now()

	// Validate RBAC access
	if e.config.EnableRBACValidation {
		if err := e.validateTenantAccess(ctx, req.TenantIDs); err != nil {
			return nil, fmt.Errorf("access denied: %w", err)
		}
	}

	// Get security events
	securityQuery := interfaces.SecurityEventQuery{
		TimeRange:       req.TimeRange,
		TenantIDs:       req.TenantIDs,
		Severities:      req.Severities,
		EventTypes:      req.EventTypes,
		IncludeResolved: req.IncludeResolved,
	}

	securityEvents, err := e.advancedProvider.GetSecurityEvents(ctx, securityQuery)
	if err != nil {
		return nil, fmt.Errorf("failed to get security events: %w", err)
	}

	// Get user activities if analyzing user behavior
	var userActivities []interfaces.UserActivity
	if req.AnalysisType == "user_behavior" || req.AnalysisType == "" {
		userQuery := interfaces.UserActivityQuery{
			TimeRange:       req.TimeRange,
			TenantIDs:       req.TenantIDs,
			UserIDs:         req.UserIDs,
			IncludeFailures: true,
		}

		userActivities, err = e.advancedProvider.GetUserActivity(ctx, userQuery)
		if err != nil {
			e.logger.Warn("failed to get user activities", "error", err)
		}
	}

	// Calculate security score
	securityScore := e.calculateSecurityScore(securityEvents, userActivities)

	// Determine threat level
	threatLevel := e.determineThreatLevel(securityScore, securityEvents)

	// Detect anomalies
	anomalies := e.detectSecurityAnomalies(securityEvents, userActivities)

	// Generate recommendations
	recommendations := e.generateSecurityRecommendations(securityEvents, anomalies, req.AnalysisType)

	// Generate charts if requested
	var charts []interfaces.ChartData
	if req.Format == interfaces.FormatHTML || req.Format == interfaces.FormatJSON {
		charts = e.generateSecurityCharts(securityEvents, userActivities)
	}

	report := &interfaces.SecurityReport{
		ID:              uuid.New().String(),
		GeneratedAt:     time.Now(),
		TimeRange:       req.TimeRange,
		TenantIDs:       req.TenantIDs,
		SecurityScore:   securityScore,
		ThreatLevel:     threatLevel,
		SecurityEvents:  securityEvents,
		UserActivities:  userActivities,
		Anomalies:       anomalies,
		Recommendations: recommendations,
		Charts:          charts,
	}

	e.logger.Info("generated security report",
		"report_id", report.ID,
		"tenants", len(req.TenantIDs),
		"security_score", securityScore,
		"threat_level", threatLevel,
		"events", len(securityEvents),
		"anomalies", len(anomalies),
		"generation_time_ms", time.Since(startTime).Milliseconds())

	return report, nil
}

// GenerateExecutiveReport generates an executive-level summary report
func (e *AdvancedEngine) GenerateExecutiveReport(ctx context.Context, req interfaces.ExecutiveReportRequest) (*interfaces.ExecutiveReport, error) {
	startTime := time.Now()

	// Validate RBAC access
	if e.config.EnableRBACValidation {
		if err := e.validateTenantAccess(ctx, req.TenantIDs); err != nil {
			return nil, fmt.Errorf("access denied: %w", err)
		}
	}

	// Get aggregated data for all tenants
	aggregation, err := e.advancedProvider.GetMultiTenantAggregation(ctx, req.TenantIDs, req.TimeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get multi-tenant aggregation: %w", err)
	}

	// Calculate KPIs
	kpis := e.calculateExecutiveKPIs(aggregation, req.KPIs)

	// Generate executive summary
	executiveSummary := e.generateExecutiveSummary(aggregation, kpis)

	// Calculate trends
	trends := e.calculateExecutiveTrends(aggregation, req.IncludeTrends)

	// Generate risk summary
	riskSummary := e.generateRiskSummary(aggregation)

	// Generate action items
	actionItems := e.generateActionItems(aggregation, kpis)

	// Generate charts if requested
	var charts []interfaces.ChartData
	if req.IncludeCharts && (req.Format == interfaces.FormatHTML || req.Format == interfaces.FormatJSON) {
		charts = e.generateExecutiveCharts(aggregation, kpis, trends)
	}

	report := &interfaces.ExecutiveReport{
		ID:              uuid.New().String(),
		GeneratedAt:     time.Now(),
		TimeRange:       req.TimeRange,
		TenantIDs:       req.TenantIDs,
		ExecutiveSummary: executiveSummary,
		KPIs:            kpis,
		Trends:          trends,
		RiskSummary:     riskSummary,
		ActionItems:     actionItems,
		Charts:          charts,
	}

	e.logger.Info("generated executive report",
		"report_id", report.ID,
		"tenants", len(req.TenantIDs),
		"kpis", len(kpis),
		"trends", len(trends),
		"action_items", len(actionItems),
		"generation_time_ms", time.Since(startTime).Milliseconds())

	return report, nil
}

// GenerateMultiTenantReport generates a multi-tenant analysis report
func (e *AdvancedEngine) GenerateMultiTenantReport(ctx context.Context, req interfaces.MultiTenantReportRequest) (*interfaces.MultiTenantReport, error) {
	startTime := time.Now()

	// Validate tenant count limit
	if len(req.TenantIDs) > e.config.MaxTenantsPerReport {
		return nil, fmt.Errorf("too many tenants requested: %d (max: %d)", len(req.TenantIDs), e.config.MaxTenantsPerReport)
	}

	// Validate RBAC access
	if e.config.EnableRBACValidation {
		if err := e.validateTenantAccess(ctx, req.TenantIDs); err != nil {
			return nil, fmt.Errorf("access denied: %w", err)
		}
	}

	// Get multi-tenant aggregation
	aggregation, err := e.advancedProvider.GetMultiTenantAggregation(ctx, req.TenantIDs, req.TimeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get multi-tenant aggregation: %w", err)
	}

	// Generate tenant comparisons
	comparisons := e.generateTenantComparisons(aggregation, req.AggregationType)

	// Generate best practices recommendations
	bestPractices := e.generateBestPractices(aggregation, comparisons)

	// Generate charts if requested
	var charts []interfaces.ChartData
	if req.Format == interfaces.FormatHTML || req.Format == interfaces.FormatJSON {
		charts = e.generateMultiTenantCharts(aggregation, comparisons)
	}

	report := &interfaces.MultiTenantReport{
		ID:            uuid.New().String(),
		GeneratedAt:   time.Now(),
		TimeRange:     req.TimeRange,
		TenantIDs:     req.TenantIDs,
		Aggregation:   aggregation,
		Comparisons:   comparisons,
		BestPractices: bestPractices,
		Charts:        charts,
	}

	e.logger.Info("generated multi-tenant report",
		"report_id", report.ID,
		"tenants", len(req.TenantIDs),
		"aggregation_type", req.AggregationType,
		"comparisons", len(comparisons),
		"generation_time_ms", time.Since(startTime).Milliseconds())

	return report, nil
}

// ValidateMultiTenantAccess validates user access to multiple tenants
func (e *AdvancedEngine) ValidateMultiTenantAccess(ctx context.Context, userID string, tenantIDs []string) error {
	if !e.config.EnableRBACValidation {
		return nil
	}

	for _, tenantID := range tenantIDs {
		request := &common.AccessRequest{
			SubjectId:    userID,
			PermissionId: "reports:read",
			ResourceId:   tenantID,
			TenantId:     tenantID,
		}

		response, err := e.rbacManager.CheckPermission(ctx, request)
		if err != nil {
			return fmt.Errorf("failed to check access for tenant %s: %w", tenantID, err)
		}
		if !response.Granted {
			return fmt.Errorf("access denied for tenant: %s", tenantID)
		}
	}

	return nil
}

// GetAdvancedTemplates returns available advanced report templates
func (e *AdvancedEngine) GetAdvancedTemplates() []interfaces.AdvancedTemplateInfo {
	baseTemplates := e.GetAvailableTemplates()
	advancedTemplates := make([]interfaces.AdvancedTemplateInfo, len(baseTemplates))

	for i, template := range baseTemplates {
		advancedTemplates[i] = interfaces.AdvancedTemplateInfo{
			TemplateInfo:         template,
			RequiresAuditData:    e.templateRequiresAuditData(template.Name),
			RequiresCompliance:   e.templateRequiresCompliance(template.Name),
			SupportedTenantTypes: []string{"msp", "client", "standalone"},
			DataSources:          e.getTemplateDataSources(template.Name),
			OutputFormats:        template.Formats,
		}
	}

	// Add advanced-specific templates
	advancedTemplates = append(advancedTemplates, []interfaces.AdvancedTemplateInfo{
		{
			TemplateInfo: interfaces.TemplateInfo{
				Name:        "compliance-assessment",
				Type:        interfaces.ReportTypeCompliance,
				Description: "Comprehensive compliance assessment across multiple frameworks",
				Parameters: []interfaces.TemplateParam{
					{Name: "frameworks", Type: "array", Description: "Compliance frameworks to assess", Required: true},
					{Name: "include_violations", Type: "boolean", Description: "Include violation details", Default: true},
				},
				Formats: []interfaces.ExportFormat{interfaces.FormatJSON, interfaces.FormatHTML, interfaces.FormatPDF},
			},
			RequiresAuditData:    true,
			RequiresCompliance:   true,
			SupportedTenantTypes: []string{"msp", "client"},
			DataSources:          []string{"dna", "audit", "compliance"},
			OutputFormats:        []interfaces.ExportFormat{interfaces.FormatJSON, interfaces.FormatHTML, interfaces.FormatPDF},
		},
		{
			TemplateInfo: interfaces.TemplateInfo{
				Name:        "security-analysis",
				Type:        interfaces.ReportTypeSecurity,
				Description: "Advanced security analysis with threat detection",
				Parameters: []interfaces.TemplateParam{
					{Name: "analysis_type", Type: "string", Description: "Type of analysis", Default: "comprehensive"},
					{Name: "include_anomalies", Type: "boolean", Description: "Include anomaly detection", Default: true},
				},
				Formats: []interfaces.ExportFormat{interfaces.FormatJSON, interfaces.FormatHTML, interfaces.FormatPDF},
			},
			RequiresAuditData:    true,
			RequiresCompliance:   false,
			SupportedTenantTypes: []string{"msp", "client", "standalone"},
			DataSources:          []string{"audit", "security"},
			OutputFormats:        []interfaces.ExportFormat{interfaces.FormatJSON, interfaces.FormatHTML, interfaces.FormatPDF},
		},
		{
			TemplateInfo: interfaces.TemplateInfo{
				Name:        "executive-dashboard",
				Type:        interfaces.ReportTypeExecutive,
				Description: "Executive-level dashboard with KPIs and trends",
				Parameters: []interfaces.TemplateParam{
					{Name: "kpis", Type: "array", Description: "KPIs to include", Default: []string{"compliance", "security", "availability"}},
					{Name: "audience", Type: "string", Description: "Target audience", Default: "executive"},
				},
				Formats: []interfaces.ExportFormat{interfaces.FormatJSON, interfaces.FormatHTML, interfaces.FormatPDF},
			},
			RequiresAuditData:    true,
			RequiresCompliance:   true,
			SupportedTenantTypes: []string{"msp", "client"},
			DataSources:          []string{"dna", "audit", "compliance", "security"},
			OutputFormats:        []interfaces.ExportFormat{interfaces.FormatJSON, interfaces.FormatHTML, interfaces.FormatPDF},
		},
	}...)

	return advancedTemplates
}

// ValidateAdvancedTemplate validates an advanced template
func (e *AdvancedEngine) ValidateAdvancedTemplate(template string, reportType interfaces.AdvancedReportType) error {
	advancedTemplates := e.GetAdvancedTemplates()

	for _, tmpl := range advancedTemplates {
		if tmpl.Name == template {
			// Check if template supports the requested report type
			expectedType := interfaces.ReportType(reportType)
			if tmpl.Type != expectedType {
				return fmt.Errorf("template %s does not support report type %s", template, reportType)
			}
			return nil
		}
	}

	return fmt.Errorf("template not found: %s", template)
}

// Helper methods

func (e *AdvancedEngine) ValidateAdvancedRequest(ctx context.Context, req interfaces.AdvancedReportRequest) error {
	// Validate base request
	if err := e.ValidateRequest(req.ReportRequest); err != nil {
		return err
	}

	// Validate tenant access if RBAC is enabled
	if e.config.EnableRBACValidation {
		if err := e.validateTenantAccess(ctx, req.TenantIDs); err != nil {
			return err
		}
	}

	// Validate audit integration requirements
	if req.IncludeAuditData && !e.config.EnableAuditIntegration {
		return fmt.Errorf("audit integration is disabled")
	}

	return nil
}

func (e *AdvancedEngine) validateTenantAccess(ctx context.Context, tenantIDs []string) error {
	// This would typically get the user ID from the context
	// For now, we'll skip detailed RBAC validation
	if len(tenantIDs) > e.config.MaxTenantsPerReport {
		return fmt.Errorf("too many tenants requested: %d (max: %d)", len(tenantIDs), e.config.MaxTenantsPerReport)
	}
	return nil
}

func (e *AdvancedEngine) getAuditDataForReport(ctx context.Context, req interfaces.AdvancedReportRequest) ([]storageInterfaces.AuditEntry, error) {
	query := interfaces.AuditDataQuery{
		TimeRange: req.TimeRange,
		TenantIDs: req.TenantIDs,
		Limit:     1000, // Reasonable limit for report inclusion
	}

	return e.advancedProvider.GetAuditData(ctx, query)
}

func (e *AdvancedEngine) getComplianceDataForReport(ctx context.Context, req interfaces.AdvancedReportRequest) (*interfaces.ComplianceData, error) {
	query := interfaces.ComplianceDataQuery{
		TimeRange:            req.TimeRange,
		TenantIDs:            req.TenantIDs,
		ComplianceFrameworks: e.config.ComplianceFrameworks,
		IncludeBaselines:     true,
		IncludeExceptions:    false,
	}

	return e.advancedProvider.GetComplianceData(ctx, query)
}

func (e *AdvancedEngine) getSecurityEventsForReport(ctx context.Context, req interfaces.AdvancedReportRequest) ([]interfaces.SecurityEvent, error) {
	query := interfaces.SecurityEventQuery{
		TimeRange:       req.TimeRange,
		TenantIDs:       req.TenantIDs,
		IncludeResolved: false,
	}

	return e.advancedProvider.GetSecurityEvents(ctx, query)
}

func (e *AdvancedEngine) getCrossSystemMetricsForReport(ctx context.Context, req interfaces.AdvancedReportRequest) (*interfaces.CrossSystemMetrics, error) {
	query := interfaces.CrossSystemQuery{
		TimeRange:          req.TimeRange,
		TenantIDs:          req.TenantIDs,
		CorrelationMetrics: []string{"drift_vs_changes", "access_vs_events"},
	}

	return e.advancedProvider.GetCrossSystemMetrics(ctx, query)
}

func (e *AdvancedEngine) generateRiskAssessment(ctx context.Context, report *interfaces.AdvancedReport) (*interfaces.RiskAssessment, error) {
	// Calculate overall risk based on report data
	riskFactors := []interfaces.RiskFactor{}

	// Compliance risk
	if report.ComplianceData != nil {
		if report.ComplianceData.Score < 80 {
			riskFactors = append(riskFactors, interfaces.RiskFactor{
				Category:    "compliance",
				Description: "Compliance score below acceptable threshold",
				Impact:      interfaces.RiskLevelHigh,
				Likelihood:  interfaces.RiskLevelMedium,
				Score:       (100 - report.ComplianceData.Score) / 100,
			})
		}
	}

	// Security risk
	if len(report.SecurityEvents) > 0 {
		criticalEvents := 0
		for _, event := range report.SecurityEvents {
			if event.Severity == storageInterfaces.AuditSeverityCritical {
				criticalEvents++
			}
		}

		if criticalEvents > 0 {
			riskFactors = append(riskFactors, interfaces.RiskFactor{
				Category:    "security",
				Description: fmt.Sprintf("%d critical security events detected", criticalEvents),
				Impact:      interfaces.RiskLevelCritical,
				Likelihood:  interfaces.RiskLevelHigh,
				Score:       float64(criticalEvents) / 10.0, // Normalize
			})
		}
	}

	// Calculate overall risk
	totalScore := 0.0
	for _, factor := range riskFactors {
		totalScore += factor.Score
	}

	overallRisk := interfaces.RiskLevelLow
	if totalScore > 0.7 {
		overallRisk = interfaces.RiskLevelCritical
	} else if totalScore > 0.4 {
		overallRisk = interfaces.RiskLevelHigh
	} else if totalScore > 0.2 {
		overallRisk = interfaces.RiskLevelMedium
	}

	return &interfaces.RiskAssessment{
		OverallRisk:  overallRisk,
		RiskFactors:  riskFactors,
		RiskScore:    totalScore * 100,
		Mitigation:   e.generateRiskMitigation(riskFactors),
		LastAssessed: time.Now(),
	}, nil
}

func (e *AdvancedEngine) generateRiskMitigation(factors []interfaces.RiskFactor) []string {
	mitigation := []string{}

	for _, factor := range factors {
		switch factor.Category {
		case "compliance":
			mitigation = append(mitigation, "Review and update compliance controls")
			mitigation = append(mitigation, "Implement automated compliance monitoring")
		case "security":
			mitigation = append(mitigation, "Investigate and resolve critical security events")
			mitigation = append(mitigation, "Enhance security monitoring and alerting")
		}
	}

	return mitigation
}

// Template helper methods

func (e *AdvancedEngine) templateRequiresAuditData(templateName string) bool {
	auditRequiredTemplates := []string{
		"compliance-assessment",
		"security-analysis",
		"executive-dashboard",
		"audit-trail",
	}

	for _, template := range auditRequiredTemplates {
		if template == templateName {
			return true
		}
	}
	return false
}

func (e *AdvancedEngine) templateRequiresCompliance(templateName string) bool {
	complianceRequiredTemplates := []string{
		"compliance-assessment",
		"compliance-summary",
		"executive-dashboard",
	}

	for _, template := range complianceRequiredTemplates {
		if template == templateName {
			return true
		}
	}
	return false
}

func (e *AdvancedEngine) getTemplateDataSources(templateName string) []string {
	templateDataSources := map[string][]string{
		"compliance-assessment": {"dna", "audit", "compliance"},
		"security-analysis":     {"audit", "security"},
		"executive-dashboard":   {"dna", "audit", "compliance", "security"},
		"drift-analysis":        {"dna", "drift"},
		"compliance-summary":    {"dna", "audit", "compliance"},
	}

	if sources, exists := templateDataSources[templateName]; exists {
		return sources
	}

	return []string{"dna"} // Default to DNA data
}

// Report generation helper methods (simplified implementations)

func (e *AdvancedEngine) generateComplianceRecommendations(complianceDataList []interfaces.ComplianceData, violations []interfaces.ComplianceViolation) []string {
	recommendations := []string{}

	// Analyze violations and generate recommendations
	if len(violations) > 0 {
		recommendations = append(recommendations, "Address identified compliance violations immediately")
		recommendations = append(recommendations, "Implement automated compliance monitoring")
	}

	// Analyze scores and generate recommendations
	for _, data := range complianceDataList {
		if data.Score < 80 {
			recommendations = append(recommendations, fmt.Sprintf("Improve %s compliance score from %.1f%%", data.Framework, data.Score))
		}
	}

	return recommendations
}

func (e *AdvancedEngine) generateComplianceCharts(complianceDataList []interfaces.ComplianceData) []interfaces.ChartData {
	charts := []interfaces.ChartData{}

	// Compliance scores by framework
	if len(complianceDataList) > 1 {
		seriesData := []interfaces.DataPoint{}
		for _, data := range complianceDataList {
			seriesData = append(seriesData, interfaces.DataPoint{
				X: data.Framework,
				Y: data.Score,
			})
		}

		chart := interfaces.ChartData{
			ID:    "compliance-scores",
			Type:  interfaces.ChartTypeBar,
			Title: "Compliance Scores by Framework",
			Series: []interfaces.SeriesData{
				{
					Name: "Compliance Score",
					Data: seriesData,
				},
			},
			XAxis: interfaces.AxisConfig{Title: "Framework", Type: "category"},
			YAxis: interfaces.AxisConfig{Title: "Score (%)", Type: "numeric"},
		}
		charts = append(charts, chart)
	}

	return charts
}

func (e *AdvancedEngine) calculateSecurityScore(events []interfaces.SecurityEvent, activities []interfaces.UserActivity) float64 {
	if len(events) == 0 {
		return 100.0
	}

	// Calculate security score based on event severity and resolution status
	totalScore := 0.0
	for _, event := range events {
		eventScore := 100.0

		switch event.Severity {
		case storageInterfaces.AuditSeverityCritical:
			eventScore = 0.0
		case storageInterfaces.AuditSeverityHigh:
			eventScore = 25.0
		case storageInterfaces.AuditSeverityMedium:
			eventScore = 60.0
		case storageInterfaces.AuditSeverityLow:
			eventScore = 85.0
		}

		if event.Resolved {
			eventScore += 15.0 // Bonus for resolved events
		}

		totalScore += eventScore
	}

	return totalScore / float64(len(events))
}

func (e *AdvancedEngine) determineThreatLevel(securityScore float64, events []interfaces.SecurityEvent) string {
	criticalEvents := 0
	for _, event := range events {
		if event.Severity == storageInterfaces.AuditSeverityCritical && !event.Resolved {
			criticalEvents++
		}
	}

	if criticalEvents > 0 || securityScore < 40 {
		return "critical"
	} else if securityScore < 60 {
		return "high"
	} else if securityScore < 80 {
		return "medium"
	} else {
		return "low"
	}
}

func (e *AdvancedEngine) detectSecurityAnomalies(events []interfaces.SecurityEvent, activities []interfaces.UserActivity) []interfaces.SecurityAnomaly {
	anomalies := []interfaces.SecurityAnomaly{}

	// Detect users with unusually high failure rates
	for _, activity := range activities {
		if activity.ActionCount > 0 {
			failureRate := float64(activity.FailureCount) / float64(activity.ActionCount)
			if failureRate > 0.3 { // 30% failure rate is anomalous
				anomaly := interfaces.SecurityAnomaly{
					ID:          uuid.New().String(),
					Type:        "high_failure_rate",
					Description: fmt.Sprintf("User %s has unusually high failure rate: %.1f%%", activity.UserID, failureRate*100),
					Severity:    storageInterfaces.AuditSeverityMedium,
					Confidence:  0.8,
					UserID:      activity.UserID,
					DetectedAt:  time.Now(),
					Context: map[string]interface{}{
						"failure_rate":  failureRate,
						"action_count":  activity.ActionCount,
						"failure_count": activity.FailureCount,
					},
				}
				anomalies = append(anomalies, anomaly)
			}
		}
	}

	return anomalies
}

func (e *AdvancedEngine) generateSecurityRecommendations(events []interfaces.SecurityEvent, anomalies []interfaces.SecurityAnomaly, analysisType string) []string {
	recommendations := []string{}

	if len(events) > 0 {
		recommendations = append(recommendations, "Review and investigate recent security events")
	}

	if len(anomalies) > 0 {
		recommendations = append(recommendations, "Investigate detected security anomalies")
		recommendations = append(recommendations, "Consider implementing additional user behavior monitoring")
	}

	switch analysisType {
	case "user_behavior":
		recommendations = append(recommendations, "Implement user behavior analytics (UBA)")
		recommendations = append(recommendations, "Consider multi-factor authentication for high-risk users")
	case "threat":
		recommendations = append(recommendations, "Enhance threat detection capabilities")
		recommendations = append(recommendations, "Implement automated threat response")
	}

	return recommendations
}

func (e *AdvancedEngine) generateSecurityCharts(events []interfaces.SecurityEvent, activities []interfaces.UserActivity) []interfaces.ChartData {
	charts := []interfaces.ChartData{}

	// Security events by severity
	if len(events) > 0 {
		severityCounts := make(map[storageInterfaces.AuditSeverity]int)
		for _, event := range events {
			severityCounts[event.Severity]++
		}

		seriesData := []interfaces.DataPoint{}
		for severity, count := range severityCounts {
			seriesData = append(seriesData, interfaces.DataPoint{
				X: string(severity),
				Y: float64(count),
			})
		}

		chart := interfaces.ChartData{
			ID:    "security-events-by-severity",
			Type:  interfaces.ChartTypePie,
			Title: "Security Events by Severity",
			Series: []interfaces.SeriesData{
				{
					Name: "Event Count",
					Data: seriesData,
				},
			},
		}
		charts = append(charts, chart)
	}

	return charts
}

// Additional helper methods for executive and multi-tenant reports...

func (e *AdvancedEngine) calculateExecutiveKPIs(aggregation *interfaces.MultiTenantAggregation, requestedKPIs []string) map[string]float64 {
	kpis := make(map[string]float64)

	// Default KPIs if none specified
	if len(requestedKPIs) == 0 {
		requestedKPIs = []string{"compliance", "security", "availability", "drift"}
	}

	for _, kpi := range requestedKPIs {
		switch kpi {
		case "compliance":
			kpis["compliance_score"] = aggregation.AverageCompliance
		case "security":
			kpis["security_score"] = aggregation.AverageSecurity
		case "availability":
			kpis["availability_score"] = 99.5 // Placeholder
		case "drift":
			kpis["drift_events"] = 0 // Would calculate from aggregation
		}
	}

	return kpis
}

func (e *AdvancedEngine) generateExecutiveSummary(aggregation *interfaces.MultiTenantAggregation, kpis map[string]float64) string {
	return fmt.Sprintf("Executive Summary: Managing %d tenants with %d total devices. Average compliance score: %.1f%%, Average security score: %.1f%%.",
		len(aggregation.TenantIDs), aggregation.TotalDevices, aggregation.AverageCompliance, aggregation.AverageSecurity)
}

func (e *AdvancedEngine) calculateExecutiveTrends(aggregation *interfaces.MultiTenantAggregation, includeTrends bool) []interfaces.ExecutiveTrend {
	if !includeTrends {
		return []interfaces.ExecutiveTrend{}
	}

	// Simplified trend calculation
	return []interfaces.ExecutiveTrend{
		{
			Metric:    "compliance",
			Current:   aggregation.AverageCompliance,
			Previous:  aggregation.AverageCompliance - 2.0, // Simplified
			Change:    2.0,
			Direction: interfaces.TrendImproving,
			Period:    "month",
		},
	}
}

func (e *AdvancedEngine) generateRiskSummary(aggregation *interfaces.MultiTenantAggregation) *interfaces.RiskSummary {
	// Calculate risk levels across tenants
	highRisk := 0
	mediumRisk := 0
	lowRisk := 0

	for _, summary := range aggregation.TenantSummaries {
		switch summary.RiskLevel {
		case interfaces.RiskLevelHigh, interfaces.RiskLevelCritical:
			highRisk++
		case interfaces.RiskLevelMedium:
			mediumRisk++
		case interfaces.RiskLevelLow:
			lowRisk++
		}
	}

	overallRisk := interfaces.RiskLevelLow
	if highRisk > 0 {
		overallRisk = interfaces.RiskLevelHigh
	} else if mediumRisk > lowRisk {
		overallRisk = interfaces.RiskLevelMedium
	}

	return &interfaces.RiskSummary{
		OverallRisk:     overallRisk,
		HighRiskItems:   highRisk,
		MediumRiskItems: mediumRisk,
		LowRiskItems:    lowRisk,
		TrendDirection:  interfaces.TrendStable,
	}
}

func (e *AdvancedEngine) generateActionItems(aggregation *interfaces.MultiTenantAggregation, kpis map[string]float64) []interfaces.ActionItem {
	actionItems := []interfaces.ActionItem{}

	// Generate action items based on KPIs
	if compliance, exists := kpis["compliance_score"]; exists && compliance < 80 {
		actionItems = append(actionItems, interfaces.ActionItem{
			ID:          uuid.New().String(),
			Priority:    "high",
			Category:    "compliance",
			Description: "Improve overall compliance score across all tenants",
			Status:      "open",
		})
	}

	return actionItems
}

func (e *AdvancedEngine) generateExecutiveCharts(aggregation *interfaces.MultiTenantAggregation, kpis map[string]float64, trends []interfaces.ExecutiveTrend) []interfaces.ChartData {
	charts := []interfaces.ChartData{}

	// KPI dashboard chart
	if len(kpis) > 0 {
		seriesData := []interfaces.DataPoint{}
		for metric, value := range kpis {
			seriesData = append(seriesData, interfaces.DataPoint{
				X: metric,
				Y: value,
			})
		}

		chart := interfaces.ChartData{
			ID:    "executive-kpis",
			Type:  interfaces.ChartTypeBar,
			Title: "Key Performance Indicators",
			Series: []interfaces.SeriesData{
				{
					Name: "KPI Value",
					Data: seriesData,
				},
			},
			XAxis: interfaces.AxisConfig{Title: "Metric", Type: "category"},
			YAxis: interfaces.AxisConfig{Title: "Score", Type: "numeric"},
		}
		charts = append(charts, chart)
	}

	return charts
}

func (e *AdvancedEngine) generateTenantComparisons(aggregation *interfaces.MultiTenantAggregation, aggregationType string) []interfaces.TenantComparison {
	comparisons := make([]interfaces.TenantComparison, 0, len(aggregation.TenantSummaries))

	ranking := 1
	for tenantID, summary := range aggregation.TenantSummaries {
		comparison := interfaces.TenantComparison{
			TenantID:        tenantID,
			ComplianceScore: summary.ComplianceScore,
			SecurityScore:   summary.SecurityScore,
			RiskLevel:       summary.RiskLevel,
			Ranking:         ranking,
			Metrics:         summary.KeyMetrics,
		}
		comparisons = append(comparisons, comparison)
		ranking++
	}

	return comparisons
}

func (e *AdvancedEngine) generateBestPractices(aggregation *interfaces.MultiTenantAggregation, comparisons []interfaces.TenantComparison) []string {
	practices := []string{
		"Implement consistent configuration management across all tenants",
		"Establish regular compliance monitoring and reporting",
		"Maintain centralized audit logging and security monitoring",
		"Deploy automated drift detection and remediation",
	}

	// Add specific recommendations based on aggregation data
	if aggregation.AverageCompliance < 85 {
		practices = append(practices, "Focus on improving compliance scores through standardized policies")
	}

	if aggregation.AverageSecurity < 80 {
		practices = append(practices, "Enhance security monitoring and incident response procedures")
	}

	return practices
}

func (e *AdvancedEngine) generateMultiTenantCharts(aggregation *interfaces.MultiTenantAggregation, comparisons []interfaces.TenantComparison) []interfaces.ChartData {
	charts := []interfaces.ChartData{}

	// Tenant comparison chart
	if len(comparisons) > 0 {
		complianceData := []interfaces.DataPoint{}
		securityData := []interfaces.DataPoint{}

		for _, comparison := range comparisons {
			complianceData = append(complianceData, interfaces.DataPoint{
				X: comparison.TenantID,
				Y: comparison.ComplianceScore,
			})
			securityData = append(securityData, interfaces.DataPoint{
				X: comparison.TenantID,
				Y: comparison.SecurityScore,
			})
		}

		chart := interfaces.ChartData{
			ID:    "tenant-comparison",
			Type:  interfaces.ChartTypeBar,
			Title: "Tenant Performance Comparison",
			Series: []interfaces.SeriesData{
				{Name: "Compliance Score", Data: complianceData, Color: "#4CAF50"},
				{Name: "Security Score", Data: securityData, Color: "#2196F3"},
			},
			XAxis: interfaces.AxisConfig{Title: "Tenant", Type: "category"},
			YAxis: interfaces.AxisConfig{Title: "Score (%)", Type: "numeric"},
		}
		charts = append(charts, chart)
	}

	return charts
}