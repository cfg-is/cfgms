package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Engine implements the ReportEngine interface
type Engine struct {
	dataProvider      interfaces.DataProvider
	templateProcessor interfaces.TemplateProcessor
	exporter          interfaces.Exporter
	cache             interfaces.ReportCache
	logger            logging.Logger
	config            Config
}

// Config contains configuration for the report engine
type Config struct {
	CacheEnabled    bool          `json:"cache_enabled"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	MaxDevices      int           `json:"max_devices"`
	MaxTimeRange    time.Duration `json:"max_time_range"`
	TimeoutDuration time.Duration `json:"timeout_duration"`
}

// DefaultConfig returns default configuration for the report engine
func DefaultConfig() Config {
	return Config{
		CacheEnabled:    true,
		CacheTTL:        time.Hour,
		MaxDevices:      1000,
		MaxTimeRange:    30 * 24 * time.Hour, // 30 days
		TimeoutDuration: 5 * time.Minute,
	}
}

// New creates a new report engine instance
func New(
	dataProvider interfaces.DataProvider,
	templateProcessor interfaces.TemplateProcessor,
	exporter interfaces.Exporter,
	cache interfaces.ReportCache,
	logger logging.Logger,
) *Engine {
	return &Engine{
		dataProvider:      dataProvider,
		templateProcessor: templateProcessor,
		exporter:          exporter,
		cache:             cache,
		logger:            logger,
		config:            DefaultConfig(),
	}
}

// WithConfig sets custom configuration for the engine
func (e *Engine) WithConfig(config Config) *Engine {
	e.config = config
	return e
}

// GenerateReport generates a report based on the provided request
func (e *Engine) GenerateReport(ctx context.Context, req interfaces.ReportRequest) (*interfaces.Report, error) {
	startTime := time.Now()
	
	// Validate the request
	if err := e.ValidateRequest(req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Generate cache key
	cacheKey := e.generateCacheKey(req)
	
	// Check cache if enabled
	if e.config.CacheEnabled {
		if cached, err := e.cache.Get(ctx, cacheKey); err == nil && cached != nil {
			e.logger.Info("report cache hit",
				"request_type", req.Type,
				"template", req.Template,
				"cache_key", cacheKey)
			
			cached.Metadata.CacheHit = true
			return cached, nil
		}
	}

	// Create context with timeout
	ctxWithTimeout, cancel := context.WithTimeout(ctx, e.config.TimeoutDuration)
	defer cancel()

	// Gather report data
	reportData, err := e.gatherReportData(ctxWithTimeout, req)
	if err != nil {
		return nil, fmt.Errorf("failed to gather report data: %w", err)
	}

	// Process template to generate report
	report, err := e.templateProcessor.ProcessTemplate(
		ctxWithTimeout,
		req.Template,
		*reportData,
		req.Parameters,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to process template: %w", err)
	}

	// Enrich report with metadata
	generationTime := time.Since(startTime)
	e.enrichReportMetadata(report, req, reportData, generationTime)

	// Cache the report if enabled
	if e.config.CacheEnabled {
		if err := e.cache.Set(ctx, cacheKey, report, e.config.CacheTTL); err != nil {
			e.logger.Warn("failed to cache report", "error", err)
		}
	}

	e.logger.Info("report generated successfully",
		"type", req.Type,
		"template", req.Template,
		"devices", len(reportData.DNARecords),
		"generation_ms", generationTime.Milliseconds())

	return report, nil
}

// GetAvailableTemplates returns information about available report templates
func (e *Engine) GetAvailableTemplates() []interfaces.TemplateInfo {
	// This would typically be loaded from template configuration
	return []interfaces.TemplateInfo{
		{
			Name:        "compliance-summary",
			Type:        interfaces.ReportTypeCompliance,
			Description: "High-level compliance status with drift summary",
			Parameters: []interfaces.TemplateParam{
				{
					Name:        "baseline_date",
					Type:        "datetime",
					Description: "Date to use as compliance baseline",
					Required:    false,
				},
				{
					Name:        "include_details",
					Type:        "boolean",
					Description: "Include detailed drift information",
					Required:    false,
					Default:     true,
				},
			},
			Formats: []interfaces.ExportFormat{
				interfaces.FormatJSON,
				interfaces.FormatHTML,
				interfaces.FormatPDF,
			},
		},
		{
			Name:        "executive-dashboard",
			Type:        interfaces.ReportTypeExecutive,
			Description: "Executive overview with trend analysis and KPIs",
			Parameters: []interfaces.TemplateParam{
				{
					Name:        "include_charts",
					Type:        "boolean",
					Description: "Include trend charts and visualizations",
					Required:    false,
					Default:     true,
				},
			},
			Formats: []interfaces.ExportFormat{
				interfaces.FormatJSON,
				interfaces.FormatHTML,
				interfaces.FormatPDF,
			},
		},
		{
			Name:        "drift-analysis",
			Type:        interfaces.ReportTypeDrift,
			Description: "Detailed analysis of configuration drift events",
			Parameters: []interfaces.TemplateParam{
				{
					Name:        "severity_filter",
					Type:        "string",
					Description: "Filter events by severity (critical, warning, info)",
					Required:    false,
				},
				{
					Name:        "group_by_device",
					Type:        "boolean",
					Description: "Group drift events by device",
					Required:    false,
					Default:     false,
				},
			},
			Formats: []interfaces.ExportFormat{
				interfaces.FormatJSON,
				interfaces.FormatCSV,
				interfaces.FormatHTML,
			},
		},
	}
}

// ValidateTemplate validates that a template exists and is valid
func (e *Engine) ValidateTemplate(template string) error {
	return e.templateProcessor.ValidateTemplate(template)
}

// ValidateRequest validates a report request
func (e *Engine) ValidateRequest(req interfaces.ReportRequest) error {
	// Validate report type
	switch req.Type {
	case interfaces.ReportTypeCompliance, interfaces.ReportTypeExecutive, 
		 interfaces.ReportTypeDrift, interfaces.ReportTypeOperational, 
		 interfaces.ReportTypeCustom:
		// Valid types
	default:
		return fmt.Errorf("invalid report type: %s", req.Type)
	}

	// Validate template
	if req.Template == "" {
		return fmt.Errorf("template is required")
	}

	// Validate time range
	if req.TimeRange.Start.IsZero() || req.TimeRange.End.IsZero() {
		return fmt.Errorf("valid time range is required")
	}
	
	if req.TimeRange.Start.After(req.TimeRange.End) {
		return fmt.Errorf("start time must be before end time")
	}

	timeRange := req.TimeRange.End.Sub(req.TimeRange.Start)
	if timeRange > e.config.MaxTimeRange {
		return fmt.Errorf("time range too large: %v (max: %v)", timeRange, e.config.MaxTimeRange)
	}

	// Validate device limit
	if len(req.DeviceIDs) > e.config.MaxDevices {
		return fmt.Errorf("too many devices: %d (max: %d)", len(req.DeviceIDs), e.config.MaxDevices)
	}

	// Validate export format
	switch req.Format {
	case interfaces.FormatJSON, interfaces.FormatCSV, interfaces.FormatPDF, 
		 interfaces.FormatExcel, interfaces.FormatHTML:
		// Valid formats
	default:
		return fmt.Errorf("invalid export format: %s", req.Format)
	}

	return nil
}

// gatherReportData collects all data needed for report generation
func (e *Engine) gatherReportData(ctx context.Context, req interfaces.ReportRequest) (*interfaces.ReportData, error) {
	query := interfaces.DataQuery{
		TimeRange: req.TimeRange,
		DeviceIDs: req.DeviceIDs,
		TenantIDs: req.TenantIDs,
	}

	// Gather DNA records
	dnaRecords, err := e.dataProvider.GetDNAData(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get DNA data: %w", err)
	}

	// Gather drift events
	driftEvents, err := e.dataProvider.GetDriftEvents(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get drift events: %w", err)
	}

	// Get device statistics
	deviceStats, err := e.dataProvider.GetDeviceStats(ctx, req.DeviceIDs, req.TimeRange)
	if err != nil {
		return nil, fmt.Errorf("failed to get device stats: %w", err)
	}

	// Get trend data for key metrics
	trendData := make(map[string][]interfaces.TrendPoint)
	metrics := []string{"drift_events", "compliance_score", "device_count"}
	
	for _, metric := range metrics {
		trends, err := e.dataProvider.GetTrendData(ctx, metric, query)
		if err != nil {
			e.logger.Warn("failed to get trend data", "metric", metric, "error", err)
			continue
		}
		trendData[metric] = trends
	}

	return &interfaces.ReportData{
		DNARecords:  dnaRecords,
		DriftEvents: driftEvents,
		TimeRange:   req.TimeRange,
		DeviceStats: deviceStats,
		TrendData:   trendData,
	}, nil
}

// enrichReportMetadata adds metadata to the generated report
func (e *Engine) enrichReportMetadata(
	report *interfaces.Report,
	req interfaces.ReportRequest,
	data *interfaces.ReportData,
	generationTime time.Duration,
) {
	report.ID = e.generateReportID(req)
	report.Type = req.Type
	report.GeneratedAt = time.Now()
	report.TimeRange = req.TimeRange
	
	if req.Title != "" {
		report.Title = req.Title
	}
	if req.Subtitle != "" {
		report.Subtitle = req.Subtitle
	}

	report.Metadata = interfaces.ReportMetadata{
		Template:     req.Template,
		DeviceCount:  len(data.DNARecords),
		DataPoints:   len(data.DNARecords) + len(data.DriftEvents),
		GenerationMS: generationTime.Milliseconds(),
		CacheHit:     false,
		Parameters:   req.Parameters,
	}

	// Generate summary
	report.Summary = e.generateReportSummary(data)
}

// generateReportSummary creates a summary of the report data
func (e *Engine) generateReportSummary(data *interfaces.ReportData) interfaces.ReportSummary {
	summary := interfaces.ReportSummary{
		DevicesAnalyzed:  len(data.DNARecords),
		DriftEventsTotal: len(data.DriftEvents),
	}

	// Calculate compliance score (average across devices)
	var totalScore float64
	var criticalIssues int
	
	for _, stats := range data.DeviceStats {
		totalScore += stats.ComplianceScore
		if stats.RiskLevel == interfaces.RiskLevelCritical {
			criticalIssues++
		}
	}

	if len(data.DeviceStats) > 0 {
		summary.ComplianceScore = totalScore / float64(len(data.DeviceStats))
	}
	summary.CriticalIssues = criticalIssues

	// Analyze trend direction
	if trends, exists := data.TrendData["compliance_score"]; exists && len(trends) >= 2 {
		firstScore := trends[0].Value
		lastScore := trends[len(trends)-1].Value
		
		if lastScore > firstScore+0.05 {
			summary.TrendDirection = interfaces.TrendImproving
		} else if lastScore < firstScore-0.05 {
			summary.TrendDirection = interfaces.TrendDeclining
		} else {
			summary.TrendDirection = interfaces.TrendStable
		}
	} else {
		summary.TrendDirection = interfaces.TrendUnknown
	}

	// Generate key insights
	summary.KeyInsights = e.generateKeyInsights(data)
	summary.RecommendedActions = e.generateRecommendedActions(data, summary)

	return summary
}

// generateKeyInsights analyzes data to provide key insights
func (e *Engine) generateKeyInsights(data *interfaces.ReportData) []string {
	insights := make([]string, 0)

	// Analyze drift events by severity
	criticalCount := 0
	warningCount := 0
	
	for _, event := range data.DriftEvents {
		switch event.Severity {
		case drift.SeverityCritical:
			criticalCount++
		case drift.SeverityWarning:
			warningCount++
		}
	}

	if criticalCount > 0 {
		insights = append(insights, fmt.Sprintf("%d critical drift events detected requiring immediate attention", criticalCount))
	}

	if warningCount > criticalCount*2 {
		insights = append(insights, fmt.Sprintf("%d warning-level drift events indicate potential configuration instability", warningCount))
	}

	// Analyze device risk distribution
	highRiskDevices := 0
	for _, stats := range data.DeviceStats {
		if stats.RiskLevel == interfaces.RiskLevelHigh || stats.RiskLevel == interfaces.RiskLevelCritical {
			highRiskDevices++
		}
	}

	if highRiskDevices > 0 {
		percentage := float64(highRiskDevices) / float64(len(data.DeviceStats)) * 100
		insights = append(insights, fmt.Sprintf("%.1f%% of devices (%d/%d) are at high or critical risk levels", 
			percentage, highRiskDevices, len(data.DeviceStats)))
	}

	return insights
}

// generateRecommendedActions provides actionable recommendations
func (e *Engine) generateRecommendedActions(data *interfaces.ReportData, summary interfaces.ReportSummary) []string {
	actions := make([]string, 0)

	// Critical issues
	if summary.CriticalIssues > 0 {
		actions = append(actions, "Address critical risk devices immediately to prevent security or compliance violations")
	}

	// Compliance score
	if summary.ComplianceScore < 0.8 {
		actions = append(actions, "Review and update configuration baselines to improve overall compliance score")
	}

	// Trend analysis
	if summary.TrendDirection == interfaces.TrendDeclining {
		actions = append(actions, "Investigate root causes of declining compliance trends and implement corrective measures")
	}

	// Frequent drift
	frequentDriftDevices := 0
	for _, stats := range data.DeviceStats {
		if stats.ChangeFrequency > 5.0 { // More than 5 changes per day
			frequentDriftDevices++
		}
	}

	if frequentDriftDevices > 0 {
		actions = append(actions, fmt.Sprintf("Review %d devices with high change frequency (>5 changes/day) for potential automation issues", frequentDriftDevices))
	}

	return actions
}

// generateCacheKey creates a unique cache key for the request
func (e *Engine) generateCacheKey(req interfaces.ReportRequest) string {
	// Create a hash of the request parameters
	data, _ := json.Marshal(req)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("report_%s", hex.EncodeToString(hash[:8]))
}

// generateReportID creates a unique ID for the report
func (e *Engine) generateReportID(req interfaces.ReportRequest) string {
	timestamp := time.Now().Unix()
	data, _ := json.Marshal(req)
	hash := sha256.Sum256(data)
	return fmt.Sprintf("%s_%d_%s", req.Type, timestamp, hex.EncodeToString(hash[:4]))
}