package templates

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/features/reports"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Processor implements the reports.TemplateProcessor interface
type Processor struct {
	logger    logging.Logger
	templates map[string]TemplateDefinition
}

// TemplateDefinition defines how to process a specific template
type TemplateDefinition struct {
	Name        string
	Type        reports.ReportType
	Description string
	Parameters  []reports.TemplateParam
	Formats     []reports.ExportFormat
	Generator   func(ctx context.Context, data reports.ReportData, params map[string]any) (*reports.Report, error)
}

// New creates a new template processor
func New(logger logging.Logger) *Processor {
	p := &Processor{
		logger:    logger,
		templates: make(map[string]TemplateDefinition),
	}

	// Register built-in templates
	p.registerBuiltinTemplates()
	
	return p
}

// ProcessTemplate processes a template with the given data and parameters
func (p *Processor) ProcessTemplate(ctx context.Context, templateName string, data reports.ReportData, params map[string]any) (*reports.Report, error) {
	template, exists := p.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	p.logger.Debug("processing template", 
		"template", templateName, 
		"type", template.Type,
		"dna_records", len(data.DNARecords),
		"drift_events", len(data.DriftEvents))

	// Generate the report using the template's generator function
	report, err := template.Generator(ctx, data, params)
	if err != nil {
		return nil, fmt.Errorf("failed to generate report from template %s: %w", templateName, err)
	}

	return report, nil
}

// GetTemplateInfo returns information about a specific template
func (p *Processor) GetTemplateInfo(templateName string) (*reports.TemplateInfo, error) {
	template, exists := p.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	return &reports.TemplateInfo{
		Name:        template.Name,
		Type:        template.Type,
		Description: template.Description,
		Parameters:  template.Parameters,
		Formats:     template.Formats,
	}, nil
}

// ValidateTemplate validates that a template exists and is valid
func (p *Processor) ValidateTemplate(templateName string) error {
	_, exists := p.templates[templateName]
	if !exists {
		return fmt.Errorf("template not found: %s", templateName)
	}
	return nil
}

// registerBuiltinTemplates registers the built-in report templates
func (p *Processor) registerBuiltinTemplates() {
	// Compliance Summary Template
	p.templates["compliance-summary"] = TemplateDefinition{
		Name:        "compliance-summary",
		Type:        reports.ReportTypeCompliance,
		Description: "High-level compliance status with drift summary",
		Parameters: []reports.TemplateParam{
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
		Formats: []reports.ExportFormat{
			reports.FormatJSON,
			reports.FormatHTML,
			reports.FormatCSV,
		},
		Generator: p.generateComplianceSummary,
	}

	// Executive Dashboard Template
	p.templates["executive-dashboard"] = TemplateDefinition{
		Name:        "executive-dashboard",
		Type:        reports.ReportTypeExecutive,
		Description: "Executive overview with trend analysis and KPIs",
		Parameters: []reports.TemplateParam{
			{
				Name:        "include_charts",
				Type:        "boolean",
				Description: "Include trend charts and visualizations",
				Required:    false,
				Default:     true,
			},
		},
		Formats: []reports.ExportFormat{
			reports.FormatJSON,
			reports.FormatHTML,
		},
		Generator: p.generateExecutiveDashboard,
	}

	// Drift Analysis Template
	p.templates["drift-analysis"] = TemplateDefinition{
		Name:        "drift-analysis",
		Type:        reports.ReportTypeDrift,
		Description: "Detailed analysis of configuration drift events",
		Parameters: []reports.TemplateParam{
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
		Formats: []reports.ExportFormat{
			reports.FormatJSON,
			reports.FormatCSV,
			reports.FormatHTML,
		},
		Generator: p.generateDriftAnalysis,
	}
}

// generateComplianceSummary generates a compliance summary report
func (p *Processor) generateComplianceSummary(ctx context.Context, data reports.ReportData, params map[string]any) (*reports.Report, error) {
	report := &reports.Report{
		Type:      reports.ReportTypeCompliance,
		Title:     "Compliance Summary Report",
		Subtitle:  fmt.Sprintf("Analysis period: %s - %s", 
			data.TimeRange.Start.Format("Jan 2, 2006"), 
			data.TimeRange.End.Format("Jan 2, 2006")),
		TimeRange: data.TimeRange,
		Sections:  make([]reports.ReportSection, 0),
		Charts:    make([]reports.ChartData, 0),
	}

	// Check parameters
	includeDetails := true
	if val, exists := params["include_details"]; exists {
		if b, ok := val.(bool); ok {
			includeDetails = b
		}
	}

	// Generate compliance overview section
	overviewSection := p.generateComplianceOverview(data)
	report.Sections = append(report.Sections, overviewSection)

	// Generate drift summary section
	driftSection := p.generateDriftSummarySection(data)
	report.Sections = append(report.Sections, driftSection)

	// Generate device compliance section
	deviceSection := p.generateDeviceComplianceSection(data, includeDetails)
	report.Sections = append(report.Sections, deviceSection)

	// Generate compliance chart
	complianceChart := p.generateComplianceChart(data)
	if complianceChart != nil {
		report.Charts = append(report.Charts, *complianceChart)
	}

	return report, nil
}

// generateExecutiveDashboard generates an executive dashboard report
func (p *Processor) generateExecutiveDashboard(ctx context.Context, data reports.ReportData, params map[string]any) (*reports.Report, error) {
	report := &reports.Report{
		Type:      reports.ReportTypeExecutive,
		Title:     "Executive Dashboard",
		Subtitle:  "Configuration Management Overview",
		TimeRange: data.TimeRange,
		Sections:  make([]reports.ReportSection, 0),
		Charts:    make([]reports.ChartData, 0),
	}

	// Check parameters
	includeCharts := true
	if val, exists := params["include_charts"]; exists {
		if b, ok := val.(bool); ok {
			includeCharts = b
		}
	}

	// Generate KPI section
	kpiSection := p.generateKPISection(data)
	report.Sections = append(report.Sections, kpiSection)

	// Generate trends section
	trendsSection := p.generateTrendsSection(data)
	report.Sections = append(report.Sections, trendsSection)

	// Generate risk assessment section
	riskSection := p.generateRiskAssessmentSection(data)
	report.Sections = append(report.Sections, riskSection)

	// Generate charts if requested
	if includeCharts {
		// Trend chart
		trendChart := p.generateTrendChart(data)
		if trendChart != nil {
			report.Charts = append(report.Charts, *trendChart)
		}

		// Risk distribution chart
		riskChart := p.generateRiskDistributionChart(data)
		if riskChart != nil {
			report.Charts = append(report.Charts, *riskChart)
		}
	}

	return report, nil
}

// generateDriftAnalysis generates a detailed drift analysis report
func (p *Processor) generateDriftAnalysis(ctx context.Context, data reports.ReportData, params map[string]any) (*reports.Report, error) {
	report := &reports.Report{
		Type:      reports.ReportTypeDrift,
		Title:     "Configuration Drift Analysis",
		Subtitle:  "Detailed drift event analysis and recommendations",
		TimeRange: data.TimeRange,
		Sections:  make([]reports.ReportSection, 0),
		Charts:    make([]reports.ChartData, 0),
	}

	// Filter events by severity if specified
	filteredEvents := data.DriftEvents
	if severityFilter, exists := params["severity_filter"]; exists {
		if s, ok := severityFilter.(string); ok {
			filteredEvents = p.filterEventsBySeverity(data.DriftEvents, s)
		}
	}

	// Check grouping parameter
	groupByDevice := false
	if val, exists := params["group_by_device"]; exists {
		if b, ok := val.(bool); ok {
			groupByDevice = b
		}
	}

	// Generate drift overview section
	overviewSection := p.generateDriftOverviewSection(filteredEvents)
	report.Sections = append(report.Sections, overviewSection)

	// Generate detailed events section
	if groupByDevice {
		eventsSection := p.generateDriftEventsByDeviceSection(filteredEvents)
		report.Sections = append(report.Sections, eventsSection)
	} else {
		eventsSection := p.generateDriftEventsSection(filteredEvents)
		report.Sections = append(report.Sections, eventsSection)
	}

	// Generate drift timeline chart
	timelineChart := p.generateDriftTimelineChart(filteredEvents)
	if timelineChart != nil {
		report.Charts = append(report.Charts, *timelineChart)
	}

	return report, nil
}

// generateComplianceOverview creates the compliance overview section
func (p *Processor) generateComplianceOverview(data reports.ReportData) reports.ReportSection {
	// Calculate compliance metrics
	totalDevices := len(data.DeviceStats)
	compliantDevices := 0
	totalScore := 0.0

	for _, stats := range data.DeviceStats {
		totalScore += stats.ComplianceScore
		if stats.ComplianceScore >= 0.8 {
			compliantDevices++
		}
	}

	avgScore := 0.0
	if totalDevices > 0 {
		avgScore = totalScore / float64(totalDevices)
	}

	content := map[string]interface{}{
		"total_devices":      totalDevices,
		"compliant_devices":  compliantDevices,
		"compliance_rate":    float64(compliantDevices) / float64(totalDevices) * 100,
		"average_score":      avgScore,
		"total_drift_events": len(data.DriftEvents),
	}

	return reports.ReportSection{
		ID:       "compliance-overview",
		Title:    "Compliance Overview",
		Type:     reports.SectionTypeKPI,
		Content:  content,
		Priority: 1,
	}
}

// generateDriftSummarySection creates the drift summary section
func (p *Processor) generateDriftSummarySection(data reports.ReportData) reports.ReportSection {
	// Categorize drift events by severity
	severityCount := make(map[drift.Severity]int)
	for _, event := range data.DriftEvents {
		severityCount[event.Severity]++
	}

	content := map[string]interface{}{
		"critical_events": severityCount[drift.Critical],
		"warning_events":  severityCount[drift.Warning],
		"info_events":     severityCount[drift.Info],
		"total_events":    len(data.DriftEvents),
	}

	return reports.ReportSection{
		ID:       "drift-summary",
		Title:    "Configuration Drift Summary",
		Type:     reports.SectionTypeKPI,
		Content:  content,
		Priority: 2,
	}
}

// generateDeviceComplianceSection creates the device compliance section
func (p *Processor) generateDeviceComplianceSection(data reports.ReportData, includeDetails bool) reports.ReportSection {
	// Sort devices by compliance score (lowest first)
	type deviceInfo struct {
		DeviceID        string
		ComplianceScore float64
		RiskLevel       string
		DriftEvents     int
	}

	devices := make([]deviceInfo, 0, len(data.DeviceStats))
	for deviceID, stats := range data.DeviceStats {
		devices = append(devices, deviceInfo{
			DeviceID:        deviceID,
			ComplianceScore: stats.ComplianceScore,
			RiskLevel:       string(stats.RiskLevel),
			DriftEvents:     stats.DriftEventCount,
		})
	}

	sort.Slice(devices, func(i, j int) bool {
		return devices[i].ComplianceScore < devices[j].ComplianceScore
	})

	var content interface{}
	if includeDetails {
		// Include detailed table
		headers := []string{"Device ID", "Compliance Score", "Risk Level", "Drift Events"}
		rows := make([][]interface{}, len(devices))
		
		for i, device := range devices {
			rows[i] = []interface{}{
				device.DeviceID,
				fmt.Sprintf("%.2f", device.ComplianceScore),
				device.RiskLevel,
				device.DriftEvents,
			}
		}

		content = map[string]interface{}{
			"headers": headers,
			"rows":    rows,
		}
	} else {
		// Summary only
		content = fmt.Sprintf("Analyzed %d devices. Top 3 non-compliant devices need attention.", len(devices))
	}

	return reports.ReportSection{
		ID:       "device-compliance",
		Title:    "Device Compliance Details",
		Type:     reports.SectionTypeTable,
		Content:  content,
		Priority: 3,
	}
}

// generateKPISection creates the KPI section for executive dashboard
func (p *Processor) generateKPISection(data reports.ReportData) reports.ReportSection {
	// Calculate key performance indicators
	totalDevices := len(data.DeviceStats)
	highRiskDevices := 0
	avgComplianceScore := 0.0
	
	for _, stats := range data.DeviceStats {
		avgComplianceScore += stats.ComplianceScore
		if stats.RiskLevel == reports.RiskLevelHigh || stats.RiskLevel == reports.RiskLevelCritical {
			highRiskDevices++
		}
	}
	
	if totalDevices > 0 {
		avgComplianceScore /= float64(totalDevices)
	}

	content := map[string]interface{}{
		"total_devices":         totalDevices,
		"high_risk_devices":     highRiskDevices,
		"average_compliance":    avgComplianceScore,
		"total_drift_events":    len(data.DriftEvents),
		"critical_drift_events": p.countEventsBySeverity(data.DriftEvents, drift.Critical),
	}

	return reports.ReportSection{
		ID:       "kpis",
		Title:    "Key Performance Indicators",
		Type:     reports.SectionTypeKPI,
		Content:  content,
		Priority: 1,
	}
}

// generateTrendsSection creates the trends analysis section
func (p *Processor) generateTrendsSection(data reports.ReportData) reports.ReportSection {
	// Analyze trends from trend data
	trendAnalysis := make(map[string]string)
	
	for metric, trends := range data.TrendData {
		if len(trends) >= 2 {
			firstValue := trends[0].Value
			lastValue := trends[len(trends)-1].Value
			
			var direction string
			if lastValue > firstValue*1.05 {
				direction = "improving"
			} else if lastValue < firstValue*0.95 {
				direction = "declining"
			} else {
				direction = "stable"
			}
			
			trendAnalysis[metric] = direction
		}
	}

	content := map[string]interface{}{
		"trend_analysis": trendAnalysis,
		"period_days":    int(data.TimeRange.End.Sub(data.TimeRange.Start).Hours() / 24),
	}

	return reports.ReportSection{
		ID:       "trends",
		Title:    "Trend Analysis",
		Type:     reports.SectionTypeText,
		Content:  content,
		Priority: 2,
	}
}

// generateRiskAssessmentSection creates the risk assessment section
func (p *Processor) generateRiskAssessmentSection(data reports.ReportData) reports.ReportSection {
	// Calculate risk distribution
	riskCounts := make(map[reports.RiskLevel]int)
	for _, stats := range data.DeviceStats {
		riskCounts[stats.RiskLevel]++
	}

	content := map[string]interface{}{
		"critical_risk": riskCounts[reports.RiskLevelCritical],
		"high_risk":     riskCounts[reports.RiskLevelHigh],
		"medium_risk":   riskCounts[reports.RiskLevelMedium],
		"low_risk":      riskCounts[reports.RiskLevelLow],
		"total_devices": len(data.DeviceStats),
	}

	return reports.ReportSection{
		ID:       "risk-assessment",
		Title:    "Risk Assessment",
		Type:     reports.SectionTypeKPI,
		Content:  content,
		Priority: 3,
	}
}

// Helper functions for generating charts and filtering data

func (p *Processor) generateComplianceChart(data reports.ReportData) *reports.ChartData {
	if trends, exists := data.TrendData["compliance_score"]; exists && len(trends) > 0 {
		series := make([]reports.DataPoint, len(trends))
		for i, trend := range trends {
			series[i] = reports.DataPoint{
				X: trend.Timestamp,
				Y: trend.Value,
			}
		}

		return &reports.ChartData{
			ID:    "compliance-trend",
			Type:  reports.ChartTypeLine,
			Title: "Compliance Score Trend",
			Series: []reports.SeriesData{
				{
					Name: "Compliance Score",
					Data: series,
				},
			},
			XAxis: reports.AxisConfig{Title: "Time", Type: "time"},
			YAxis: reports.AxisConfig{Title: "Score", Type: "numeric"},
		}
	}
	return nil
}

func (p *Processor) generateTrendChart(data reports.ReportData) *reports.ChartData {
	// Similar to compliance chart but with multiple series
	return p.generateComplianceChart(data)
}

func (p *Processor) generateRiskDistributionChart(data reports.ReportData) *reports.ChartData {
	riskCounts := make(map[reports.RiskLevel]int)
	for _, stats := range data.DeviceStats {
		riskCounts[stats.RiskLevel]++
	}

	series := make([]reports.DataPoint, 0)
	for risk, count := range riskCounts {
		series = append(series, reports.DataPoint{
			X:     string(risk),
			Y:     float64(count),
			Label: fmt.Sprintf("%d devices", count),
		})
	}

	return &reports.ChartData{
		ID:    "risk-distribution",
		Type:  reports.ChartTypePie,
		Title: "Device Risk Distribution",
		Series: []reports.SeriesData{
			{
				Name: "Risk Levels",
				Data: series,
			},
		},
	}
}

func (p *Processor) generateDriftTimelineChart(events []drift.DriftEvent) *reports.ChartData {
	if len(events) == 0 {
		return nil
	}

	// Group events by day
	dailyCounts := make(map[string]int)
	for _, event := range events {
		day := event.Timestamp.Format("2006-01-02")
		dailyCounts[day]++
	}

	// Convert to sorted series
	days := make([]string, 0, len(dailyCounts))
	for day := range dailyCounts {
		days = append(days, day)
	}
	sort.Strings(days)

	series := make([]reports.DataPoint, len(days))
	for i, day := range days {
		parsedTime, _ := time.Parse("2006-01-02", day)
		series[i] = reports.DataPoint{
			X: parsedTime,
			Y: float64(dailyCounts[day]),
		}
	}

	return &reports.ChartData{
		ID:    "drift-timeline",
		Type:  reports.ChartTypeLine,
		Title: "Drift Events Timeline",
		Series: []reports.SeriesData{
			{
				Name: "Daily Drift Events",
				Data: series,
			},
		},
		XAxis: reports.AxisConfig{Title: "Date", Type: "time"},
		YAxis: reports.AxisConfig{Title: "Events", Type: "numeric"},
	}
}

func (p *Processor) filterEventsBySeverity(events []drift.DriftEvent, severityFilter string) []drift.DriftEvent {
	var filtered []drift.DriftEvent
	var targetSeverity drift.Severity

	switch severityFilter {
	case "critical":
		targetSeverity = drift.Critical
	case "warning":
		targetSeverity = drift.Warning
	case "info":
		targetSeverity = drift.Info
	default:
		return events // No filtering
	}

	for _, event := range events {
		if event.Severity == targetSeverity {
			filtered = append(filtered, event)
		}
	}

	return filtered
}

func (p *Processor) countEventsBySeverity(events []drift.DriftEvent, severity drift.Severity) int {
	count := 0
	for _, event := range events {
		if event.Severity == severity {
			count++
		}
	}
	return count
}

func (p *Processor) generateDriftOverviewSection(events []drift.DriftEvent) reports.ReportSection {
	severityCount := make(map[drift.Severity]int)
	for _, event := range events {
		severityCount[event.Severity]++
	}

	content := map[string]interface{}{
		"total_events":    len(events),
		"critical_events": severityCount[drift.Critical],
		"warning_events":  severityCount[drift.Warning],
		"info_events":     severityCount[drift.Info],
	}

	return reports.ReportSection{
		ID:       "drift-overview",
		Title:    "Drift Events Overview",
		Type:     reports.SectionTypeKPI,
		Content:  content,
		Priority: 1,
	}
}

func (p *Processor) generateDriftEventsSection(events []drift.DriftEvent) reports.ReportSection {
	// Create table of recent events (limited to avoid huge reports)
	maxEvents := 50
	if len(events) > maxEvents {
		events = events[:maxEvents]
	}

	headers := []string{"Timestamp", "Device ID", "Severity", "Description"}
	rows := make([][]interface{}, len(events))

	for i, event := range events {
		rows[i] = []interface{}{
			event.Timestamp.Format("2006-01-02 15:04:05"),
			event.DeviceID,
			string(event.Severity),
			event.Description,
		}
	}

	content := map[string]interface{}{
		"headers": headers,
		"rows":    rows,
	}

	return reports.ReportSection{
		ID:       "drift-events",
		Title:    fmt.Sprintf("Recent Drift Events (showing %d of %d)", len(rows), len(events)),
		Type:     reports.SectionTypeTable,
		Content:  content,
		Priority: 2,
	}
}

func (p *Processor) generateDriftEventsByDeviceSection(events []drift.DriftEvent) reports.ReportSection {
	// Group events by device
	deviceEvents := make(map[string][]drift.DriftEvent)
	for _, event := range events {
		deviceEvents[event.DeviceID] = append(deviceEvents[event.DeviceID], event)
	}

	// Create summary by device
	headers := []string{"Device ID", "Total Events", "Critical", "Warning", "Info"}
	rows := make([][]interface{}, 0, len(deviceEvents))

	for deviceID, devEvents := range deviceEvents {
		severityCount := make(map[drift.Severity]int)
		for _, event := range devEvents {
			severityCount[event.Severity]++
		}

		rows = append(rows, []interface{}{
			deviceID,
			len(devEvents),
			severityCount[drift.Critical],
			severityCount[drift.Warning],
			severityCount[drift.Info],
		})
	}

	// Sort by total events descending
	sort.Slice(rows, func(i, j int) bool {
		return rows[i][1].(int) > rows[j][1].(int)
	})

	content := map[string]interface{}{
		"headers": headers,
		"rows":    rows,
	}

	return reports.ReportSection{
		ID:       "drift-events-by-device",
		Title:    "Drift Events by Device",
		Type:     reports.SectionTypeTable,
		Content:  content,
		Priority: 2,
	}
}