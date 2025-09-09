package templates

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Processor implements the interfaces.TemplateProcessor interface
type Processor struct {
	logger    logging.Logger
	templates map[string]TemplateDefinition
}

// TemplateDefinition defines how to process a specific template
type TemplateDefinition struct {
	Name        string
	Type        interfaces.ReportType
	Description string
	Parameters  []interfaces.TemplateParam
	Formats     []interfaces.ExportFormat
	Generator   func(ctx context.Context, data interfaces.ReportData, params map[string]any) (*interfaces.Report, error)
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
func (p *Processor) ProcessTemplate(ctx context.Context, templateName string, data interfaces.ReportData, params map[string]any) (*interfaces.Report, error) {
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
func (p *Processor) GetTemplateInfo(templateName string) (*interfaces.TemplateInfo, error) {
	template, exists := p.templates[templateName]
	if !exists {
		return nil, fmt.Errorf("template not found: %s", templateName)
	}

	return &interfaces.TemplateInfo{
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
			interfaces.FormatCSV,
		},
		Generator: p.generateComplianceSummary,
	}

	// Executive Dashboard Template
	p.templates["executive-dashboard"] = TemplateDefinition{
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
		},
		Generator: p.generateExecutiveDashboard,
	}

	// Drift Analysis Template
	p.templates["drift-analysis"] = TemplateDefinition{
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
		Generator: p.generateDriftAnalysis,
	}
}

// generateComplianceSummary generates a compliance summary report
func (p *Processor) generateComplianceSummary(ctx context.Context, data interfaces.ReportData, params map[string]any) (*interfaces.Report, error) {
	report := &interfaces.Report{
		Type:      interfaces.ReportTypeCompliance,
		Title:     "Compliance Summary Report",
		Subtitle:  fmt.Sprintf("Analysis period: %s - %s", 
			data.TimeRange.Start.Format("Jan 2, 2006"), 
			data.TimeRange.End.Format("Jan 2, 2006")),
		TimeRange: data.TimeRange,
		Sections:  make([]interfaces.ReportSection, 0),
		Charts:    make([]interfaces.ChartData, 0),
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
func (p *Processor) generateExecutiveDashboard(ctx context.Context, data interfaces.ReportData, params map[string]any) (*interfaces.Report, error) {
	report := &interfaces.Report{
		Type:      interfaces.ReportTypeExecutive,
		Title:     "Executive Dashboard",
		Subtitle:  "Configuration Management Overview",
		TimeRange: data.TimeRange,
		Sections:  make([]interfaces.ReportSection, 0),
		Charts:    make([]interfaces.ChartData, 0),
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
func (p *Processor) generateDriftAnalysis(ctx context.Context, data interfaces.ReportData, params map[string]any) (*interfaces.Report, error) {
	report := &interfaces.Report{
		Type:      interfaces.ReportTypeDrift,
		Title:     "Configuration Drift Analysis",
		Subtitle:  "Detailed drift event analysis and recommendations",
		TimeRange: data.TimeRange,
		Sections:  make([]interfaces.ReportSection, 0),
		Charts:    make([]interfaces.ChartData, 0),
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
func (p *Processor) generateComplianceOverview(data interfaces.ReportData) interfaces.ReportSection {
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

	return interfaces.ReportSection{
		ID:       "compliance-overview",
		Title:    "Compliance Overview",
		Type:     interfaces.SectionTypeKPI,
		Content:  content,
		Priority: 1,
	}
}

// generateDriftSummarySection creates the drift summary section
func (p *Processor) generateDriftSummarySection(data interfaces.ReportData) interfaces.ReportSection {
	// Categorize drift events by severity
	severityCount := make(map[drift.DriftSeverity]int)
	for _, event := range data.DriftEvents {
		severityCount[event.Severity]++
	}

	content := map[string]interface{}{
		"critical_events": severityCount[drift.SeverityCritical],
		"warning_events":  severityCount[drift.SeverityWarning],
		"info_events":     severityCount[drift.SeverityInfo],
		"total_events":    len(data.DriftEvents),
	}

	return interfaces.ReportSection{
		ID:       "drift-summary",
		Title:    "Configuration Drift Summary",
		Type:     interfaces.SectionTypeKPI,
		Content:  content,
		Priority: 2,
	}
}

// generateDeviceComplianceSection creates the device compliance section
func (p *Processor) generateDeviceComplianceSection(data interfaces.ReportData, includeDetails bool) interfaces.ReportSection {
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

	return interfaces.ReportSection{
		ID:       "device-compliance",
		Title:    "Device Compliance Details",
		Type:     interfaces.SectionTypeTable,
		Content:  content,
		Priority: 3,
	}
}

// generateKPISection creates the KPI section for executive dashboard
func (p *Processor) generateKPISection(data interfaces.ReportData) interfaces.ReportSection {
	// Calculate key performance indicators
	totalDevices := len(data.DeviceStats)
	highRiskDevices := 0
	avgComplianceScore := 0.0
	
	for _, stats := range data.DeviceStats {
		avgComplianceScore += stats.ComplianceScore
		if stats.RiskLevel == interfaces.RiskLevelHigh || stats.RiskLevel == interfaces.RiskLevelCritical {
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
		"critical_drift_events": p.countEventsBySeverity(data.DriftEvents, drift.SeverityCritical),
	}

	return interfaces.ReportSection{
		ID:       "kpis",
		Title:    "Key Performance Indicators",
		Type:     interfaces.SectionTypeKPI,
		Content:  content,
		Priority: 1,
	}
}

// generateTrendsSection creates the trends analysis section
func (p *Processor) generateTrendsSection(data interfaces.ReportData) interfaces.ReportSection {
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

	return interfaces.ReportSection{
		ID:       "trends",
		Title:    "Trend Analysis",
		Type:     interfaces.SectionTypeText,
		Content:  content,
		Priority: 2,
	}
}

// generateRiskAssessmentSection creates the risk assessment section
func (p *Processor) generateRiskAssessmentSection(data interfaces.ReportData) interfaces.ReportSection {
	// Calculate risk distribution
	riskCounts := make(map[interfaces.RiskLevel]int)
	for _, stats := range data.DeviceStats {
		riskCounts[stats.RiskLevel]++
	}

	content := map[string]interface{}{
		"critical_risk": riskCounts[interfaces.RiskLevelCritical],
		"high_risk":     riskCounts[interfaces.RiskLevelHigh],
		"medium_risk":   riskCounts[interfaces.RiskLevelMedium],
		"low_risk":      riskCounts[interfaces.RiskLevelLow],
		"total_devices": len(data.DeviceStats),
	}

	return interfaces.ReportSection{
		ID:       "risk-assessment",
		Title:    "Risk Assessment",
		Type:     interfaces.SectionTypeKPI,
		Content:  content,
		Priority: 3,
	}
}

// Helper functions for generating charts and filtering data

func (p *Processor) generateComplianceChart(data interfaces.ReportData) *interfaces.ChartData {
	if trends, exists := data.TrendData["compliance_score"]; exists && len(trends) > 0 {
		series := make([]interfaces.DataPoint, len(trends))
		for i, trend := range trends {
			series[i] = interfaces.DataPoint{
				X: trend.Timestamp,
				Y: trend.Value,
			}
		}

		return &interfaces.ChartData{
			ID:    "compliance-trend",
			Type:  interfaces.ChartTypeLine,
			Title: "Compliance Score Trend",
			Series: []interfaces.SeriesData{
				{
					Name: "Compliance Score",
					Data: series,
				},
			},
			XAxis: interfaces.AxisConfig{Title: "Time", Type: "time"},
			YAxis: interfaces.AxisConfig{Title: "Score", Type: "numeric"},
		}
	}
	return nil
}

func (p *Processor) generateTrendChart(data interfaces.ReportData) *interfaces.ChartData {
	// Similar to compliance chart but with multiple series
	return p.generateComplianceChart(data)
}

func (p *Processor) generateRiskDistributionChart(data interfaces.ReportData) *interfaces.ChartData {
	riskCounts := make(map[interfaces.RiskLevel]int)
	for _, stats := range data.DeviceStats {
		riskCounts[stats.RiskLevel]++
	}

	series := make([]interfaces.DataPoint, 0)
	for risk, count := range riskCounts {
		series = append(series, interfaces.DataPoint{
			X:     string(risk),
			Y:     float64(count),
			Label: fmt.Sprintf("%d devices", count),
		})
	}

	return &interfaces.ChartData{
		ID:    "risk-distribution",
		Type:  interfaces.ChartTypePie,
		Title: "Device Risk Distribution",
		Series: []interfaces.SeriesData{
			{
				Name: "Risk Levels",
				Data: series,
			},
		},
	}
}

func (p *Processor) generateDriftTimelineChart(events []drift.DriftEvent) *interfaces.ChartData {
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

	series := make([]interfaces.DataPoint, len(days))
	for i, day := range days {
		parsedTime, _ := time.Parse("2006-01-02", day)
		series[i] = interfaces.DataPoint{
			X: parsedTime,
			Y: float64(dailyCounts[day]),
		}
	}

	return &interfaces.ChartData{
		ID:    "drift-timeline",
		Type:  interfaces.ChartTypeLine,
		Title: "Drift Events Timeline",
		Series: []interfaces.SeriesData{
			{
				Name: "Daily Drift Events",
				Data: series,
			},
		},
		XAxis: interfaces.AxisConfig{Title: "Date", Type: "time"},
		YAxis: interfaces.AxisConfig{Title: "Events", Type: "numeric"},
	}
}

func (p *Processor) filterEventsBySeverity(events []drift.DriftEvent, severityFilter string) []drift.DriftEvent {
	var filtered []drift.DriftEvent
	var targetSeverity drift.DriftSeverity

	switch severityFilter {
	case "critical":
		targetSeverity = drift.SeverityCritical
	case "warning":
		targetSeverity = drift.SeverityWarning
	case "info":
		targetSeverity = drift.SeverityInfo
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

func (p *Processor) countEventsBySeverity(events []drift.DriftEvent, severity drift.DriftSeverity) int {
	count := 0
	for _, event := range events {
		if event.Severity == severity {
			count++
		}
	}
	return count
}

func (p *Processor) generateDriftOverviewSection(events []drift.DriftEvent) interfaces.ReportSection {
	severityCount := make(map[drift.DriftSeverity]int)
	for _, event := range events {
		severityCount[event.Severity]++
	}

	content := map[string]interface{}{
		"total_events":    len(events),
		"critical_events": severityCount[drift.SeverityCritical],
		"warning_events":  severityCount[drift.SeverityWarning],
		"info_events":     severityCount[drift.SeverityInfo],
	}

	return interfaces.ReportSection{
		ID:       "drift-overview",
		Title:    "Drift Events Overview",
		Type:     interfaces.SectionTypeKPI,
		Content:  content,
		Priority: 1,
	}
}

func (p *Processor) generateDriftEventsSection(events []drift.DriftEvent) interfaces.ReportSection {
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

	return interfaces.ReportSection{
		ID:       "drift-events",
		Title:    fmt.Sprintf("Recent Drift Events (showing %d of %d)", len(rows), len(events)),
		Type:     interfaces.SectionTypeTable,
		Content:  content,
		Priority: 2,
	}
}

func (p *Processor) generateDriftEventsByDeviceSection(events []drift.DriftEvent) interfaces.ReportSection {
	// Group events by device
	deviceEvents := make(map[string][]drift.DriftEvent)
	for _, event := range events {
		deviceEvents[event.DeviceID] = append(deviceEvents[event.DeviceID], event)
	}

	// Create summary by device
	headers := []string{"Device ID", "Total Events", "Critical", "Warning", "Info"}
	rows := make([][]interface{}, 0, len(deviceEvents))

	for deviceID, devEvents := range deviceEvents {
		severityCount := make(map[drift.DriftSeverity]int)
		for _, event := range devEvents {
			severityCount[event.Severity]++
		}

		rows = append(rows, []interface{}{
			deviceID,
			len(devEvents),
			severityCount[drift.SeverityCritical],
			severityCount[drift.SeverityWarning],
			severityCount[drift.SeverityInfo],
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

	return interfaces.ReportSection{
		ID:       "drift-events-by-device",
		Title:    "Drift Events by Device",
		Type:     interfaces.SectionTypeTable,
		Content:  content,
		Priority: 2,
	}
}