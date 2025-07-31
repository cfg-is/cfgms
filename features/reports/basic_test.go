package reports

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestReportTypes validates that all report types are properly defined
func TestReportTypes(t *testing.T) {
	types := []ReportType{
		ReportTypeCompliance,
		ReportTypeExecutive,
		ReportTypeDrift,
		ReportTypeOperational,
		ReportTypeCustom,
	}

	// Ensure all types have string values
	for _, reportType := range types {
		assert.NotEmpty(t, string(reportType))
	}

	// Test specific values
	assert.Equal(t, "compliance", string(ReportTypeCompliance))
	assert.Equal(t, "executive", string(ReportTypeExecutive))
	assert.Equal(t, "drift", string(ReportTypeDrift))
}

// TestExportFormats validates that all export formats are properly defined
func TestExportFormats(t *testing.T) {
	formats := []ExportFormat{
		FormatJSON,
		FormatCSV,
		FormatPDF,
		FormatExcel,
		FormatHTML,
	}

	// Ensure all formats have string values
	for _, format := range formats {
		assert.NotEmpty(t, string(format))
	}

	// Test specific values
	assert.Equal(t, "json", string(FormatJSON))
	assert.Equal(t, "csv", string(FormatCSV))
	assert.Equal(t, "pdf", string(FormatPDF))
	assert.Equal(t, "xlsx", string(FormatExcel))
	assert.Equal(t, "html", string(FormatHTML))
}

// TestTimeRange validates TimeRange functionality
func TestTimeRange(t *testing.T) {
	now := time.Now()
	start := now.Add(-24 * time.Hour)
	
	timeRange := TimeRange{
		Start: start,
		End:   now,
	}

	assert.True(t, timeRange.Start.Before(timeRange.End))
	assert.Equal(t, 24*time.Hour, timeRange.End.Sub(timeRange.Start))
}

// TestReportRequest validates ReportRequest structure
func TestReportRequest(t *testing.T) {
	req := ReportRequest{
		Type:      ReportTypeCompliance,
		Template:  "compliance-summary",
		TimeRange: TimeRange{
			Start: time.Now().Add(-7 * 24 * time.Hour),
			End:   time.Now(),
		},
		DeviceIDs: []string{"device1", "device2"},
		Format:    FormatJSON,
		Title:     "Test Compliance Report",
		Parameters: map[string]any{
			"include_details": true,
		},
	}

	assert.Equal(t, ReportTypeCompliance, req.Type)
	assert.Equal(t, "compliance-summary", req.Template)  
	assert.Equal(t, FormatJSON, req.Format)
	assert.Equal(t, "Test Compliance Report", req.Title)
	assert.Len(t, req.DeviceIDs, 2)
	assert.Contains(t, req.DeviceIDs, "device1")
	assert.Contains(t, req.DeviceIDs, "device2")
	assert.True(t, req.Parameters["include_details"].(bool))
}

// TestTrendDirection validates trend direction enumeration
func TestTrendDirection(t *testing.T) {
	directions := []TrendDirection{
		TrendImproving,
		TrendStable,
		TrendDeclining,
		TrendUnknown,
	}

	for _, direction := range directions {
		assert.NotEmpty(t, string(direction))
	}

	assert.Equal(t, "improving", string(TrendImproving))
	assert.Equal(t, "stable", string(TrendStable))
	assert.Equal(t, "declining", string(TrendDeclining))
	assert.Equal(t, "unknown", string(TrendUnknown))
}

// TestRiskLevel validates risk level enumeration
func TestRiskLevel(t *testing.T) {
	levels := []RiskLevel{
		RiskLevelLow,
		RiskLevelMedium,
		RiskLevelHigh,
		RiskLevelCritical,
	}

	for _, level := range levels {
		assert.NotEmpty(t, string(level))
	}

	assert.Equal(t, "low", string(RiskLevelLow))
	assert.Equal(t, "medium", string(RiskLevelMedium))
	assert.Equal(t, "high", string(RiskLevelHigh))
	assert.Equal(t, "critical", string(RiskLevelCritical))
}

// TestReportSummary validates report summary structure
func TestReportSummary(t *testing.T) {
	summary := ReportSummary{
		DevicesAnalyzed:    10,
		DriftEventsTotal:   25,
		ComplianceScore:    0.85,
		CriticalIssues:     2,
		TrendDirection:     TrendImproving,
		KeyInsights:        []string{"System stability improved", "Fewer critical alerts"},
		RecommendedActions: []string{"Review non-compliant devices", "Update security policies"},
	}

	assert.Equal(t, 10, summary.DevicesAnalyzed)
	assert.Equal(t, 25, summary.DriftEventsTotal)
	assert.Equal(t, 0.85, summary.ComplianceScore)
	assert.Equal(t, 2, summary.CriticalIssues)
	assert.Equal(t, TrendImproving, summary.TrendDirection)
	assert.Len(t, summary.KeyInsights, 2)
	assert.Len(t, summary.RecommendedActions, 2)
}

// TestChartData validates chart data structure
func TestChartData(t *testing.T) {
	chartData := ChartData{
		ID:    "compliance-trend",
		Type:  ChartTypeLine,
		Title: "Compliance Score Over Time",
		Series: []SeriesData{
			{
				Name: "Compliance Score",
				Data: []DataPoint{
					{X: time.Now().Add(-24 * time.Hour), Y: 0.80},
					{X: time.Now(), Y: 0.85},
				},
				Color: "#007acc",
			},
		},
		XAxis: AxisConfig{
			Title: "Time",
			Type:  "time",
		},
		YAxis: AxisConfig{
			Title: "Score",
			Type:  "numeric",
		},
	}

	assert.Equal(t, "compliance-trend", chartData.ID)
	assert.Equal(t, ChartTypeLine, chartData.Type)
	assert.Equal(t, "Compliance Score Over Time", chartData.Title)
	assert.Len(t, chartData.Series, 1)
	assert.Equal(t, "Compliance Score", chartData.Series[0].Name)
	assert.Len(t, chartData.Series[0].Data, 2)
	assert.Equal(t, 0.80, chartData.Series[0].Data[0].Y)
	assert.Equal(t, 0.85, chartData.Series[0].Data[1].Y)
}