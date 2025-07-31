package exporters

import (
	"context"
	"time"
)

// ExportFormat defines supported export formats
type ExportFormat string

const (
	FormatJSON  ExportFormat = "json"
	FormatCSV   ExportFormat = "csv"
	FormatPDF   ExportFormat = "pdf"
	FormatExcel ExportFormat = "xlsx"
	FormatHTML  ExportFormat = "html"
)

// Report represents a generated report with metadata and content
type Report struct {
	ID          string            `json:"id"`
	Type        ReportType        `json:"type"`
	Title       string            `json:"title"`
	Subtitle    string            `json:"subtitle,omitempty"`
	GeneratedAt time.Time         `json:"generated_at"`
	TimeRange   TimeRange         `json:"time_range"`
	Metadata    ReportMetadata    `json:"metadata"`
	Sections    []ReportSection   `json:"sections"`
	Charts      []ChartData       `json:"charts,omitempty"`
	Summary     ReportSummary     `json:"summary"`
}

// ReportType defines the type of report to generate
type ReportType string

const (
	ReportTypeCompliance  ReportType = "compliance"
	ReportTypeExecutive   ReportType = "executive"
	ReportTypeDrift       ReportType = "drift"
	ReportTypeOperational ReportType = "operational"
	ReportTypeCustom      ReportType = "custom"
)

// TimeRange specifies the time period for report data
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ReportMetadata contains metadata about the report generation
type ReportMetadata struct {
	Template      string        `json:"template"`
	DeviceCount   int           `json:"device_count"`
	DataPoints    int           `json:"data_points"`
	GenerationMS  int64         `json:"generation_ms"`
	CacheHit      bool          `json:"cache_hit"`
	Parameters    map[string]any `json:"parameters,omitempty"`
}

// ReportSection represents a section of a report
type ReportSection struct {
	ID       string      `json:"id"`
	Title    string      `json:"title"`
	Type     SectionType `json:"type"`
	Content  any         `json:"content"`
	Priority int         `json:"priority"`
}

// SectionType defines the type of content in a report section
type SectionType string

const (
	SectionTypeText       SectionType = "text"
	SectionTypeTable      SectionType = "table"
	SectionTypeChart      SectionType = "chart"
	SectionTypeKPI        SectionType = "kpi"
	SectionTypeAlert      SectionType = "alert"
	SectionTypeTimeline   SectionType = "timeline"
)

// ReportSummary provides high-level insights about the report data
type ReportSummary struct {
	DevicesAnalyzed    int                    `json:"devices_analyzed"`
	DriftEventsTotal   int                    `json:"drift_events_total"`
	ComplianceScore    float64               `json:"compliance_score"`
	CriticalIssues     int                   `json:"critical_issues"`
	TrendDirection     TrendDirection        `json:"trend_direction"`
	KeyInsights        []string              `json:"key_insights"`
	RecommendedActions []string              `json:"recommended_actions"`
}

// TrendDirection indicates whether metrics are improving or declining
type TrendDirection string

const (
	TrendImproving TrendDirection = "improving"
	TrendStable    TrendDirection = "stable"
	TrendDeclining TrendDirection = "declining"
	TrendUnknown   TrendDirection = "unknown"
)

// ChartData represents data for visualization
type ChartData struct {
	ID     string    `json:"id"`
	Type   ChartType `json:"type"`
	Title  string    `json:"title"`
	Series []SeriesData `json:"series"`
	XAxis  AxisConfig `json:"x_axis"`
	YAxis  AxisConfig `json:"y_axis"`
	Config ChartConfig `json:"config,omitempty"`
}

// ChartType defines supported chart types
type ChartType string

const (
	ChartTypeLine      ChartType = "line"
	ChartTypeBar       ChartType = "bar"
	ChartTypePie       ChartType = "pie"
	ChartTypeScatter   ChartType = "scatter"
	ChartTypeHeatmap   ChartType = "heatmap"
	ChartTypeHistogram ChartType = "histogram"
)

// SeriesData represents a data series in a chart
type SeriesData struct {
	Name  string      `json:"name"`
	Data  []DataPoint `json:"data"`
	Color string      `json:"color,omitempty"`
}

// DataPoint represents a single data point in a series
type DataPoint struct {
	X     any     `json:"x"`     // time, category, or numeric value
	Y     float64 `json:"y"`     // numeric value
	Label string  `json:"label,omitempty"`
	Extra map[string]any `json:"extra,omitempty"`
}

// AxisConfig configures chart axes
type AxisConfig struct {
	Title  string `json:"title"`
	Type   string `json:"type"` // "time", "category", "numeric"
	Format string `json:"format,omitempty"`
}

// ChartConfig provides additional chart configuration
type ChartConfig struct {
	ShowLegend bool        `json:"show_legend"`
	Colors     []string    `json:"colors,omitempty"`
	Height     int         `json:"height,omitempty"`
	Options    map[string]any `json:"options,omitempty"`
}

// Exporter defines the interface for exporting reports in different formats
type Exporter interface {
	Export(ctx context.Context, report *Report, format ExportFormat) ([]byte, error)
	SupportedFormats() []ExportFormat
}