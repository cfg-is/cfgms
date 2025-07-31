package reports

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/features/steward/dna/drift"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
)

// ReportType defines the type of report to generate
type ReportType string

const (
	ReportTypeCompliance  ReportType = "compliance"
	ReportTypeExecutive   ReportType = "executive"
	ReportTypeDrift       ReportType = "drift"
	ReportTypeOperational ReportType = "operational"
	ReportTypeCustom      ReportType = "custom"
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

// ReportRequest contains all parameters needed to generate a report
type ReportRequest struct {
	Type       ReportType        `json:"type"`
	Template   string            `json:"template"`
	TimeRange  TimeRange         `json:"time_range"`
	DeviceIDs  []string          `json:"device_ids,omitempty"`
	TenantIDs  []string          `json:"tenant_ids,omitempty"`
	Format     ExportFormat      `json:"format"`
	Parameters map[string]any    `json:"parameters,omitempty"`
	Title      string            `json:"title,omitempty"`
	Subtitle   string            `json:"subtitle,omitempty"`
}

// TimeRange specifies the time period for report data
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

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

// TemplateInfo describes available report templates
type TemplateInfo struct {
	Name        string            `json:"name"`
	Type        ReportType        `json:"type"`
	Description string            `json:"description"`
	Parameters  []TemplateParam   `json:"parameters"`
	Formats     []ExportFormat    `json:"supported_formats"`
}

// TemplateParam describes a template parameter
type TemplateParam struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     any    `json:"default,omitempty"`
}

// ReportData aggregates data needed for report generation
type ReportData struct {
	DNARecords   []storage.DNARecord `json:"dna_records"`
	DriftEvents  []drift.DriftEvent  `json:"drift_events"`
	TimeRange    TimeRange           `json:"time_range"`
	DeviceStats  map[string]DeviceStats `json:"device_stats"`
	TrendData    map[string][]TrendPoint `json:"trend_data"`
}

// DeviceStats contains statistics for a specific device
type DeviceStats struct {
	DeviceID        string    `json:"device_id"`
	LastSeen        time.Time `json:"last_seen"`
	DNARecordCount  int       `json:"dna_record_count"`
	DriftEventCount int       `json:"drift_event_count"`
	ComplianceScore float64   `json:"compliance_score"`
	RiskLevel       RiskLevel `json:"risk_level"`
	ChangeFrequency float64   `json:"change_frequency"` // changes per day
}

// TrendPoint represents a point in time series data
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     float64   `json:"value"`
	Label     string    `json:"label,omitempty"`
}

// RiskLevel categorizes device risk levels
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// DataQuery specifies parameters for querying report data
type DataQuery struct {
	TimeRange TimeRange
	DeviceIDs []string
	TenantIDs []string
	Filters   map[string]string
	Limit     int
	Offset    int
}

// ReportEngine defines the interface for generating reports
type ReportEngine interface {
	GenerateReport(ctx context.Context, req ReportRequest) (*Report, error)
	GetAvailableTemplates() []TemplateInfo
	ValidateTemplate(template string) error
	ValidateRequest(req ReportRequest) error
}

// DataProvider defines the interface for retrieving report data
type DataProvider interface {
	GetDNAData(ctx context.Context, query DataQuery) ([]storage.DNARecord, error)
	GetDriftEvents(ctx context.Context, query DataQuery) ([]drift.DriftEvent, error)
	GetDeviceStats(ctx context.Context, deviceIDs []string, timeRange TimeRange) (map[string]DeviceStats, error)
	GetTrendData(ctx context.Context, metric string, query DataQuery) ([]TrendPoint, error)
}

// Exporter defines the interface for exporting reports in different formats
type Exporter interface {
	Export(ctx context.Context, report *Report, format ExportFormat) ([]byte, error)
	SupportedFormats() []ExportFormat
}

// TemplateProcessor defines the interface for processing report templates
type TemplateProcessor interface {
	ProcessTemplate(ctx context.Context, templateName string, data ReportData, params map[string]any) (*Report, error)
	GetTemplateInfo(templateName string) (*TemplateInfo, error)
	ValidateTemplate(templateName string) error
}

// ReportCache defines the interface for caching generated reports
type ReportCache interface {
	Get(ctx context.Context, key string) (*Report, error)
	Set(ctx context.Context, key string, report *Report, ttl time.Duration) error
	Delete(ctx context.Context, key string) error
	Clear(ctx context.Context) error
}