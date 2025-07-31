# DNA Monitoring - Comprehensive Reporting System Design

## Overview
This document outlines the design for Story #81: implementing a comprehensive DNA monitoring and reporting system that builds upon the existing DNA collection, storage, and drift detection infrastructure.

## Architecture Overview

### Core Components

```
features/reports/
├── engine/          # Report generation engine
├── templates/       # Report templates (compliance, executive, drift)
├── exporters/       # Multi-format export (PDF, CSV, JSON)
├── scheduler/       # Automated report generation and distribution
├── dashboard/       # Real-time monitoring APIs
└── charts/          # Visualization data preparation
```

### Data Flow

1. **Data Sources** → DNA Storage + Drift Detection
2. **Report Engine** → Query data using existing storage APIs
3. **Template Processing** → Generate reports using template system
4. **Export Processing** → Convert to requested format (PDF/CSV/JSON)
5. **Distribution** → Schedule and deliver reports

## Component Design

### 1. Report Engine (`features/reports/engine/`)

**Core Interface:**
```go
type ReportEngine interface {
    GenerateReport(ctx context.Context, req ReportRequest) (*Report, error)
    GetAvailableTemplates() []TemplateInfo
    ValidateTemplate(template string) error
}

type ReportRequest struct {
    Type        ReportType        // compliance, executive, drift, custom
    Template    string           // template name or custom template
    TimeRange   TimeRange        // start/end times for data
    Devices     []string         // specific device IDs (optional)
    Tenants     []string         // tenant hierarchy filter
    Format      ExportFormat     // json, csv, pdf, excel
    Parameters  map[string]any   // template parameters
}
```

**Report Types:**
- **Compliance Reports**: Drift from baselines, compliance status
- **Executive Dashboards**: High-level trends and summaries
- **Drift Reports**: Detailed change analysis
- **Custom Reports**: User-defined template-based reports

### 2. Template System Integration (`features/reports/templates/`)

**Leverage Existing Templates:**
- Extend existing `features/templates/` system
- Add DNA-specific template functions
- Support conditional logic for different report types

**Template Categories:**
```
templates/reports/
├── compliance/      # Compliance officer reports
│   ├── drift-summary.html
│   ├── baseline-compliance.html
│   └── security-posture.html
├── executive/       # Executive dashboards
│   ├── overview.html
│   ├── trends.html
│   └── risk-summary.html
├── operational/     # Daily operations reports
│   ├── drift-details.html
│   ├── device-health.html
│   └── change-log.html
└── custom/          # User-defined templates
```

### 3. Export System (`features/reports/exporters/`)

**Multi-Format Support:**
```go
type Exporter interface {
    Export(ctx context.Context, report *Report, format ExportFormat) ([]byte, error)
    SupportedFormats() []ExportFormat
}

type ExportFormat string
const (
    FormatJSON  ExportFormat = "json"
    FormatCSV   ExportFormat = "csv" 
    FormatPDF   ExportFormat = "pdf"
    FormatExcel ExportFormat = "xlsx"
    FormatHTML  ExportFormat = "html"
)
```

**Implementation:**
- **JSON**: Native Go marshaling
- **CSV**: Tabular data extraction from report
- **PDF**: HTML-to-PDF conversion using wkhtmltopdf or similar
- **Excel**: XLSX generation for complex data tables
- **HTML**: Direct template rendering

### 4. Scheduling System (`features/reports/scheduler/`)

**Automated Generation:**
```go
type Scheduler interface {
    ScheduleReport(ctx context.Context, schedule ReportSchedule) error
    CancelSchedule(ctx context.Context, scheduleID string) error
    ListSchedules(ctx context.Context) ([]ReportSchedule, error)
}

type ReportSchedule struct {
    ID           string
    Name         string
    ReportRequest ReportRequest
    CronSchedule string           // "0 9 * * MON" (9am every Monday)
    Recipients   []Recipient      // email, webhook, file system
    Enabled      bool
}
```

**Distribution Methods:**
- **Email**: SMTP delivery with attachments
- **Webhooks**: HTTP POST to external systems
- **File System**: Save to configured directories
- **API Integration**: Push to external monitoring tools

### 5. Dashboard APIs (`features/reports/dashboard/`)

**Real-time Monitoring Endpoints:**
```go
// REST API endpoints under /api/v1/reports/
GET  /api/v1/reports/dashboard/overview        # Executive overview data
GET  /api/v1/reports/dashboard/trends          # Trend analysis data
GET  /api/v1/reports/dashboard/alerts          # Active drift alerts
GET  /api/v1/reports/drift/summary             # Drift summary stats
GET  /api/v1/reports/compliance/status         # Compliance status
POST /api/v1/reports/generate                  # Generate ad-hoc report
GET  /api/v1/reports/schedules                 # List scheduled reports
POST /api/v1/reports/schedules                 # Create report schedule
```

### 6. Visualization Support (`features/reports/charts/`)

**Chart Data Preparation:**
```go
type ChartData struct {
    Type   ChartType              // line, bar, pie, scatter
    Title  string
    Series []SeriesData
    XAxis  AxisConfig
    YAxis  AxisConfig
}

type SeriesData struct {
    Name   string
    Data   []DataPoint
    Color  string
}
```

**Supported Visualizations:**
- **Time Series**: DNA attribute changes over time
- **Bar Charts**: Device counts, drift categories
- **Pie Charts**: OS distribution, compliance status
- **Heat Maps**: Risk levels across device groups

## Integration with Existing Systems

### 1. DNA Storage Integration
```go
// Use existing storage Manager for data queries
func (e *reportEngine) queryDNAData(ctx context.Context, req DataQuery) ([]DNARecord, error) {
    return e.storageManager.QueryRecords(ctx, storage.QueryOptions{
        TimeRange: req.TimeRange,
        DeviceIDs: req.DeviceIDs,
        Metadata:  req.Filters,
    })
}
```

### 2. Drift Detection Integration
```go
// Use existing drift events for monitoring reports
func (e *reportEngine) getDriftEvents(ctx context.Context, timeRange TimeRange) ([]DriftEvent, error) {
    return e.driftDetector.GetEvents(ctx, drift.EventQuery{
        StartTime: timeRange.Start,
        EndTime:   timeRange.End,
        Severity:  []drift.Severity{drift.Critical, drift.Warning},
    })
}
```

### 3. Template System Extension
```go
// Extend existing template resolver with DNA functions
func (r *dnaTemplateResolver) ResolveDNAFunction(name string, args []any) (any, error) {
    switch name {
    case "drift_count":
        return r.getDriftCount(args[0].(time.Time), args[1].(time.Time))
    case "compliance_status":
        return r.getComplianceStatus(args[0].(string))
    // ... more DNA-specific functions
    }
}
```

## Performance Considerations

### 1. Report Caching
- Cache generated reports for common time ranges
- Invalidate cache when underlying DNA data changes
- Use content-addressable caching based on query parameters

### 2. Async Processing
- Generate large reports asynchronously
- Provide status polling endpoints for long-running reports
- Queue system for scheduled report generation

### 3. Data Pagination
- Support paginated queries for large datasets
- Streaming export for very large reports
- Configurable memory limits for report generation

## Security and Access Control

### 1. RBAC Integration
- Inherit tenant-based access control from existing system
- Role-based report template access
- Audit logging for report generation and access

### 2. Data Sensitivity
- Sanitize sensitive DNA attributes in reports
- Configurable field inclusion/exclusion
- PII protection in exported data

## Implementation Plan

### Phase 1: Core Report Engine
1. Create basic report engine with JSON export
2. Implement compliance report templates
3. Add REST API endpoints for ad-hoc reports

### Phase 2: Advanced Features
1. Add PDF/CSV/Excel export support
2. Implement executive dashboard templates
3. Create visualization data preparation

### Phase 3: Automation
1. Build scheduling system
2. Add email distribution
3. Implement report caching

### Phase 4: Advanced Analytics
1. Add trend analysis
2. Implement predictive analytics
3. Create custom template builder

## Success Criteria

- [ ] Generate compliance reports showing drift from baselines
- [ ] Create executive dashboards with trend analysis  
- [ ] Export reports in multiple formats (PDF, CSV, JSON)
- [ ] Schedule automated report generation and distribution
- [ ] Include visual charts and graphs for easy interpretation

## Technical Requirements

- Template-based report generation for flexibility
- Report caching for performance
- Modular report components for reuse
- Custom report definitions via API
- Integration with existing DNA storage and drift detection
- Multi-tenant support with proper access control