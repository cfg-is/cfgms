// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package exporters

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// MultiFormatExporter implements the Exporter interface
type MultiFormatExporter struct {
	logger logging.Logger
	config Config
}

// Config contains configuration for the exporter
type Config struct {
	HTMLTemplate string `json:"html_template"`
	PDFEnabled   bool   `json:"pdf_enabled"`
	PDFCommand   string `json:"pdf_command"` // Command to convert HTML to PDF
}

// DefaultConfig returns default exporter configuration
func DefaultConfig() Config {
	return Config{
		HTMLTemplate: defaultHTMLTemplate,
		PDFEnabled:   false, // Disable PDF by default as it requires external tools
		PDFCommand:   "wkhtmltopdf --page-size A4 --orientation Portrait --margin-top 1in --margin-bottom 1in --margin-left 0.75in --margin-right 0.75in",
	}
}

// New creates a new multi-format exporter
func New(logger logging.Logger) *MultiFormatExporter {
	return &MultiFormatExporter{
		logger: logger,
		config: DefaultConfig(),
	}
}

// WithConfig sets custom configuration
func (e *MultiFormatExporter) WithConfig(config Config) *MultiFormatExporter {
	e.config = config
	return e
}

// Export exports a report in the specified format
func (e *MultiFormatExporter) Export(ctx context.Context, report *interfaces.Report, format interfaces.ExportFormat) ([]byte, error) {
	e.logger.Debug("exporting report", "format", format, "report_id", report.ID)

	switch format {
	case interfaces.FormatJSON:
		return e.exportJSON(report)
	case interfaces.FormatCSV:
		return e.exportCSV(report)
	case interfaces.FormatHTML:
		return e.exportHTML(report)
	case interfaces.FormatPDF:
		return e.exportPDF(ctx, report)
	case interfaces.FormatExcel:
		return e.exportExcel(report)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// SupportedFormats returns the formats supported by this exporter
func (e *MultiFormatExporter) SupportedFormats() []interfaces.ExportFormat {
	formats := []interfaces.ExportFormat{
		interfaces.FormatJSON,
		interfaces.FormatCSV,
		interfaces.FormatHTML,
	}

	if e.config.PDFEnabled {
		formats = append(formats, interfaces.FormatPDF)
	}

	// Excel export would require additional dependencies
	// formats = append(formats, interfaces.FormatExcel)

	return formats
}

// exportJSON exports the report as JSON
func (e *MultiFormatExporter) exportJSON(report *interfaces.Report) ([]byte, error) {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal report to JSON: %w", err)
	}
	return data, nil
}

// exportCSV exports the report as CSV
func (e *MultiFormatExporter) exportCSV(report *interfaces.Report) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)

	// Write header information
	if err := writer.Write([]string{"Report Title", report.Title}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Report Type", string(report.Type)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Generated At", report.GeneratedAt.Format(time.RFC3339)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Time Range", fmt.Sprintf("%s to %s",
		report.TimeRange.Start.Format(time.RFC3339),
		report.TimeRange.End.Format(time.RFC3339))}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{}); err != nil { // Empty row
		return nil, err
	}

	// Write summary information
	if err := writer.Write([]string{"Summary"}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Devices Analyzed", strconv.Itoa(report.Summary.DevicesAnalyzed)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Drift Events Total", strconv.Itoa(report.Summary.DriftEventsTotal)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Compliance Score", fmt.Sprintf("%.2f", report.Summary.ComplianceScore)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Critical Issues", strconv.Itoa(report.Summary.CriticalIssues)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{"Trend Direction", string(report.Summary.TrendDirection)}); err != nil {
		return nil, err
	}
	if err := writer.Write([]string{}); err != nil { // Empty row
		return nil, err
	}

	// Write key insights
	if len(report.Summary.KeyInsights) > 0 {
		if err := writer.Write([]string{"Key Insights"}); err != nil {
			return nil, err
		}
		for i, insight := range report.Summary.KeyInsights {
			if err := writer.Write([]string{strconv.Itoa(i + 1), insight}); err != nil {
				return nil, err
			}
		}
		if err := writer.Write([]string{}); err != nil { // Empty row
			return nil, err
		}
	}

	// Write recommended actions
	if len(report.Summary.RecommendedActions) > 0 {
		if err := writer.Write([]string{"Recommended Actions"}); err != nil {
			return nil, err
		}
		for i, action := range report.Summary.RecommendedActions {
			if err := writer.Write([]string{strconv.Itoa(i + 1), action}); err != nil {
				return nil, err
			}
		}
		if err := writer.Write([]string{}); err != nil { // Empty row
			return nil, err
		}
	}

	// Write section data
	for _, section := range report.Sections {
		if err := writer.Write([]string{fmt.Sprintf("Section: %s", section.Title)}); err != nil {
			return nil, err
		}

		// Handle different section types
		switch section.Type {
		case interfaces.SectionTypeTable:
			if tableData, ok := section.Content.(map[string]interface{}); ok {
				if err := e.writeTableDataToCSV(writer, tableData); err != nil {
					return nil, err
				}
			}
		case interfaces.SectionTypeKPI:
			if kpiData, ok := section.Content.(map[string]interface{}); ok {
				if err := e.writeKPIDataToCSV(writer, kpiData); err != nil {
					return nil, err
				}
			}
		default:
			// For other section types, write as string
			if err := writer.Write([]string{"Content", fmt.Sprintf("%v", section.Content)}); err != nil {
				return nil, err
			}
		}
		if err := writer.Write([]string{}); err != nil { // Empty row
			return nil, err
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("failed to write CSV: %w", err)
	}

	return buf.Bytes(), nil
}

// exportHTML exports the report as HTML
func (e *MultiFormatExporter) exportHTML(report *interfaces.Report) ([]byte, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("January 2, 2006 at 3:04 PM")
		},
		"formatFloat": func(f float64) string {
			return fmt.Sprintf("%.2f", f)
		},
		"formatPercent": func(f float64) string {
			return fmt.Sprintf("%.1f%%", f*100)
		},
		"upper": strings.ToUpper,
		"title": func(s string) string {
			if s == "" {
				return s
			}
			runes := []rune(s)
			runes[0] = unicode.ToUpper(runes[0])
			return string(runes)
		},
	}).Parse(e.config.HTMLTemplate)

	if err != nil {
		return nil, fmt.Errorf("failed to parse HTML template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, report); err != nil {
		return nil, fmt.Errorf("failed to execute HTML template: %w", err)
	}

	return buf.Bytes(), nil
}

// exportPDF exports the report as PDF (requires external tool)
func (e *MultiFormatExporter) exportPDF(ctx context.Context, report *interfaces.Report) ([]byte, error) {
	if !e.config.PDFEnabled {
		return nil, fmt.Errorf("PDF export is not enabled")
	}

	// This would require implementing HTML-to-PDF conversion
	// using an external tool like wkhtmltopdf or a Go library
	// For now, return an error indicating it's not implemented
	e.logger.Warn("PDF export not fully implemented - would require external tool integration")
	return nil, fmt.Errorf("PDF export not implemented - requires external PDF generation tool")
}

// exportExcel exports the report as Excel file
func (e *MultiFormatExporter) exportExcel(report *interfaces.Report) ([]byte, error) {
	// Excel export would require a library like excelize
	// For now, return an error indicating it's not implemented
	e.logger.Warn("Excel export not implemented - would require additional dependencies")
	return nil, fmt.Errorf("excel export not implemented - requires additional dependencies")
}

// writeTableDataToCSV writes table data to CSV writer
func (e *MultiFormatExporter) writeTableDataToCSV(writer *csv.Writer, data map[string]interface{}) error {
	// Extract headers and rows from table data
	if headers, ok := data["headers"].([]interface{}); ok {
		headerStrings := make([]string, len(headers))
		for i, h := range headers {
			headerStrings[i] = fmt.Sprintf("%v", h)
		}
		if err := writer.Write(headerStrings); err != nil {
			return err
		}
	}

	if rows, ok := data["rows"].([]interface{}); ok {
		for _, row := range rows {
			if rowData, ok := row.([]interface{}); ok {
				rowStrings := make([]string, len(rowData))
				for i, cell := range rowData {
					rowStrings[i] = fmt.Sprintf("%v", cell)
				}
				if err := writer.Write(rowStrings); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// writeKPIDataToCSV writes KPI data to CSV writer
func (e *MultiFormatExporter) writeKPIDataToCSV(writer *csv.Writer, data map[string]interface{}) error {
	if err := writer.Write([]string{"Metric", "Value", "Unit"}); err != nil {
		return err
	}

	for key, value := range data {
		valueStr := fmt.Sprintf("%v", value)
		if err := writer.Write([]string{key, valueStr, ""}); err != nil {
			return err
		}
	}
	return nil
}

// defaultHTMLTemplate is the default HTML template for reports
const defaultHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .header {
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .title {
            font-size: 2.5em;
            font-weight: bold;
            color: #007acc;
            margin: 0;
        }
        .subtitle {
            font-size: 1.2em;
            color: #666;
            margin: 10px 0 0 0;
        }
        .metadata {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        .metadata-item {
            display: inline-block;
            margin-right: 30px;
            margin-bottom: 10px;
        }
        .metadata-label {
            font-weight: bold;
            color: #555;
        }
        .summary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 30px;
        }
        .summary h2 {
            margin-top: 0;
            font-size: 1.8em;
        }
        .kpi-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .kpi-card {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .kpi-value {
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .kpi-label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .trend-improving { color: #4CAF50; }
        .trend-stable { color: #FF9800; }
        .trend-declining { color: #F44336; }
        .trend-unknown { color: #9E9E9E; }
        .insights, .actions {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }
        .insights h3, .actions h3 {
            margin-top: 0;
            color: #333;
            font-size: 1.4em;
        }
        .insights ul, .actions ul {
            padding-left: 20px;
        }
        .insights li, .actions li {
            margin-bottom: 10px;
            line-height: 1.5;
        }
        .section {
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 30px;
        }
        .section h3 {
            margin-top: 0;
            color: #007acc;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
        }
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        .table th, .table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .table th {
            background-color: #f8f9fa;
            font-weight: bold;
        }
        .table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .footer {
            text-align: center;
            padding-top: 20px;
            border-top: 1px solid #e0e0e0;
            color: #666;
            font-size: 0.9em;
        }
        @media print {
            body { font-size: 12px; }
            .header { break-after: avoid; }
            .section { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">{{.Title}}</h1>
        {{if .Subtitle}}<p class="subtitle">{{.Subtitle}}</p>{{end}}
    </div>

    <div class="metadata">
        <div class="metadata-item">
            <span class="metadata-label">Report Type:</span> {{title .Type}}
        </div>
        <div class="metadata-item">
            <span class="metadata-label">Generated:</span> {{formatTime .GeneratedAt}}
        </div>
        <div class="metadata-item">
            <span class="metadata-label">Time Range:</span> {{formatTime .TimeRange.Start}} - {{formatTime .TimeRange.End}}
        </div>
        <div class="metadata-item">
            <span class="metadata-label">Devices:</span> {{.Metadata.DeviceCount}}
        </div>
        <div class="metadata-item">
            <span class="metadata-label">Generation Time:</span> {{.Metadata.GenerationMS}}ms
        </div>
    </div>

    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-value">{{.Summary.DevicesAnalyzed}}</div>
                <div class="kpi-label">Devices Analyzed</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value">{{.Summary.DriftEventsTotal}}</div>
                <div class="kpi-label">Drift Events</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value">{{formatPercent .Summary.ComplianceScore}}</div>
                <div class="kpi-label">Compliance Score</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value">{{.Summary.CriticalIssues}}</div>
                <div class="kpi-label">Critical Issues</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-value trend-{{.Summary.TrendDirection}}">{{upper .Summary.TrendDirection}}</div>
                <div class="kpi-label">Trend Direction</div>
            </div>
        </div>
    </div>

    {{if .Summary.KeyInsights}}
    <div class="insights">
        <h3>Key Insights</h3>
        <ul>
            {{range .Summary.KeyInsights}}
            <li>{{.}}</li>
            {{end}}
        </ul>
    </div>
    {{end}}

    {{if .Summary.RecommendedActions}}
    <div class="actions">
        <h3>Recommended Actions</h3>
        <ul>
            {{range .Summary.RecommendedActions}}
            <li>{{.}}</li>
            {{end}}
        </ul>
    </div>
    {{end}}

    {{range .Sections}}
    <div class="section">
        <h3>{{.Title}}</h3>
        {{if eq .Type "table"}}
            <!-- Table content rendering would go here -->
            <p><em>Table data: {{.Content}}</em></p>
        {{else if eq .Type "kpi"}}
            <!-- KPI content rendering would go here -->
            <p><em>KPI data: {{.Content}}</em></p>
        {{else}}
            <p>{{.Content}}</p>
        {{end}}
    </div>
    {{end}}

    <div class="footer">
        <p>Generated by CFGMS DNA Monitoring System • Report ID: {{.ID}}</p>
    </div>
</body>
</html>`
