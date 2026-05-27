// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package exporters

import (
	"archive/zip"
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
}

// DefaultConfig returns default exporter configuration
func DefaultConfig() Config {
	return Config{
		HTMLTemplate: defaultHTMLTemplate,
		PDFEnabled:   true,
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
	e.logger.Debug("exporting report", "format", logging.SanitizeLogValue(string(format)), "report_id", logging.SanitizeLogValue(report.ID))

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
		interfaces.FormatExcel,
	}

	if e.config.PDFEnabled {
		formats = append(formats, interfaces.FormatPDF)
	}

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

// exportPDF generates a minimal valid PDF-1.4 document using pure stdlib byte-stream
// construction — no external tools or libraries required.
func (e *MultiFormatExporter) exportPDF(_ context.Context, report *interfaces.Report) ([]byte, error) {
	if !e.config.PDFEnabled {
		return nil, fmt.Errorf("PDF export is not enabled; set Config.PDFEnabled = true to enable")
	}

	stream := buildReportPDFContentStream(report)

	var buf bytes.Buffer
	buf.WriteString("%PDF-1.4\n")

	// Track byte offset of each object (1-indexed; index 0 unused).
	var offsets [5]int

	offsets[1] = buf.Len()
	fmt.Fprintf(&buf, "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")

	offsets[2] = buf.Len()
	fmt.Fprintf(&buf, "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")

	offsets[3] = buf.Len()
	fmt.Fprintf(&buf, "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]"+
		" /Contents 4 0 R /Resources << /Font << /F1 << /Type /Font /Subtype /Type1"+
		" /BaseFont /Helvetica >> >> >> >>\nendobj\n")

	offsets[4] = buf.Len()
	fmt.Fprintf(&buf, "4 0 obj\n<< /Length %d >>\nstream\n%sendstream\nendobj\n",
		len(stream), stream)

	xrefOffset := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 5\n")
	// Each xref entry must be exactly 20 bytes: 10-digit-offset SP 5-digit-gen SP n|f CR LF
	fmt.Fprintf(&buf, "0000000000 65535 f\r\n")
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n\r\n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n%d\n", xrefOffset)
	buf.WriteString("%%EOF\n")

	return buf.Bytes(), nil
}

// buildReportPDFContentStream builds a BT…ET text block for a single-page report PDF.
func buildReportPDFContentStream(report *interfaces.Report) string {
	body := fmt.Sprintf(
		"Generated: %s | Type: %s | Devices: %d | Compliance: %.1f%% | Drift: %d | Critical: %d | Trend: %s",
		report.GeneratedAt.Format(time.RFC3339),
		string(report.Type),
		report.Summary.DevicesAnalyzed,
		report.Summary.ComplianceScore*100,
		report.Summary.DriftEventsTotal,
		report.Summary.CriticalIssues,
		string(report.Summary.TrendDirection),
	)

	var b strings.Builder
	b.WriteString("BT\n")
	fmt.Fprintf(&b, "/F1 14 Tf\n50 730 Td\n(%s) Tj\n", pdfEscapeString(report.Title))
	fmt.Fprintf(&b, "/F1 10 Tf\n0 -25 Td\n(%s) Tj\n", pdfEscapeString(body))
	b.WriteString("ET\n")
	return b.String()
}

// pdfEscapeString escapes characters that are special inside PDF literal strings.
func pdfEscapeString(s string) string {
	var b strings.Builder
	for _, ch := range s {
		switch ch {
		case '\\':
			b.WriteString("\\\\")
		case '(':
			b.WriteString("\\(")
		case ')':
			b.WriteString("\\)")
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			if ch > 126 {
				b.WriteByte(' ') // Type1 fonts only cover printable ASCII
			} else {
				b.WriteRune(ch)
			}
		}
	}
	return b.String()
}

// exportExcel generates a minimal valid XLSX file using archive/zip and inline XML.
// XLSX is the Open XML Spreadsheet format (ISO/IEC 29500); it requires no external dependencies.
func (e *MultiFormatExporter) exportExcel(report *interfaces.Report) ([]byte, error) {
	rows := buildExcelRows(report)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	entries := []struct {
		name    string
		content string
	}{
		{"[Content_Types].xml", xlsxContentTypes},
		{"_rels/.rels", xlsxRootRels},
		{"xl/workbook.xml", xlsxWorkbook},
		{"xl/_rels/workbook.xml.rels", xlsxWorkbookRels},
		{"xl/worksheets/sheet1.xml", buildSheetXML(rows)},
	}
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			return nil, fmt.Errorf("failed to create XLSX entry %s: %w", e.name, err)
		}
		if _, err := fmt.Fprint(w, e.content); err != nil {
			return nil, fmt.Errorf("failed to write XLSX entry %s: %w", e.name, err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize XLSX: %w", err)
	}
	return buf.Bytes(), nil
}

// buildExcelRows converts a report into a two-column row slice suitable for an XLSX sheet.
func buildExcelRows(report *interfaces.Report) [][]string {
	var rows [][]string

	rows = append(rows,
		[]string{"Report Title", report.Title},
		[]string{"Report Type", string(report.Type)},
		[]string{"Generated At", report.GeneratedAt.Format(time.RFC3339)},
		[]string{"Time Range", fmt.Sprintf("%s to %s",
			report.TimeRange.Start.Format(time.RFC3339),
			report.TimeRange.End.Format(time.RFC3339))},
		[]string{},
		[]string{"Summary"},
		[]string{"Devices Analyzed", strconv.Itoa(report.Summary.DevicesAnalyzed)},
		[]string{"Drift Events Total", strconv.Itoa(report.Summary.DriftEventsTotal)},
		[]string{"Compliance Score", fmt.Sprintf("%.2f", report.Summary.ComplianceScore)},
		[]string{"Critical Issues", strconv.Itoa(report.Summary.CriticalIssues)},
		[]string{"Trend Direction", string(report.Summary.TrendDirection)},
		[]string{},
	)

	if len(report.Summary.KeyInsights) > 0 {
		rows = append(rows, []string{"Key Insights"})
		for i, insight := range report.Summary.KeyInsights {
			rows = append(rows, []string{strconv.Itoa(i + 1), insight})
		}
		rows = append(rows, []string{})
	}

	if len(report.Summary.RecommendedActions) > 0 {
		rows = append(rows, []string{"Recommended Actions"})
		for i, action := range report.Summary.RecommendedActions {
			rows = append(rows, []string{strconv.Itoa(i + 1), action})
		}
		rows = append(rows, []string{})
	}

	for _, section := range report.Sections {
		rows = append(rows, []string{fmt.Sprintf("Section: %s", section.Title)})
		rows = append(rows, []string{"Content", fmt.Sprintf("%v", section.Content)})
		rows = append(rows, []string{})
	}

	return rows
}

// buildSheetXML produces the xl/worksheets/sheet1.xml content for the given rows.
func buildSheetXML(rows [][]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	b.WriteString(`<sheetData>`)
	for rowIdx, row := range rows {
		rowNum := rowIdx + 1
		fmt.Fprintf(&b, `<row r="%d">`, rowNum)
		for colIdx, cell := range row {
			cellRef := fmt.Sprintf("%s%d", xlsxColLetter(colIdx+1), rowNum)
			fmt.Fprintf(&b, `<c r="%s" t="inlineStr"><is><t>%s</t></is></c>`,
				cellRef, xmlEscapeString(cell))
		}
		b.WriteString(`</row>`)
	}
	b.WriteString(`</sheetData>`)
	b.WriteString(`</worksheet>`)
	return b.String()
}

// xlsxColLetter converts a 1-based column index to an Excel column letter (A–Z, AA–AZ, …).
func xlsxColLetter(col int) string {
	if col <= 26 {
		return string(rune('A' + col - 1))
	}
	return string(rune('A'+(col-1)/26-1)) + string(rune('A'+(col-1)%26))
}

// xmlEscapeString escapes the five predefined XML entities.
func xmlEscapeString(s string) string {
	var b strings.Builder
	for _, ch := range s {
		switch ch {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&apos;")
		default:
			b.WriteRune(ch)
		}
	}
	return b.String()
}

// XLSX static components — these are fixed for any single-sheet workbook.
const xlsxContentTypes = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>` +
	`<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>` +
	`</Types>`

const xlsxRootRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>` +
	`</Relationships>`

const xlsxWorkbook = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"` +
	` xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">` +
	`<sheets><sheet name="Report" sheetId="1" r:id="rId1"/></sheets>` +
	`</workbook>`

const xlsxWorkbookRels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` +
	`<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` +
	`<Relationship Id="rId1"` +
	` Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"` +
	` Target="worksheets/sheet1.xml"/>` +
	`</Relationships>`

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
