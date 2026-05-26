// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package exporters

import (
	"archive/zip"
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonTrivialReport returns a report with sections, insights, and actions to exercise
// all branches of the export logic.
func nonTrivialReport() *interfaces.Report {
	now := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	return &interfaces.Report{
		ID:          "test-report-707",
		Type:        interfaces.ReportTypeCompliance,
		Title:       "Q1 Compliance Report",
		Subtitle:    "Quarterly device compliance analysis",
		GeneratedAt: now,
		TimeRange: interfaces.TimeRange{
			Start: now.Add(-30 * 24 * time.Hour),
			End:   now,
		},
		Metadata: interfaces.ReportMetadata{
			Template:     "compliance-standard",
			DeviceCount:  150,
			DataPoints:   4500,
			GenerationMS: 234,
		},
		Summary: interfaces.ReportSummary{
			DevicesAnalyzed:    150,
			DriftEventsTotal:   42,
			ComplianceScore:    0.94,
			CriticalIssues:     3,
			TrendDirection:     interfaces.TrendImproving,
			KeyInsights:        []string{"Device compliance improved 4% vs last quarter", "3 critical issues require immediate attention"},
			RecommendedActions: []string{"Patch 12 devices with pending OS updates", "Review firewall rules on segment B"},
		},
		Sections: []interfaces.ReportSection{
			{
				ID:      "sec-1",
				Title:   "Device Overview",
				Type:    interfaces.SectionTypeText,
				Content: "150 devices were analyzed during this period",
			},
			{
				ID:    "sec-2",
				Title: "Compliance Table",
				Type:  interfaces.SectionTypeTable,
				Content: map[string]interface{}{
					"headers": []interface{}{"Device", "Score", "Status"},
					"rows": []interface{}{
						[]interface{}{"device-001", "0.98", "Compliant"},
						[]interface{}{"device-002", "0.72", "Non-Compliant"},
					},
				},
			},
			{
				ID:    "sec-3",
				Title: "KPI Summary",
				Type:  interfaces.SectionTypeKPI,
				Content: map[string]interface{}{
					"compliance_rate": 0.94,
					"device_count":    150,
				},
			},
		},
	}
}

// TestExporterMethods exercises PDF and Excel export with a non-trivial report payload.
func TestExporterMethods(t *testing.T) {
	logger := logging.NewNoopLogger()
	report := nonTrivialReport()
	ctx := context.Background()

	t.Run("PDF_produces_valid_document", func(t *testing.T) {
		exporter := New(logger).WithConfig(Config{
			HTMLTemplate: defaultHTMLTemplate,
			PDFEnabled:   true,
		})
		data, err := exporter.Export(ctx, report, interfaces.FormatPDF)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		require.GreaterOrEqual(t, len(data), 4, "PDF output must be at least 4 bytes")
		assert.Equal(t, "%PDF", string(data[:4]), "PDF must begin with %%PDF magic bytes")
		assert.Contains(t, string(data), "%%EOF", "PDF must contain %%EOF trailer marker")
		assert.Contains(t, string(data), report.Title, "PDF must embed the report title")
	})

	t.Run("PDF_disabled_returns_error", func(t *testing.T) {
		exporter := New(logger).WithConfig(Config{
			HTMLTemplate: defaultHTMLTemplate,
			PDFEnabled:   false,
		})
		_, err := exporter.Export(ctx, report, interfaces.FormatPDF)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not enabled")
	})

	t.Run("Excel_produces_valid_XLSX", func(t *testing.T) {
		exporter := New(logger)
		data, err := exporter.Export(ctx, report, interfaces.FormatExcel)
		require.NoError(t, err)
		require.NotEmpty(t, data)

		// XLSX is a ZIP archive; all ZIP files begin with PK magic bytes.
		require.GreaterOrEqual(t, len(data), 2, "XLSX output must be at least 2 bytes")
		assert.Equal(t, "PK", string(data[:2]), "XLSX must begin with ZIP magic bytes")

		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		require.NoError(t, err, "XLSX must be a valid ZIP archive")

		names := make(map[string]bool, len(zr.File))
		for _, f := range zr.File {
			names[f.Name] = true
		}
		assert.True(t, names["[Content_Types].xml"], "XLSX must contain [Content_Types].xml")
		assert.True(t, names["xl/workbook.xml"], "XLSX must contain xl/workbook.xml")
		assert.True(t, names["xl/worksheets/sheet1.xml"], "XLSX must contain sheet1.xml")
	})

	t.Run("Excel_sheet_contains_report_data", func(t *testing.T) {
		exporter := New(logger)
		data, err := exporter.Export(ctx, report, interfaces.FormatExcel)
		require.NoError(t, err)

		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		require.NoError(t, err)

		var sheetContent string
		for _, f := range zr.File {
			if f.Name == "xl/worksheets/sheet1.xml" {
				rc, err := f.Open()
				require.NoError(t, err)
				var buf bytes.Buffer
				_, err = buf.ReadFrom(rc)
				require.NoError(t, err)
				require.NoError(t, rc.Close())
				sheetContent = buf.String()
				break
			}
		}
		require.NotEmpty(t, sheetContent, "sheet1.xml must be present and non-empty")
		assert.Contains(t, sheetContent, report.Title, "sheet must contain report title")
		assert.Contains(t, sheetContent, "Compliance Score", "sheet must contain compliance score label")
		assert.Contains(t, sheetContent, "Key Insights", "sheet must contain key insights section")
		assert.Contains(t, sheetContent, "Device Overview", "sheet must contain section title")
	})

	t.Run("SupportedFormats_includes_Excel", func(t *testing.T) {
		exporter := New(logger)
		formats := exporter.SupportedFormats()
		assert.Contains(t, formats, interfaces.FormatExcel, "Excel must appear in SupportedFormats")
	})

	t.Run("SupportedFormats_includes_PDF_when_enabled", func(t *testing.T) {
		exporter := New(logger).WithConfig(Config{PDFEnabled: true})
		formats := exporter.SupportedFormats()
		assert.Contains(t, formats, interfaces.FormatPDF, "PDF must appear in SupportedFormats when enabled")
	})

	t.Run("SupportedFormats_excludes_PDF_when_disabled", func(t *testing.T) {
		exporter := New(logger).WithConfig(Config{PDFEnabled: false})
		formats := exporter.SupportedFormats()
		assert.NotContains(t, formats, interfaces.FormatPDF, "PDF must not appear in SupportedFormats when disabled")
	})

	t.Run("DefaultConfig_PDF_enabled", func(t *testing.T) {
		cfg := DefaultConfig()
		assert.True(t, cfg.PDFEnabled, "PDF must be enabled by default")
	})
}

// TestPDFEscapeString verifies that PDF special characters are correctly escaped.
func TestPDFEscapeString(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`hello`, `hello`},
		{`say (hi)`, `say \(hi\)`},
		{`back\slash`, `back\\slash`},
		{"new\nline", "new line"},
		{"carriage\rreturn", "carriage return"},
	}
	for _, tc := range cases {
		got := pdfEscapeString(tc.input)
		assert.Equal(t, tc.want, got, "pdfEscapeString(%q)", tc.input)
	}
}

// TestXMLEscapeString verifies that XML special characters are correctly escaped.
func TestXMLEscapeString(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{`plain`, `plain`},
		{`a & b`, `a &amp; b`},
		{`<tag>`, `&lt;tag&gt;`},
		{`"quoted"`, `&quot;quoted&quot;`},
		{`it's`, `it&apos;s`},
	}
	for _, tc := range cases {
		got := xmlEscapeString(tc.input)
		assert.Equal(t, tc.want, got, "xmlEscapeString(%q)", tc.input)
	}
}

// TestXlsxColLetter verifies column letter generation for common indices.
func TestXlsxColLetter(t *testing.T) {
	cases := []struct {
		col  int
		want string
	}{
		{1, "A"},
		{2, "B"},
		{26, "Z"},
		{27, "AA"},
		{28, "AB"},
	}
	for _, tc := range cases {
		got := xlsxColLetter(tc.col)
		assert.Equal(t, tc.want, got, "xlsxColLetter(%d)", tc.col)
	}
}

// TestBuildExcelRows verifies that the row builder captures all report sections.
func TestBuildExcelRows(t *testing.T) {
	report := nonTrivialReport()
	rows := buildExcelRows(report)

	flat := make([]string, 0)
	for _, row := range rows {
		flat = append(flat, strings.Join(row, "|"))
	}
	joined := strings.Join(flat, "\n")

	assert.Contains(t, joined, report.Title)
	assert.Contains(t, joined, "Compliance Score")
	assert.Contains(t, joined, "Key Insights")
	assert.Contains(t, joined, "Recommended Actions")
	assert.Contains(t, joined, "Device Overview")
}
