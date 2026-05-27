// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package templates

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newTestProcessor returns a Processor with all built-in templates registered.
func newTestProcessor() *Processor {
	return New(logging.NewNoopLogger())
}

// emptyData returns a minimal ReportData with a valid TimeRange.
func emptyData() interfaces.ReportData {
	return interfaces.ReportData{
		TimeRange: interfaces.TimeRange{
			Start: time.Now().Add(-24 * time.Hour),
			End:   time.Now(),
		},
	}
}

// --- ProcessTemplate ---

func TestProcessTemplate_ValidTemplate(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "compliance-summary", emptyData(), nil)
	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, interfaces.ReportTypeCompliance, report.Type)
	assert.NotEmpty(t, report.Sections)
}

func TestProcessTemplate_UnknownTemplate(t *testing.T) {
	p := newTestProcessor()
	_, err := p.ProcessTemplate(context.Background(), "nonexistent-template", emptyData(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template not found")
}

// --- GetTemplateInfo ---

func TestGetTemplateInfo_ValidTemplate(t *testing.T) {
	p := newTestProcessor()
	info, err := p.GetTemplateInfo("drift-analysis")
	require.NoError(t, err)
	assert.Equal(t, "drift-analysis", info.Name)
	assert.Equal(t, interfaces.ReportTypeDrift, info.Type)
	assert.NotEmpty(t, info.Description)
}

func TestGetTemplateInfo_UnknownTemplate(t *testing.T) {
	p := newTestProcessor()
	_, err := p.GetTemplateInfo("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template not found")
}

// --- ValidateTemplate ---

func TestValidateTemplate_ValidTemplate(t *testing.T) {
	p := newTestProcessor()
	assert.NoError(t, p.ValidateTemplate("executive-dashboard"))
}

func TestValidateTemplate_UnknownTemplate(t *testing.T) {
	p := newTestProcessor()
	err := p.ValidateTemplate("does-not-exist")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "template not found")
}

// --- stub generators: verify section structure ---

// Each stub generator must return a non-nil report with at least one section of the
// expected type. The exact KPI values are representative defaults (see design-decision
// comments in processor.go) and are not asserted here.

func TestGenerateSecurityAssessment_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "security-assessment", emptyData(), nil)
	require.NoError(t, err)
	require.NotNil(t, report)
	assert.Equal(t, interfaces.ReportTypeSecurity, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "security-overview", report.Sections[0].ID)
}

func TestGenerateOperationalHealth_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "operational-health", emptyData(), nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeOperational, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "health-overview", report.Sections[0].ID)
}

func TestGenerateCISCompliance_Structure(t *testing.T) {
	p := newTestProcessor()
	params := map[string]any{"cis_version": "v8"}
	report, err := p.ProcessTemplate(context.Background(), "cis-compliance", emptyData(), params)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeCompliance, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "cis-compliance", report.Sections[0].ID)
}

func TestGenerateHIPAACompliance_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "hipaa-compliance", emptyData(), nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeCompliance, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "hipaa-compliance", report.Sections[0].ID)
}

func TestGenerateMultiTenantSummary_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "multi-tenant-summary", emptyData(), nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeMultiTenant, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "multi-tenant-overview", report.Sections[0].ID)
}

func TestGenerateChangeManagement_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "change-management", emptyData(), nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeOperational, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "change-management", report.Sections[0].ID)
}

func TestGenerateAuditTrail_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "audit-trail", emptyData(), nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeAudit, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "audit-overview", report.Sections[0].ID)
}

func TestGenerateResourceUtilization_Structure(t *testing.T) {
	p := newTestProcessor()
	report, err := p.ProcessTemplate(context.Background(), "resource-utilization", emptyData(), nil)
	require.NoError(t, err)
	assert.Equal(t, interfaces.ReportTypeOperational, report.Type)
	require.NotEmpty(t, report.Sections)
	assert.Equal(t, "resource-utilization", report.Sections[0].ID)
}
