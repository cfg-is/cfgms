// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package templates

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/reports/interfaces"
	"github.com/cfgis/cfgms/pkg/dna/drift"
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

// --- withdrawn templates ---

// These templates returned fixed values with no data source in ReportData and
// were withdrawn. Fails if any of them is registered again.
var withdrawnTemplates = []string{
	"security-assessment",
	"operational-health",
	"cis-compliance",
	"hipaa-compliance",
	"multi-tenant-summary",
	"change-management",
	"audit-trail",
	"resource-utilization",
}

func TestWithdrawnTemplates_NotRegistered(t *testing.T) {
	p := newTestProcessor()
	for _, name := range withdrawnTemplates {
		t.Run(name, func(t *testing.T) {
			_, err := p.ProcessTemplate(context.Background(), name, emptyData(), nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "template not found")

			_, err = p.GetTemplateInfo(name)
			require.Error(t, err)

			require.Error(t, p.ValidateTemplate(name))
		})
	}
}

// --- remaining templates compute from ReportData ---

func driftData(events int) interfaces.ReportData {
	d := emptyData()
	for i := 0; i < events; i++ {
		d.DriftEvents = append(d.DriftEvents, drift.DriftEvent{
			ID:       fmt.Sprintf("evt-%d", i),
			DeviceID: fmt.Sprintf("device-%d", i),
			Severity: drift.SeverityCritical,
		})
	}
	return d
}

func TestRemainingTemplates_ReflectInput(t *testing.T) {
	p := newTestProcessor()
	for _, name := range []string{"compliance-summary", "executive-dashboard"} {
		t.Run(name, func(t *testing.T) {
			small, err := p.ProcessTemplate(context.Background(), name, driftData(1), nil)
			require.NoError(t, err)
			require.NotEmpty(t, small.Sections)

			large, err := p.ProcessTemplate(context.Background(), name, driftData(5), nil)
			require.NoError(t, err)
			require.NotEmpty(t, large.Sections)

			a, err := json.Marshal(small.Sections)
			require.NoError(t, err)
			b, err := json.Marshal(large.Sections)
			require.NoError(t, err)
			assert.NotEqual(t, string(a), string(b))
		})
	}
}
