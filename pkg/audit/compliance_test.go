// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TestNewComplianceReporter tests compliance reporter creation
func TestNewComplianceReporter(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	assert.NotNil(t, reporter)
	assert.Equal(t, manager, reporter.manager)
}

// TestGenerateReport tests compliance report generation
func TestGenerateReport(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	ctx := context.Background()
	now := time.Now().UTC()

	// Create and store test audit entries via the manager's store directly
	testEntries := []*interfaces.AuditEntry{
		{
			ID:           "entry1",
			TenantID:     "test-tenant",
			Timestamp:    now.Add(-1 * time.Hour),
			EventType:    interfaces.AuditEventAuthentication,
			Action:       "login",
			UserID:       "user1",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "session",
			ResourceID:   "session1",
			Result:       interfaces.AuditResultSuccess,
			Severity:     interfaces.AuditSeverityMedium,
			Source:       "test",
			Version:      "1.0",
		},
		{
			ID:           "entry2",
			TenantID:     "test-tenant",
			Timestamp:    now.Add(-2 * time.Hour),
			EventType:    interfaces.AuditEventSecurityEvent,
			Action:       "failed_login_attempt",
			UserID:       "user2",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "security",
			ResourceID:   "incident1",
			Result:       interfaces.AuditResultFailure,
			Severity:     interfaces.AuditSeverityHigh,
			Source:       "test",
			Version:      "1.0",
		},
		{
			ID:           "entry3",
			TenantID:     "test-tenant",
			Timestamp:    now.Add(-3 * time.Hour),
			EventType:    interfaces.AuditEventAuthorization,
			Action:       "access_denied",
			UserID:       "user3",
			UserType:     interfaces.AuditUserTypeHuman,
			ResourceType: "config",
			ResourceID:   "config1",
			Result:       interfaces.AuditResultDenied,
			Severity:     interfaces.AuditSeverityMedium,
			Source:       "test",
			Version:      "1.0",
		},
	}

	for _, entry := range testEntries {
		err := manager.store.StoreAuditEntry(ctx, entry)
		require.NoError(t, err)
	}

	req := &ComplianceReportRequest{
		TenantID:    "test-tenant",
		ReportType:  ComplianceReportGeneral,
		GeneratedBy: "test-user",
		TimeRange: interfaces.TimeRange{
			Start: &[]time.Time{now.Add(-4 * time.Hour)}[0],
			End:   &now,
		},
	}

	report, err := reporter.GenerateReport(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, report)

	assert.Equal(t, "test-tenant", report.TenantID)
	assert.Equal(t, ComplianceReportGeneral, report.ReportType)
	assert.Equal(t, "test-user", report.GeneratedBy)
	assert.Equal(t, int64(3), report.TotalEvents)
	assert.Equal(t, int64(1), report.FailedActionsCount)
	assert.Equal(t, int64(1), report.SecurityEventsCount)

	assert.Equal(t, int64(1), report.EventsByType["authentication"])
	assert.Equal(t, int64(1), report.EventsByType["security_event"])
	assert.Equal(t, int64(1), report.EventsByType["authorization"])

	assert.Equal(t, int64(1), report.EventsByResult["success"])
	assert.Equal(t, int64(1), report.EventsByResult["failure"])
	assert.Equal(t, int64(1), report.EventsByResult["denied"])

	assert.NotEmpty(t, report.SecurityFindings)
	assert.NotEmpty(t, report.AccessFindings)

	assert.Len(t, report.UserActivityReport, 3)
	for _, userActivity := range report.UserActivityReport {
		assert.Equal(t, int64(1), userActivity.TotalActions)
	}

	assert.Len(t, report.ResourceAccessReport, 3)

	assert.NotEqual(t, ComplianceStatusCompliant, report.ComplianceStatus)
}

// TestGenerateReport_ValidationErrors tests validation error handling
func TestGenerateReport_ValidationErrors(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	ctx := context.Background()

	req := &ComplianceReportRequest{
		TenantID:    "",
		ReportType:  ComplianceReportGeneral,
		GeneratedBy: "test-user",
		TimeRange:   interfaces.TimeRange{},
	}

	_, err := reporter.GenerateReport(ctx, req)
	assert.Error(t, err)
	assert.Equal(t, interfaces.ErrTenantIDRequired, err)
}

// TestExportReport tests report export functionality
func TestExportReport(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	ctx := context.Background()
	now := time.Now().UTC()

	report := &ComplianceReport{
		ID:          "test-report",
		TenantID:    "test-tenant",
		GeneratedAt: now,
		GeneratedBy: "test-user",
		ReportType:  ComplianceReportSecurity,
		TotalEvents: 5,
		EventsByType: map[string]int64{
			"authentication": 2,
			"authorization":  1,
			"security_event": 2,
		},
		EventsByResult: map[string]int64{
			"success": 3,
			"failure": 1,
			"denied":  1,
		},
		FailedActionsCount:  1,
		SecurityEventsCount: 2,
		ComplianceStatus:    ComplianceStatusWarnings,
		SecurityFindings: []ComplianceFinding{
			{
				ID:          "security-finding-1",
				Category:    "Security",
				Severity:    interfaces.AuditSeverityHigh,
				Title:       "Security Event: failed_login",
				Description: "Multiple failed login attempts detected",
				Count:       5,
				FirstSeen:   now.Add(-2 * time.Hour),
				LastSeen:    now.Add(-1 * time.Hour),
			},
		},
		AccessFindings: []ComplianceFinding{
			{
				ID:          "access-finding-1",
				Category:    "Access Control",
				Severity:    interfaces.AuditSeverityMedium,
				Title:       "Access Denied: unauthorized_access",
				Description: "Unauthorized access attempts detected",
				Count:       3,
				FirstSeen:   now.Add(-3 * time.Hour),
				LastSeen:    now.Add(-1 * time.Hour),
			},
		},
	}

	t.Run("JSON Export", func(t *testing.T) {
		data, err := reporter.ExportReport(ctx, report, ExportFormatJSON)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		jsonStr := string(data)
		assert.Contains(t, jsonStr, "test-report")
		assert.Contains(t, jsonStr, "test-tenant")
		assert.Contains(t, jsonStr, "security_findings")
		assert.Contains(t, jsonStr, "access_findings")
	})

	t.Run("CSV Export", func(t *testing.T) {
		data, err := reporter.ExportReport(ctx, report, ExportFormatCSV)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		csvStr := string(data)
		lines := strings.Split(csvStr, "\n")
		assert.GreaterOrEqual(t, len(lines), 2)

		assert.Contains(t, lines[0], "Category,Type,Count,Description,Severity,First Seen,Last Seen")

		assert.Contains(t, csvStr, "Security")
		assert.Contains(t, csvStr, "Access Control")
	})

	t.Run("HTML Export", func(t *testing.T) {
		data, err := reporter.ExportReport(ctx, report, ExportFormatHTML)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		htmlStr := string(data)
		assert.Contains(t, htmlStr, "<!DOCTYPE html>")
		assert.Contains(t, htmlStr, "<title>Compliance Report")
		assert.Contains(t, htmlStr, "test-report")
		assert.Contains(t, htmlStr, "test-tenant")
		assert.Contains(t, htmlStr, "Summary Statistics")
	})

	t.Run("Unsupported Format", func(t *testing.T) {
		_, err := reporter.ExportReport(ctx, report, "xml")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported export format")
	})
}

// TestComplianceStatusAssessment tests compliance status determination
func TestComplianceStatusAssessment(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	tests := []struct {
		name             string
		securityFindings []ComplianceFinding
		failedActions    int64
		expectedStatus   ComplianceStatus
	}{
		{
			name:             "compliant - no issues",
			securityFindings: []ComplianceFinding{},
			failedActions:    0,
			expectedStatus:   ComplianceStatusCompliant,
		},
		{
			name: "warnings - medium severity findings",
			securityFindings: []ComplianceFinding{
				{Severity: interfaces.AuditSeverityMedium},
			},
			failedActions:  5,
			expectedStatus: ComplianceStatusWarnings,
		},
		{
			name: "violations - high severity findings",
			securityFindings: []ComplianceFinding{
				{Severity: interfaces.AuditSeverityHigh},
				{Severity: interfaces.AuditSeverityHigh},
				{Severity: interfaces.AuditSeverityHigh},
				{Severity: interfaces.AuditSeverityHigh},
				{Severity: interfaces.AuditSeverityHigh},
				{Severity: interfaces.AuditSeverityHigh},
			},
			failedActions:  50,
			expectedStatus: ComplianceStatusViolations,
		},
		{
			name: "critical - critical severity findings",
			securityFindings: []ComplianceFinding{
				{Severity: interfaces.AuditSeverityCritical},
			},
			failedActions:  0,
			expectedStatus: ComplianceStatusCritical,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ComplianceReport{
				SecurityFindings:   tt.securityFindings,
				FailedActionsCount: tt.failedActions,
			}

			reporter.assessCompliance(report)
			assert.Equal(t, tt.expectedStatus, report.ComplianceStatus)
		})
	}
}

// TestComplianceFindingGeneration tests finding generation logic
func TestComplianceFindingGeneration(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	now := time.Now().UTC()
	entries := []*interfaces.AuditEntry{
		{
			ID:        "security1",
			EventType: interfaces.AuditEventSecurityEvent,
			Action:    "intrusion_attempt",
			Timestamp: now.Add(-1 * time.Hour),
			Severity:  interfaces.AuditSeverityCritical,
			Result:    interfaces.AuditResultFailure,
		},
		{
			ID:        "security2",
			EventType: interfaces.AuditEventSecurityEvent,
			Action:    "intrusion_attempt",
			Timestamp: now.Add(-2 * time.Hour),
			Severity:  interfaces.AuditSeverityCritical,
			Result:    interfaces.AuditResultFailure,
		},
		{
			ID:        "auth1",
			EventType: interfaces.AuditEventAuthorization,
			Action:    "access_resource",
			Timestamp: now.Add(-1 * time.Hour),
			Severity:  interfaces.AuditSeverityHigh,
			Result:    interfaces.AuditResultDenied,
		},
		{
			ID:        "config1",
			EventType: interfaces.AuditEventConfiguration,
			Action:    "update_config",
			Timestamp: now.Add(-1 * time.Hour),
			Severity:  interfaces.AuditSeverityMedium,
			Result:    interfaces.AuditResultError,
		},
	}

	report := &ComplianceReport{}
	reporter.generateFindings(report, entries)

	require.Len(t, report.SecurityFindings, 1)
	securityFinding := report.SecurityFindings[0]
	assert.Equal(t, "security-intrusion_attempt", securityFinding.ID)
	assert.Equal(t, "Security", securityFinding.Category)
	assert.Equal(t, interfaces.AuditSeverityCritical, securityFinding.Severity)
	assert.Equal(t, int64(2), securityFinding.Count)

	require.Len(t, report.AccessFindings, 1)
	accessFinding := report.AccessFindings[0]
	assert.Equal(t, "access-denied-access_resource", accessFinding.ID)
	assert.Equal(t, "Access Control", accessFinding.Category)
	assert.Equal(t, interfaces.AuditSeverityHigh, accessFinding.Severity)
	assert.Equal(t, int64(1), accessFinding.Count)

	require.Len(t, report.ConfigFindings, 1)
	configFinding := report.ConfigFindings[0]
	assert.Equal(t, "config-failed-update_config", configFinding.ID)
	assert.Equal(t, "Configuration", configFinding.Category)
	assert.Equal(t, interfaces.AuditSeverityMedium, configFinding.Severity)
	assert.Equal(t, int64(1), configFinding.Count)
}

// TestRecommendationGeneration tests recommendation generation logic
func TestRecommendationGeneration(t *testing.T) {
	manager := newTestManager(t, "test")
	reporter := NewComplianceReporter(manager)

	tests := []struct {
		name                    string
		failedActions           int64
		securityEvents          int64
		accessFindingsCount     int
		expectedRecommendations int
	}{
		{
			name:                    "no issues - no recommendations",
			failedActions:           5,
			securityEvents:          2,
			accessFindingsCount:     1,
			expectedRecommendations: 0,
		},
		{
			name:                    "high failed actions",
			failedActions:           100,
			securityEvents:          5,
			accessFindingsCount:     2,
			expectedRecommendations: 1,
		},
		{
			name:                    "high security events",
			failedActions:           10,
			securityEvents:          50,
			accessFindingsCount:     2,
			expectedRecommendations: 1,
		},
		{
			name:                    "many access findings",
			failedActions:           10,
			securityEvents:          5,
			accessFindingsCount:     10,
			expectedRecommendations: 1,
		},
		{
			name:                    "all issues",
			failedActions:           100,
			securityEvents:          50,
			accessFindingsCount:     10,
			expectedRecommendations: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := &ComplianceReport{
				FailedActionsCount:  tt.failedActions,
				SecurityEventsCount: tt.securityEvents,
				AccessFindings:      make([]ComplianceFinding, tt.accessFindingsCount),
			}

			reporter.generateRecommendations(report)
			assert.Len(t, report.Recommendations, tt.expectedRecommendations)

			categories := make(map[string]bool)
			for _, rec := range report.Recommendations {
				categories[rec.Category] = true
			}

			if tt.failedActions > 50 {
				assert.True(t, categories["Reliability"], "Should have reliability recommendation")
			}
			if tt.securityEvents > 10 {
				assert.True(t, categories["Security"], "Should have security recommendation")
			}
			if tt.accessFindingsCount > 5 {
				assert.True(t, categories["Access Control"], "Should have access control recommendation")
			}
		})
	}
}
