// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package audit provides compliance reporting functionality
package audit

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// ComplianceReporter generates compliance reports from audit data
type ComplianceReporter struct {
	manager *Manager
}

// NewComplianceReporter creates a new compliance reporter
func NewComplianceReporter(manager *Manager) *ComplianceReporter {
	return &ComplianceReporter{
		manager: manager,
	}
}

// ComplianceReport represents a comprehensive compliance report
type ComplianceReport struct {
	ID          string               `json:"id"`
	TenantID    string               `json:"tenant_id"`
	GeneratedAt time.Time            `json:"generated_at"`
	GeneratedBy string               `json:"generated_by"`
	ReportType  ComplianceReportType `json:"report_type"`
	TimeRange   interfaces.TimeRange `json:"time_range"`

	// Summary statistics
	TotalEvents         int64            `json:"total_events"`
	EventsByType        map[string]int64 `json:"events_by_type"`
	EventsByResult      map[string]int64 `json:"events_by_result"`
	EventsBySeverity    map[string]int64 `json:"events_by_severity"`
	FailedActionsCount  int64            `json:"failed_actions_count"`
	SecurityEventsCount int64            `json:"security_events_count"`

	// Detailed findings
	SecurityFindings     []ComplianceFinding     `json:"security_findings"`
	AccessFindings       []ComplianceFinding     `json:"access_findings"`
	ConfigFindings       []ComplianceFinding     `json:"config_findings"`
	UserActivityReport   []UserActivitySummary   `json:"user_activity_report"`
	ResourceAccessReport []ResourceAccessSummary `json:"resource_access_report"`

	// Compliance status
	ComplianceStatus ComplianceStatus           `json:"compliance_status"`
	Violations       []ComplianceViolation      `json:"violations"`
	Recommendations  []ComplianceRecommendation `json:"recommendations"`
}

// ComplianceReportType defines types of compliance reports
type ComplianceReportType string

const (
	ComplianceReportSOC2     ComplianceReportType = "soc2"     // SOC 2 compliance
	ComplianceReportGDPR     ComplianceReportType = "gdpr"     // GDPR compliance
	ComplianceReportHIPAA    ComplianceReportType = "hipaa"    // HIPAA compliance
	ComplianceReportSecurity ComplianceReportType = "security" // Security audit
	ComplianceReportAccess   ComplianceReportType = "access"   // Access review
	ComplianceReportGeneral  ComplianceReportType = "general"  // General audit
)

// ComplianceStatus represents overall compliance status
type ComplianceStatus string

const (
	ComplianceStatusCompliant  ComplianceStatus = "compliant"
	ComplianceStatusWarnings   ComplianceStatus = "warnings"
	ComplianceStatusViolations ComplianceStatus = "violations"
	ComplianceStatusCritical   ComplianceStatus = "critical"
)

// ComplianceFinding represents a specific compliance finding
type ComplianceFinding struct {
	ID          string                   `json:"id"`
	Category    string                   `json:"category"`
	Severity    interfaces.AuditSeverity `json:"severity"`
	Title       string                   `json:"title"`
	Description string                   `json:"description"`
	Count       int64                    `json:"count"`
	FirstSeen   time.Time                `json:"first_seen"`
	LastSeen    time.Time                `json:"last_seen"`
	Examples    []string                 `json:"examples,omitempty"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string                   `json:"id"`
	Rule        string                   `json:"rule"`
	Severity    interfaces.AuditSeverity `json:"severity"`
	Description string                   `json:"description"`
	UserID      string                   `json:"user_id,omitempty"`
	ResourceID  string                   `json:"resource_id,omitempty"`
	Timestamp   time.Time                `json:"timestamp"`
	Details     map[string]interface{}   `json:"details,omitempty"`
}

// ComplianceRecommendation represents a compliance recommendation
type ComplianceRecommendation struct {
	ID          string                   `json:"id"`
	Category    string                   `json:"category"`
	Priority    interfaces.AuditSeverity `json:"priority"`
	Title       string                   `json:"title"`
	Description string                   `json:"description"`
	Actions     []string                 `json:"actions"`
}

// UserActivitySummary summarizes user activity for compliance reporting
type UserActivitySummary struct {
	UserID          string                   `json:"user_id"`
	UserType        interfaces.AuditUserType `json:"user_type"`
	TotalActions    int64                    `json:"total_actions"`
	FailedActions   int64                    `json:"failed_actions"`
	LastActivity    time.Time                `json:"last_activity"`
	UniqueResources int64                    `json:"unique_resources"`
	SecurityEvents  int64                    `json:"security_events"`
	HighRiskActions []string                 `json:"high_risk_actions,omitempty"`
}

// ResourceAccessSummary summarizes resource access for compliance reporting
type ResourceAccessSummary struct {
	ResourceType   string    `json:"resource_type"`
	ResourceID     string    `json:"resource_id"`
	ResourceName   string    `json:"resource_name,omitempty"`
	TotalAccesses  int64     `json:"total_accesses"`
	UniqueUsers    int64     `json:"unique_users"`
	LastAccessed   time.Time `json:"last_accessed"`
	AccessPatterns []string  `json:"access_patterns,omitempty"`
	SecurityEvents int64     `json:"security_events"`
}

// GenerateReport generates a comprehensive compliance report
func (r *ComplianceReporter) GenerateReport(ctx context.Context, req *ComplianceReportRequest) (*ComplianceReport, error) {
	if req.TenantID == "" {
		return nil, interfaces.ErrTenantIDRequired
	}

	// Create the report structure
	report := &ComplianceReport{
		ID:          fmt.Sprintf("compliance-%s-%d", req.ReportType, time.Now().Unix()),
		TenantID:    req.TenantID,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: req.GeneratedBy,
		ReportType:  req.ReportType,
		TimeRange:   req.TimeRange,
	}

	// Query all relevant audit entries
	filter := &interfaces.AuditFilter{
		TenantID:  req.TenantID,
		TimeRange: &req.TimeRange,
		Limit:     10000, // High limit for comprehensive analysis
		SortBy:    "timestamp",
		Order:     "desc",
	}

	entries, err := r.manager.QueryEntries(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit entries: %w", err)
	}

	// Analyze entries and populate report
	r.analyzeEntries(report, entries)
	r.generateFindings(report, entries)
	r.generateUserActivityReport(report, entries)
	r.generateResourceAccessReport(report, entries)
	r.assessCompliance(report)
	r.generateRecommendations(report)

	return report, nil
}

// ExportReport exports a compliance report in the specified format
func (r *ComplianceReporter) ExportReport(ctx context.Context, report *ComplianceReport, format ExportFormat) ([]byte, error) {
	switch format {
	case ExportFormatJSON:
		return json.MarshalIndent(report, "", "  ")
	case ExportFormatCSV:
		return r.exportCSV(report)
	case ExportFormatHTML:
		return r.exportHTML(report)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// ComplianceReportRequest defines parameters for generating a compliance report
type ComplianceReportRequest struct {
	TenantID       string               `json:"tenant_id"`
	ReportType     ComplianceReportType `json:"report_type"`
	TimeRange      interfaces.TimeRange `json:"time_range"`
	GeneratedBy    string               `json:"generated_by"`
	IncludeDetails bool                 `json:"include_details"`
}

// ExportFormat defines supported export formats
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatHTML ExportFormat = "html"
)

// analyzeEntries performs statistical analysis of audit entries
func (r *ComplianceReporter) analyzeEntries(report *ComplianceReport, entries []*interfaces.AuditEntry) {
	report.TotalEvents = int64(len(entries))
	report.EventsByType = make(map[string]int64)
	report.EventsByResult = make(map[string]int64)
	report.EventsBySeverity = make(map[string]int64)

	for _, entry := range entries {
		// Count by type
		report.EventsByType[string(entry.EventType)]++

		// Count by result
		report.EventsByResult[string(entry.Result)]++

		// Count by severity
		report.EventsBySeverity[string(entry.Severity)]++

		// Count specific categories
		if entry.Result == interfaces.AuditResultFailure || entry.Result == interfaces.AuditResultError {
			report.FailedActionsCount++
		}

		if entry.EventType == interfaces.AuditEventSecurityEvent {
			report.SecurityEventsCount++
		}
	}
}

// generateFindings generates compliance findings by category
func (r *ComplianceReporter) generateFindings(report *ComplianceReport, entries []*interfaces.AuditEntry) {
	securityFindings := make(map[string]*ComplianceFinding)
	accessFindings := make(map[string]*ComplianceFinding)
	configFindings := make(map[string]*ComplianceFinding)

	for _, entry := range entries {
		switch entry.EventType {
		case interfaces.AuditEventSecurityEvent:
			key := fmt.Sprintf("security-%s", entry.Action)
			if finding, exists := securityFindings[key]; exists {
				finding.Count++
				if entry.Timestamp.After(finding.LastSeen) {
					finding.LastSeen = entry.Timestamp
				}
			} else {
				securityFindings[key] = &ComplianceFinding{
					ID:          key,
					Category:    "Security",
					Severity:    entry.Severity,
					Title:       fmt.Sprintf("Security Event: %s", entry.Action),
					Description: fmt.Sprintf("Security event of type '%s' detected", entry.Action),
					Count:       1,
					FirstSeen:   entry.Timestamp,
					LastSeen:    entry.Timestamp,
				}
			}

		case interfaces.AuditEventAuthorization:
			if entry.Result == interfaces.AuditResultDenied {
				key := fmt.Sprintf("access-denied-%s", entry.Action)
				if finding, exists := accessFindings[key]; exists {
					finding.Count++
					if entry.Timestamp.After(finding.LastSeen) {
						finding.LastSeen = entry.Timestamp
					}
				} else {
					accessFindings[key] = &ComplianceFinding{
						ID:          key,
						Category:    "Access Control",
						Severity:    entry.Severity,
						Title:       fmt.Sprintf("Access Denied: %s", entry.Action),
						Description: fmt.Sprintf("Access denied for action '%s'", entry.Action),
						Count:       1,
						FirstSeen:   entry.Timestamp,
						LastSeen:    entry.Timestamp,
					}
				}
			}

		case interfaces.AuditEventConfiguration:
			if entry.Result != interfaces.AuditResultSuccess {
				key := fmt.Sprintf("config-failed-%s", entry.Action)
				if finding, exists := configFindings[key]; exists {
					finding.Count++
					if entry.Timestamp.After(finding.LastSeen) {
						finding.LastSeen = entry.Timestamp
					}
				} else {
					configFindings[key] = &ComplianceFinding{
						ID:          key,
						Category:    "Configuration",
						Severity:    entry.Severity,
						Title:       fmt.Sprintf("Configuration Issue: %s", entry.Action),
						Description: fmt.Sprintf("Configuration action '%s' failed", entry.Action),
						Count:       1,
						FirstSeen:   entry.Timestamp,
						LastSeen:    entry.Timestamp,
					}
				}
			}
		}
	}

	// Convert maps to slices
	report.SecurityFindings = make([]ComplianceFinding, 0, len(securityFindings))
	for _, finding := range securityFindings {
		report.SecurityFindings = append(report.SecurityFindings, *finding)
	}

	report.AccessFindings = make([]ComplianceFinding, 0, len(accessFindings))
	for _, finding := range accessFindings {
		report.AccessFindings = append(report.AccessFindings, *finding)
	}

	report.ConfigFindings = make([]ComplianceFinding, 0, len(configFindings))
	for _, finding := range configFindings {
		report.ConfigFindings = append(report.ConfigFindings, *finding)
	}

	// Sort findings by severity and count
	sortFindings := func(findings []ComplianceFinding) {
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].Severity != findings[j].Severity {
				return severityPriority(findings[i].Severity) > severityPriority(findings[j].Severity)
			}
			return findings[i].Count > findings[j].Count
		})
	}

	sortFindings(report.SecurityFindings)
	sortFindings(report.AccessFindings)
	sortFindings(report.ConfigFindings)
}

// generateUserActivityReport generates user activity summaries
func (r *ComplianceReporter) generateUserActivityReport(report *ComplianceReport, entries []*interfaces.AuditEntry) {
	userActivity := make(map[string]*UserActivitySummary)
	resourcesByUser := make(map[string]map[string]bool)

	for _, entry := range entries {
		if _, exists := userActivity[entry.UserID]; !exists {
			userActivity[entry.UserID] = &UserActivitySummary{
				UserID:   entry.UserID,
				UserType: entry.UserType,
			}
			resourcesByUser[entry.UserID] = make(map[string]bool)
		}

		summary := userActivity[entry.UserID]
		summary.TotalActions++

		if entry.Timestamp.After(summary.LastActivity) {
			summary.LastActivity = entry.Timestamp
		}

		if entry.Result == interfaces.AuditResultFailure || entry.Result == interfaces.AuditResultError {
			summary.FailedActions++
		}

		if entry.EventType == interfaces.AuditEventSecurityEvent {
			summary.SecurityEvents++
		}

		// Track unique resources
		resourceKey := fmt.Sprintf("%s:%s", entry.ResourceType, entry.ResourceID)
		resourcesByUser[entry.UserID][resourceKey] = true

		// Track high-risk actions
		if entry.Severity == interfaces.AuditSeverityCritical || entry.Severity == interfaces.AuditSeverityHigh {
			summary.HighRiskActions = append(summary.HighRiskActions, entry.Action)
		}
	}

	// Convert to slice and calculate unique resources
	report.UserActivityReport = make([]UserActivitySummary, 0, len(userActivity))
	for userID, summary := range userActivity {
		summary.UniqueResources = int64(len(resourcesByUser[userID]))

		// Deduplicate high-risk actions
		if len(summary.HighRiskActions) > 0 {
			uniqueActions := make(map[string]bool)
			deduped := make([]string, 0)
			for _, action := range summary.HighRiskActions {
				if !uniqueActions[action] {
					uniqueActions[action] = true
					deduped = append(deduped, action)
				}
			}
			summary.HighRiskActions = deduped
		}

		report.UserActivityReport = append(report.UserActivityReport, *summary)
	}

	// Sort by total actions descending
	sort.Slice(report.UserActivityReport, func(i, j int) bool {
		return report.UserActivityReport[i].TotalActions > report.UserActivityReport[j].TotalActions
	})
}

// generateResourceAccessReport generates resource access summaries
func (r *ComplianceReporter) generateResourceAccessReport(report *ComplianceReport, entries []*interfaces.AuditEntry) {
	resourceAccess := make(map[string]*ResourceAccessSummary)
	usersByResource := make(map[string]map[string]bool)

	for _, entry := range entries {
		resourceKey := fmt.Sprintf("%s:%s", entry.ResourceType, entry.ResourceID)

		if _, exists := resourceAccess[resourceKey]; !exists {
			resourceAccess[resourceKey] = &ResourceAccessSummary{
				ResourceType: entry.ResourceType,
				ResourceID:   entry.ResourceID,
				ResourceName: entry.ResourceName,
			}
			usersByResource[resourceKey] = make(map[string]bool)
		}

		summary := resourceAccess[resourceKey]
		summary.TotalAccesses++

		if entry.Timestamp.After(summary.LastAccessed) {
			summary.LastAccessed = entry.Timestamp
		}

		if entry.EventType == interfaces.AuditEventSecurityEvent {
			summary.SecurityEvents++
		}

		// Track unique users
		usersByResource[resourceKey][entry.UserID] = true

		// Track access patterns
		pattern := fmt.Sprintf("%s:%s", string(entry.UserType), entry.Action)
		summary.AccessPatterns = append(summary.AccessPatterns, pattern)
	}

	// Convert to slice and calculate unique users
	report.ResourceAccessReport = make([]ResourceAccessSummary, 0, len(resourceAccess))
	for resourceKey, summary := range resourceAccess {
		summary.UniqueUsers = int64(len(usersByResource[resourceKey]))

		// Deduplicate access patterns
		if len(summary.AccessPatterns) > 0 {
			uniquePatterns := make(map[string]bool)
			deduped := make([]string, 0)
			for _, pattern := range summary.AccessPatterns {
				if !uniquePatterns[pattern] {
					uniquePatterns[pattern] = true
					deduped = append(deduped, pattern)
				}
			}
			summary.AccessPatterns = deduped
		}

		report.ResourceAccessReport = append(report.ResourceAccessReport, *summary)
	}

	// Sort by total accesses descending
	sort.Slice(report.ResourceAccessReport, func(i, j int) bool {
		return report.ResourceAccessReport[i].TotalAccesses > report.ResourceAccessReport[j].TotalAccesses
	})
}

// assessCompliance determines overall compliance status
func (r *ComplianceReporter) assessCompliance(report *ComplianceReport) {
	criticalFindings := 0
	highFindings := 0
	violations := 0

	// Count findings by severity
	allFindings := append(append(report.SecurityFindings, report.AccessFindings...), report.ConfigFindings...)
	for _, finding := range allFindings {
		switch finding.Severity {
		case interfaces.AuditSeverityCritical:
			criticalFindings++
		case interfaces.AuditSeverityHigh:
			highFindings++
		}
	}

	// Generate violations based on findings
	for _, finding := range report.SecurityFindings {
		if finding.Severity == interfaces.AuditSeverityCritical {
			violations++
			report.Violations = append(report.Violations, ComplianceViolation{
				ID:          finding.ID,
				Rule:        "Security Event Critical",
				Severity:    finding.Severity,
				Description: finding.Description,
				Timestamp:   finding.LastSeen,
			})
		}
	}

	// Determine overall status
	if criticalFindings > 0 || violations > 0 {
		report.ComplianceStatus = ComplianceStatusCritical
	} else if highFindings > 5 || report.FailedActionsCount > 100 {
		report.ComplianceStatus = ComplianceStatusViolations
	} else if highFindings > 0 || report.FailedActionsCount > 10 || len(allFindings) > 0 {
		report.ComplianceStatus = ComplianceStatusWarnings
	} else {
		report.ComplianceStatus = ComplianceStatusCompliant
	}
}

// generateRecommendations generates compliance recommendations
func (r *ComplianceReporter) generateRecommendations(report *ComplianceReport) {
	recommendations := []ComplianceRecommendation{}

	if report.FailedActionsCount > 50 {
		recommendations = append(recommendations, ComplianceRecommendation{
			ID:          "reduce-failures",
			Category:    "Reliability",
			Priority:    interfaces.AuditSeverityHigh,
			Title:       "Reduce Failed Actions",
			Description: fmt.Sprintf("High number of failed actions detected (%d). Review system stability and user training.", report.FailedActionsCount),
			Actions:     []string{"Review system logs", "Improve error handling", "Provide user training"},
		})
	}

	if report.SecurityEventsCount > 10 {
		recommendations = append(recommendations, ComplianceRecommendation{
			ID:          "investigate-security",
			Category:    "Security",
			Priority:    interfaces.AuditSeverityCritical,
			Title:       "Investigate Security Events",
			Description: fmt.Sprintf("High number of security events detected (%d). Immediate investigation required.", report.SecurityEventsCount),
			Actions:     []string{"Review security events", "Check for anomalous activity", "Update security policies"},
		})
	}

	if len(report.AccessFindings) > 5 {
		recommendations = append(recommendations, ComplianceRecommendation{
			ID:          "review-access",
			Category:    "Access Control",
			Priority:    interfaces.AuditSeverityMedium,
			Title:       "Review Access Controls",
			Description: fmt.Sprintf("Multiple access control findings detected (%d). Review permissions and policies.", len(report.AccessFindings)),
			Actions:     []string{"Audit user permissions", "Review role assignments", "Update access policies"},
		})
	}

	report.Recommendations = recommendations
}

// exportCSV exports the compliance report as CSV
func (r *ComplianceReporter) exportCSV(report *ComplianceReport) ([]byte, error) {
	var buf strings.Builder
	writer := csv.NewWriter(&buf)

	// Write headers
	headers := []string{"Category", "Type", "Count", "Description", "Severity", "First Seen", "Last Seen"}
	if err := writer.Write(headers); err != nil {
		return nil, fmt.Errorf("failed to write CSV headers: %w", err)
	}

	// Write findings
	allFindings := append(append(report.SecurityFindings, report.AccessFindings...), report.ConfigFindings...)
	for _, finding := range allFindings {
		record := []string{
			finding.Category,
			finding.Title,
			fmt.Sprintf("%d", finding.Count),
			finding.Description,
			string(finding.Severity),
			finding.FirstSeen.Format(time.RFC3339),
			finding.LastSeen.Format(time.RFC3339),
		}
		if err := writer.Write(record); err != nil {
			return nil, fmt.Errorf("failed to write CSV record: %w", err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("CSV writer error: %w", err)
	}

	return []byte(buf.String()), nil
}

// exportHTML exports the compliance report as HTML
func (r *ComplianceReporter) exportHTML(report *ComplianceReport) ([]byte, error) {
	// Simple HTML template for compliance report
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - %s</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f5f5f5; padding: 20px; border-radius: 5px; }
        .status-%s { color: %s; font-weight: bold; }
        .section { margin: 20px 0; }
        table { border-collapse: collapse; width: 100%%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .severity-critical { color: red; font-weight: bold; }
        .severity-high { color: orange; font-weight: bold; }
        .severity-medium { color: blue; }
        .severity-low { color: green; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Compliance Report</h1>
        <p><strong>Report ID:</strong> %s</p>
        <p><strong>Tenant ID:</strong> %s</p>
        <p><strong>Generated:</strong> %s</p>
        <p><strong>Status:</strong> <span class="status-%s">%s</span></p>
        <p><strong>Total Events:</strong> %d</p>
    </div>`,
		report.ReportType,
		report.ComplianceStatus, getStatusColor(report.ComplianceStatus),
		report.ID,
		report.TenantID,
		report.GeneratedAt.Format(time.RFC3339),
		report.ComplianceStatus, report.ComplianceStatus,
		report.TotalEvents,
	)

	// Add summary statistics
	html += `
    <div class="section">
        <h2>Summary Statistics</h2>
        <table>
            <tr><th>Metric</th><th>Count</th></tr>`

	for eventType, count := range report.EventsByType {
		html += fmt.Sprintf("<tr><td>%s Events</td><td>%d</td></tr>", eventType, count)
	}

	html += fmt.Sprintf(`
            <tr><td>Failed Actions</td><td>%d</td></tr>
            <tr><td>Security Events</td><td>%d</td></tr>
        </table>
    </div>`, report.FailedActionsCount, report.SecurityEventsCount)

	html += `</body></html>`

	return []byte(html), nil
}

// Helper functions

func severityPriority(severity interfaces.AuditSeverity) int {
	switch severity {
	case interfaces.AuditSeverityCritical:
		return 4
	case interfaces.AuditSeverityHigh:
		return 3
	case interfaces.AuditSeverityMedium:
		return 2
	case interfaces.AuditSeverityLow:
		return 1
	default:
		return 0
	}
}

func getStatusColor(status ComplianceStatus) string {
	switch status {
	case ComplianceStatusCompliant:
		return "green"
	case ComplianceStatusWarnings:
		return "orange"
	case ComplianceStatusViolations:
		return "red"
	case ComplianceStatusCritical:
		return "darkred"
	default:
		return "black"
	}
}
