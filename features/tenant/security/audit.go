package security

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TenantSecurityAuditLogger handles security-related audit logging for multi-tenant operations
type TenantSecurityAuditLogger struct {
	entries []TenantSecurityAuditEntry
	mutex   sync.RWMutex
}

// TenantSecurityAuditEntry represents a single tenant security audit entry
type TenantSecurityAuditEntry struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	EventType      TenantSecurityEventType `json:"event_type"`
	TenantID       string                 `json:"tenant_id"`
	SubjectID      string                 `json:"subject_id,omitempty"`
	ResourceID     string                 `json:"resource_id,omitempty"`
	Action         string                 `json:"action"`
	Result         string                 `json:"result"`
	Details        map[string]interface{} `json:"details,omitempty"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	SessionID      string                 `json:"session_id,omitempty"`
	Severity       AuditSeverity          `json:"severity"`
	ComplianceInfo *ComplianceAuditInfo   `json:"compliance_info,omitempty"`
}

// TenantSecurityEventType defines types of tenant security events
type TenantSecurityEventType string

const (
	TenantSecurityEventIsolationRuleChange TenantSecurityEventType = "isolation_rule_change"
	TenantSecurityEventAccessAttempt       TenantSecurityEventType = "access_attempt"
	TenantSecurityEventPolicyViolation     TenantSecurityEventType = "policy_violation"
	TenantSecurityEventCrossTenantAccess   TenantSecurityEventType = "cross_tenant_access"
	TenantSecurityEventDataExfiltration    TenantSecurityEventType = "data_exfiltration"
	TenantSecurityEventUnauthorizedAccess  TenantSecurityEventType = "unauthorized_access"
	TenantSecurityEventComplianceViolation TenantSecurityEventType = "compliance_violation"
	TenantSecurityEventSecurityPolicyChange TenantSecurityEventType = "security_policy_change"
)

// AuditSeverity defines the severity levels for audit events
type AuditSeverity string

const (
	AuditSeverityInfo     AuditSeverity = "info"
	AuditSeverityWarning  AuditSeverity = "warning"
	AuditSeverityError    AuditSeverity = "error"
	AuditSeverityCritical AuditSeverity = "critical"
)

// ComplianceAuditInfo contains compliance-specific audit information
type ComplianceAuditInfo struct {
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	RequirementsMet      []string `json:"requirements_met"`
	RequirementsViolated []string `json:"requirements_violated"`
	DataClassification   string   `json:"data_classification,omitempty"`
	RetentionPeriod      int      `json:"retention_period,omitempty"` // Days
}

// NewTenantSecurityAuditLogger creates a new tenant security audit logger
func NewTenantSecurityAuditLogger() *TenantSecurityAuditLogger {
	return &TenantSecurityAuditLogger{
		entries: make([]TenantSecurityAuditEntry, 0),
		mutex:   sync.RWMutex{},
	}
}

// LogIsolationRuleChange logs changes to tenant isolation rules
func (tsal *TenantSecurityAuditLogger) LogIsolationRuleChange(ctx context.Context, action, tenantID string, newRule, oldRule *IsolationRule) error {
	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("isolation-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventIsolationRuleChange,
		TenantID:  tenantID,
		Action:    action,
		Result:    "success",
		Severity:  AuditSeverityInfo,
		Details: map[string]interface{}{
			"new_rule": newRule,
			"old_rule": oldRule,
		},
	}

	// Determine severity based on changes
	if tsal.isSecurityDowngrade(newRule, oldRule) {
		entry.Severity = AuditSeverityWarning
		entry.Details["security_downgrade"] = true
	}

	// Add compliance information
	if newRule != nil {
		entry.ComplianceInfo = &ComplianceAuditInfo{
			ComplianceFrameworks: []string{string(newRule.ComplianceLevel)},
			DataClassification:   tsal.getDataClassification(newRule.ComplianceLevel),
			RetentionPeriod:      tsal.getRetentionPeriod(newRule.ComplianceLevel),
		}
	}

	return tsal.addEntry(entry)
}

// LogAccessAttempt logs tenant access attempts with security context
func (tsal *TenantSecurityAuditLogger) LogAccessAttempt(ctx context.Context, request *TenantAccessRequest, response *TenantAccessResponse) error {
	severity := AuditSeverityInfo
	if !response.Granted {
		severity = AuditSeverityWarning
	}

	// Escalate severity for suspicious patterns
	if tsal.isSuspiciousAccess(request, response) {
		severity = AuditSeverityError
	}

	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("access-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventAccessAttempt,
		TenantID:  request.TargetTenantID,
		SubjectID: request.SubjectID,
		ResourceID: request.ResourceID,
		Action:    fmt.Sprintf("access_%s", request.AccessLevel),
		Result:    tsal.getResultString(response.Granted),
		Severity:  severity,
		SourceIP:  request.Context["source_ip"],
		UserAgent: request.Context["user_agent"],
		SessionID: request.Context["session_id"],
		Details: map[string]interface{}{
			"requested_level": request.AccessLevel,
			"source_tenant":   request.SubjectTenantID,
			"reason":         response.Reason,
		},
	}

	// Add cross-tenant specific information
	if request.SubjectTenantID != request.TargetTenantID {
		entry.EventType = TenantSecurityEventCrossTenantAccess
		entry.Details["cross_tenant"] = true
		entry.Details["source_tenant_id"] = request.SubjectTenantID
	}

	return tsal.addEntry(entry)
}

// LogPolicyViolation logs security policy violations
func (tsal *TenantSecurityAuditLogger) LogPolicyViolation(ctx context.Context, tenantID, subjectID, policyID, violation string, context map[string]interface{}) error {
	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("violation-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventPolicyViolation,
		TenantID:  tenantID,
		SubjectID: subjectID,
		Action:    "policy_violation",
		Result:    "blocked",
		Severity:  AuditSeverityError,
		Details: map[string]interface{}{
			"policy_id":  policyID,
			"violation":  violation,
			"context":    context,
		},
	}

	return tsal.addEntry(entry)
}

// LogComplianceViolation logs compliance-related violations
func (tsal *TenantSecurityAuditLogger) LogComplianceViolation(ctx context.Context, tenantID, framework, requirement, violation string) error {
	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("compliance-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventComplianceViolation,
		TenantID:  tenantID,
		Action:    "compliance_violation",
		Result:    "violation_detected",
		Severity:  AuditSeverityCritical,
		Details: map[string]interface{}{
			"framework":   framework,
			"requirement": requirement,
			"violation":   violation,
		},
		ComplianceInfo: &ComplianceAuditInfo{
			ComplianceFrameworks: []string{framework},
			RequirementsViolated: []string{requirement},
		},
	}

	return tsal.addEntry(entry)
}

// GetAuditEntries retrieves audit entries with filtering options
func (tsal *TenantSecurityAuditLogger) GetAuditEntries(ctx context.Context, filter *TenantSecurityAuditFilter) ([]TenantSecurityAuditEntry, error) {
	tsal.mutex.RLock()
	defer tsal.mutex.RUnlock()

	var filtered []TenantSecurityAuditEntry

	for _, entry := range tsal.entries {
		if tsal.matchesFilter(entry, filter) {
			filtered = append(filtered, entry)
		}
	}

	// Apply pagination
	if filter != nil && filter.Limit > 0 {
		start := filter.Offset
		end := start + filter.Limit

		if start >= len(filtered) {
			return []TenantSecurityAuditEntry{}, nil
		}

		if end > len(filtered) {
			end = len(filtered)
		}

		filtered = filtered[start:end]
	}

	return filtered, nil
}

// GetSecurityReport generates a comprehensive security report
func (tsal *TenantSecurityAuditLogger) GetSecurityReport(ctx context.Context, tenantID string, period time.Duration) (*TenantSecurityReport, error) {
	filter := &TenantSecurityAuditFilter{
		TenantID:  tenantID,
		StartTime: time.Now().Add(-period),
		EndTime:   time.Now(),
	}

	entries, err := tsal.GetAuditEntries(ctx, filter)
	if err != nil {
		return nil, err
	}

	report := &TenantSecurityReport{
		TenantID:       tenantID,
		ReportPeriod:   period,
		GeneratedAt:    time.Now(),
		TotalEntries:   len(entries),
		EventSummary:   make(map[TenantSecurityEventType]int),
		SeveritySummary: make(map[AuditSeverity]int),
		SecurityAlerts: []SecurityAlert{},
		ComplianceStatus: ComplianceStatus{},
	}

	// Analyze entries
	var failedAttempts, crossTenantAccess, policyViolations int
	var lastViolation *time.Time

	for _, entry := range entries {
		// Count by event type
		report.EventSummary[entry.EventType]++
		
		// Count by severity
		report.SeveritySummary[entry.Severity]++

		// Track specific security metrics
		if entry.EventType == TenantSecurityEventAccessAttempt && entry.Result == "denied" {
			failedAttempts++
		}

		if entry.EventType == TenantSecurityEventCrossTenantAccess {
			crossTenantAccess++
		}

		if entry.EventType == TenantSecurityEventPolicyViolation {
			policyViolations++
			if lastViolation == nil || entry.Timestamp.After(*lastViolation) {
				lastViolation = &entry.Timestamp
			}
		}
	}

	// Generate security alerts based on thresholds
	if failedAttempts > 10 {
		report.SecurityAlerts = append(report.SecurityAlerts, SecurityAlert{
			Type:        "excessive_failed_attempts",
			Severity:    "high",
			Description: fmt.Sprintf("%d failed access attempts detected", failedAttempts),
			Count:       failedAttempts,
		})
	}

	if crossTenantAccess > 0 {
		report.SecurityAlerts = append(report.SecurityAlerts, SecurityAlert{
			Type:        "cross_tenant_activity",
			Severity:    "medium",
			Description: fmt.Sprintf("%d cross-tenant access attempts detected", crossTenantAccess),
			Count:       crossTenantAccess,
		})
	}

	if policyViolations > 0 {
		severity := "medium"
		if policyViolations > 5 {
			severity = "high"
		}
		report.SecurityAlerts = append(report.SecurityAlerts, SecurityAlert{
			Type:        "policy_violations",
			Severity:    severity,
			Description: fmt.Sprintf("%d security policy violations detected", policyViolations),
			Count:       policyViolations,
			LastSeen:    lastViolation,
		})
	}

	return report, nil
}

// addEntry adds a new audit entry
func (tsal *TenantSecurityAuditLogger) addEntry(entry TenantSecurityAuditEntry) error {
	tsal.mutex.Lock()
	defer tsal.mutex.Unlock()

	tsal.entries = append(tsal.entries, entry)
	return nil
}

// matchesFilter checks if an audit entry matches the given filter
func (tsal *TenantSecurityAuditLogger) matchesFilter(entry TenantSecurityAuditEntry, filter *TenantSecurityAuditFilter) bool {
	if filter == nil {
		return true
	}

	if filter.TenantID != "" && entry.TenantID != filter.TenantID {
		return false
	}

	if filter.SubjectID != "" && entry.SubjectID != filter.SubjectID {
		return false
	}

	if filter.EventType != "" && entry.EventType != TenantSecurityEventType(filter.EventType) {
		return false
	}

	if filter.Severity != "" && entry.Severity != AuditSeverity(filter.Severity) {
		return false
	}

	if !filter.StartTime.IsZero() && entry.Timestamp.Before(filter.StartTime) {
		return false
	}

	if !filter.EndTime.IsZero() && entry.Timestamp.After(filter.EndTime) {
		return false
	}

	return true
}

// Helper methods
func (tsal *TenantSecurityAuditLogger) isSecurityDowngrade(newRule, oldRule *IsolationRule) bool {
	if oldRule == nil {
		return false
	}

	// Check if new rule is less restrictive than old rule
	if newRule.CrossTenantAccess.AllowCrossTenantAccess && !oldRule.CrossTenantAccess.AllowCrossTenantAccess {
		return true
	}

	if !newRule.DataResidency.RequireEncryption && oldRule.DataResidency.RequireEncryption {
		return true
	}

	return false
}

func (tsal *TenantSecurityAuditLogger) isSuspiciousAccess(request *TenantAccessRequest, response *TenantAccessResponse) bool {
	// Simple heuristics for suspicious access patterns
	if request.SubjectTenantID != request.TargetTenantID && !response.Granted {
		return true
	}

	return false
}

func (tsal *TenantSecurityAuditLogger) getResultString(granted bool) string {
	if granted {
		return "granted"
	}
	return "denied"
}

func (tsal *TenantSecurityAuditLogger) getDataClassification(level ComplianceLevel) string {
	switch level {
	case ComplianceLevelHIPAA:
		return "PHI"
	case ComplianceLevelPCIDSS:
		return "PCI"
	case ComplianceLevelFedRAMP:
		return "Controlled"
	default:
		return "Internal"
	}
}

func (tsal *TenantSecurityAuditLogger) getRetentionPeriod(level ComplianceLevel) int {
	switch level {
	case ComplianceLevelHIPAA:
		return 2555 // 7 years
	case ComplianceLevelSOX:
		return 2555 // 7 years
	case ComplianceLevelPCIDSS:
		return 365 // 1 year
	case ComplianceLevelFedRAMP:
		return 1095 // 3 years
	default:
		return 365 // 1 year default
	}
}

// Supporting types
type TenantSecurityAuditFilter struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	SubjectID string    `json:"subject_id,omitempty"`
	EventType string    `json:"event_type,omitempty"`
	Severity  string    `json:"severity,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Limit     int       `json:"limit,omitempty"`
	Offset    int       `json:"offset,omitempty"`
}

type TenantSecurityReport struct {
	TenantID         string                                  `json:"tenant_id"`
	ReportPeriod     time.Duration                           `json:"report_period"`
	GeneratedAt      time.Time                               `json:"generated_at"`
	TotalEntries     int                                     `json:"total_entries"`
	EventSummary     map[TenantSecurityEventType]int         `json:"event_summary"`
	SeveritySummary  map[AuditSeverity]int                   `json:"severity_summary"`
	SecurityAlerts   []SecurityAlert                         `json:"security_alerts"`
	ComplianceStatus ComplianceStatus                        `json:"compliance_status"`
}

type SecurityAlert struct {
	Type        string     `json:"type"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Count       int        `json:"count"`
	LastSeen    *time.Time `json:"last_seen,omitempty"`
}

type ComplianceStatus struct {
	Framework        string    `json:"framework,omitempty"`
	Status           string    `json:"status,omitempty"`
	LastAssessment   time.Time `json:"last_assessment,omitempty"`
	RequirementsMet  int       `json:"requirements_met"`
	TotalRequirements int      `json:"total_requirements"`
}