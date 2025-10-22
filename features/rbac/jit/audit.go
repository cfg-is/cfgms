package jit

import (
	"context"
	"fmt"
	"time"
)

// JITAuditLogger handles audit logging for JIT access events
type JITAuditLogger struct {
	entries []JITAuditEntry
}

// NewJITAuditLogger creates a new JIT audit logger
func NewJITAuditLogger() *JITAuditLogger {
	return &JITAuditLogger{
		entries: make([]JITAuditEntry, 0),
	}
}

// JITAuditEntry represents an audit log entry for JIT access events
type JITAuditEntry struct {
	ID             string                 `json:"id"`
	Timestamp      time.Time              `json:"timestamp"`
	EventType      JITAuditEventType      `json:"event_type"`
	TenantID       string                 `json:"tenant_id"`
	ActorID        string                 `json:"actor_id"`    // Who performed the action
	SubjectID      string                 `json:"subject_id"`  // Who the action affects
	ResourceID     string                 `json:"resource_id"` // Request ID or Grant ID
	Action         string                 `json:"action"`
	Status         string                 `json:"status"`
	Reason         string                 `json:"reason,omitempty"`
	Duration       *time.Duration         `json:"duration,omitempty"`
	Permissions    []string               `json:"permissions,omitempty"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	SessionID      string                 `json:"session_id,omitempty"`
	Details        map[string]interface{} `json:"details,omitempty"`
	Severity       JITAuditSeverity       `json:"severity"`
	ComplianceInfo *JITComplianceInfo     `json:"compliance_info,omitempty"`
}

// JITAuditEventType defines the types of JIT access audit events
type JITAuditEventType string

const (
	JITAuditEventAccessRequested     JITAuditEventType = "access_requested"
	JITAuditEventAccessApproved      JITAuditEventType = "access_approved"
	JITAuditEventAccessDenied        JITAuditEventType = "access_denied"
	JITAuditEventAccessActivated     JITAuditEventType = "access_activated"
	JITAuditEventAccessDeactivated   JITAuditEventType = "access_deactivated"
	JITAuditEventAccessExtended      JITAuditEventType = "access_extended"
	JITAuditEventAccessRevoked       JITAuditEventType = "access_revoked"
	JITAuditEventAccessExpired       JITAuditEventType = "access_expired"
	JITAuditEventAccessUsed          JITAuditEventType = "access_used"
	JITAuditEventApprovalEscalated   JITAuditEventType = "approval_escalated"
	JITAuditEventPolicyViolation     JITAuditEventType = "policy_violation"
	JITAuditEventComplianceViolation JITAuditEventType = "compliance_violation"
)

// JITAuditSeverity defines the severity levels for audit events
type JITAuditSeverity string

const (
	JITAuditSeverityInfo     JITAuditSeverity = "info"
	JITAuditSeverityWarning  JITAuditSeverity = "warning"
	JITAuditSeverityCritical JITAuditSeverity = "critical"
	JITAuditSeverityHigh     JITAuditSeverity = "high"
)

// JITComplianceInfo contains compliance-related information
type JITComplianceInfo struct {
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	RequirementsChecked  []string `json:"requirements_checked"`
	RequirementsViolated []string `json:"requirements_violated"`
	Controls             []string `json:"controls"`
	Evidence             string   `json:"evidence,omitempty"`
}

// LogAccessRequest logs a JIT access request event
func (jal *JITAuditLogger) LogAccessRequest(ctx context.Context, request *JITAccessRequest, action string) error {
	entry := JITAuditEntry{
		ID:          fmt.Sprintf("request-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   JITAuditEventAccessRequested,
		TenantID:    request.TenantID,
		ActorID:     request.RequesterID,
		SubjectID:   request.RequesterID,
		ResourceID:  request.ID,
		Action:      action,
		Status:      string(request.Status),
		Reason:      request.Justification,
		Duration:    &request.Duration,
		Permissions: request.Permissions,
		Severity:    jal.determineSeverity(request),
		Details: map[string]interface{}{
			"emergency_access": request.EmergencyAccess,
			"auto_approve":     request.AutoApprove,
			"priority":         request.Priority,
			"resources":        request.ResourceIDs,
		},
		ComplianceInfo: jal.generateComplianceInfo(request),
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// LogAccessApproval logs a JIT access approval event
func (jal *JITAuditLogger) LogAccessApproval(ctx context.Context, request *JITAccessRequest, grant *JITAccessGrant, approverID string) error {
	entry := JITAuditEntry{
		ID:          fmt.Sprintf("approval-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   JITAuditEventAccessApproved,
		TenantID:    request.TenantID,
		ActorID:     approverID,
		SubjectID:   request.RequesterID,
		ResourceID:  request.ID,
		Action:      "approve",
		Status:      "approved",
		Reason:      grant.ApprovalReason,
		Duration:    &request.Duration,
		Permissions: request.Permissions,
		Severity:    JITAuditSeverityInfo,
		Details: map[string]interface{}{
			"grant_id":          grant.ID,
			"expires_at":        grant.ExpiresAt,
			"activation_method": grant.ActivationMethod,
			"conditions":        grant.Conditions,
		},
		ComplianceInfo: jal.generateComplianceInfo(request),
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// LogAccessDenial logs a JIT access denial event
func (jal *JITAuditLogger) LogAccessDenial(ctx context.Context, request *JITAccessRequest, reviewerID, reason string) error {
	entry := JITAuditEntry{
		ID:          fmt.Sprintf("denial-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   JITAuditEventAccessDenied,
		TenantID:    request.TenantID,
		ActorID:     reviewerID,
		SubjectID:   request.RequesterID,
		ResourceID:  request.ID,
		Action:      "deny",
		Status:      "denied",
		Reason:      reason,
		Duration:    &request.Duration,
		Permissions: request.Permissions,
		Severity:    JITAuditSeverityWarning,
		Details: map[string]interface{}{
			"original_justification": request.Justification,
			"emergency_access":       request.EmergencyAccess,
			"priority":               request.Priority,
		},
		ComplianceInfo: jal.generateComplianceInfo(request),
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// LogAccessExtension logs a JIT access extension event
func (jal *JITAuditLogger) LogAccessExtension(ctx context.Context, grant *JITAccessGrant, requesterID string, duration time.Duration, reason string) error {
	entry := JITAuditEntry{
		ID:          fmt.Sprintf("extension-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   JITAuditEventAccessExtended,
		TenantID:    grant.TenantID,
		ActorID:     requesterID,
		SubjectID:   grant.RequesterID,
		ResourceID:  grant.ID,
		Action:      "extend",
		Status:      "extended",
		Reason:      reason,
		Duration:    &duration,
		Permissions: grant.Permissions,
		Severity:    JITAuditSeverityInfo,
		Details: map[string]interface{}{
			"original_expires_at": grant.ExpiresAt.Add(-duration),
			"new_expires_at":      grant.ExpiresAt,
			"extensions_used":     grant.ExtensionsUsed,
			"max_extensions":      grant.MaxExtensions,
		},
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// LogAccessRevocation logs a JIT access revocation event
func (jal *JITAuditLogger) LogAccessRevocation(ctx context.Context, grant *JITAccessGrant, revokerID, reason string) error {
	entry := JITAuditEntry{
		ID:          fmt.Sprintf("revocation-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   JITAuditEventAccessRevoked,
		TenantID:    grant.TenantID,
		ActorID:     revokerID,
		SubjectID:   grant.RequesterID,
		ResourceID:  grant.ID,
		Action:      "revoke",
		Status:      "revoked",
		Reason:      reason,
		Permissions: grant.Permissions,
		Severity:    JITAuditSeverityHigh,
		Details: map[string]interface{}{
			"original_expires_at": grant.ExpiresAt,
			"remaining_duration":  time.Until(grant.ExpiresAt),
			"delegation_id":       grant.DelegationID,
		},
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// LogAccessUsage logs when JIT access is actually used
func (jal *JITAuditLogger) LogAccessUsage(ctx context.Context, grant *JITAccessGrant, action, resourceID string, context map[string]interface{}) error {
	entry := JITAuditEntry{
		ID:          fmt.Sprintf("usage-%d", time.Now().UnixNano()),
		Timestamp:   time.Now(),
		EventType:   JITAuditEventAccessUsed,
		TenantID:    grant.TenantID,
		ActorID:     grant.RequesterID,
		SubjectID:   grant.RequesterID,
		ResourceID:  grant.ID,
		Action:      action,
		Status:      "used",
		Permissions: grant.Permissions,
		Severity:    JITAuditSeverityInfo,
		Details: map[string]interface{}{
			"accessed_resource": resourceID,
			"context":           context,
			"remaining_time":    time.Until(grant.ExpiresAt),
		},
	}

	// Enhanced logging for emergency access
	if len(grant.Conditions) > 0 {
		for _, condition := range grant.Conditions {
			if condition.Type == ConditionTypeAuditEnhanced {
				entry.Severity = JITAuditSeverityHigh
				entry.Details["enhanced_audit"] = true
				break
			}
		}
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// LogPolicyViolation logs policy violations related to JIT access
func (jal *JITAuditLogger) LogPolicyViolation(ctx context.Context, tenantID, subjectID, violationType, description string, details map[string]interface{}) error {
	entry := JITAuditEntry{
		ID:        fmt.Sprintf("violation-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: JITAuditEventPolicyViolation,
		TenantID:  tenantID,
		ActorID:   subjectID,
		SubjectID: subjectID,
		Action:    "policy_violation",
		Status:    "violation",
		Reason:    description,
		Severity:  JITAuditSeverityCritical,
		Details:   details,
	}

	jal.entries = append(jal.entries, entry)
	return nil
}

// GetAuditEntries retrieves audit entries with optional filtering
func (jal *JITAuditLogger) GetAuditEntries(ctx context.Context, filter *JITAuditFilter) ([]JITAuditEntry, error) {
	var results []JITAuditEntry

	for _, entry := range jal.entries {
		if jal.matchesAuditFilter(entry, filter) {
			results = append(results, entry)
		}
	}

	return results, nil
}

// GetJITAuditReport generates a comprehensive audit report
func (jal *JITAuditLogger) GetJITAuditReport(ctx context.Context, tenantID string, period time.Duration) (*JITAuditReport, error) {
	filter := &JITAuditFilter{
		TenantID: tenantID,
		DateFrom: func() *time.Time { t := time.Now().Add(-period); return &t }(),
		DateTo:   func() *time.Time { t := time.Now(); return &t }(),
	}

	entries, err := jal.GetAuditEntries(ctx, filter)
	if err != nil {
		return nil, err
	}

	report := &JITAuditReport{
		TenantID:        tenantID,
		ReportPeriod:    period,
		GeneratedAt:     time.Now(),
		TotalEvents:     len(entries),
		EventSummary:    make(map[JITAuditEventType]int),
		SeveritySummary: make(map[JITAuditSeverity]int),
	}

	var highRiskEvents []JITAuditEntry
	var complianceViolations []JITAuditEntry
	uniqueUsers := make(map[string]bool)

	for _, entry := range entries {
		report.EventSummary[entry.EventType]++
		report.SeveritySummary[entry.Severity]++
		uniqueUsers[entry.SubjectID] = true

		if entry.Severity == JITAuditSeverityCritical || entry.Severity == JITAuditSeverityHigh {
			highRiskEvents = append(highRiskEvents, entry)
		}

		if entry.EventType == JITAuditEventComplianceViolation {
			complianceViolations = append(complianceViolations, entry)
		}
	}

	report.UniqueUsers = len(uniqueUsers)
	report.HighRiskEvents = highRiskEvents
	report.ComplianceViolations = complianceViolations

	return report, nil
}

// Helper methods

func (jal *JITAuditLogger) determineSeverity(request *JITAccessRequest) JITAuditSeverity {
	if request.EmergencyAccess {
		return JITAuditSeverityCritical
	}
	if request.Priority == AccessPriorityCritical || request.Priority == AccessPriorityEmergency {
		return JITAuditSeverityHigh
	}
	if request.Duration > 8*time.Hour {
		return JITAuditSeverityWarning
	}
	return JITAuditSeverityInfo
}

func (jal *JITAuditLogger) generateComplianceInfo(request *JITAccessRequest) *JITComplianceInfo {
	info := &JITComplianceInfo{
		ComplianceFrameworks: []string{"iso27001", "soc2"},
		RequirementsChecked:  []string{"access_control", "audit_logging"},
	}

	// Add emergency access compliance requirements
	if request.EmergencyAccess {
		info.ComplianceFrameworks = append(info.ComplianceFrameworks, "incident_response")
		info.RequirementsChecked = append(info.RequirementsChecked, "emergency_procedures")
		info.Controls = append(info.Controls, "emergency_access_logging")
	}

	return info
}

func (jal *JITAuditLogger) matchesAuditFilter(entry JITAuditEntry, filter *JITAuditFilter) bool {
	if filter == nil {
		return true
	}

	if filter.TenantID != "" && entry.TenantID != filter.TenantID {
		return false
	}
	if filter.EventType != "" && entry.EventType != JITAuditEventType(filter.EventType) {
		return false
	}
	if filter.ActorID != "" && entry.ActorID != filter.ActorID {
		return false
	}
	if filter.DateFrom != nil && entry.Timestamp.Before(*filter.DateFrom) {
		return false
	}
	if filter.DateTo != nil && entry.Timestamp.After(*filter.DateTo) {
		return false
	}

	return true
}

// Supporting types

// JITAuditFilter for filtering audit entries
type JITAuditFilter struct {
	TenantID  string     `json:"tenant_id,omitempty"`
	EventType string     `json:"event_type,omitempty"`
	ActorID   string     `json:"actor_id,omitempty"`
	SubjectID string     `json:"subject_id,omitempty"`
	Severity  string     `json:"severity,omitempty"`
	DateFrom  *time.Time `json:"date_from,omitempty"`
	DateTo    *time.Time `json:"date_to,omitempty"`
}

// JITAuditReport represents a comprehensive audit report
type JITAuditReport struct {
	TenantID             string                    `json:"tenant_id"`
	ReportPeriod         time.Duration             `json:"report_period"`
	GeneratedAt          time.Time                 `json:"generated_at"`
	TotalEvents          int                       `json:"total_events"`
	UniqueUsers          int                       `json:"unique_users"`
	EventSummary         map[JITAuditEventType]int `json:"event_summary"`
	SeveritySummary      map[JITAuditSeverity]int  `json:"severity_summary"`
	HighRiskEvents       []JITAuditEntry           `json:"high_risk_events"`
	ComplianceViolations []JITAuditEntry           `json:"compliance_violations"`
}
