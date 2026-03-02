// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/api/proto/common"
)

// defaultMaxAuditEntries is the maximum number of audit entries before trimming.
// When exceeded, the oldest 10% of entries are removed to prevent unbounded memory growth.
const defaultMaxAuditEntries = 100_000

// AuditLogger handles permission audit logging and compliance reporting
type AuditLogger struct {
	entries    []*common.PermissionAuditEntry
	maxEntries int
	mutex      sync.RWMutex
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger() *AuditLogger {
	return &AuditLogger{
		entries:    make([]*common.PermissionAuditEntry, 0),
		maxEntries: defaultMaxAuditEntries,
	}
}

// LogPermissionCheck logs a permission check operation
func (a *AuditLogger) LogPermissionCheck(ctx context.Context, req *common.AccessRequest, resp *common.AccessResponse, sourceIP, userAgent string) error {
	entry := common.PermissionAuditEntry{
		Id:           uuid.New().String(),
		SubjectId:    req.SubjectId,
		Action:       "check",
		PermissionId: req.PermissionId,
		ResourceId:   req.ResourceId,
		TenantId:     req.TenantId,
		Granted:      resp.Granted,
		Reason:       resp.Reason,
		Context:      req.Context,
		Timestamp:    time.Now().Unix(),
		SourceIp:     sourceIP,
		UserAgent:    userAgent,
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.entries = append(a.entries, &entry)
	a.trimEntriesLocked()

	return nil
}

// LogPermissionGrant logs a permission grant operation
func (a *AuditLogger) LogPermissionGrant(ctx context.Context, subjectID, permissionID, resourceID, tenantID, grantedBy string, context map[string]string) error {
	entry := common.PermissionAuditEntry{
		Id:           uuid.New().String(),
		SubjectId:    subjectID,
		Action:       "grant",
		PermissionId: permissionID,
		ResourceId:   resourceID,
		TenantId:     tenantID,
		Granted:      true,
		Reason:       fmt.Sprintf("permission granted by %s", grantedBy),
		Context:      context,
		Timestamp:    time.Now().Unix(),
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.entries = append(a.entries, &entry)
	a.trimEntriesLocked()

	return nil
}

// LogPermissionRevoke logs a permission revoke operation
func (a *AuditLogger) LogPermissionRevoke(ctx context.Context, subjectID, permissionID, resourceID, tenantID, revokedBy string, context map[string]string) error {
	entry := common.PermissionAuditEntry{
		Id:           uuid.New().String(),
		SubjectId:    subjectID,
		Action:       "revoke",
		PermissionId: permissionID,
		ResourceId:   resourceID,
		TenantId:     tenantID,
		Granted:      false,
		Reason:       fmt.Sprintf("permission revoked by %s", revokedBy),
		Context:      context,
		Timestamp:    time.Now().Unix(),
	}

	a.mutex.Lock()
	defer a.mutex.Unlock()
	a.entries = append(a.entries, &entry)
	a.trimEntriesLocked()

	return nil
}

// LogPermissionDelegate logs a permission delegation operation
func (a *AuditLogger) LogPermissionDelegate(ctx context.Context, delegatorID, delegateeID, tenantID string, permissionIDs []string, context map[string]string) error {
	for _, permissionID := range permissionIDs {
		entry := common.PermissionAuditEntry{
			Id:           uuid.New().String(),
			SubjectId:    delegateeID,
			Action:       "delegate",
			PermissionId: permissionID,
			TenantId:     tenantID,
			Granted:      true,
			Reason:       fmt.Sprintf("permission delegated by %s", delegatorID),
			Context:      context,
			Timestamp:    time.Now().Unix(),
		}

		a.mutex.Lock()
		a.entries = append(a.entries, &entry)
		a.trimEntriesLocked()
		a.mutex.Unlock()
	}

	return nil
}

// GetAuditEntries retrieves audit entries with optional filtering
func (a *AuditLogger) GetAuditEntries(ctx context.Context, filter *AuditFilter) ([]*common.PermissionAuditEntry, error) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	var filtered []*common.PermissionAuditEntry

	for _, entry := range a.entries {
		if a.matchesFilter(entry, filter) {
			filtered = append(filtered, entry)
		}
	}

	// Apply pagination
	if filter != nil && filter.Limit > 0 {
		start := filter.Offset
		end := start + filter.Limit

		if start >= len(filtered) {
			return []*common.PermissionAuditEntry{}, nil
		}

		if end > len(filtered) {
			end = len(filtered)
		}

		filtered = filtered[start:end]
	}

	return filtered, nil
}

// GetComplianceReport generates a compliance report for audit entries
func (a *AuditLogger) GetComplianceReport(ctx context.Context, filter *AuditFilter) (*ComplianceReport, error) {
	entries, err := a.GetAuditEntries(ctx, filter)
	if err != nil {
		return nil, err
	}

	report := &ComplianceReport{
		GeneratedAt:      time.Now(),
		Filter:           filter,
		TotalEntries:     len(entries),
		SuccessfulAccess: 0,
		DeniedAccess:     0,
		UniqueSubjects:   make(map[string]bool),
		UniqueResources:  make(map[string]bool),
		ActionBreakdown:  make(map[string]int),
		HourlyActivity:   make(map[int]int),
	}

	for _, entry := range entries {
		if entry.Granted {
			report.SuccessfulAccess++
		} else {
			report.DeniedAccess++
		}

		report.UniqueSubjects[entry.SubjectId] = true
		if entry.ResourceId != "" {
			report.UniqueResources[entry.ResourceId] = true
		}

		report.ActionBreakdown[entry.Action]++

		hour := time.Unix(entry.Timestamp, 0).Hour()
		report.HourlyActivity[hour]++
	}

	report.UniqueSubjectCount = len(report.UniqueSubjects)
	report.UniqueResourceCount = len(report.UniqueResources)

	return report, nil
}

// GetSecurityAlerts identifies potential security issues from audit logs
func (a *AuditLogger) GetSecurityAlerts(ctx context.Context, lookbackHours int) ([]*SecurityAlert, error) {
	cutoffTime := time.Now().Add(-time.Duration(lookbackHours) * time.Hour).Unix()

	filter := &AuditFilter{
		StartTime: cutoffTime,
	}

	entries, err := a.GetAuditEntries(ctx, filter)
	if err != nil {
		return nil, err
	}

	var alerts []*SecurityAlert

	// Detect excessive failed access attempts
	failedAttempts := make(map[string]int)
	for _, entry := range entries {
		if !entry.Granted {
			failedAttempts[entry.SubjectId]++
		}
	}

	for subjectID, count := range failedAttempts {
		if count > 10 { // Configurable threshold
			alerts = append(alerts, &SecurityAlert{
				Type:        "excessive_failed_attempts",
				Severity:    "high",
				SubjectID:   subjectID,
				Description: fmt.Sprintf("Subject %s has %d failed access attempts", subjectID, count),
				Timestamp:   time.Now().Unix(),
			})
		}
	}

	// Detect unusual access patterns (access outside normal hours)
	for _, entry := range entries {
		hour := time.Unix(entry.Timestamp, 0).Hour()
		if (hour < 6 || hour > 22) && entry.Granted {
			alerts = append(alerts, &SecurityAlert{
				Type:        "unusual_hours_access",
				Severity:    "medium",
				SubjectID:   entry.SubjectId,
				Description: fmt.Sprintf("Access granted to %s at unusual hour: %d:00", entry.SubjectId, hour),
				Timestamp:   entry.Timestamp,
			})
		}
	}

	// Detect privilege escalation patterns
	escalationAttempts := make(map[string][]string)
	for _, entry := range entries {
		if entry.Action == "grant" || entry.Action == "delegate" {
			escalationAttempts[entry.SubjectId] = append(escalationAttempts[entry.SubjectId], entry.PermissionId)
		}
	}

	for subjectID, permissions := range escalationAttempts {
		if len(permissions) > 5 { // Configurable threshold
			alerts = append(alerts, &SecurityAlert{
				Type:        "potential_privilege_escalation",
				Severity:    "high",
				SubjectID:   subjectID,
				Description: fmt.Sprintf("Subject %s has been granted/delegated %d permissions recently", subjectID, len(permissions)),
				Timestamp:   time.Now().Unix(),
			})
		}
	}

	return alerts, nil
}

// ExportAuditLog exports audit entries in various formats
func (a *AuditLogger) ExportAuditLog(ctx context.Context, filter *AuditFilter, format string) ([]byte, error) {
	entries, err := a.GetAuditEntries(ctx, filter)
	if err != nil {
		return nil, err
	}

	switch format {
	case "json":
		return json.MarshalIndent(entries, "", "  ")
	case "csv":
		return a.exportCSV(entries)
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}
}

// trimEntriesLocked removes the oldest 10% of entries when max is exceeded.
// Must be called while holding a.mutex write lock.
func (a *AuditLogger) trimEntriesLocked() {
	if len(a.entries) > a.maxEntries {
		trimCount := a.maxEntries / 10
		if trimCount < 1 {
			trimCount = 1
		}
		a.entries = a.entries[trimCount:]
	}
}

// matchesFilter checks if an audit entry matches the given filter
func (a *AuditLogger) matchesFilter(entry *common.PermissionAuditEntry, filter *AuditFilter) bool {
	if filter == nil {
		return true
	}

	if filter.SubjectID != "" && entry.SubjectId != filter.SubjectID {
		return false
	}

	if filter.TenantID != "" && entry.TenantId != filter.TenantID {
		return false
	}

	if filter.Action != "" && entry.Action != filter.Action {
		return false
	}

	if filter.PermissionID != "" && entry.PermissionId != filter.PermissionID {
		return false
	}

	if filter.ResourceID != "" && entry.ResourceId != filter.ResourceID {
		return false
	}

	if filter.StartTime > 0 && entry.Timestamp < filter.StartTime {
		return false
	}

	if filter.EndTime > 0 && entry.Timestamp > filter.EndTime {
		return false
	}

	if filter.GrantedOnly != nil && entry.Granted != *filter.GrantedOnly {
		return false
	}

	return true
}

// exportCSV converts audit entries to CSV format
func (a *AuditLogger) exportCSV(entries []*common.PermissionAuditEntry) ([]byte, error) {
	csv := "ID,Subject ID,Action,Permission ID,Resource ID,Tenant ID,Granted,Reason,Timestamp,Source IP\n"

	for _, entry := range entries {
		csv += fmt.Sprintf("%s,%s,%s,%s,%s,%s,%t,%s,%d,%s\n",
			entry.Id, entry.SubjectId, entry.Action, entry.PermissionId, entry.ResourceId,
			entry.TenantId, entry.Granted, entry.Reason, entry.Timestamp, entry.SourceIp)
	}

	return []byte(csv), nil
}

// AuditFilter represents filtering options for audit queries
type AuditFilter struct {
	SubjectID    string `json:"subject_id,omitempty"`
	TenantID     string `json:"tenant_id,omitempty"`
	Action       string `json:"action,omitempty"`
	PermissionID string `json:"permission_id,omitempty"`
	ResourceID   string `json:"resource_id,omitempty"`
	StartTime    int64  `json:"start_time,omitempty"`
	EndTime      int64  `json:"end_time,omitempty"`
	GrantedOnly  *bool  `json:"granted_only,omitempty"`
	Limit        int    `json:"limit,omitempty"`
	Offset       int    `json:"offset,omitempty"`
}

// ComplianceReport represents a compliance audit report
type ComplianceReport struct {
	GeneratedAt         time.Time       `json:"generated_at"`
	Filter              *AuditFilter    `json:"filter"`
	TotalEntries        int             `json:"total_entries"`
	SuccessfulAccess    int             `json:"successful_access"`
	DeniedAccess        int             `json:"denied_access"`
	UniqueSubjects      map[string]bool `json:"-"` // Internal use only
	UniqueSubjectCount  int             `json:"unique_subject_count"`
	UniqueResources     map[string]bool `json:"-"` // Internal use only
	UniqueResourceCount int             `json:"unique_resource_count"`
	ActionBreakdown     map[string]int  `json:"action_breakdown"`
	HourlyActivity      map[int]int     `json:"hourly_activity"`
}

// SecurityAlert represents a potential security issue
type SecurityAlert struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	SubjectID   string `json:"subject_id"`
	Description string `json:"description"`
	Timestamp   int64  `json:"timestamp"`
}
