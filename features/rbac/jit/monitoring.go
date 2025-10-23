// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package jit

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// JITAccessMonitor provides real-time monitoring and alerting for JIT access
type JITAccessMonitor struct {
	accessManager       *JITAccessManager
	elevationManager    *PrivilegeElevationManager
	timeController      *TimeBasedAccessController
	auditLogger         *JITAuditLogger
	alertRules          map[string]*AlertRule
	activeAlerts        map[string]*ActiveAlert
	monitoringStats     *MonitoringStats
	notificationService NotificationService
	mutex               sync.RWMutex
	stopChannel         chan struct{}
	monitorInterval     time.Duration
}

// NewJITAccessMonitor creates a new JIT access monitor
func NewJITAccessMonitor(
	accessManager *JITAccessManager,
	elevationManager *PrivilegeElevationManager,
	timeController *TimeBasedAccessController,
	notificationService NotificationService,
) *JITAccessMonitor {
	return &JITAccessMonitor{
		accessManager:       accessManager,
		elevationManager:    elevationManager,
		timeController:      timeController,
		auditLogger:         NewJITAuditLogger(),
		alertRules:          make(map[string]*AlertRule),
		activeAlerts:        make(map[string]*ActiveAlert),
		monitoringStats:     &MonitoringStats{},
		notificationService: notificationService,
		mutex:               sync.RWMutex{},
		stopChannel:         make(chan struct{}),
		monitorInterval:     30 * time.Second, // Monitor every 30 seconds
	}
}

// AlertRule defines rules for generating alerts
type AlertRule struct {
	ID              string        `json:"id"`
	Name            string        `json:"name"`
	TenantID        string        `json:"tenant_id,omitempty"`
	Type            AlertType     `json:"type"`
	Severity        AlertSeverity `json:"severity"`
	Condition       string        `json:"condition"`
	Threshold       interface{}   `json:"threshold"`
	TimeWindow      time.Duration `json:"time_window"`
	Enabled         bool          `json:"enabled"`
	NotifyOnTrigger bool          `json:"notify_on_trigger"`
	NotifyOnResolve bool          `json:"notify_on_resolve"`
	Recipients      []string      `json:"recipients"`
	Cooldown        time.Duration `json:"cooldown"`
	LastTriggered   *time.Time    `json:"last_triggered,omitempty"`
	TriggerCount    int           `json:"trigger_count"`
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// ActiveAlert represents an active alert
type ActiveAlert struct {
	ID             string                 `json:"id"`
	RuleID         string                 `json:"rule_id"`
	TenantID       string                 `json:"tenant_id,omitempty"`
	Type           AlertType              `json:"type"`
	Severity       AlertSeverity          `json:"severity"`
	Title          string                 `json:"title"`
	Description    string                 `json:"description"`
	TriggeredAt    time.Time              `json:"triggered_at"`
	LastUpdated    time.Time              `json:"last_updated"`
	Status         AlertStatus            `json:"status"`
	AffectedGrants []string               `json:"affected_grants,omitempty"`
	AffectedUsers  []string               `json:"affected_users,omitempty"`
	MetricValue    interface{}            `json:"metric_value,omitempty"`
	Threshold      interface{}            `json:"threshold,omitempty"`
	AutoResolved   bool                   `json:"auto_resolved"`
	ResolvedAt     *time.Time             `json:"resolved_at,omitempty"`
	ResolvedBy     string                 `json:"resolved_by,omitempty"`
	ResolutionNote string                 `json:"resolution_note,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

// MonitoringStats tracks monitoring statistics
type MonitoringStats struct {
	ActiveGrants         int                   `json:"active_grants"`
	TotalRequests        int                   `json:"total_requests"`
	PendingRequests      int                   `json:"pending_requests"`
	ApprovedRequests     int                   `json:"approved_requests"`
	DeniedRequests       int                   `json:"denied_requests"`
	ExpiredGrants        int                   `json:"expired_grants"`
	RevokedGrants        int                   `json:"revoked_grants"`
	ActiveElevations     int                   `json:"active_elevations"`
	BreakGlassAccesses   int                   `json:"break_glass_accesses"`
	HighRiskActivities   int                   `json:"high_risk_activities"`
	ActiveAlerts         int                   `json:"active_alerts"`
	AlertsByType         map[AlertType]int     `json:"alerts_by_type"`
	AlertsBySeverity     map[AlertSeverity]int `json:"alerts_by_severity"`
	ComplianceViolations int                   `json:"compliance_violations"`
	AverageRequestTime   time.Duration         `json:"average_request_time"`
	AverageGrantDuration time.Duration         `json:"average_grant_duration"`
	TopRequesters        []UserActivityStat    `json:"top_requesters"`
	TopApprovers         []UserActivityStat    `json:"top_approvers"`
	PermissionUsageStats map[string]int        `json:"permission_usage_stats"`
	LastUpdated          time.Time             `json:"last_updated"`
}

// UserActivityStat represents user activity statistics
type UserActivityStat struct {
	UserID       string    `json:"user_id"`
	TenantID     string    `json:"tenant_id"`
	Count        int       `json:"count"`
	LastActivity time.Time `json:"last_activity"`
}

// AlertType defines types of alerts
type AlertType string

const (
	AlertTypeUnusualActivity          AlertType = "unusual_activity"
	AlertTypeHighVolumeRequests       AlertType = "high_volume_requests"
	AlertTypeBreakGlassUsage          AlertType = "break_glass_usage"
	AlertTypeElevationAnomaly         AlertType = "elevation_anomaly"
	AlertTypeComplianceViolation      AlertType = "compliance_violation"
	AlertTypeSuspiciousPattern        AlertType = "suspicious_pattern"
	AlertTypeExpiredGrantsExcess      AlertType = "expired_grants_excess"
	AlertTypeFailedApprovals          AlertType = "failed_approvals"
	AlertTypePermissionEscalation     AlertType = "permission_escalation"
	AlertTypeTimeRestrictionViolation AlertType = "time_restriction_violation"
)

// AlertSeverity defines alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityHigh     AlertSeverity = "high"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertStatus defines alert status
type AlertStatus string

const (
	AlertStatusActive     AlertStatus = "active"
	AlertStatusResolved   AlertStatus = "resolved"
	AlertStatusSuppressed AlertStatus = "suppressed"
	AlertStatusIgnored    AlertStatus = "ignored"
)

// Start begins the JIT access monitoring
func (jam *JITAccessMonitor) Start(ctx context.Context) error {
	// Initialize default alert rules
	jam.initializeDefaultAlertRules()

	ticker := time.NewTicker(jam.monitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-jam.stopChannel:
			return nil
		case <-ticker.C:
			jam.performMonitoringCycle(ctx)
		}
	}
}

// Stop stops the JIT access monitoring
func (jam *JITAccessMonitor) Stop() {
	close(jam.stopChannel)
}

// performMonitoringCycle performs a complete monitoring cycle
func (jam *JITAccessMonitor) performMonitoringCycle(ctx context.Context) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	// Update monitoring statistics
	jam.updateMonitoringStats(ctx)

	// Evaluate alert rules
	jam.evaluateAlertRules(ctx)

	// Check for compliance violations
	jam.checkComplianceViolations(ctx)

	// Detect unusual patterns
	jam.detectUnusualPatterns(ctx)

	// Clean up resolved alerts
	jam.cleanupResolvedAlerts()
}

// updateMonitoringStats updates monitoring statistics
func (jam *JITAccessMonitor) updateMonitoringStats(ctx context.Context) {
	stats := jam.monitoringStats

	// Get active grants
	activeGrants, _ := jam.accessManager.GetActiveGrants(ctx, "", "")
	stats.ActiveGrants = len(activeGrants)

	// Count requests by status
	allRequests, _ := jam.accessManager.ListRequests(ctx, nil)
	stats.TotalRequests = len(allRequests)

	stats.PendingRequests = 0
	stats.ApprovedRequests = 0
	stats.DeniedRequests = 0

	for _, request := range allRequests {
		switch request.Status {
		case JITAccessRequestStatusPending:
			stats.PendingRequests++
		case JITAccessRequestStatusApproved:
			stats.ApprovedRequests++
		case JITAccessRequestStatusDenied:
			stats.DeniedRequests++
		}
	}

	// Get elevation statistics
	if jam.elevationManager != nil {
		elevatedSessions, _ := jam.elevationManager.GetElevatedSessions(ctx, &ElevationFilter{})
		stats.ActiveElevations = 0
		stats.BreakGlassAccesses = 0

		for _, session := range elevatedSessions {
			if session.Status == ElevationStatusActive {
				stats.ActiveElevations++
				if session.ElevationType == ElevationTypeBreakGlass {
					stats.BreakGlassAccesses++
				}
			}
		}
	}

	// Count active alerts
	stats.ActiveAlerts = 0
	stats.AlertsByType = make(map[AlertType]int)
	stats.AlertsBySeverity = make(map[AlertSeverity]int)

	for _, alert := range jam.activeAlerts {
		if alert.Status == AlertStatusActive {
			stats.ActiveAlerts++
			stats.AlertsByType[alert.Type]++
			stats.AlertsBySeverity[alert.Severity]++
		}
	}

	stats.LastUpdated = time.Now()
}

// evaluateAlertRules evaluates all enabled alert rules
func (jam *JITAccessMonitor) evaluateAlertRules(ctx context.Context) {
	for _, rule := range jam.alertRules {
		if !rule.Enabled {
			continue
		}

		// Check cooldown period
		if rule.LastTriggered != nil && time.Since(*rule.LastTriggered) < rule.Cooldown {
			continue
		}

		// Evaluate the rule condition
		triggered, value, err := jam.evaluateAlertCondition(ctx, rule)
		if err != nil {
			continue // Log error in production
		}

		if triggered {
			jam.triggerAlert(ctx, rule, value)
		}
	}
}

// evaluateAlertCondition evaluates a specific alert rule condition
func (jam *JITAccessMonitor) evaluateAlertCondition(ctx context.Context, rule *AlertRule) (bool, interface{}, error) {
	switch rule.Type {
	case AlertTypeHighVolumeRequests:
		return jam.evaluateHighVolumeRequests(ctx, rule)
	case AlertTypeBreakGlassUsage:
		return jam.evaluateBreakGlassUsage(ctx, rule)
	case AlertTypeUnusualActivity:
		return jam.evaluateUnusualActivity(ctx, rule)
	case AlertTypeElevationAnomaly:
		return jam.evaluateElevationAnomaly(ctx, rule)
	default:
		return false, nil, fmt.Errorf("unknown alert type: %s", rule.Type)
	}
}

// evaluateHighVolumeRequests checks for high volume of JIT access requests
func (jam *JITAccessMonitor) evaluateHighVolumeRequests(ctx context.Context, rule *AlertRule) (bool, interface{}, error) {
	threshold, ok := rule.Threshold.(int)
	if !ok {
		return false, nil, fmt.Errorf("invalid threshold type for high volume requests")
	}

	// Count requests in the time window
	cutoff := time.Now().Add(-rule.TimeWindow)
	filter := &JITAccessRequestFilter{
		TenantID: rule.TenantID,
		DateFrom: &cutoff,
	}

	requests, err := jam.accessManager.ListRequests(ctx, filter)
	if err != nil {
		return false, nil, err
	}

	requestCount := len(requests)
	return requestCount > threshold, requestCount, nil
}

// evaluateBreakGlassUsage checks for break-glass access usage
func (jam *JITAccessMonitor) evaluateBreakGlassUsage(ctx context.Context, rule *AlertRule) (bool, interface{}, error) {
	if jam.elevationManager == nil {
		return false, nil, nil
	}

	// Count break-glass sessions in the time window
	cutoff := time.Now().Add(-rule.TimeWindow)
	filter := &ElevationFilter{
		TenantID: rule.TenantID,
		DateFrom: &cutoff,
	}

	sessions, err := jam.elevationManager.GetElevatedSessions(ctx, filter)
	if err != nil {
		return false, nil, err
	}

	breakGlassCount := 0
	for _, session := range sessions {
		if session.ElevationType == ElevationTypeBreakGlass {
			breakGlassCount++
		}
	}

	threshold, ok := rule.Threshold.(int)
	if !ok {
		threshold = 1 // Default: any break-glass usage triggers alert
	}

	return breakGlassCount >= threshold, breakGlassCount, nil
}

// evaluateUnusualActivity checks for unusual JIT access patterns
func (jam *JITAccessMonitor) evaluateUnusualActivity(ctx context.Context, rule *AlertRule) (bool, interface{}, error) {
	// This is a simplified implementation
	// In production, this would use machine learning or statistical analysis

	cutoff := time.Now().Add(-rule.TimeWindow)
	filter := &JITAccessRequestFilter{
		TenantID: rule.TenantID,
		DateFrom: &cutoff,
	}

	requests, err := jam.accessManager.ListRequests(ctx, filter)
	if err != nil {
		return false, nil, err
	}

	// Look for unusual patterns (simplified)
	userRequestCounts := make(map[string]int)
	for _, request := range requests {
		userRequestCounts[request.RequesterID]++
	}

	// Flag if any user has made significantly more requests than usual
	threshold, ok := rule.Threshold.(int)
	if !ok {
		threshold = 10 // Default threshold
	}

	for userID, count := range userRequestCounts {
		if count > threshold {
			return true, map[string]interface{}{
				"user_id": userID,
				"count":   count,
			}, nil
		}
	}

	return false, nil, nil
}

// evaluateElevationAnomaly checks for privilege elevation anomalies
func (jam *JITAccessMonitor) evaluateElevationAnomaly(ctx context.Context, rule *AlertRule) (bool, interface{}, error) {
	if jam.elevationManager == nil {
		return false, nil, nil
	}

	cutoff := time.Now().Add(-rule.TimeWindow)
	filter := &ElevationFilter{
		TenantID: rule.TenantID,
		DateFrom: &cutoff,
	}

	sessions, err := jam.elevationManager.GetElevatedSessions(ctx, filter)
	if err != nil {
		return false, nil, err
	}

	// Check for anomalies in elevation patterns
	highLevelElevations := 0
	for _, session := range sessions {
		if session.ElevationLevel == ElevationLevelMaximum ||
			session.ElevationLevel == ElevationLevelBreakGlass {
			highLevelElevations++
		}
	}

	threshold, ok := rule.Threshold.(int)
	if !ok {
		threshold = 3 // Default threshold for high-level elevations
	}

	return highLevelElevations > threshold, highLevelElevations, nil
}

// triggerAlert triggers an alert when a rule condition is met
func (jam *JITAccessMonitor) triggerAlert(ctx context.Context, rule *AlertRule, value interface{}) {
	alertID := fmt.Sprintf("alert-%s-%d", rule.ID, time.Now().UnixNano())

	alert := &ActiveAlert{
		ID:          alertID,
		RuleID:      rule.ID,
		TenantID:    rule.TenantID,
		Type:        rule.Type,
		Severity:    rule.Severity,
		Title:       fmt.Sprintf("JIT Access Alert: %s", rule.Name),
		Description: jam.generateAlertDescription(rule, value),
		TriggeredAt: time.Now(),
		LastUpdated: time.Now(),
		Status:      AlertStatusActive,
		MetricValue: value,
		Threshold:   rule.Threshold,
		Context: map[string]interface{}{
			"rule_condition": rule.Condition,
			"time_window":    rule.TimeWindow,
		},
	}

	jam.activeAlerts[alertID] = alert

	// Update rule state
	now := time.Now()
	rule.LastTriggered = &now
	rule.TriggerCount++

	// Send notifications if enabled
	if rule.NotifyOnTrigger && jam.notificationService != nil {
		jam.sendAlertNotification(ctx, alert, "triggered")
	}

	// Audit the alert
	_ = jam.auditLogger.LogPolicyViolation(ctx, rule.TenantID, "system", string(rule.Type), alert.Description, map[string]interface{}{
		"alert_id":     alertID,
		"rule_id":      rule.ID,
		"metric_value": value,
		"threshold":    rule.Threshold,
	})
}

// checkComplianceViolations checks for compliance violations
func (jam *JITAccessMonitor) checkComplianceViolations(ctx context.Context) {
	// Check for access patterns that might violate compliance requirements
	// This is a simplified implementation

	cutoff := time.Now().Add(-24 * time.Hour)
	filter := &JITAuditFilter{
		DateFrom: &cutoff,
		Severity: string(JITAuditSeverityHigh),
	}

	entries, err := jam.auditLogger.GetAuditEntries(ctx, filter)
	if err != nil {
		return
	}

	// Look for patterns that might indicate compliance violations
	for _, entry := range entries {
		if entry.EventType == JITAuditEventAccessUsed && entry.Severity == JITAuditSeverityCritical {
			// This might indicate a compliance violation
			jam.flagComplianceViolation(ctx, entry)
		}
	}
}

// detectUnusualPatterns detects unusual patterns in JIT access usage
func (jam *JITAccessMonitor) detectUnusualPatterns(ctx context.Context) {
	// Implement pattern detection algorithms
	// This could include:
	// - Unusual time-of-day access
	// - Unusual duration requests
	// - Unusual permission combinations
	// - Geographic anomalies
}

// flagComplianceViolation flags a potential compliance violation
func (jam *JITAccessMonitor) flagComplianceViolation(ctx context.Context, entry JITAuditEntry) {
	alertID := fmt.Sprintf("compliance-%d", time.Now().UnixNano())

	alert := &ActiveAlert{
		ID:            alertID,
		TenantID:      entry.TenantID,
		Type:          AlertTypeComplianceViolation,
		Severity:      AlertSeverityCritical,
		Title:         "Potential Compliance Violation Detected",
		Description:   fmt.Sprintf("High-risk JIT access activity detected: %s", entry.Action),
		TriggeredAt:   time.Now(),
		LastUpdated:   time.Now(),
		Status:        AlertStatusActive,
		AffectedUsers: []string{entry.SubjectID},
		Context: map[string]interface{}{
			"audit_entry_id": entry.ID,
			"event_type":     entry.EventType,
			"severity":       entry.Severity,
		},
	}

	jam.activeAlerts[alertID] = alert

	// Always send notifications for compliance violations
	if jam.notificationService != nil {
		jam.sendAlertNotification(ctx, alert, "compliance_violation")
	}
}

// sendAlertNotification sends notifications for alerts
func (jam *JITAccessMonitor) sendAlertNotification(ctx context.Context, alert *ActiveAlert, eventType string) {
	// In a real implementation, this would format and send alert notifications
	// through various channels (email, Slack, webhook, etc.)
}

// cleanupResolvedAlerts removes old resolved alerts
func (jam *JITAccessMonitor) cleanupResolvedAlerts() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour) // Keep alerts for 7 days

	for alertID, alert := range jam.activeAlerts {
		if alert.Status == AlertStatusResolved &&
			alert.ResolvedAt != nil &&
			alert.ResolvedAt.Before(cutoff) {
			delete(jam.activeAlerts, alertID)
		}
	}
}

// initializeDefaultAlertRules sets up default alert rules
func (jam *JITAccessMonitor) initializeDefaultAlertRules() {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	// High volume requests alert
	jam.alertRules["high-volume-requests"] = &AlertRule{
		ID:              "high-volume-requests",
		Name:            "High Volume JIT Access Requests",
		Type:            AlertTypeHighVolumeRequests,
		Severity:        AlertSeverityWarning,
		Condition:       "request_count > threshold",
		Threshold:       50, // More than 50 requests in time window
		TimeWindow:      time.Hour,
		Enabled:         true,
		NotifyOnTrigger: true,
		Cooldown:        30 * time.Minute,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Break-glass usage alert
	jam.alertRules["break-glass-usage"] = &AlertRule{
		ID:              "break-glass-usage",
		Name:            "Break-Glass Access Usage",
		Type:            AlertTypeBreakGlassUsage,
		Severity:        AlertSeverityCritical,
		Condition:       "break_glass_count >= threshold",
		Threshold:       1, // Any break-glass usage
		TimeWindow:      time.Hour,
		Enabled:         true,
		NotifyOnTrigger: true,
		Cooldown:        time.Minute, // Low cooldown for critical alerts
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Unusual activity alert
	jam.alertRules["unusual-activity"] = &AlertRule{
		ID:              "unusual-activity",
		Name:            "Unusual JIT Access Activity",
		Type:            AlertTypeUnusualActivity,
		Severity:        AlertSeverityHigh,
		Condition:       "unusual_pattern_detected",
		Threshold:       10, // More than 10 requests per user
		TimeWindow:      4 * time.Hour,
		Enabled:         true,
		NotifyOnTrigger: true,
		Cooldown:        2 * time.Hour,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

// generateAlertDescription generates a description for an alert
func (jam *JITAccessMonitor) generateAlertDescription(rule *AlertRule, value interface{}) string {
	switch rule.Type {
	case AlertTypeHighVolumeRequests:
		return fmt.Sprintf("High volume of JIT access requests detected: %v requests in %s (threshold: %v)",
			value, rule.TimeWindow, rule.Threshold)
	case AlertTypeBreakGlassUsage:
		return fmt.Sprintf("Break-glass access detected: %v instances in %s",
			value, rule.TimeWindow)
	case AlertTypeUnusualActivity:
		return fmt.Sprintf("Unusual JIT access activity pattern detected: %+v", value)
	default:
		return fmt.Sprintf("Alert condition met for rule: %s", rule.Name)
	}
}

// GetActiveAlerts returns active alerts with optional filtering
func (jam *JITAccessMonitor) GetActiveAlerts(ctx context.Context, filter *AlertFilter) ([]*ActiveAlert, error) {
	jam.mutex.RLock()
	defer jam.mutex.RUnlock()

	var results []*ActiveAlert
	for _, alert := range jam.activeAlerts {
		if jam.matchesAlertFilter(alert, filter) {
			results = append(results, alert)
		}
	}

	return results, nil
}

// GetMonitoringStats returns current monitoring statistics
func (jam *JITAccessMonitor) GetMonitoringStats(ctx context.Context) (*MonitoringStats, error) {
	jam.mutex.RLock()
	defer jam.mutex.RUnlock()

	// Update stats before returning
	jam.updateMonitoringStats(ctx)
	return jam.monitoringStats, nil
}

// Helper methods

func (jam *JITAccessMonitor) matchesAlertFilter(alert *ActiveAlert, filter *AlertFilter) bool {
	if filter == nil {
		return true
	}

	if filter.Type != "" && alert.Type != AlertType(filter.Type) {
		return false
	}
	if filter.Severity != "" && alert.Severity != AlertSeverity(filter.Severity) {
		return false
	}
	if filter.Status != "" && alert.Status != AlertStatus(filter.Status) {
		return false
	}
	if filter.TenantID != "" && alert.TenantID != filter.TenantID {
		return false
	}

	return true
}

// Supporting types

// AlertFilter for filtering alerts
type AlertFilter struct {
	Type     string `json:"type,omitempty"`
	Severity string `json:"severity,omitempty"`
	Status   string `json:"status,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}
