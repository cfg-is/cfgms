package patch

import (
	"context"
	"fmt"
	"time"
)

// AlertLevel defines the severity of a compliance alert
type AlertLevel string

const (
	// AlertLevelInfo indicates informational alert
	AlertLevelInfo AlertLevel = "info"

	// AlertLevelWarning indicates compliance is approaching breach (7 days)
	AlertLevelWarning AlertLevel = "warning"

	// AlertLevelCritical indicates compliance breach is imminent (1 day)
	AlertLevelCritical AlertLevel = "critical"

	// AlertLevelBreach indicates compliance has been breached
	AlertLevelBreach AlertLevel = "breach"
)

// ComplianceAlert represents a compliance alert for a device
type ComplianceAlert struct {
	// DeviceID is the unique identifier for the device
	DeviceID string `json:"device_id"`

	// DeviceName is the human-readable device name
	DeviceName string `json:"device_name"`

	// Level is the alert severity level
	Level AlertLevel `json:"level"`

	// Status is the overall compliance status
	Status ComplianceStatus `json:"status"`

	// DaysUntilBreach is the number of days until compliance breach
	DaysUntilBreach int `json:"days_until_breach"`

	// MissingPatches is the list of missing patches
	MissingPatches []MissingPatchInfo `json:"missing_patches"`

	// Timestamp is when the alert was generated
	Timestamp time.Time `json:"timestamp"`

	// Message is a human-readable alert message
	Message string `json:"message"`

	// Details contains additional alert context
	Details map[string]interface{} `json:"details,omitempty"`

	// PreviousAlerts tracks when this device was previously alerted
	PreviousAlerts []time.Time `json:"previous_alerts,omitempty"`
}

// AlertConfig defines configuration for compliance alerting
type AlertConfig struct {
	// Enabled determines if alerting is active
	Enabled bool `yaml:"enabled" json:"enabled"`

	// WarningThreshold is days before breach to send warning alerts (default: 7)
	WarningThreshold int `yaml:"warning_threshold" json:"warning_threshold"`

	// CriticalThreshold is days before breach to send critical alerts (default: 1)
	CriticalThreshold int `yaml:"critical_threshold" json:"critical_threshold"`

	// AlertInterval is minimum time between alerts for same device (default: 24h)
	AlertInterval time.Duration `yaml:"alert_interval" json:"alert_interval"`

	// MaxAlertsPerDay limits alerts per device per day (default: 3)
	MaxAlertsPerDay int `yaml:"max_alerts_per_day" json:"max_alerts_per_day"`

	// DeliveryChannels defines where to send alerts
	DeliveryChannels []AlertChannel `yaml:"delivery_channels" json:"delivery_channels"`

	// SuppressInfo suppresses informational alerts
	SuppressInfo bool `yaml:"suppress_info" json:"suppress_info"`

	// EscalationPolicy defines alert escalation rules
	EscalationPolicy *EscalationPolicy `yaml:"escalation_policy,omitempty" json:"escalation_policy,omitempty"`
}

// AlertChannel defines an alert delivery channel
type AlertChannel struct {
	// Type is the channel type (email, webhook, slack, teams, etc.)
	Type string `yaml:"type" json:"type"`

	// Target is the destination (email address, webhook URL, etc.)
	Target string `yaml:"target" json:"target"`

	// MinLevel is the minimum alert level for this channel
	MinLevel AlertLevel `yaml:"min_level" json:"min_level"`

	// WorkflowName is the workflow to trigger for alert delivery
	WorkflowName string `yaml:"workflow_name,omitempty" json:"workflow_name,omitempty"`

	// Config contains channel-specific configuration
	Config map[string]interface{} `yaml:"config,omitempty" json:"config,omitempty"`
}

// EscalationPolicy defines alert escalation rules
type EscalationPolicy struct {
	// Enabled determines if escalation is active
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Levels defines escalation levels and timing
	Levels []EscalationLevel `yaml:"levels" json:"levels"`

	// MaxEscalations limits total escalations per alert
	MaxEscalations int `yaml:"max_escalations" json:"max_escalations"`
}

// EscalationLevel defines a single escalation level
type EscalationLevel struct {
	// AfterDuration is how long to wait before escalating
	AfterDuration time.Duration `yaml:"after_duration" json:"after_duration"`

	// Channels defines where to escalate
	Channels []AlertChannel `yaml:"channels" json:"channels"`

	// RequiresAck determines if acknowledgment is required
	RequiresAck bool `yaml:"requires_ack" json:"requires_ack"`
}

// AlertingManager manages compliance alerting
type AlertingManager struct {
	config       AlertConfig
	patchModule  *PatchModule
	alertHistory map[string][]time.Time // deviceID -> alert timestamps
}

// NewAlertingManager creates a new alerting manager
func NewAlertingManager(config AlertConfig, patchModule *PatchModule) *AlertingManager {
	// Set defaults
	if config.WarningThreshold == 0 {
		config.WarningThreshold = 7
	}
	if config.CriticalThreshold == 0 {
		config.CriticalThreshold = 1
	}
	if config.AlertInterval == 0 {
		config.AlertInterval = 24 * time.Hour
	}
	if config.MaxAlertsPerDay == 0 {
		config.MaxAlertsPerDay = 3
	}

	return &AlertingManager{
		config:       config,
		patchModule:  patchModule,
		alertHistory: make(map[string][]time.Time),
	}
}

// CheckDevice checks compliance for a device and generates alerts if needed
func (am *AlertingManager) CheckDevice(ctx context.Context, deviceID string) (*ComplianceAlert, error) {
	if !am.config.Enabled {
		return nil, nil
	}

	// Get compliance report
	report, err := am.patchModule.GetComplianceReport(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get compliance report: %w", err)
	}

	// Determine alert level based on compliance status and days until breach
	level := am.determineAlertLevel(report)

	// Check if we should suppress this alert
	if am.shouldSuppressAlert(deviceID, level) {
		return nil, nil
	}

	// Create alert
	alert := &ComplianceAlert{
		DeviceID:        deviceID,
		DeviceName:      report.DeviceName,
		Level:           level,
		Status:          report.Status,
		DaysUntilBreach: report.DaysUntilBreach,
		MissingPatches:  report.MissingPatches,
		Timestamp:       time.Now(),
		Message:         am.generateAlertMessage(report, level),
		Details:         am.generateAlertDetails(report),
		PreviousAlerts:  am.alertHistory[deviceID],
	}

	// Record alert in history
	am.recordAlert(deviceID)

	return alert, nil
}

// CheckDevices checks compliance for multiple devices
func (am *AlertingManager) CheckDevices(ctx context.Context, deviceIDs []string) ([]*ComplianceAlert, error) {
	alerts := make([]*ComplianceAlert, 0, len(deviceIDs))

	for _, deviceID := range deviceIDs {
		alert, err := am.CheckDevice(ctx, deviceID)
		if err != nil {
			// Log error but continue with other devices
			continue
		}

		if alert != nil {
			alerts = append(alerts, alert)
		}
	}

	return alerts, nil
}

// DeliverAlert delivers an alert through configured channels
func (am *AlertingManager) DeliverAlert(ctx context.Context, alert *ComplianceAlert) error {
	if alert == nil {
		return nil
	}

	// Filter channels by alert level
	channels := am.getChannelsForLevel(alert.Level)
	if len(channels) == 0 {
		return nil
	}

	// Deliver to each channel
	var lastErr error
	for _, channel := range channels {
		if err := am.deliverToChannel(ctx, alert, channel); err != nil {
			lastErr = err
			// Continue with other channels even if one fails
		}
	}

	return lastErr
}

// determineAlertLevel determines the alert level based on compliance report
func (am *AlertingManager) determineAlertLevel(report *ComplianceReport) AlertLevel {
	switch report.Status {
	case ComplianceStatusNonCompliant:
		return AlertLevelBreach

	case ComplianceStatusCritical:
		// Critical status means less than critical threshold days
		return AlertLevelCritical

	case ComplianceStatusWarning:
		// Warning status means less than warning threshold days
		return AlertLevelWarning

	case ComplianceStatusCompliant:
		// Compliant - no alert or info only
		return AlertLevelInfo

	default:
		return AlertLevelInfo
	}
}

// shouldSuppressAlert checks if alert should be suppressed
func (am *AlertingManager) shouldSuppressAlert(deviceID string, level AlertLevel) bool {
	// Always suppress info alerts if configured
	if level == AlertLevelInfo && am.config.SuppressInfo {
		return true
	}

	// Check alert history
	history, exists := am.alertHistory[deviceID]
	if !exists || len(history) == 0 {
		return false
	}

	now := time.Now()

	// Check if we've exceeded max alerts per day
	todayCount := 0
	for _, ts := range history {
		if now.Sub(ts) < 24*time.Hour {
			todayCount++
		}
	}

	if todayCount >= am.config.MaxAlertsPerDay {
		return true
	}

	// Check if alert interval has elapsed
	lastAlert := history[len(history)-1]
	return now.Sub(lastAlert) < am.config.AlertInterval
}

// generateAlertMessage generates a human-readable alert message
func (am *AlertingManager) generateAlertMessage(report *ComplianceReport, level AlertLevel) string {
	deviceName := report.DeviceName
	if deviceName == "" {
		deviceName = "Unknown Device"
	}

	switch level {
	case AlertLevelBreach:
		return fmt.Sprintf("COMPLIANCE BREACH: %s is non-compliant with %d overdue patches. Immediate action required.",
			deviceName, len(report.MissingPatches))

	case AlertLevelCritical:
		return fmt.Sprintf("CRITICAL: %s will breach compliance in %d day(s). %d patches need installation.",
			deviceName, report.DaysUntilBreach, len(report.MissingPatches))

	case AlertLevelWarning:
		return fmt.Sprintf("WARNING: %s is approaching compliance breach in %d days. %d patches pending.",
			deviceName, report.DaysUntilBreach, len(report.MissingPatches))

	case AlertLevelInfo:
		return fmt.Sprintf("INFO: %s is compliant. All patches up to date.",
			deviceName)

	default:
		return fmt.Sprintf("Compliance status for %s: %s", deviceName, report.Status)
	}
}

// generateAlertDetails generates additional alert context
func (am *AlertingManager) generateAlertDetails(report *ComplianceReport) map[string]interface{} {
	details := make(map[string]interface{})

	details["os_version"] = report.OSVersion
	details["total_missing_patches"] = len(report.MissingPatches)
	details["win11_upgrade_eligible"] = report.Win11UpgradeEligible

	// Count by severity
	criticalCount := 0
	importantCount := 0
	moderateCount := 0
	for _, patch := range report.MissingPatches {
		switch patch.Severity {
		case "critical":
			criticalCount++
		case "important":
			importantCount++
		case "moderate":
			moderateCount++
		}
	}

	details["critical_patches"] = criticalCount
	details["important_patches"] = importantCount
	details["moderate_patches"] = moderateCount

	// Add most overdue patch
	if len(report.MissingPatches) > 0 {
		mostOverdue := report.MissingPatches[0]
		for _, p := range report.MissingPatches {
			if p.DaysOverdue > mostOverdue.DaysOverdue {
				mostOverdue = p
			}
		}
		details["most_overdue_patch"] = map[string]interface{}{
			"id":           mostOverdue.ID,
			"title":        mostOverdue.Title,
			"severity":     mostOverdue.Severity,
			"days_overdue": mostOverdue.DaysOverdue,
		}
	}

	// Add compatibility issues if any
	if len(report.CompatibilityIssues) > 0 {
		details["compatibility_issues"] = report.CompatibilityIssues
	}

	return details
}

// recordAlert records an alert in the history
func (am *AlertingManager) recordAlert(deviceID string) {
	now := time.Now()

	// Initialize history if needed
	if am.alertHistory[deviceID] == nil {
		am.alertHistory[deviceID] = make([]time.Time, 0)
	}

	// Add current alert
	am.alertHistory[deviceID] = append(am.alertHistory[deviceID], now)

	// Clean up old history (keep last 30 days)
	cutoff := now.Add(-30 * 24 * time.Hour)
	filtered := make([]time.Time, 0)
	for _, ts := range am.alertHistory[deviceID] {
		if ts.After(cutoff) {
			filtered = append(filtered, ts)
		}
	}
	am.alertHistory[deviceID] = filtered
}

// getChannelsForLevel returns channels that should receive alerts at given level
func (am *AlertingManager) getChannelsForLevel(level AlertLevel) []AlertChannel {
	channels := make([]AlertChannel, 0)

	for _, channel := range am.config.DeliveryChannels {
		if am.shouldSendToChannel(level, channel.MinLevel) {
			channels = append(channels, channel)
		}
	}

	return channels
}

// shouldSendToChannel checks if alert level meets channel minimum
func (am *AlertingManager) shouldSendToChannel(alertLevel, minLevel AlertLevel) bool {
	// Define level hierarchy
	levels := map[AlertLevel]int{
		AlertLevelInfo:     0,
		AlertLevelWarning:  1,
		AlertLevelCritical: 2,
		AlertLevelBreach:   3,
	}

	return levels[alertLevel] >= levels[minLevel]
}

// deliverToChannel delivers alert to a specific channel
func (am *AlertingManager) deliverToChannel(ctx context.Context, alert *ComplianceAlert, channel AlertChannel) error {
	// This would integrate with the workflow engine or direct delivery mechanisms
	// For now, this is a placeholder that would be implemented based on channel type

	switch channel.Type {
	case "workflow":
		// Trigger workflow with alert data
		return am.triggerWorkflow(ctx, channel.WorkflowName, alert)

	case "webhook":
		// Send HTTP POST to webhook URL
		return am.sendWebhook(ctx, channel.Target, alert)

	case "email":
		// Send email (would integrate with email provider)
		return fmt.Errorf("email delivery not yet implemented")

	case "slack":
		// Send Slack message (would integrate with Slack API)
		return fmt.Errorf("slack delivery not yet implemented")

	case "teams":
		// Send Microsoft Teams message (would integrate with Teams API)
		return fmt.Errorf("teams delivery not yet implemented")

	default:
		return fmt.Errorf("unsupported channel type: %s", channel.Type)
	}
}

// triggerWorkflow triggers a workflow for alert delivery
func (am *AlertingManager) triggerWorkflow(ctx context.Context, workflowName string, alert *ComplianceAlert) error {
	// This would integrate with the workflow engine
	// For now, return not implemented
	return fmt.Errorf("workflow integration not yet implemented: %s", workflowName)
}

// sendWebhook sends alert to a webhook URL
func (am *AlertingManager) sendWebhook(ctx context.Context, url string, alert *ComplianceAlert) error {
	// This would use HTTP client to POST alert data
	// For now, return not implemented
	return fmt.Errorf("webhook delivery not yet implemented: %s", url)
}

// DefaultAlertConfig returns default alerting configuration
func DefaultAlertConfig() AlertConfig {
	return AlertConfig{
		Enabled:           true,
		WarningThreshold:  7, // 7 days warning
		CriticalThreshold: 1, // 1 day critical
		AlertInterval:     24 * time.Hour,
		MaxAlertsPerDay:   3,
		SuppressInfo:      true,
		DeliveryChannels: []AlertChannel{
			{
				Type:     "webhook",
				Target:   "",
				MinLevel: AlertLevelWarning,
			},
		},
	}
}

// ComplianceScheduler manages scheduled compliance checks
type ComplianceScheduler struct {
	alertingManager *AlertingManager
	checkInterval   time.Duration
	deviceIDs       []string
}

// NewComplianceScheduler creates a new compliance scheduler
func NewComplianceScheduler(alertingManager *AlertingManager, checkInterval time.Duration, deviceIDs []string) *ComplianceScheduler {
	if checkInterval == 0 {
		checkInterval = 1 * time.Hour // Default to hourly checks
	}

	return &ComplianceScheduler{
		alertingManager: alertingManager,
		checkInterval:   checkInterval,
		deviceIDs:       deviceIDs,
	}
}

// Start begins scheduled compliance checking
func (cs *ComplianceScheduler) Start(ctx context.Context) error {
	ticker := time.NewTicker(cs.checkInterval)
	defer ticker.Stop()

	// Run immediate check (errors logged internally)
	_ = cs.runCheck(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-ticker.C:
			// Continue checking even on errors (errors logged internally)
			_ = cs.runCheck(ctx)
		}
	}
}

// runCheck performs a compliance check for all devices
func (cs *ComplianceScheduler) runCheck(ctx context.Context) error {
	alerts, err := cs.alertingManager.CheckDevices(ctx, cs.deviceIDs)
	if err != nil {
		return err
	}

	// Deliver each alert
	for _, alert := range alerts {
		if err := cs.alertingManager.DeliverAlert(ctx, alert); err != nil {
			// Log error but continue with other alerts
			continue
		}
	}

	return nil
}
