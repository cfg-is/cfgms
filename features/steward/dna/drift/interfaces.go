// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package drift provides real-time configuration drift detection for DNA monitoring.
//
// The drift detection system monitors DNA state changes and identifies
// unauthorized or unexpected configuration modifications within minutes of occurrence.
//
// Key features:
// - Real-time drift detection with 5-minute response time
// - Severity categorization (critical, warning, info)
// - Smart filtering to reduce false positives
// - Custom drift detection rules and policies
// - Machine learning-based anomaly detection
//
// Basic usage:
//
//	detector := drift.NewDetector(config, logger)
//	events := detector.DetectDrift(previousDNA, currentDNA)
//	for _, event := range events {
//		log.Printf("Drift detected: %s", event.Description)
//	}
package drift

import (
	"context"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// Detector defines the interface for drift detection operations.
//
// Detectors analyze DNA state changes and generate drift events when
// unauthorized or unexpected modifications are detected.
type Detector interface {
	// DetectDrift compares two DNA states and returns detected drift events
	DetectDrift(ctx context.Context, previous, current *commonpb.DNA) ([]*DriftEvent, error)

	// DetectDriftBatch processes multiple DNA comparisons efficiently
	DetectDriftBatch(ctx context.Context, comparisons []*DNAComparison) ([]*DriftEvent, error)

	// ValidateRules validates drift detection rules configuration
	ValidateRules(rules []*DriftRule) error

	// UpdateRules updates the active drift detection rules
	UpdateRules(rules []*DriftRule) error

	// GetStats returns drift detection statistics
	GetStats() *DetectorStats

	// Close releases detector resources
	Close() error
}

// Monitor defines the interface for continuous drift monitoring.
//
// Monitors run background processes to continuously scan for drift
// across all managed devices with configurable intervals.
type Monitor interface {
	// Start begins continuous drift monitoring
	Start(ctx context.Context) error

	// Stop halts drift monitoring
	Stop() error

	// SetInterval updates the monitoring scan interval
	SetInterval(interval time.Duration)

	// GetMonitoredDevices returns list of devices being monitored
	GetMonitoredDevices() []string

	// AddDevice adds a device to drift monitoring
	AddDevice(deviceID string) error

	// RemoveDevice removes a device from drift monitoring
	RemoveDevice(deviceID string) error

	// GetMonitorStats returns monitoring statistics
	GetMonitorStats() *MonitorStats
}

// RuleEngine defines the interface for custom drift detection rules.
//
// Rule engines allow defining custom policies for what constitutes
// drift based on attribute types, values, and change patterns.
type RuleEngine interface {
	// EvaluateRules evaluates all active rules against a drift event
	EvaluateRules(ctx context.Context, event *DriftEvent) (*RuleResult, error)

	// AddRule adds a new drift detection rule
	AddRule(rule *DriftRule) error

	// RemoveRule removes a drift detection rule
	RemoveRule(ruleID string) error

	// GetRules returns all active rules
	GetRules() []*DriftRule

	// ValidateRules validates drift detection rules configuration
	ValidateRules(rules []*DriftRule) error

	// TestRule tests a rule against sample data
	TestRule(rule *DriftRule, testData *DNAComparison) (*RuleResult, error)

	// Close releases rule engine resources
	Close() error
}

// Filter defines the interface for drift event filtering.
//
// Filters reduce false positives by analyzing change patterns,
// system context, and expected variations in DNA attributes.
type Filter interface {
	// FilterEvents filters out false positive drift events
	FilterEvents(ctx context.Context, events []*DriftEvent) ([]*DriftEvent, error)

	// IsExpectedChange determines if a change is expected/normal
	IsExpectedChange(change *AttributeChange) (bool, string)

	// AddWhitelist adds an attribute pattern to the whitelist
	AddWhitelist(pattern *WhitelistPattern) error

	// RemoveWhitelist removes a whitelist pattern
	RemoveWhitelist(patternID string) error

	// GetFilterStats returns filtering statistics
	GetFilterStats() *FilterStats

	// Close releases filter resources
	Close() error
}

// DriftEvent represents a detected configuration drift.
type DriftEvent struct {
	// Event identification
	ID        string    `json:"id"`
	DeviceID  string    `json:"device_id"`
	Timestamp time.Time `json:"timestamp"`

	// Event details
	Severity    DriftSeverity `json:"severity"`
	Category    DriftCategory `json:"category"`
	Title       string        `json:"title"`
	Description string        `json:"description"`

	// Change details
	Changes     []*AttributeChange `json:"changes"`
	ChangeCount int                `json:"change_count"`

	// Context
	PreviousDNA *commonpb.DNA `json:"previous_dna,omitempty"`
	CurrentDNA  *commonpb.DNA `json:"current_dna,omitempty"`

	// Analysis metadata
	DetectionTime  time.Duration `json:"detection_time"`
	RulesTriggered []string      `json:"rules_triggered"`
	Confidence     float64       `json:"confidence"` // 0.0-1.0
	RiskScore      float64       `json:"risk_score"` // 0.0-1.0
	Impact         DriftImpact   `json:"impact"`

	// Response metadata
	Status         DriftStatus `json:"status"`
	Acknowledged   bool        `json:"acknowledged"`
	AcknowledgedBy string      `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time  `json:"acknowledged_at,omitempty"`
	Resolution     string      `json:"resolution,omitempty"`
}

// AttributeChange represents a specific attribute change in DNA.
type AttributeChange struct {
	Attribute     string        `json:"attribute"`
	PreviousValue string        `json:"previous_value"`
	CurrentValue  string        `json:"current_value"`
	ChangeType    ChangeType    `json:"change_type"`
	Severity      DriftSeverity `json:"severity"`
	Category      string        `json:"category"` // "hardware", "software", "network", "security"
	Impact        string        `json:"impact"`   // Human-readable impact description
}

// DNAComparison represents a comparison between two DNA states.
type DNAComparison struct {
	DeviceID   string        `json:"device_id"`
	Previous   *commonpb.DNA `json:"previous"`
	Current    *commonpb.DNA `json:"current"`
	ComparedAt time.Time     `json:"compared_at"`
}

// DriftRule defines a custom drift detection rule.
type DriftRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`

	// Rule conditions
	Conditions []*RuleCondition `json:"conditions"`
	Operator   RuleOperator     `json:"operator"` // "AND", "OR"

	// Rule actions
	Severity DriftSeverity `json:"severity"`
	Category DriftCategory `json:"category"`
	Actions  []RuleAction  `json:"actions"`

	// Rule metadata
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	CreatedBy string    `json:"created_by"`
	Priority  int       `json:"priority"` // 1-10, higher = more important

	// Rule statistics
	TriggeredCount int64      `json:"triggered_count"`
	LastTriggered  *time.Time `json:"last_triggered,omitempty"`
}

// RuleCondition defines a condition for drift rule evaluation.
type RuleCondition struct {
	Type      ConditionType `json:"type"`
	Attribute string        `json:"attribute,omitempty"`
	Operator  string        `json:"operator"` // "equals", "contains", "regex", "changed", "threshold"
	Value     string        `json:"value,omitempty"`
	Threshold float64       `json:"threshold,omitempty"`
	Pattern   string        `json:"pattern,omitempty"`
}

// WhitelistPattern defines a pattern for expected changes.
type WhitelistPattern struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Attribute  string     `json:"attribute"`
	Pattern    string     `json:"pattern"` // Regex pattern for expected values
	Reason     string     `json:"reason"`  // Why this change is expected
	ValidUntil *time.Time `json:"valid_until,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// RuleResult represents the result of rule evaluation.
type RuleResult struct {
	RuleID      string       `json:"rule_id"`
	Matched     bool         `json:"matched"`
	Confidence  float64      `json:"confidence"`
	Actions     []RuleAction `json:"actions"`
	Message     string       `json:"message"`
	EvaluatedAt time.Time    `json:"evaluated_at"`
}

// DetectorStats provides statistics about drift detection.
type DetectorStats struct {
	TotalComparisons     int64            `json:"total_comparisons"`
	DriftEventsDetected  int64            `json:"drift_events_detected"`
	CriticalEvents       int64            `json:"critical_events"`
	WarningEvents        int64            `json:"warning_events"`
	InfoEvents           int64            `json:"info_events"`
	FalsePositives       int64            `json:"false_positives"`
	AverageDetectionTime time.Duration    `json:"avg_detection_time"`
	RulesTriggered       map[string]int64 `json:"rules_triggered"`
	LastDetection        *time.Time       `json:"last_detection,omitempty"`
}

// MonitorStats provides statistics about drift monitoring.
type MonitorStats struct {
	MonitoredDevices    int           `json:"monitored_devices"`
	ScanInterval        time.Duration `json:"scan_interval"`
	LastScanTime        time.Time     `json:"last_scan_time"`
	ScansCompleted      int64         `json:"scans_completed"`
	AverageScanDuration time.Duration `json:"avg_scan_duration"`
	DevicesWithDrift    int           `json:"devices_with_drift"`
	PendingScans        int           `json:"pending_scans"`
	MonitoringStatus    MonitorStatus `json:"monitoring_status"`
}

// FilterStats provides statistics about drift event filtering.
type FilterStats struct {
	EventsProcessed     int64         `json:"events_processed"`
	EventsFiltered      int64         `json:"events_filtered"`
	FilteringRate       float64       `json:"filtering_rate"`
	WhitelistMatches    int64         `json:"whitelist_matches"`
	FalsePositivesSaved int64         `json:"false_positives_saved"`
	AverageFilterTime   time.Duration `json:"avg_filter_time"`
}

// Enum types

// DriftSeverity defines the severity levels for drift events.
type DriftSeverity string

const (
	SeverityCritical DriftSeverity = "critical" // Security-related or system-breaking changes
	SeverityWarning  DriftSeverity = "warning"  // Important changes that need attention
	SeverityInfo     DriftSeverity = "info"     // Minor changes for informational purposes
)

// DriftCategory defines categories of drift events.
type DriftCategory string

const (
	CategorySecurity      DriftCategory = "security"      // Security-related changes
	CategoryCompliance    DriftCategory = "compliance"    // Compliance-related changes
	CategoryPerformance   DriftCategory = "performance"   // Performance-impacting changes
	CategoryConfiguration DriftCategory = "configuration" // General configuration changes
	CategoryInventory     DriftCategory = "inventory"     // Hardware/software inventory changes
)

// ChangeType defines types of attribute changes.
type ChangeType string

const (
	ChangeTypeAdded    ChangeType = "added"    // New attribute added
	ChangeTypeRemoved  ChangeType = "removed"  // Attribute removed
	ChangeTypeModified ChangeType = "modified" // Existing attribute changed
)

// DriftImpact defines the potential impact of drift.
type DriftImpact string

const (
	ImpactHigh   DriftImpact = "high"   // High impact on security, compliance, or operations
	ImpactMedium DriftImpact = "medium" // Medium impact with noticeable effects
	ImpactLow    DriftImpact = "low"    // Low impact, informational
)

// DriftStatus defines the status of a drift event.
type DriftStatus string

const (
	StatusNew          DriftStatus = "new"          // Recently detected
	StatusAcknowledged DriftStatus = "acknowledged" // Acknowledged by operator
	StatusResolved     DriftStatus = "resolved"     // Issue resolved
	StatusIgnored      DriftStatus = "ignored"      // Marked as expected/ignored
)

// RuleOperator defines logical operators for rule conditions.
type RuleOperator string

const (
	OperatorAND RuleOperator = "AND"
	OperatorOR  RuleOperator = "OR"
)

// ConditionType defines types of rule conditions.
type ConditionType string

const (
	ConditionAttributeMatch  ConditionType = "attribute_match"  // Match specific attribute value
	ConditionAttributeChange ConditionType = "attribute_change" // Attribute changed
	ConditionThreshold       ConditionType = "threshold"        // Numeric threshold exceeded
	ConditionPattern         ConditionType = "pattern"          // Pattern matching
	ConditionFrequency       ConditionType = "frequency"        // Change frequency
)

// RuleAction defines actions to take when rules are triggered.
type RuleAction string

const (
	ActionAlert    RuleAction = "alert"    // Generate alert
	ActionEmail    RuleAction = "email"    // Send email notification
	ActionWebhook  RuleAction = "webhook"  // Call webhook
	ActionBlock    RuleAction = "block"    // Block the change if possible
	ActionLog      RuleAction = "log"      // Log to audit trail
	ActionEscalate RuleAction = "escalate" // Escalate to higher severity
)

// MonitorStatus defines the status of drift monitoring.
type MonitorStatus string

const (
	MonitorStatusRunning MonitorStatus = "running"
	MonitorStatusStopped MonitorStatus = "stopped"
	MonitorStatusError   MonitorStatus = "error"
)
