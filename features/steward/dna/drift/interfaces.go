// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package drift provides real-time DNA drift detection.
//
// The public surface after the drift-trim (Issue #921):
//
//   - Detector / NewDetector — compare two DNA states, return DriftEvent slices
//   - DriftEvent, AttributeChange, DNAComparison — event and change data types
//   - DriftSeverity (SeverityCritical / SeverityWarning / SeverityInfo) — severity
//   - DriftCategory, ChangeType, DriftImpact, DriftStatus — classification enums
//   - DetectorStats — runtime statistics from the detector
//
// Basic usage:
//
//	detector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logger)
//	events, err := detector.DetectDrift(ctx, previousDNA, currentDNA)
//
// The monitor, event-publisher, rule-engine, and filter subsystems had zero
// external callers and were retired in this PR to reduce maintenance surface.
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

	// GetStats returns drift detection statistics
	GetStats() *DetectorStats

	// Close releases detector resources
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
