// Package drift provides real-time DNA drift detection and monitoring capabilities.
//
// This package implements comprehensive drift detection for DNA (system fingerprint) data,
// allowing detection of unauthorized or unexpected system configuration changes within
// minutes of occurrence.
//
// Key Components:
//
// Detector: Analyzes DNA state changes and generates drift events with severity categorization.
// The detector supports configurable rules, smart filtering, and machine learning-based
// anomaly detection to minimize false positives while ensuring critical changes are detected.
//
// Filter: Reduces false positive drift events by applying intelligent filtering based on
// expected change patterns, temporal analysis, and configurable whitelist patterns.
//
// RuleEngine: Provides a flexible rule system for defining custom drift detection policies
// with support for complex conditions, logical operators, and automated response actions.
//
// Monitor: Implements continuous background monitoring with configurable scan intervals,
// parallel processing, and health monitoring for managed devices.
//
// Integration: Seamlessly integrates with the DNA storage system to provide automated
// drift detection based on stored DNA history and real-time DNA collection.
//
// Basic Usage:
//
//	// Create drift service
//	service, err := drift.NewDriftService(
//		drift.DefaultDetectorConfig(),
//		drift.DefaultFilterConfig(),
//		drift.DefaultRuleEngineConfig(),
//		drift.DefaultMonitorConfig(),
//		logger,
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer service.Close()
//
//	// Detect drift between two DNA states
//	events, err := service.GetDetector().DetectDrift(ctx, previousDNA, currentDNA)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Process detected events
//	for _, event := range events {
//		log.Printf("Drift detected: %s (severity: %s, confidence: %.2f)",
//			event.Title, event.Severity, event.Confidence)
//	}
//
// Advanced Usage with Integration:
//
//	// Create integrated service with DNA storage
//	integrator, err := drift.NewDNADriftIntegrator(
//		storageManager,
//		driftService,
//		drift.DefaultIntegrationConfig(),
//		logger,
//	)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Start automatic drift detection
//	go integrator.StartAutoDetection(ctx)
//
//	// Detect drift for specific device
//	events, err := integrator.DetectDriftForDevice(ctx, "device-123")
//	if err != nil {
//		log.Printf("Drift detection failed: %v", err)
//	}
//
// Custom Rules:
//
//	// Define custom drift rule
//	rule := &drift.DriftRule{
//		ID:       "critical-service-down",
//		Name:     "Critical Service Down",
//		Enabled:  true,
//		Priority: 9,
//		Conditions: []*drift.RuleCondition{
//			{
//				Type:      drift.ConditionAttributeMatch,
//				Attribute: "service_.*_status",
//				Operator:  "equals",
//				Value:     "stopped",
//			},
//		},
//		Severity: drift.SeverityCritical,
//		Actions:  []drift.RuleAction{drift.ActionAlert, drift.ActionEscalate},
//	}
//
//	// Add rule to engine
//	err = service.GetDetector().UpdateRules([]*drift.DriftRule{rule})
//	if err != nil {
//		log.Printf("Failed to add rule: %v", err)
//	}
//
package drift

import (
	"context"
	
	commonpb "github.com/cfgis/cfgms/api/proto/common"
)

// Package version information
const (
	Version = "1.0.0"
	Name    = "cfgms-drift-detection"
)

// Package-level convenience functions

// QuickDetectDrift provides a simple interface for one-off drift detection.
//
// This function creates a detector with default configuration, performs drift
// detection, and cleans up resources automatically. It's suitable for simple
// use cases where you don't need persistent detector instances.
func QuickDetectDrift(previous, current *commonpb.DNA) ([]*DriftEvent, error) {
	detector, err := NewDetector(DefaultDetectorConfig(), nil)
	if err != nil {
		return nil, err
	}
	defer detector.Close()
	
	ctx := context.Background()
	return detector.DetectDrift(ctx, previous, current)
}

// QuickFilterEvents provides a simple interface for filtering drift events.
//
// This function creates a filter with default configuration, filters the events,
// and cleans up resources automatically.
func QuickFilterEvents(events []*DriftEvent) ([]*DriftEvent, error) {
	filter, err := NewFilter(DefaultFilterConfig(), nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := filter.Close(); closeErr != nil {
			// Log error but don't return it as it might mask the main error
		}
	}()
	
	ctx := context.Background()
	return filter.FilterEvents(ctx, events)
}

// ValidateRule validates a drift rule configuration.
//
// This is a convenience function that creates a temporary rule engine to
// validate the rule without requiring a persistent engine instance.
func ValidateRule(rule *DriftRule) error {
	engine, err := NewRuleEngine(DefaultRuleEngineConfig(), nil)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := engine.Close(); closeErr != nil {
			// Log error but don't return it as it might mask the main error
		}
	}()
	
	return engine.ValidateRules([]*DriftRule{rule})
}

// CompareConfigurations compares two sets of configuration attributes and returns
// a summary of changes without full drift event generation.
//
// This is useful for quick configuration comparisons where you only need
// change statistics rather than full drift analysis.
func CompareConfigurations(previous, current map[string]string) *ComparisonSummary {
	summary := &ComparisonSummary{
		Added:    make([]string, 0),
		Removed:  make([]string, 0),
		Modified: make([]string, 0),
	}
	
	// Check for added and modified attributes
	for key, currentValue := range current {
		if previousValue, exists := previous[key]; exists {
			if previousValue != currentValue {
				summary.Modified = append(summary.Modified, key)
			}
		} else {
			summary.Added = append(summary.Added, key)
		}
	}
	
	// Check for removed attributes
	for key := range previous {
		if _, exists := current[key]; !exists {
			summary.Removed = append(summary.Removed, key)
		}
	}
	
	summary.TotalChanges = len(summary.Added) + len(summary.Removed) + len(summary.Modified)
	
	return summary
}

// ComparisonSummary provides a summary of configuration changes.
type ComparisonSummary struct {
	Added        []string `json:"added"`         // Newly added attributes
	Removed      []string `json:"removed"`       // Removed attributes
	Modified     []string `json:"modified"`      // Modified attributes
	TotalChanges int      `json:"total_changes"` // Total number of changes
}

// GetPackageInfo returns information about the drift detection package.
func GetPackageInfo() *PackageInfo {
	return &PackageInfo{
		Name:    Name,
		Version: Version,
		Features: []string{
			"Real-time drift detection",
			"Smart false positive filtering",
			"Custom rule engine",
			"Background monitoring",
			"DNA storage integration",
			"Machine learning support",
			"Configurable alerting",
			"Performance optimization",
		},
		SupportedSeverities: []DriftSeverity{
			SeverityCritical,
			SeverityWarning,
			SeverityInfo,
		},
		SupportedCategories: []DriftCategory{
			CategorySecurity,
			CategoryCompliance,
			CategoryPerformance,
			CategoryConfiguration,
			CategoryInventory,
		},
	}
}

// PackageInfo provides information about the drift detection package.
type PackageInfo struct {
	Name                string          `json:"name"`
	Version             string          `json:"version"`
	Features            []string        `json:"features"`
	SupportedSeverities []DriftSeverity `json:"supported_severities"`
	SupportedCategories []DriftCategory `json:"supported_categories"`
}