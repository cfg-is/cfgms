// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package drift provides real-time DNA drift detection and monitoring capabilities.
//
// Key Components:
//
// Detector: Analyzes DNA state changes and generates drift events with severity
// categorization. Supports configurable critical/security attribute patterns and
// batch processing.
//
// Basic Usage:
//
//	detector, err := drift.NewDetector(drift.DefaultDetectorConfig(), logger)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer detector.Close()
//
//	events, err := detector.DetectDrift(ctx, previousDNA, currentDNA)
//	for _, event := range events {
//		log.Printf("Drift detected: %s (severity: %s, confidence: %.2f)",
//			event.Title, event.Severity, event.Confidence)
//	}
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

// QuickDetectDrift provides a simple interface for one-off drift detection.
//
// Creates a detector with default configuration, performs drift detection,
// and cleans up resources automatically.
func QuickDetectDrift(previous, current *commonpb.DNA) ([]*DriftEvent, error) {
	detector, err := NewDetector(DefaultDetectorConfig(), nil)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = detector.Close()
	}()

	ctx := context.Background()
	return detector.DetectDrift(ctx, previous, current)
}

// CompareConfigurations compares two sets of configuration attributes and returns
// a summary of changes without full drift event generation.
func CompareConfigurations(previous, current map[string]string) *ComparisonSummary {
	summary := &ComparisonSummary{
		Added:    make([]string, 0),
		Removed:  make([]string, 0),
		Modified: make([]string, 0),
	}

	for key, currentValue := range current {
		if previousValue, exists := previous[key]; exists {
			if previousValue != currentValue {
				summary.Modified = append(summary.Modified, key)
			}
		} else {
			summary.Added = append(summary.Added, key)
		}
	}

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
			"Severity categorization (critical, warning, info)",
			"Batch processing",
			"Configurable attribute patterns",
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
