// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package drift

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

func createTestDNA(id string, attributes map[string]string) *commonpb.DNA {
	return &commonpb.DNA{
		Id:          id,
		Attributes:  attributes,
		LastUpdated: timestamppb.New(time.Now()),
	}
}

func createTestLogger() logging.Logger {
	return logging.NewLogger("debug")
}

// Detector Tests

func TestDetector_DetectDrift_BasicChanges(t *testing.T) {
	detector, err := NewDetector(DefaultDetectorConfig(), createTestLogger())
	require.NoError(t, err)
	defer func() {
		if err := detector.Close(); err != nil {
			t.Logf("Failed to close detector: %v", err)
		}
	}()

	previous := createTestDNA("device1", map[string]string{
		"hostname":     "server1",
		"cpu_count":    "4",
		"memory_total": "8GB",
		"os_version":   "Ubuntu 20.04",
	})

	current := createTestDNA("device1", map[string]string{
		"hostname":     "server1-new", // Changed
		"cpu_count":    "4",
		"memory_total": "16GB",         // Changed
		"os_version":   "Ubuntu 22.04", // Changed
		"new_service":  "nginx",        // Added
	})

	ctx := context.Background()
	events, err := detector.DetectDrift(ctx, previous, current)
	require.NoError(t, err)

	assert.NotEmpty(t, events)

	// The test input has exactly 4 changes: hostname, memory_total, os_version modified
	// and new_service added. All 4 must be detected.
	totalChanges := 0
	for _, event := range events {
		totalChanges += len(event.Changes)
	}
	assert.Equal(t, 4, totalChanges)

	for _, event := range events {
		assert.Equal(t, "device1", event.DeviceID)
		assert.NotEmpty(t, event.ID)
		assert.NotEmpty(t, event.Title)
		assert.NotEmpty(t, event.Description)
		assert.Greater(t, event.Confidence, 0.0)
		assert.LessOrEqual(t, event.Confidence, 1.0)
		assert.Greater(t, event.RiskScore, 0.0)
		assert.LessOrEqual(t, event.RiskScore, 1.0)
	}
}

func TestDetector_DetectDrift_SecurityChanges(t *testing.T) {
	config := DefaultDetectorConfig()
	config.SecurityAttributes = []string{".*firewall.*", ".*security.*", ".*admin.*"}

	detector, err := NewDetector(config, createTestLogger())
	require.NoError(t, err)
	defer func() {
		if err := detector.Close(); err != nil {
			t.Logf("Failed to close detector: %v", err)
		}
	}()

	previous := createTestDNA("device1", map[string]string{
		"firewall_enabled": "true",
		"admin_user":       "admin",
		"security_policy":  "strict",
	})

	current := createTestDNA("device1", map[string]string{
		"firewall_enabled": "false",      // Critical security change
		"admin_user":       "root",       // Critical security change
		"security_policy":  "permissive", // Critical security change
	})

	ctx := context.Background()
	events, err := detector.DetectDrift(ctx, previous, current)
	require.NoError(t, err)

	assert.NotEmpty(t, events)

	foundCritical := false
	for _, event := range events {
		if event.Severity == SeverityCritical {
			foundCritical = true
		}

		for _, change := range event.Changes {
			if change.Category == "security" {
				assert.Equal(t, SeverityCritical, change.Severity)
			}
		}
	}
	assert.True(t, foundCritical, "Should detect critical security changes")
}

func TestDetector_DetectDrift_NoChanges(t *testing.T) {
	detector, err := NewDetector(DefaultDetectorConfig(), createTestLogger())
	require.NoError(t, err)
	defer func() {
		if err := detector.Close(); err != nil {
			t.Logf("Failed to close detector: %v", err)
		}
	}()

	dna := createTestDNA("device1", map[string]string{
		"hostname":   "server1",
		"cpu_count":  "4",
		"os_version": "Ubuntu 20.04",
	})

	ctx := context.Background()
	events, err := detector.DetectDrift(ctx, dna, dna)
	require.NoError(t, err)

	assert.Empty(t, events, "Should not detect drift when DNA is identical")
}

func TestDetector_DetectDrift_InvalidInput(t *testing.T) {
	detector, err := NewDetector(DefaultDetectorConfig(), createTestLogger())
	require.NoError(t, err)
	defer func() {
		if err := detector.Close(); err != nil {
			t.Logf("Failed to close detector: %v", err)
		}
	}()

	ctx := context.Background()

	_, err = detector.DetectDrift(ctx, nil, createTestDNA("device1", map[string]string{}))
	assert.Error(t, err)

	_, err = detector.DetectDrift(ctx, createTestDNA("device1", map[string]string{}), nil)
	assert.Error(t, err)

	previous := createTestDNA("device1", map[string]string{})
	current := createTestDNA("device2", map[string]string{})
	_, err = detector.DetectDrift(ctx, previous, current)
	assert.Error(t, err)
}

func TestDetector_DetectDriftBatch(t *testing.T) {
	detector, err := NewDetector(DefaultDetectorConfig(), createTestLogger())
	require.NoError(t, err)
	defer func() {
		if err := detector.Close(); err != nil {
			t.Logf("Failed to close detector: %v", err)
		}
	}()

	comparisons := []*DNAComparison{
		{
			DeviceID:   "device1",
			Previous:   createTestDNA("device1", map[string]string{"hostname": "server1"}),
			Current:    createTestDNA("device1", map[string]string{"hostname": "server1-new"}),
			ComparedAt: time.Now(),
		},
		{
			DeviceID:   "device2",
			Previous:   createTestDNA("device2", map[string]string{"os": "Ubuntu 20.04"}),
			Current:    createTestDNA("device2", map[string]string{"os": "Ubuntu 22.04"}),
			ComparedAt: time.Now(),
		},
	}

	ctx := context.Background()
	events, err := detector.DetectDriftBatch(ctx, comparisons)
	require.NoError(t, err)

	assert.NotEmpty(t, events)

	t.Logf("Total events generated: %d", len(events))
	deviceIDs := make(map[string]bool)
	for _, event := range events {
		deviceIDs[event.DeviceID] = true
		t.Logf("Event for device %s: %s (changes: %d)", event.DeviceID, event.Title, len(event.Changes))
	}

	// Both device comparisons have clear changes and must produce events.
	assert.Contains(t, deviceIDs, "device1", "batch must detect drift for device1")
	assert.Contains(t, deviceIDs, "device2", "batch must detect drift for device2")
}

func TestDetector_GetStats(t *testing.T) {
	detector, err := NewDetector(DefaultDetectorConfig(), createTestLogger())
	require.NoError(t, err)
	defer func() { _ = detector.Close() }()

	stats := detector.GetStats()
	require.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.TotalComparisons)

	ctx := context.Background()
	previous := createTestDNA("device1", map[string]string{"hostname": "old"})
	current := createTestDNA("device1", map[string]string{"hostname": "new"})
	_, err = detector.DetectDrift(ctx, previous, current)
	require.NoError(t, err)

	stats = detector.GetStats()
	assert.Equal(t, int64(1), stats.TotalComparisons)
}

func TestDetector_DefaultConfig(t *testing.T) {
	config := DefaultDetectorConfig()
	require.NotNil(t, config)
	assert.Greater(t, config.ConfidenceThreshold, 0.0)
	assert.LessOrEqual(t, config.ConfidenceThreshold, 1.0)
	assert.NotEmpty(t, config.CriticalAttributes)
	assert.NotEmpty(t, config.SecurityAttributes)
	assert.Greater(t, config.MaxChangesPerEvent, 0)
}

func BenchmarkDetector_DetectDrift(b *testing.B) {
	detector, err := NewDetector(DefaultDetectorConfig(), createTestLogger())
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := detector.Close(); err != nil {
			b.Logf("Failed to close detector: %v", err)
		}
	}()

	previous := createTestDNA("device1", map[string]string{
		"hostname":     "server1",
		"cpu_count":    "4",
		"memory_total": "8GB",
		"os_version":   "Ubuntu 20.04",
	})

	current := createTestDNA("device1", map[string]string{
		"hostname":     "server1-new",
		"cpu_count":    "8",
		"memory_total": "16GB",
		"os_version":   "Ubuntu 22.04",
	})

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := detector.DetectDrift(ctx, previous, current)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Package-level convenience function tests

func TestQuickDetectDrift_DetectsChanges(t *testing.T) {
	previous := createTestDNA("device1", map[string]string{"hostname": "old"})
	current := createTestDNA("device1", map[string]string{"hostname": "new"})

	events, err := QuickDetectDrift(previous, current)
	require.NoError(t, err)
	assert.NotEmpty(t, events)
}

func TestQuickDetectDrift_NilInputReturnsError(t *testing.T) {
	_, err := QuickDetectDrift(nil, createTestDNA("device1", map[string]string{}))
	assert.Error(t, err)
}

func TestQuickDetectDrift_NoChanges(t *testing.T) {
	dna := createTestDNA("device1", map[string]string{"hostname": "stable"})
	events, err := QuickDetectDrift(dna, dna)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestCompareConfigurations_DetectsAllChangeTypes(t *testing.T) {
	previous := map[string]string{
		"keep":    "same",
		"modify":  "old",
		"removed": "gone",
	}
	current := map[string]string{
		"keep":   "same",
		"modify": "new",
		"added":  "fresh",
	}

	summary := CompareConfigurations(previous, current)
	require.NotNil(t, summary)
	assert.Contains(t, summary.Modified, "modify")
	assert.Contains(t, summary.Added, "added")
	assert.Contains(t, summary.Removed, "removed")
	assert.Equal(t, 3, summary.TotalChanges)
}

func TestCompareConfigurations_EmptyMaps(t *testing.T) {
	summary := CompareConfigurations(map[string]string{}, map[string]string{})
	require.NotNil(t, summary)
	assert.Equal(t, 0, summary.TotalChanges)
	assert.Empty(t, summary.Added)
	assert.Empty(t, summary.Removed)
	assert.Empty(t, summary.Modified)
}

func TestCompareConfigurations_AllAdded(t *testing.T) {
	summary := CompareConfigurations(map[string]string{}, map[string]string{"a": "1", "b": "2"})
	assert.Equal(t, 2, summary.TotalChanges)
	assert.Len(t, summary.Added, 2)
	assert.Empty(t, summary.Removed)
	assert.Empty(t, summary.Modified)
}

func TestCompareConfigurations_AllRemoved(t *testing.T) {
	summary := CompareConfigurations(map[string]string{"a": "1", "b": "2"}, map[string]string{})
	assert.Equal(t, 2, summary.TotalChanges)
	assert.Len(t, summary.Removed, 2)
	assert.Empty(t, summary.Added)
	assert.Empty(t, summary.Modified)
}

func TestGetPackageInfo_ReturnsValidInfo(t *testing.T) {
	info := GetPackageInfo()
	require.NotNil(t, info)
	assert.Equal(t, Name, info.Name)
	assert.Equal(t, Version, info.Version)
	assert.NotEmpty(t, info.Features)
	assert.Contains(t, info.SupportedSeverities, SeverityCritical)
	assert.Contains(t, info.SupportedSeverities, SeverityWarning)
	assert.Contains(t, info.SupportedSeverities, SeverityInfo)
	assert.NotEmpty(t, info.SupportedCategories)
}

// Detector invalid config tests

func TestNewDetector_InvalidConfidenceThreshold(t *testing.T) {
	config := DefaultDetectorConfig()
	config.ConfidenceThreshold = 1.5 // out of [0,1]
	_, err := NewDetector(config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "confidence threshold")
}

func TestNewDetector_InvalidAnomalyThreshold(t *testing.T) {
	config := DefaultDetectorConfig()
	config.AnomalyThreshold = -0.1 // out of [0,1]
	_, err := NewDetector(config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "anomaly threshold")
}

func TestNewDetector_ZeroMaxChanges(t *testing.T) {
	config := DefaultDetectorConfig()
	config.MaxChangesPerEvent = 0
	_, err := NewDetector(config, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "max changes per event")
}

// Concurrent stats access must not race under -race.

func TestDetector_ConcurrentDetectDriftAndGetStats(t *testing.T) {
	detector, err := NewDetector(DefaultDetectorConfig(), nil)
	require.NoError(t, err)
	defer func() { _ = detector.Close() }()

	previous := createTestDNA("device1", map[string]string{"hostname": "old"})
	current := createTestDNA("device1", map[string]string{"hostname": "new"})
	ctx := context.Background()

	const goroutines = 8
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = detector.DetectDrift(ctx, previous, current)
		}()
		go func() {
			defer wg.Done()
			_ = detector.GetStats()
		}()
	}

	wg.Wait()

	stats := detector.GetStats()
	assert.GreaterOrEqual(t, stats.TotalComparisons, int64(1))
}
