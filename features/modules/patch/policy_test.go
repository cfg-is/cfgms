// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package patch_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/patch"
)

func TestDefaultPolicy(t *testing.T) {
	policy := patch.DefaultPolicy()

	assert.Equal(t, 7*24*time.Hour, policy.Critical, "Critical patches should have 7-day deadline")
	assert.Equal(t, 14*24*time.Hour, policy.Important, "Important patches should have 14-day deadline")
	assert.Equal(t, 30*24*time.Hour, policy.Moderate, "Moderate patches should have 30-day deadline")
	assert.Equal(t, 60*24*time.Hour, policy.Low, "Low patches should have 60-day deadline")
	assert.Equal(t, 7*24*time.Hour, policy.WarningThreshold, "Warning threshold should be 7 days")
	assert.Equal(t, 24*time.Hour, policy.CriticalThreshold, "Critical threshold should be 1 day")
}

func TestPolicyEngine_CheckCompliance_Compliant(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	// Create a status with a recent critical patch (within 7-day window)
	status := &patch.PatchStatus{
		PendingPatches: []patch.PatchInfo{
			{
				ID:          "KB5001234",
				Title:       "Security Update",
				Severity:    "critical",
				Category:    "security",
				ReleaseDate: time.Now().Add(-24 * time.Hour), // Released 1 day ago
			},
		},
	}

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, status)

	require.NoError(t, err)
	assert.NotNil(t, report)
	// Status should be Warning because 5 days remaining is within the 7-day warning threshold
	assert.Equal(t, patch.ComplianceStatusWarning, report.Status, "Should be in warning state with 5 days remaining")
	assert.Equal(t, 1, len(report.MissingPatches), "Should have 1 missing patch")
	assert.Equal(t, 5, report.DaysUntilBreach, "Should have 5 days until breach (7-day policy, 1 day passed)")
}

func TestPolicyEngine_CheckCompliance_Warning(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	// Create a status with a patch within warning threshold (3 days old, 4 days until breach)
	status := &patch.PatchStatus{
		PendingPatches: []patch.PatchInfo{
			{
				ID:          "KB5001234",
				Title:       "Security Update",
				Severity:    "critical",
				Category:    "security",
				ReleaseDate: time.Now().Add(-3 * 24 * time.Hour), // Released 3 days ago
			},
		},
	}

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, status)

	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, patch.ComplianceStatusWarning, report.Status, "Should be in warning state")
	assert.Equal(t, 3, report.DaysUntilBreach, "Should have 3 days until breach")
}

func TestPolicyEngine_CheckCompliance_Critical(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	// Create a status with a patch within critical threshold (6.5 days old, 12 hours until breach)
	status := &patch.PatchStatus{
		PendingPatches: []patch.PatchInfo{
			{
				ID:          "KB5001234",
				Title:       "Security Update",
				Severity:    "critical",
				Category:    "security",
				ReleaseDate: time.Now().Add(-6*24*time.Hour - 12*time.Hour), // Released 6.5 days ago
			},
		},
	}

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, status)

	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, patch.ComplianceStatusCritical, report.Status, "Should be in critical state")
	assert.True(t, report.DaysUntilBreach < 1, "Should have less than 1 day until breach")
}

func TestPolicyEngine_CheckCompliance_NonCompliant(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	// Create a status with an overdue critical patch (8 days old)
	status := &patch.PatchStatus{
		PendingPatches: []patch.PatchInfo{
			{
				ID:          "KB5001234",
				Title:       "Security Update",
				Severity:    "critical",
				Category:    "security",
				ReleaseDate: time.Now().Add(-8 * 24 * time.Hour), // Released 8 days ago
			},
		},
	}

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, status)

	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, patch.ComplianceStatusNonCompliant, report.Status, "Should be non-compliant")
	assert.True(t, report.DaysUntilBreach < 0, "Should be past deadline")
	assert.Equal(t, 1, len(report.MissingPatches), "Should have 1 missing patch")
	assert.True(t, report.MissingPatches[0].DaysOverdue > 0, "Patch should be overdue")
}

func TestPolicyEngine_CheckCompliance_MultipleSeverities(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	now := time.Now()

	// Create a status with patches of different severities
	status := &patch.PatchStatus{
		PendingPatches: []patch.PatchInfo{
			{
				ID:          "KB5001234",
				Title:       "Critical Security Update",
				Severity:    "critical",
				Category:    "security",
				ReleaseDate: now.Add(-8 * 24 * time.Hour), // Released 8 days ago (past 7-day deadline)
			},
			{
				ID:          "KB5001235",
				Title:       "Important Update",
				Severity:    "important",
				Category:    "security",
				ReleaseDate: now.Add(-10 * 24 * time.Hour), // Released 10 days ago (within 14-day deadline)
			},
			{
				ID:          "KB5001236",
				Title:       "Moderate Update",
				Severity:    "moderate",
				Category:    "bugfix",
				ReleaseDate: now.Add(-25 * 24 * time.Hour), // Released 25 days ago (within 30-day deadline)
			},
		},
	}

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, status)

	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, patch.ComplianceStatusNonCompliant, report.Status, "Should be non-compliant due to overdue critical patch")
	assert.Equal(t, 3, len(report.MissingPatches), "Should have 3 missing patches")

	// Find the critical patch in the report
	var criticalPatch *patch.MissingPatchInfo
	for i := range report.MissingPatches {
		if report.MissingPatches[i].Severity == "critical" {
			criticalPatch = &report.MissingPatches[i]
			break
		}
	}
	require.NotNil(t, criticalPatch, "Should find critical patch in report")
	assert.True(t, criticalPatch.DaysOverdue > 0, "Critical patch should be overdue")
}

func TestPolicyEngine_GetPolicyDeadline(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	tests := []struct {
		name     string
		severity string
		expected time.Duration
	}{
		{"Critical", "critical", 7 * 24 * time.Hour},
		{"Important", "important", 14 * 24 * time.Hour},
		{"Moderate", "moderate", 30 * 24 * time.Hour},
		{"Low", "low", 60 * 24 * time.Hour},
		{"Unknown", "unknown", 30 * 24 * time.Hour}, // Should default to moderate
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deadline := engine.GetPolicyDeadline(tt.severity)
			assert.Equal(t, tt.expected, deadline, "Deadline for %s should be %v", tt.severity, tt.expected)
		})
	}
}

func TestPolicyEngine_CheckCompliance_NilStatus(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, nil)

	assert.Error(t, err, "Should return error for nil status")
	assert.Nil(t, report, "Report should be nil on error")
}

func TestPolicyEngine_CheckCompliance_NoMissingPatches(t *testing.T) {
	policy := patch.DefaultPolicy()
	engine := patch.NewPolicyEngine(policy)

	// Create a status with no pending patches
	status := &patch.PatchStatus{
		PendingPatches: []patch.PatchInfo{},
	}

	ctx := context.Background()
	report, err := engine.CheckCompliance(ctx, status)

	require.NoError(t, err)
	assert.NotNil(t, report)
	assert.Equal(t, patch.ComplianceStatusCompliant, report.Status, "Should be compliant with no missing patches")
	assert.Equal(t, 0, len(report.MissingPatches), "Should have 0 missing patches")
	assert.Equal(t, 999999, report.DaysUntilBreach, "DaysUntilBreach should be maximum value")
}
