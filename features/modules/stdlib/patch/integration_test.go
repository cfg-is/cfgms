// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPatchModule_WithPolicyEngine tests the patch module with policy engine integration
func TestPatchModule_WithPolicyEngine(t *testing.T) {
	// Create a custom policy with strict deadlines
	policy := PatchPolicy{
		Critical:          3 * 24 * time.Hour, // 3 days for critical
		Important:         7 * 24 * time.Hour, // 7 days for important
		Moderate:          14 * 24 * time.Hour,
		Low:               30 * 24 * time.Hour,
		WarningThreshold:  2 * 24 * time.Hour,
		CriticalThreshold: 24 * time.Hour,
	}

	// Create mock patch manager with no pending patches
	mockManager := NewInMemoryPatchManager()
	mockManager.SetAvailablePatches([]PatchInfo{}) // Clear default patches

	// Create patch module with policy
	module, err := NewPatchModuleWithPolicy(mockManager, policy, nil, "test-device")
	require.NoError(t, err)
	require.NotNil(t, module)

	ctx := context.Background()

	// Get compliance report
	report, err := module.GetComplianceReport(ctx)
	require.NoError(t, err)
	assert.NotNil(t, report)

	// Should be compliant with no pending patches
	assert.Equal(t, ComplianceStatusCompliant, report.Status)
}

func TestPatchModule_ComplianceWithOverduePatches(t *testing.T) {
	policy := DefaultPolicy()

	// Create mock manager with overdue patches
	mockManager := NewInMemoryPatchManager()

	// Add an overdue critical patch (10 days old)
	mockManager.SetAvailablePatches([]PatchInfo{
		{
			ID:          "KB9999999",
			Title:       "Critical Security Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-10 * 24 * time.Hour),
			Installed:   false,
		},
	})

	module, err := NewPatchModuleWithPolicy(mockManager, policy, nil, "test-device")
	require.NoError(t, err)

	ctx := context.Background()

	// Get compliance report
	report, err := module.GetComplianceReport(ctx)
	require.NoError(t, err)

	// Should be non-compliant due to overdue critical patch
	assert.Equal(t, ComplianceStatusNonCompliant, report.Status)
	assert.Equal(t, 1, len(report.MissingPatches))
	assert.True(t, report.MissingPatches[0].DaysOverdue > 0)
}

func TestPatchModule_ComplianceWithWarningState(t *testing.T) {
	policy := DefaultPolicy()

	mockManager := NewInMemoryPatchManager()

	// Add a patch that's approaching deadline (3 days old, 4 days left)
	// Critical policy is 7 days, so 3 days old = 4 days until breach
	// CriticalThreshold is 1 day, WarningThreshold is 7 days
	// With 4 days left, it's > 1 day but < 7 days, so should be Warning
	mockManager.SetAvailablePatches([]PatchInfo{
		{
			ID:          "KB8888888",
			Title:       "Important Security Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-3 * 24 * time.Hour),
			Installed:   false,
		},
	})

	module, err := NewPatchModuleWithPolicy(mockManager, policy, nil, "test-device")
	require.NoError(t, err)

	ctx := context.Background()

	report, err := module.GetComplianceReport(ctx)
	require.NoError(t, err)

	// Should be in warning state (within 7-day warning threshold, but > 1-day critical threshold)
	assert.Equal(t, ComplianceStatusWarning, report.Status)
	assert.True(t, report.DaysUntilBreach > 1 && report.DaysUntilBreach < 7,
		"Expected days until breach between 1 and 7, got %d", report.DaysUntilBreach)
}

func TestPatchModule_SetPolicy(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	module, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	// Update policy
	newPolicy := PatchPolicy{
		Critical:          1 * 24 * time.Hour, // Very strict 1-day deadline
		Important:         2 * 24 * time.Hour,
		Moderate:          7 * 24 * time.Hour,
		Low:               14 * 24 * time.Hour,
		WarningThreshold:  12 * time.Hour,
		CriticalThreshold: 6 * time.Hour,
	}

	module.SetPolicy(newPolicy)

	// Add a 2-day old critical patch
	mockManager.SetAvailablePatches([]PatchInfo{
		{
			ID:          "KB7777777",
			Title:       "Critical Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-2 * 24 * time.Hour),
			Installed:   false,
		},
	})

	ctx := context.Background()
	report, err := module.GetComplianceReport(ctx)
	require.NoError(t, err)

	// Should be non-compliant with strict 1-day policy
	assert.Equal(t, ComplianceStatusNonCompliant, report.Status)
}

func TestPatchModule_WithMaintenanceWindow(t *testing.T) {
	policy := DefaultPolicy()
	mockManager := NewInMemoryPatchManager()

	// Schedule a maintenance window that opens two hours from now, so the device
	// is not currently inside a window but has an upcoming one.
	windowMgr := NewInMemoryWindowManager()
	windowMgr.AddWindow("test-device", MaintenanceWindow{
		Start:            time.Now().Add(2 * time.Hour),
		Duration:         time.Hour,
		AllowReboot:      true,
		AllowMaintenance: true,
	})

	module, err := NewPatchModuleWithPolicy(mockManager, policy, windowMgr, "test-device")
	require.NoError(t, err)

	ctx := context.Background()

	// Should be able to get next maintenance window
	nextWindow, err := module.GetNextMaintenanceWindow(ctx)
	require.NoError(t, err)
	assert.True(t, nextWindow.After(time.Now()))
}

func TestPatchModule_RebootBlockedByMaintenanceWindow(t *testing.T) {
	policy := DefaultPolicy()
	mockManager := NewInMemoryPatchManager()

	// Set mock to require reboot
	mockManager.SetRebootRequired(true)

	// The only scheduled window opens two hours from now, so a reboot right now
	// falls outside any active window and must be blocked.
	windowMgr := NewInMemoryWindowManager()
	windowMgr.AddWindow("test-device", MaintenanceWindow{
		Start:            time.Now().Add(2 * time.Hour),
		Duration:         time.Hour,
		AllowReboot:      true,
		AllowMaintenance: true,
	})

	module, err := NewPatchModuleWithPolicy(mockManager, policy, windowMgr, "test-device")
	require.NoError(t, err)

	// Create config with auto-reboot
	config := &Config{
		PatchType:  "security",
		AutoReboot: true,
		TestMode:   true,
	}

	ctx := context.Background()

	// Should fail with maintenance window error because reboot is blocked
	err = module.Set(ctx, "test-resource", config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "maintenance window")
}

func TestPatchModule_RebootAllowedInMaintenanceWindow(t *testing.T) {
	policy := DefaultPolicy()
	mockManager := NewInMemoryPatchManager()

	// Set mock to require reboot
	mockManager.SetRebootRequired(true)

	// Schedule a window that opened an hour ago and is still open, so the device
	// is currently inside a window that permits reboots.
	windowMgr := NewInMemoryWindowManager()
	windowMgr.AddWindow("test-device", MaintenanceWindow{
		Start:            time.Now().Add(-1 * time.Hour),
		Duration:         2 * time.Hour,
		AllowReboot:      true,
		AllowMaintenance: true,
	})

	module, err := NewPatchModuleWithPolicy(mockManager, policy, windowMgr, "test-device")
	require.NoError(t, err)

	// Create config with auto-reboot
	config := &Config{
		PatchType:  "security",
		AutoReboot: true,
		TestMode:   true,
	}

	ctx := context.Background()

	// Should succeed because we're in maintenance window
	err = module.Set(ctx, "test-resource", config)
	assert.NoError(t, err)
}

func TestPatchModule_CheckCompliance(t *testing.T) {
	policy := DefaultPolicy()
	mockManager := NewInMemoryPatchManager()
	mockManager.SetAvailablePatches([]PatchInfo{}) // Clear default patches

	module, err := NewPatchModuleWithPolicy(mockManager, policy, nil, "test-device")
	require.NoError(t, err)

	ctx := context.Background()

	// Check compliance status
	status, err := module.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, ComplianceStatusCompliant, status)
}

func TestPatchModule_MultipleComplianceChecks(t *testing.T) {
	policy := DefaultPolicy()
	ctx := context.Background()

	// First scenario: compliant system
	mockManager1 := NewInMemoryPatchManager()
	mockManager1.SetAvailablePatches([]PatchInfo{}) // No patches

	module1, err := NewPatchModuleWithPolicy(mockManager1, policy, nil, "test-device")
	require.NoError(t, err)

	status1, err := module1.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, ComplianceStatusCompliant, status1)

	// Second scenario: non-compliant system with overdue patch
	// Create a new module instance to test different state
	mockManager2 := NewInMemoryPatchManager()
	mockManager2.SetAvailablePatches([]PatchInfo{
		{
			ID:          "KB6666666",
			Title:       "Overdue Critical Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-10 * 24 * time.Hour),
			Installed:   false,
		},
	})

	module2, err := NewPatchModuleWithPolicy(mockManager2, policy, nil, "test-device")
	require.NoError(t, err)

	status2, err := module2.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, ComplianceStatusNonCompliant, status2)
}

func TestPatchModule_GetComplianceReport_Detailed(t *testing.T) {
	policy := PatchPolicy{
		Critical:          5 * 24 * time.Hour,
		Important:         10 * 24 * time.Hour,
		Moderate:          20 * 24 * time.Hour,
		Low:               40 * 24 * time.Hour,
		WarningThreshold:  3 * 24 * time.Hour,
		CriticalThreshold: 24 * time.Hour,
	}

	mockManager := NewInMemoryPatchManager()

	// Add multiple patches with different severities and ages
	// Policy: Critical=5d, Important=10d, Moderate=20d, CriticalThreshold=1d, WarningThreshold=3d
	mockManager.SetAvailablePatches([]PatchInfo{
		{
			ID:          "KB1111111",
			Title:       "Critical Patch 1",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-1 * 24 * time.Hour), // 1 day old, 4 days left (Warning)
			Installed:   false,
		},
		{
			ID:          "KB2222222",
			Title:       "Important Patch 1",
			Severity:    "important",
			Category:    "security",
			ReleaseDate: time.Now().Add(-7 * 24 * time.Hour), // 7 days old, 3 days left (Warning)
			Installed:   false,
		},
		{
			ID:          "KB3333333",
			Title:       "Moderate Patch 1",
			Severity:    "moderate",
			Category:    "bugfix",
			ReleaseDate: time.Now().Add(-15 * 24 * time.Hour), // 15 days old, 5 days left (Compliant)
			Installed:   false,
		},
	})

	module, err := NewPatchModuleWithPolicy(mockManager, policy, nil, "test-device")
	require.NoError(t, err)

	ctx := context.Background()

	report, err := module.GetComplianceReport(ctx)
	require.NoError(t, err)
	assert.NotNil(t, report)

	// Should have 3 missing patches
	assert.Equal(t, 3, len(report.MissingPatches))

	// Critical patch should be in warning state (1 day old, 4 days left)
	// This is the patch closest to deadline, so it determines overall status
	assert.Equal(t, ComplianceStatusWarning, report.Status)

	// Verify each patch is tracked
	var criticalFound, importantFound, moderateFound bool
	for _, mp := range report.MissingPatches {
		switch mp.Severity {
		case "critical":
			criticalFound = true
			assert.True(t, mp.DaysOverdue <= 0, "Critical patch should not be overdue")
		case "important":
			importantFound = true
			assert.True(t, mp.DaysOverdue <= 0, "Important patch should not be overdue")
		case "moderate":
			moderateFound = true
			assert.True(t, mp.DaysOverdue <= 0, "Moderate patch should not be overdue")
		}
	}

	assert.True(t, criticalFound, "Should find critical patch")
	assert.True(t, importantFound, "Should find important patch")
	assert.True(t, moderateFound, "Should find moderate patch")
}

func TestPatchModule_SetDeviceID(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	module, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	// Set device ID
	module.SetDeviceID("new-device-id")

	// Verify device-ID propagation by scheduling an upcoming window keyed to the
	// new device ID and confirming the module resolves it.
	windowMgr := NewInMemoryWindowManager()
	windowMgr.AddWindow("new-device-id", MaintenanceWindow{
		Start:            time.Now().Add(1 * time.Hour),
		Duration:         time.Hour,
		AllowReboot:      true,
		AllowMaintenance: true,
	})

	module.SetWindowManager(windowMgr)

	ctx := context.Background()
	nextWindow, err := module.GetNextMaintenanceWindow(ctx)
	require.NoError(t, err)
	assert.True(t, nextWindow.After(time.Now()))
}
