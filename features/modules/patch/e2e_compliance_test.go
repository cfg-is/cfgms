// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package patch_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules/patch"
)

// TestE2E_ComplianceWorkflow_CompliantSystem tests the full compliance workflow
// for a system that is compliant with patch policy
func TestE2E_ComplianceWorkflow_CompliantSystem(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create patch policy (7-day deadline for critical patches)
	policy := patch.PatchPolicy{
		Critical:          7 * 24 * time.Hour,
		Important:         14 * 24 * time.Hour,
		Moderate:          30 * 24 * time.Hour,
		Low:               60 * 24 * time.Hour,
		WarningThreshold:  7 * 24 * time.Hour,
		CriticalThreshold: 24 * time.Hour,
	}

	// Step 2: Create mock patch manager with no pending patches (compliant)
	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{}) // No patches needed

	// Step 3: Create patch module with policy
	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-1",
	)
	require.NoError(t, err)

	// Step 4: Check compliance status
	status, err := patchModule.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusCompliant, status)

	// Step 5: Get detailed compliance report
	report, err := patchModule.GetComplianceReport(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusCompliant, report.Status)
	assert.Equal(t, 0, len(report.MissingPatches))

	// Step 6: Create alerting manager
	alertConfig := patch.DefaultAlertConfig()
	alertConfig.SuppressInfo = false // Don't suppress info alerts for testing

	alertManager := patch.NewAlertingManager(alertConfig, patchModule)

	// Step 7: Check for alerts (should be info level - compliant)
	alert, err := alertManager.CheckDevice(ctx, "test-device-1")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, patch.AlertLevelInfo, alert.Level)
	assert.Equal(t, patch.ComplianceStatusCompliant, alert.Status)

	t.Log("✓ Compliant system workflow completed successfully")
}

// TestE2E_ComplianceWorkflow_WarningSystem tests the full compliance workflow
// for a system approaching compliance breach
func TestE2E_ComplianceWorkflow_WarningSystem(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create patch policy
	policy := patch.DefaultPolicy()

	// Step 2: Create mock with patch approaching deadline
	// Critical patch released 3 days ago, 4 days left before 7-day deadline
	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB8888888",
			Title:       "Critical Security Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-3 * 24 * time.Hour),
			Installed:   false,
		},
	})

	// Step 3: Create patch module
	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-2",
	)
	require.NoError(t, err)

	// Step 4: Check compliance - should be in warning state
	status, err := patchModule.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusWarning, status)

	// Step 5: Get detailed report
	report, err := patchModule.GetComplianceReport(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusWarning, report.Status)
	assert.Equal(t, 1, len(report.MissingPatches))
	assert.Greater(t, report.DaysUntilBreach, 0)
	assert.Less(t, report.DaysUntilBreach, 7)

	// Step 6: Generate alert
	alertConfig := patch.DefaultAlertConfig()
	alertManager := patch.NewAlertingManager(alertConfig, patchModule)

	alert, err := alertManager.CheckDevice(ctx, "test-device-2")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, patch.AlertLevelWarning, alert.Level)
	assert.Contains(t, alert.Message, "WARNING")
	assert.Greater(t, alert.DaysUntilBreach, 0)

	t.Log("✓ Warning system workflow completed successfully")
	t.Logf("  Days until breach: %d", report.DaysUntilBreach)
	t.Logf("  Missing patches: %d", len(report.MissingPatches))
}

// TestE2E_ComplianceWorkflow_CriticalSystem tests the full compliance workflow
// for a system about to breach compliance
func TestE2E_ComplianceWorkflow_CriticalSystem(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create patch policy
	policy := patch.DefaultPolicy()

	// Step 2: Create mock with patch very close to deadline
	// Critical patch released 6.5 days ago, 12 hours left
	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB7777777",
			Title:       "Critical Security Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-6*24*time.Hour - 12*time.Hour),
			Installed:   false,
		},
	})

	// Step 3: Create patch module
	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-3",
	)
	require.NoError(t, err)

	// Step 4: Check compliance - should be critical
	status, err := patchModule.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusCritical, status)

	// Step 5: Get detailed report
	report, err := patchModule.GetComplianceReport(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusCritical, report.Status)
	assert.True(t, report.DaysUntilBreach < 1)

	// Step 6: Generate critical alert
	alertConfig := patch.DefaultAlertConfig()
	alertManager := patch.NewAlertingManager(alertConfig, patchModule)

	alert, err := alertManager.CheckDevice(ctx, "test-device-3")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, patch.AlertLevelCritical, alert.Level)
	assert.Contains(t, alert.Message, "CRITICAL")

	t.Log("✓ Critical system workflow completed successfully")
	t.Logf("  Days until breach: %d", report.DaysUntilBreach)
}

// TestE2E_ComplianceWorkflow_NonCompliantSystem tests the full compliance workflow
// for a system that has breached compliance
func TestE2E_ComplianceWorkflow_NonCompliantSystem(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create patch policy
	policy := patch.DefaultPolicy()

	// Step 2: Create mock with overdue patch
	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB6666666",
			Title:       "Overdue Critical Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-10 * 24 * time.Hour),
			Installed:   false,
		},
	})

	// Step 3: Create patch module
	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-4",
	)
	require.NoError(t, err)

	// Step 4: Check compliance - should be non-compliant
	status, err := patchModule.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusNonCompliant, status)

	// Step 5: Get detailed report
	report, err := patchModule.GetComplianceReport(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusNonCompliant, report.Status)
	assert.True(t, report.DaysUntilBreach < 0)
	assert.True(t, report.MissingPatches[0].DaysOverdue > 0)

	// Step 6: Generate breach alert
	alertConfig := patch.DefaultAlertConfig()
	alertManager := patch.NewAlertingManager(alertConfig, patchModule)

	alert, err := alertManager.CheckDevice(ctx, "test-device-4")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, patch.AlertLevelBreach, alert.Level)
	assert.Contains(t, alert.Message, "BREACH")

	t.Log("✓ Non-compliant system workflow completed successfully")
	t.Logf("  Days overdue: %d", -report.DaysUntilBreach)
}

// TestE2E_UpgradeWorkflow_CompatibleDevice tests the full upgrade workflow
// for a device compatible with Windows 11
func TestE2E_UpgradeWorkflow_CompatibleDevice(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create Windows 11 compatible DNA
	dna := &commonpb.DNA{
		Id: "test-device-5",
		Attributes: map[string]string{
			"tpm_version":   "2.0",
			"bios_mode":     "UEFI",
			"cpu_cores":     "4",
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "8",
			"storage_gb":    "256",
			"secure_boot":   "enabled",
		},
	}

	// Step 2: Create compatibility checker
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	// Step 3: Check compatibility
	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	assert.True(t, result.Compatible)
	assert.Equal(t, 0, len(result.MissingRequirements))

	// Step 4: Create upgrade policy (enabled)
	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = true // Use test mode

	// Step 5: Create patch module and upgrade manager
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	upgradeManager := patch.NewUpgradeManager(
		patchModule,
		checker,
		policy,
		nil,
		"test-device-5",
	)

	// Step 6: Check upgrade eligibility
	eligibility, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	assert.True(t, eligibility.Compatible)

	// Step 7: Perform test upgrade
	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.NoError(t, err)

	t.Log("✓ Compatible device upgrade workflow completed successfully")
}

// TestE2E_UpgradeWorkflow_IncompatibleDevice tests the full upgrade workflow
// for a device incompatible with Windows 11
func TestE2E_UpgradeWorkflow_IncompatibleDevice(t *testing.T) {
	ctx := context.Background()

	// Step 1: Create Windows 11 incompatible DNA (TPM 1.2, Legacy BIOS)
	dna := &commonpb.DNA{
		Id: "test-device-6",
		Attributes: map[string]string{
			"tpm_version":   "1.2", // TPM 1.2 not supported
			"bios_mode":     "Legacy",
			"cpu_cores":     "2",
			"cpu_speed_ghz": "1.5",
			"ram_gb":        "4",
			"storage_gb":    "128",
			"secure_boot":   "disabled",
		},
	}

	// Step 2: Create compatibility checker
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	// Step 3: Check compatibility
	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	assert.False(t, result.Compatible)
	assert.Greater(t, len(result.MissingRequirements), 0)

	// Step 4: Create upgrade policy with blocking enabled
	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.BlockIncompatible = true
	policy.TestMode = false

	// Step 5: Create patch module and upgrade manager
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	upgradeManager := patch.NewUpgradeManager(
		patchModule,
		checker,
		policy,
		nil,
		"test-device-6",
	)

	// Step 6: Check upgrade eligibility
	eligibility, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	assert.False(t, eligibility.Compatible)

	// Step 7: Attempt upgrade - should be blocked
	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not compatible")

	t.Log("✓ Incompatible device upgrade workflow completed successfully")
	t.Logf("  Missing requirements: %v", result.MissingRequirements)
}

// TestE2E_ComplianceScheduler tests the scheduled compliance checking
func TestE2E_ComplianceScheduler(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Step 1: Create patch policy and module
	policy := patch.DefaultPolicy()
	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB5555555",
			Title:       "Test Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-3 * 24 * time.Hour),
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-7",
	)
	require.NoError(t, err)

	// Step 2: Create alerting manager
	alertConfig := patch.DefaultAlertConfig()
	alertManager := patch.NewAlertingManager(alertConfig, patchModule)

	// Step 3: Create compliance scheduler with short interval
	deviceIDs := []string{"device-1", "device-2", "device-3"}
	scheduler := patch.NewComplianceScheduler(alertManager, 10*time.Millisecond, deviceIDs)
	require.NotNil(t, scheduler)

	// Step 4: Start scheduler (will run at least once before timeout)
	err = scheduler.Start(ctx)
	assert.Error(t, err) // Should return context.DeadlineExceeded
	assert.Equal(t, context.DeadlineExceeded, err)

	t.Log("✓ Compliance scheduler workflow completed successfully")
}

// TestE2E_FullComplianceCycle tests a complete compliance management cycle
func TestE2E_FullComplianceCycle(t *testing.T) {
	ctx := context.Background()

	// Step 1: Setup - Create policy and module
	policy := patch.DefaultPolicy()
	mockManager := patch.NewMockPatchManager()

	// Start with overdue patch
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB1111111",
			Title:       "Critical Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-10 * 24 * time.Hour),
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-8",
	)
	require.NoError(t, err)

	// Step 2: Initial compliance check - should be non-compliant
	status, err := patchModule.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusNonCompliant, status)

	// Step 3: Generate alert
	alertConfig := patch.DefaultAlertConfig()
	alertManager := patch.NewAlertingManager(alertConfig, patchModule)

	alert, err := alertManager.CheckDevice(ctx, "test-device-8")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, patch.AlertLevelBreach, alert.Level)

	// Step 4: "Install" the patch (simulate remediation)
	config := &patch.Config{
		PatchType:  "security",
		AutoReboot: false,
		TestMode:   true,
	}

	err = patchModule.Set(ctx, "test-resource", config)
	require.NoError(t, err)

	// Step 5: Clear patches to simulate successful installation
	mockManager.SetAvailablePatches([]patch.PatchInfo{})

	// Step 6: Create new module instance to get fresh data
	patchModule2, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		policy,
		nil,
		"test-device-8",
	)
	require.NoError(t, err)

	// Step 7: Recheck compliance - should now be compliant
	status, err = patchModule2.CheckCompliance(ctx)
	require.NoError(t, err)
	assert.Equal(t, patch.ComplianceStatusCompliant, status)

	// Step 8: Verify no more breach alerts (use patchModule2 with fresh data)
	alertConfig.SuppressInfo = false
	alertManager = patch.NewAlertingManager(alertConfig, patchModule2)

	alert, err = alertManager.CheckDevice(ctx, "test-device-8")
	require.NoError(t, err)
	require.NotNil(t, alert)
	assert.Equal(t, patch.AlertLevelInfo, alert.Level)

	t.Log("✓ Full compliance cycle completed successfully")
	t.Log("  Initial status: non-compliant (breach)")
	t.Log("  After patch: compliant")
}
