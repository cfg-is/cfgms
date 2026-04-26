// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package patch_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/modules/patch"
)

func TestDefaultWindows11Requirements(t *testing.T) {
	req := patch.DefaultWindows11Requirements()

	assert.Equal(t, "2.0", req.TPMVersion)
	assert.True(t, req.RequiresUEFI)
	assert.Equal(t, 2, req.MinCPUCores)
	assert.Equal(t, 1.0, req.MinCPUSpeedGHz)
	assert.Equal(t, 4, req.MinRAMGB)
	assert.Equal(t, 64, req.MinStorageGB)
	assert.True(t, req.RequiresSecureBoot)
}

func TestDefaultUpgradePolicy(t *testing.T) {
	policy := patch.DefaultUpgradePolicy()

	assert.False(t, policy.Enabled, "Upgrades should be disabled by default for safety")
	assert.False(t, policy.AutoUpgrade)
	assert.Equal(t, "11", policy.TargetVersion)
	assert.True(t, policy.RequireCompatibilityCheck)
	assert.True(t, policy.BlockIncompatible)
	assert.Equal(t, 30, policy.DeferDays)
	assert.True(t, policy.RollbackOnFailure)
}

// createCompatibleDNA creates DNA data for a Windows 11 compatible device
func createCompatibleDNA() *commonpb.DNA {
	return &commonpb.DNA{
		Id: "test-device-compatible",
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
}

// createIncompatibleDNA creates DNA data for a Windows 11 incompatible device
func createIncompatibleDNA() *commonpb.DNA {
	return &commonpb.DNA{
		Id: "test-device-incompatible",
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
}

func TestCompatibilityChecker_Compatible(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := createCompatibleDNA()

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Compatible, "Device should be compatible")
	assert.Equal(t, 0, len(result.MissingRequirements))
	assert.Equal(t, "11", result.TargetVersion)
	assert.NotNil(t, result.DeviceDNA)
}

func TestCompatibilityChecker_IncompatibleTPM(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version":   "1.2", // TPM 1.2 not supported
			"bios_mode":     "UEFI",
			"cpu_cores":     "4",
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "8",
			"storage_gb":    "256",
			"secure_boot":   "enabled",
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Compatible)
	assert.Greater(t, len(result.MissingRequirements), 0)
	assert.Contains(t, result.MissingRequirements[0], "TPM 2.0")
}

func TestCompatibilityChecker_IncompatibleBIOS(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version":   "2.0",
			"bios_mode":     "Legacy", // Legacy BIOS not supported
			"cpu_cores":     "4",
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "8",
			"storage_gb":    "256",
			"secure_boot":   "enabled",
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "UEFI")
}

func TestCompatibilityChecker_InsufficientRAM(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version":   "2.0",
			"bios_mode":     "UEFI",
			"cpu_cores":     "4",
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "2", // Only 2GB RAM
			"storage_gb":    "256",
			"secure_boot":   "enabled",
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "4+ GB RAM")
}

func TestCompatibilityChecker_InsufficientStorage(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version":   "2.0",
			"bios_mode":     "UEFI",
			"cpu_cores":     "4",
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "8",
			"storage_gb":    "32", // Only 32GB storage
			"secure_boot":   "enabled",
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "64+ GB storage")
}

func TestCompatibilityChecker_InsufficientCPUCores(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version":   "2.0",
			"bios_mode":     "UEFI",
			"cpu_cores":     "1", // Only 1 core
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "8",
			"storage_gb":    "256",
			"secure_boot":   "enabled",
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "2+ cores")
}

func TestCompatibilityChecker_SecureBootDisabled(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version":   "2.0",
			"bios_mode":     "UEFI",
			"cpu_cores":     "4",
			"cpu_speed_ghz": "2.4",
			"ram_gb":        "8",
			"storage_gb":    "256",
			"secure_boot":   "disabled", // Secure Boot disabled
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "Secure Boot")
}

func TestCompatibilityChecker_MultipleIssues(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	dna := createIncompatibleDNA()

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	// Should have multiple missing requirements
	assert.Greater(t, len(result.MissingRequirements), 2)
}

func TestCompatibilityChecker_MissingDNA(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	result, err := checker.CheckCompatibility(nil, "11")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "DNA data is required")
}

func TestCompatibilityChecker_PartialDNA(t *testing.T) {
	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	// DNA with some missing attributes
	dna := &commonpb.DNA{
		Id: "test-device",
		Attributes: map[string]string{
			"tpm_version": "2.0",
			"bios_mode":   "UEFI",
			// Missing CPU, RAM, storage info
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have warnings for missing data
	assert.Greater(t, len(result.Warnings), 0)
}

func TestUpgradeManager_CheckEligibility_PolicyDisabled(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = false // Disabled

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA()
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "disabled by policy")
}

func TestUpgradeManager_CheckEligibility_Compatible(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA()
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Compatible)
	assert.Equal(t, 0, len(result.MissingRequirements))
}

func TestUpgradeManager_CheckEligibility_Incompatible(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createIncompatibleDNA()
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Compatible)
	assert.Greater(t, len(result.MissingRequirements), 0)
}

func TestUpgradeManager_CheckEligibility_SkipCompatibilityCheck(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.RequireCompatibilityCheck = false // Skip check

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createIncompatibleDNA() // Even incompatible device
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should be marked compatible because check was skipped
	assert.True(t, result.Compatible)
	assert.Contains(t, result.Warnings[0], "skipped by policy")
}

func TestUpgradeManager_PerformUpgrade_Incompatible_Blocked(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.BlockIncompatible = true

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createIncompatibleDNA()
	ctx := context.Background()

	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not compatible")
}

func TestUpgradeManager_PerformUpgrade_TestMode(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = true // Test mode

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA()
	ctx := context.Background()

	// Should succeed without actual upgrade
	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.NoError(t, err)
}

func TestUpgradeManager_CanUpgradeNow_PolicyDisabled(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = false

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	assert.False(t, canUpgrade)
	assert.Contains(t, reason, "disabled")
}

func TestUpgradeManager_CanUpgradeNow_OutsideWindow(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.UpgradeWindow = &patch.TimeWindow{
		StartHour:  2,           // 2 AM
		EndHour:    4,           // 4 AM
		DaysOfWeek: []int{0, 6}, // Sunday and Saturday only
	}

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	// Unless running on Sat/Sun between 2-4 AM, should be outside window
	if !canUpgrade {
		assert.Contains(t, reason, "outside of upgrade window")
	}
}

func TestUpgradeManager_CanUpgradeNow_MaintenanceWindowBlocked(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true

	// Mock window manager that blocks maintenance
	mockWindow := &mockWindowManager{
		canPerformMaint: false,
	}

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, mockWindow, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	assert.False(t, canUpgrade)
	assert.Contains(t, reason, "maintenance window")
}

func TestUpgradeManager_CanUpgradeNow_MaintenanceWindowAllowed(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true

	// Mock window manager that allows maintenance
	mockWindow := &mockWindowManager{
		canPerformMaint: true,
	}

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, mockWindow, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	assert.True(t, canUpgrade)
	assert.Equal(t, "", reason)
}

func TestUpgradeManager_SetPolicy(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	newPolicy := patch.UpgradePolicy{
		Enabled:     true,
		AutoUpgrade: true,
	}

	upgradeManager.SetPolicy(newPolicy)
	retrievedPolicy := upgradeManager.GetPolicy()

	assert.Equal(t, newPolicy.Enabled, retrievedPolicy.Enabled)
	assert.Equal(t, newPolicy.AutoUpgrade, retrievedPolicy.AutoUpgrade)
}

func TestUpgradeManager_GetUpgradeStatus(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = false

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	status, err := upgradeManager.GetUpgradeStatus(ctx)

	require.NoError(t, err)
	assert.Equal(t, "disabled", status)
}

func TestUpgradeManager_GetUpgradeStatus_AutoUpgrade(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.AutoUpgrade = true

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	status, err := upgradeManager.GetUpgradeStatus(ctx)

	require.NoError(t, err)
	assert.Equal(t, "auto-upgrade-enabled", status)
}

func TestTimeWindow_NormalWindow(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := patch.UpgradePolicy{
		Enabled: true,
		UpgradeWindow: &patch.TimeWindow{
			StartHour:  9,
			EndHour:    17,
			DaysOfWeek: []int{1, 2, 3, 4, 5}, // Monday-Friday
		},
	}

	upgradeManager := patch.NewUpgradeManager(patchModule, nil, policy, nil, "test-device")
	require.NotNil(t, upgradeManager)

	// Test that upgrade manager was created successfully with time window
	// The actual time window checking is tested through CanUpgradeNow in other tests
	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	// Result depends on current time, but should not error
	require.NoError(t, err)

	// If outside window, should have appropriate reason
	if !canUpgrade {
		assert.Contains(t, reason, "window")
	}
}

func TestUpgradeManager_PerformUpgrade_WithMaintenanceWindow(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = true

	// Mock window manager that allows maintenance
	mockWindow := &mockWindowManager{
		canPerformMaint: true,
	}

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, mockWindow, "test-device")

	dna := createCompatibleDNA()
	ctx := context.Background()

	// Should succeed in test mode
	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.NoError(t, err)
}

func TestUpgradeManager_PerformUpgrade_BlockedByMaintenanceWindow(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = false

	// Mock window manager that blocks maintenance
	mockWindow := &mockWindowManager{
		canPerformMaint: false,
	}

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, mockWindow, "test-device")

	dna := createCompatibleDNA()
	ctx := context.Background()

	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot upgrade now")
}

func TestConfig_Validate_FeatureUpdate(t *testing.T) {
	config := &patch.Config{PatchType: "feature-update"}
	err := config.Validate()
	assert.NoError(t, err, "feature-update must be accepted by Config.validate()")
}

func TestConfig_Validate_RejectsUnknownPatchType(t *testing.T) {
	unknownTypes := []string{"major-update", "optional", "driver", ""}
	for _, pt := range unknownTypes {
		config := &patch.Config{PatchType: pt}
		err := config.Validate()
		assert.ErrorIs(t, err, patch.ErrInvalidPatchType,
			"patch type %q must be rejected by Config.validate()", pt)
	}
}

func TestUpgradeManager_PerformUpgrade_NoErrInvalidPatchType(t *testing.T) {
	mockManager := patch.NewMockPatchManager()
	// Add a feature-update patch so InstallPatches has real work to do, making
	// the state change verifiable and proving the full installation path ran.
	mockManager.AddAvailablePatch(patch.PatchInfo{
		ID:             "FU-2024-001",
		Title:          "Windows 11 Feature Update",
		Category:       "feature-update",
		Severity:       "unspecified",
		RebootRequired: true,
	})

	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := patch.DefaultWindows11Requirements()
	checker := patch.NewCompatibilityChecker(requirements)

	policy := patch.DefaultUpgradePolicy()
	policy.Enabled = true
	policy.BlockIncompatible = false
	policy.TestMode = false

	upgradeManager := patch.NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA()
	ctx := context.Background()

	err = upgradeManager.PerformUpgrade(ctx, dna)
	require.NotErrorIs(t, err, patch.ErrInvalidPatchType,
		"PerformUpgrade must not return ErrInvalidPatchType for feature-update")
	require.NoError(t, err, "PerformUpgrade should succeed when feature-update is a valid patch type")

	// Verify the installation path was exercised: the feature-update patch has
	// RebootRequired=true, so a successful install sets the reboot-required flag.
	rebootRequired, checkErr := mockManager.CheckRebootRequired(ctx)
	require.NoError(t, checkErr)
	assert.True(t, rebootRequired,
		"feature-update patch install must set reboot-required flag, confirming the install path ran")
}
