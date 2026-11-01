// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package patch

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
)

func TestDefaultWindows11Requirements(t *testing.T) {
	req := DefaultWindows11Requirements()

	assert.Equal(t, "2.0", req.TPMVersion)
	assert.True(t, req.RequiresUEFI)
	assert.Equal(t, 2, req.MinCPUCores)
	assert.Equal(t, 1.0, req.MinCPUSpeedGHz)
	assert.Equal(t, 4, req.MinRAMGB)
	assert.Equal(t, 64, req.MinStorageGB)
	assert.True(t, req.RequiresSecureBoot)
}

func TestDefaultUpgradePolicy(t *testing.T) {
	policy := DefaultUpgradePolicy()

	assert.False(t, policy.Enabled, "Upgrades should be disabled by default for safety")
	assert.False(t, policy.AutoUpgrade)
	assert.Equal(t, "11", policy.TargetVersion)
	assert.True(t, policy.RequireCompatibilityCheck)
	assert.True(t, policy.BlockIncompatible)
	assert.Equal(t, 30, policy.DeferDays)
	assert.True(t, policy.RollbackOnFailure)
}

// buildFragment constructs a host:* fragment with the given key-value payload.
// Values in data must be string, as gatherers emit string attributes.
func buildFragment(t *testing.T, kind string, data map[string]interface{}) *commonpb.Fragment {
	t.Helper()
	frag, err := sdna.NewFragment(kind, "gatherer", sdna.MapState(data))
	require.NoError(t, err, "NewFragment(%q)", kind)
	return frag
}

// createCompatibleDNA builds DNA with host:* fragments for a Windows 11 compatible device.
func createCompatibleDNA(t *testing.T) *commonpb.DNA {
	t.Helper()
	return &commonpb.DNA{
		Id: "test-device-compatible",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
		},
	}
}

// createIncompatibleDNA builds DNA with host:* fragments for a Windows 11 incompatible device.
func createIncompatibleDNA(t *testing.T) *commonpb.DNA {
	t.Helper()
	return &commonpb.DNA{
		Id: "test-device-incompatible",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "1.2", // TPM 1.2 not supported
				"bios_mode":   "Legacy",
				"secure_boot": "disabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "2",
				"cpu_max_clock_speed": "1500MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "4.00",
				"storage_gb":      "128",
			}),
		},
	}
}

func TestCompatibilityChecker_Compatible(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := createCompatibleDNA(t)

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Compatible, "Device should be compatible")
	assert.Equal(t, 0, len(result.MissingRequirements))
	assert.Equal(t, "11", result.TargetVersion)
	assert.NotNil(t, result.DeviceDNA)
}

func TestCompatibilityChecker_IncompatibleTPM(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "1.2", // TPM 1.2 not supported
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
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
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "Legacy", // Legacy BIOS not supported
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "UEFI")
}

func TestCompatibilityChecker_InsufficientRAM(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "2.00", // Only 2 GB RAM
				"storage_gb":      "256",
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "4+ GB RAM")
}

func TestCompatibilityChecker_InsufficientStorage(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "32", // Only 32 GB storage
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "64+ GB storage")
}

func TestCompatibilityChecker_InsufficientCPUCores(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "1", // Only 1 core
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "2+ cores")
}

func TestCompatibilityChecker_SecureBootDisabled(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "disabled", // Secure Boot disabled
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	assert.Contains(t, result.MissingRequirements[0], "Secure Boot")
}

func TestCompatibilityChecker_MultipleIssues(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := createIncompatibleDNA(t)

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)

	assert.False(t, result.Compatible)
	// Should have multiple missing requirements
	assert.Greater(t, len(result.MissingRequirements), 2)
}

func TestCompatibilityChecker_MissingDNA(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	result, err := checker.CheckCompatibility(nil, "11")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "DNA data is required")
}

func TestCompatibilityChecker_PartialDNA(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	// DNA with only host:bios — CPU, RAM, storage fragments absent.
	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			// host:cpu and host:memory absent
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should have warnings for missing CPU, RAM, storage data
	assert.Greater(t, len(result.Warnings), 0)
}

// TestCompatibilityChecker_BIOSModeAbsent verifies that a missing bios_mode key
// in the host:bios fragment produces the expected warning (not a blocking failure).
func TestCompatibilityChecker_BIOSModeAbsent(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"secure_boot": "enabled",
				// bios_mode absent
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_cores":           "4",
				"cpu_max_clock_speed": "2400MHz",
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Absent bios_mode produces a warning, not a blocking requirement.
	assert.True(t, result.Compatible, "absent bios_mode should only warn, not block")
	require.NotEmpty(t, result.Warnings)
	assert.Contains(t, result.Warnings[0], "BIOS mode could not be determined")
}

// TestCompatibilityChecker_CPUCoresAbsent verifies that a missing cpu_cores key
// in the host:cpu fragment produces the expected warning (not a blocking failure).
func TestCompatibilityChecker_CPUCoresAbsent(t *testing.T) {
	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	dna := &commonpb.DNA{
		Id: "test-device",
		Fragments: []*commonpb.Fragment{
			buildFragment(t, "host:bios", map[string]interface{}{
				"tpm_version": "2.0",
				"bios_mode":   "UEFI",
				"secure_boot": "enabled",
			}),
			buildFragment(t, "host:cpu", map[string]interface{}{
				"cpu_max_clock_speed": "2400MHz",
				// cpu_cores absent
			}),
			buildFragment(t, "host:memory", map[string]interface{}{
				"memory_total_gb": "8.00",
				"storage_gb":      "256",
			}),
		},
	}

	result, err := checker.CheckCompatibility(dna, "11")
	require.NoError(t, err)
	require.NotNil(t, result)

	// Absent cpu_cores produces a warning, not a blocking requirement.
	assert.Contains(t, result.Warnings, "CPU core count could not be determined")
}

func TestUpgradeManager_CheckEligibility_PolicyDisabled(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = false // Disabled

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA(t)
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "disabled by policy")
}

func TestUpgradeManager_CheckEligibility_Compatible(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA(t)
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, result.Compatible)
	assert.Equal(t, 0, len(result.MissingRequirements))
}

func TestUpgradeManager_CheckEligibility_Incompatible(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createIncompatibleDNA(t)
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.False(t, result.Compatible)
	assert.Greater(t, len(result.MissingRequirements), 0)
}

func TestUpgradeManager_CheckEligibility_SkipCompatibilityCheck(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.RequireCompatibilityCheck = false // Skip check

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createIncompatibleDNA(t) // Even incompatible device
	ctx := context.Background()

	result, err := upgradeManager.CheckUpgradeEligibility(ctx, dna)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Should be marked compatible because check was skipped
	assert.True(t, result.Compatible)
	assert.Contains(t, result.Warnings[0], "skipped by policy")
}

func TestUpgradeManager_PerformUpgrade_Incompatible_Blocked(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.BlockIncompatible = true

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createIncompatibleDNA(t)
	ctx := context.Background()

	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not compatible")
}

func TestUpgradeManager_PerformUpgrade_TestMode(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = true // Test mode

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA(t)
	ctx := context.Background()

	// Should succeed without actual upgrade
	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.NoError(t, err)
}

func TestUpgradeManager_CanUpgradeNow_PolicyDisabled(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	policy.Enabled = false

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	assert.False(t, canUpgrade)
	assert.Contains(t, reason, "disabled")
}

func TestUpgradeManager_CanUpgradeNow_OutsideWindow(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.UpgradeWindow = &TimeWindow{
		StartHour:  2,           // 2 AM
		EndHour:    4,           // 4 AM
		DaysOfWeek: []int{0, 6}, // Sunday and Saturday only
	}

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	// Window membership is evaluated against an injected time, so every boundary
	// is asserted against fixed clock values rather than the wall clock.
	// 2026-08-15 is a Saturday, 2026-08-16 a Sunday, 2026-08-19 a Wednesday.
	tests := []struct {
		name     string
		now      time.Time
		expected bool
	}{
		{"saturday at window start", time.Date(2026, 8, 15, 2, 0, 0, 0, time.UTC), true},
		{"saturday last minute of window", time.Date(2026, 8, 15, 3, 59, 59, 0, time.UTC), true},
		{"saturday one minute before window", time.Date(2026, 8, 15, 1, 59, 59, 0, time.UTC), false},
		{"saturday at window end is exclusive", time.Date(2026, 8, 15, 4, 0, 0, 0, time.UTC), false},
		{"sunday inside window", time.Date(2026, 8, 16, 3, 0, 0, 0, time.UTC), true},
		{"wednesday inside hours but disallowed day", time.Date(2026, 8, 19, 3, 0, 0, 0, time.UTC), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, upgradeManager.isInUpgradeWindow(tc.now))
		})
	}

	ctx := context.Background()

	// CanUpgradeNow reads the wall clock, so drive it with a window that provably
	// cannot contain "now": all days are allowed, but the single open hour is the
	// one twelve hours away from the current hour. The outcome is the same
	// regardless of when the suite runs, including across an hour rollover.
	closedStart := (time.Now().Hour() + 12) % 24
	policy.UpgradeWindow = &TimeWindow{StartHour: closedStart, EndHour: closedStart + 1}
	upgradeManager.SetPolicy(policy)

	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)
	require.NoError(t, err)
	assert.False(t, canUpgrade)
	assert.Contains(t, reason, "outside of upgrade window")

	// A window that spans every hour of every day is always open, so the upgrade
	// window must not be the thing blocking the upgrade.
	policy.UpgradeWindow = &TimeWindow{StartHour: 0, EndHour: 24}
	upgradeManager.SetPolicy(policy)

	canUpgrade, reason, err = upgradeManager.CanUpgradeNow(ctx)
	require.NoError(t, err)
	assert.True(t, canUpgrade)
	assert.Equal(t, "", reason)
}

func TestUpgradeManager_CanUpgradeNow_MaintenanceWindowBlocked(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true

	// No maintenance window is scheduled, so the device is never inside one and
	// maintenance is denied.
	windowMgr := NewInMemoryWindowManager()

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, windowMgr, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	assert.False(t, canUpgrade)
	assert.Contains(t, reason, "maintenance window")
}

func TestUpgradeManager_CanUpgradeNow_MaintenanceWindowAllowed(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true

	// Schedule a currently-open window that permits maintenance.
	windowMgr := NewInMemoryWindowManager()
	windowMgr.AddWindow("test-device", MaintenanceWindow{
		Start:            time.Now().Add(-1 * time.Hour),
		Duration:         2 * time.Hour,
		AllowReboot:      true,
		AllowMaintenance: true,
	})

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, windowMgr, "test-device")

	ctx := context.Background()
	canUpgrade, reason, err := upgradeManager.CanUpgradeNow(ctx)

	assert.NoError(t, err)
	assert.True(t, canUpgrade)
	assert.Equal(t, "", reason)
}

func TestUpgradeManager_SetPolicy(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	upgradeManager := NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	newPolicy := UpgradePolicy{
		Enabled:     true,
		AutoUpgrade: true,
	}

	upgradeManager.SetPolicy(newPolicy)
	retrievedPolicy := upgradeManager.GetPolicy()

	assert.Equal(t, newPolicy.Enabled, retrievedPolicy.Enabled)
	assert.Equal(t, newPolicy.AutoUpgrade, retrievedPolicy.AutoUpgrade)
}

func TestUpgradeManager_GetUpgradeStatus(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	policy.Enabled = false

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	status, err := upgradeManager.GetUpgradeStatus(ctx)

	require.NoError(t, err)
	assert.Equal(t, "disabled", status)
}

func TestUpgradeManager_GetUpgradeStatus_AutoUpgrade(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.AutoUpgrade = true

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, nil, "test-device")

	ctx := context.Background()
	status, err := upgradeManager.GetUpgradeStatus(ctx)

	require.NoError(t, err)
	assert.Equal(t, "auto-upgrade-enabled", status)
}

func TestTimeWindow_NormalWindow(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	policy := UpgradePolicy{
		Enabled: true,
		UpgradeWindow: &TimeWindow{
			StartHour:  9,
			EndHour:    17,
			DaysOfWeek: []int{1, 2, 3, 4, 5}, // Monday-Friday
		},
	}

	upgradeManager := NewUpgradeManager(patchModule, nil, policy, nil, "test-device")
	require.NotNil(t, upgradeManager)

	// A normal (non-overnight) window is inclusive of StartHour and exclusive of
	// EndHour, and only on the listed days. Each case injects a fixed time so the
	// assertions hold regardless of when the suite runs.
	// 2026-08-17 is a Monday, 2026-08-21 a Friday, 2026-08-15 a Saturday and
	// 2026-08-16 a Sunday.
	tests := []struct {
		name     string
		now      time.Time
		expected bool
	}{
		{"monday at window start", time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC), true},
		{"monday mid window", time.Date(2026, 8, 17, 13, 30, 0, 0, time.UTC), true},
		{"monday last minute of window", time.Date(2026, 8, 17, 16, 59, 59, 0, time.UTC), true},
		{"monday at window end is exclusive", time.Date(2026, 8, 17, 17, 0, 0, 0, time.UTC), false},
		{"monday one minute before window", time.Date(2026, 8, 17, 8, 59, 59, 0, time.UTC), false},
		{"friday mid window", time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC), true},
		{"saturday inside hours but disallowed day", time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC), false},
		{"sunday inside hours but disallowed day", time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, upgradeManager.isInUpgradeWindow(tc.now))
		})
	}
}

func TestUpgradeManager_PerformUpgrade_WithMaintenanceWindow(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = true

	// Schedule a currently-open window that permits maintenance.
	windowMgr := NewInMemoryWindowManager()
	windowMgr.AddWindow("test-device", MaintenanceWindow{
		Start:            time.Now().Add(-1 * time.Hour),
		Duration:         2 * time.Hour,
		AllowReboot:      true,
		AllowMaintenance: true,
	})

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, windowMgr, "test-device")

	dna := createCompatibleDNA(t)
	ctx := context.Background()

	// Should succeed in test mode
	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.NoError(t, err)
}

func TestUpgradeManager_PerformUpgrade_BlockedByMaintenanceWindow(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.TestMode = false

	// No maintenance window is scheduled, so maintenance is denied and the
	// upgrade cannot proceed.
	windowMgr := NewInMemoryWindowManager()

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, windowMgr, "test-device")

	dna := createCompatibleDNA(t)
	ctx := context.Background()

	err = upgradeManager.PerformUpgrade(ctx, dna)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "cannot upgrade now")
}

func TestConfig_Validate_FeatureUpdate(t *testing.T) {
	config := &Config{PatchType: "feature-update"}
	err := config.Validate()
	assert.NoError(t, err, "feature-update must be accepted by Config.validate()")
}

func TestConfig_Validate_RejectsUnknownPatchType(t *testing.T) {
	unknownTypes := []string{"major-update", "optional", "driver", ""}
	for _, pt := range unknownTypes {
		config := &Config{PatchType: pt}
		err := config.Validate()
		assert.ErrorIs(t, err, ErrInvalidPatchType,
			"patch type %q must be rejected by Config.validate()", pt)
	}
}

func TestUpgradeManager_PerformUpgrade_NoErrInvalidPatchType(t *testing.T) {
	mockManager := NewInMemoryPatchManager()
	// Add a feature-update patch so InstallPatches has real work to do, making
	// the state change verifiable and proving the full installation path ran.
	mockManager.AddAvailablePatch(PatchInfo{
		ID:             "FU-2024-001",
		Title:          "Windows 11 Feature Update",
		Category:       "feature-update",
		Severity:       "unspecified",
		RebootRequired: true,
	})

	patchModule, err := NewPatchModule(mockManager)
	require.NoError(t, err)

	requirements := DefaultWindows11Requirements()
	checker := NewCompatibilityChecker(requirements)

	policy := DefaultUpgradePolicy()
	policy.Enabled = true
	policy.BlockIncompatible = false
	policy.TestMode = false

	upgradeManager := NewUpgradeManager(patchModule, checker, policy, nil, "test-device")

	dna := createCompatibleDNA(t)
	ctx := context.Background()

	err = upgradeManager.PerformUpgrade(ctx, dna)
	// The primary assertion: feature-update is a valid patch type, so the error must NOT be
	// ErrInvalidPatchType (which would indicate the patch type was rejected before install).
	require.NotErrorIs(t, err, ErrInvalidPatchType,
		"PerformUpgrade must not return ErrInvalidPatchType for feature-update")
	// Fail-closed: the patchModule has no window manager injected, so canReboot returns false
	// when the feature-update patch requires a reboot. In production the factory always injects
	// a Gate; ungated devices receive a Gate whose CanReboot returns true.
	require.ErrorIs(t, err, ErrMaintenanceWindowNotActive,
		"without a configured gate, auto-reboot is denied fail-closed after install")

	// Verify the installation path was exercised: the feature-update patch has
	// RebootRequired=true, so a successful install sets the reboot-required flag even
	// when the auto-reboot itself is denied by the fail-closed gate.
	rebootRequired, checkErr := mockManager.CheckRebootRequired(ctx)
	require.NoError(t, checkErr)
	assert.True(t, rebootRequired,
		"feature-update patch install must set reboot-required flag, confirming the install path ran")
}
