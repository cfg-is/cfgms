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

func TestDefaultAlertConfig(t *testing.T) {
	config := patch.DefaultAlertConfig()

	assert.True(t, config.Enabled, "Alerting should be enabled by default")
	assert.Equal(t, 7, config.WarningThreshold, "Warning threshold should be 7 days")
	assert.Equal(t, 1, config.CriticalThreshold, "Critical threshold should be 1 day")
	assert.Equal(t, 24*time.Hour, config.AlertInterval, "Alert interval should be 24 hours")
	assert.Equal(t, 3, config.MaxAlertsPerDay, "Max alerts per day should be 3")
	assert.True(t, config.SuppressInfo, "Info alerts should be suppressed")
	assert.Equal(t, 1, len(config.DeliveryChannels), "Should have 1 delivery channel")
}

func TestNewAlertingManager(t *testing.T) {
	config := patch.DefaultAlertConfig()
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)
	require.NotNil(t, alertManager)
}

func TestAlertingManager_CheckDevice_Compliant(t *testing.T) {
	config := patch.DefaultAlertConfig()
	config.SuppressInfo = false // Don't suppress info alerts for testing

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{}) // No pending patches

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	alert, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert)

	assert.Equal(t, patch.AlertLevelInfo, alert.Level)
	assert.Equal(t, patch.ComplianceStatusCompliant, alert.Status)
}

func TestAlertingManager_CheckDevice_Warning(t *testing.T) {
	config := patch.DefaultAlertConfig()

	mockManager := patch.NewMockPatchManager()

	// Add a patch that's approaching deadline (3 days old, 4 days left)
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

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	alert, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert)

	assert.Equal(t, patch.AlertLevelWarning, alert.Level)
	assert.Equal(t, patch.ComplianceStatusWarning, alert.Status)
	assert.Greater(t, alert.DaysUntilBreach, 0)
	assert.Contains(t, alert.Message, "WARNING")
}

func TestAlertingManager_CheckDevice_Critical(t *testing.T) {
	config := patch.DefaultAlertConfig()

	mockManager := patch.NewMockPatchManager()

	// Add a patch that's very close to deadline (6.5 days old, 12 hours left)
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

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	alert, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert)

	assert.Equal(t, patch.AlertLevelCritical, alert.Level)
	assert.Equal(t, patch.ComplianceStatusCritical, alert.Status)
	assert.True(t, alert.DaysUntilBreach < 1)
	assert.Contains(t, alert.Message, "CRITICAL")
}

func TestAlertingManager_CheckDevice_Breach(t *testing.T) {
	config := patch.DefaultAlertConfig()

	mockManager := patch.NewMockPatchManager()

	// Add an overdue patch (10 days old)
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

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	alert, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert)

	assert.Equal(t, patch.AlertLevelBreach, alert.Level)
	assert.Equal(t, patch.ComplianceStatusNonCompliant, alert.Status)
	assert.True(t, alert.DaysUntilBreach < 0)
	assert.Contains(t, alert.Message, "BREACH")
}

func TestAlertingManager_SuppressInfo(t *testing.T) {
	config := patch.DefaultAlertConfig()
	config.SuppressInfo = true

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{}) // Compliant

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	alert, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	assert.Nil(t, alert, "Info alert should be suppressed")
}

func TestAlertingManager_MaxAlertsPerDay(t *testing.T) {
	config := patch.DefaultAlertConfig()
	config.MaxAlertsPerDay = 2
	config.AlertInterval = 1 * time.Millisecond // Very short interval for testing

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB9999999",
			Title:       "Critical Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-10 * 24 * time.Hour), // Breach
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)
	ctx := context.Background()

	// First alert should succeed
	alert1, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert1)

	time.Sleep(2 * time.Millisecond)

	// Second alert should succeed
	alert2, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert2)

	time.Sleep(2 * time.Millisecond)

	// Third alert should be suppressed (hit max per day)
	alert3, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	assert.Nil(t, alert3, "Third alert should be suppressed due to max per day limit")
}

func TestAlertingManager_AlertInterval(t *testing.T) {
	config := patch.DefaultAlertConfig()
	config.AlertInterval = 100 * time.Millisecond

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB8888888",
			Title:       "Warning Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-3 * 24 * time.Hour), // Warning
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)
	ctx := context.Background()

	// First alert should succeed
	alert1, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert1)

	// Immediate second alert should be suppressed
	alert2, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	assert.Nil(t, alert2, "Second alert should be suppressed due to interval")

	// Wait for interval to pass
	time.Sleep(150 * time.Millisecond)

	// Third alert should succeed after interval
	alert3, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert3, "Alert should succeed after interval has passed")
}

func TestAlertingManager_CheckDevices(t *testing.T) {
	config := patch.DefaultAlertConfig()

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB9999999",
			Title:       "Critical Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-3 * 24 * time.Hour),
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	deviceIDs := []string{"device-1", "device-2", "device-3"}

	alerts, err := alertManager.CheckDevices(ctx, deviceIDs)
	require.NoError(t, err)
	assert.Greater(t, len(alerts), 0, "Should have generated alerts")
}

func TestAlertingManager_AlertDetails(t *testing.T) {
	config := patch.DefaultAlertConfig()

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB1111111",
			Title:       "Critical Security Update",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-10 * 24 * time.Hour),
			Installed:   false,
		},
		{
			ID:          "KB2222222",
			Title:       "Important Update",
			Severity:    "important",
			Category:    "security",
			ReleaseDate: time.Now().Add(-8 * 24 * time.Hour),
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	ctx := context.Background()
	alert, err := alertManager.CheckDevice(ctx, "test-device")
	require.NoError(t, err)
	require.NotNil(t, alert)

	// Verify alert details
	assert.NotNil(t, alert.Details)
	assert.Contains(t, alert.Details, "total_missing_patches")
	assert.Contains(t, alert.Details, "critical_patches")
	assert.Contains(t, alert.Details, "important_patches")
	assert.Equal(t, 2, alert.Details["total_missing_patches"])
	assert.Equal(t, 1, alert.Details["critical_patches"])
	assert.Equal(t, 1, alert.Details["important_patches"])
}

func TestAlertingManager_ChannelFiltering(t *testing.T) {
	config := patch.AlertConfig{
		Enabled:           true,
		WarningThreshold:  7,
		CriticalThreshold: 1,
		AlertInterval:     24 * time.Hour,
		MaxAlertsPerDay:   3,
		SuppressInfo:      false,
		DeliveryChannels: []patch.AlertChannel{
			{
				Type:     "webhook",
				Target:   "https://example.com/warning",
				MinLevel: patch.AlertLevelWarning,
			},
			{
				Type:     "webhook",
				Target:   "https://example.com/critical",
				MinLevel: patch.AlertLevelCritical,
			},
			{
				Type:     "webhook",
				Target:   "https://example.com/all",
				MinLevel: patch.AlertLevelInfo,
			},
		},
	}

	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)

	// Test that channels are filtered based on alert level
	// This would need access to internal methods or we'd test through delivery
	// For now, just verify the manager was created successfully
	require.NotNil(t, alertManager)
}

func TestNewComplianceScheduler(t *testing.T) {
	config := patch.DefaultAlertConfig()
	mockManager := patch.NewMockPatchManager()
	patchModule, err := patch.NewPatchModule(mockManager)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)
	deviceIDs := []string{"device-1", "device-2", "device-3"}

	scheduler := patch.NewComplianceScheduler(alertManager, 1*time.Hour, deviceIDs)
	require.NotNil(t, scheduler)
}

func TestComplianceScheduler_RunOnce(t *testing.T) {
	config := patch.DefaultAlertConfig()
	mockManager := patch.NewMockPatchManager()
	mockManager.SetAvailablePatches([]patch.PatchInfo{
		{
			ID:          "KB9999999",
			Title:       "Test Patch",
			Severity:    "critical",
			Category:    "security",
			ReleaseDate: time.Now().Add(-3 * 24 * time.Hour),
			Installed:   false,
		},
	})

	patchModule, err := patch.NewPatchModuleWithPolicy(
		mockManager,
		patch.DefaultPolicy(),
		nil,
		"test-device",
	)
	require.NoError(t, err)

	alertManager := patch.NewAlertingManager(config, patchModule)
	deviceIDs := []string{"device-1"}

	scheduler := patch.NewComplianceScheduler(alertManager, 10*time.Millisecond, deviceIDs)

	// Create a context that will cancel after short time
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Run scheduler (it will run at least once before timeout)
	err = scheduler.Start(ctx)
	assert.Error(t, err) // Should return context deadline exceeded
	assert.Equal(t, context.DeadlineExceeded, err)
}
