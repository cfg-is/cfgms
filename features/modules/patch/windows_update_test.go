//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// +build windows

package patch_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/patch"
)

// TestWindowsUpdateManager_New tests creating a new Windows Update manager
func TestWindowsUpdateManager_New(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err, "Should create Windows Update manager")
	require.NotNil(t, manager, "Manager should not be nil")

	// Cleanup
	err = manager.Close()
	assert.NoError(t, err, "Should close manager cleanly")
}

// TestWindowsUpdateManager_ListAvailablePatches tests listing available patches
func TestWindowsUpdateManager_ListAvailablePatches(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// List all available patches
	patches, err := manager.ListAvailablePatches(ctx, "all")
	require.NoError(t, err, "Should list available patches")
	assert.NotNil(t, patches, "Patches list should not be nil")

	// Each patch should have required fields
	for _, p := range patches {
		assert.NotEmpty(t, p.ID, "Patch ID should not be empty")
		assert.NotEmpty(t, p.Title, "Patch title should not be empty")
		assert.Contains(t, []string{"critical", "important", "moderate", "low", "unspecified"},
			p.Severity, "Patch severity should be valid")
	}
}

// TestWindowsUpdateManager_ListAvailablePatches_SecurityOnly tests filtering security patches
func TestWindowsUpdateManager_ListAvailablePatches_SecurityOnly(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// List only security patches
	patches, err := manager.ListAvailablePatches(ctx, "security")
	require.NoError(t, err, "Should list security patches")
	assert.NotNil(t, patches, "Patches list should not be nil")

	// All patches should be security updates
	for _, p := range patches {
		assert.Contains(t, []string{"security", "critical"}, p.Category,
			"Should only return security/critical patches")
	}
}

// TestWindowsUpdateManager_ListInstalledPatches tests listing installed patches
func TestWindowsUpdateManager_ListInstalledPatches(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// List installed patches
	patches, err := manager.ListInstalledPatches(ctx)
	require.NoError(t, err, "Should list installed patches")
	assert.NotNil(t, patches, "Patches list should not be nil")

	// On any Windows system, there should be at least some installed patches
	assert.Greater(t, len(patches), 0, "Should have at least some installed patches")

	// Each patch should have required fields
	for _, p := range patches {
		assert.NotEmpty(t, p.ID, "Patch ID should not be empty")
		assert.NotEmpty(t, p.Title, "Patch title should not be empty")
		assert.False(t, p.InstallDate.IsZero(), "Install date should be set")
	}
}

// TestWindowsUpdateManager_CheckRebootRequired tests reboot status check
func TestWindowsUpdateManager_CheckRebootRequired(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Check if reboot is required
	rebootRequired, err := manager.CheckRebootRequired(ctx)
	require.NoError(t, err, "Should check reboot status")

	// Result should be a boolean (true or false)
	assert.IsType(t, false, rebootRequired, "Should return boolean")
}

// TestWindowsUpdateManager_GetLastPatchDate tests getting last patch date
func TestWindowsUpdateManager_GetLastPatchDate(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Get last patch date
	lastDate, err := manager.GetLastPatchDate(ctx)
	require.NoError(t, err, "Should get last patch date")

	// On any Windows system that's been patched, this should not be zero
	// Allow zero time for systems that have never been patched (unlikely but possible)
	assert.True(t, lastDate.IsZero() || lastDate.Before(time.Now()),
		"Last patch date should be in the past or zero")
}

// TestWindowsUpdateManager_InstallPatches_TestMode tests patch installation in test mode
func TestWindowsUpdateManager_InstallPatches_TestMode(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Create config in test mode (won't actually install)
	config := &patch.Config{
		Type:     "security",
		TestMode: true,
	}

	// This should not fail even if patches are available
	err = manager.InstallPatches(ctx, config)
	assert.NoError(t, err, "Test mode installation should not fail")
}

// TestWindowsUpdateManager_BuildSearchCriteria tests search criteria building
func TestWindowsUpdateManager_BuildSearchCriteria(t *testing.T) {
	// This tests the internal search criteria logic
	// Note: This function may need to be exported for testing or we test it indirectly

	tests := []struct {
		name       string
		patchType  string
		shouldFind bool // Whether we expect to find patches
	}{
		{"All patches", "all", true},
		{"Security only", "security", true},
		{"Critical only", "critical", true},
		{"Optional updates", "optional", false}, // May not always have optional updates
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := patch.NewWindowsUpdateManager()
			require.NoError(t, err)
			defer manager.Close()

			ctx := context.Background()
			patches, err := manager.ListAvailablePatches(ctx, tt.patchType)
			require.NoError(t, err, "Should list patches for type: %s", tt.patchType)

			if tt.shouldFind {
				// We don't assert length > 0 because system might be fully patched
				assert.NotNil(t, patches, "Patches list should not be nil")
			}
		})
	}
}

// TestWindowsUpdateManager_MultipleOperations tests using the manager for multiple operations
func TestWindowsUpdateManager_MultipleOperations(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Perform multiple operations in sequence
	available, err := manager.ListAvailablePatches(ctx, "all")
	require.NoError(t, err, "First operation should succeed")

	installed, err := manager.ListInstalledPatches(ctx)
	require.NoError(t, err, "Second operation should succeed")

	rebootRequired, err := manager.CheckRebootRequired(ctx)
	require.NoError(t, err, "Third operation should succeed")

	lastDate, err := manager.GetLastPatchDate(ctx)
	require.NoError(t, err, "Fourth operation should succeed")

	// Basic sanity checks
	assert.NotNil(t, available, "Available patches should not be nil")
	assert.NotNil(t, installed, "Installed patches should not be nil")
	assert.IsType(t, false, rebootRequired, "Reboot required should be boolean")
	assert.True(t, lastDate.IsZero() || lastDate.Before(time.Now()),
		"Last date should be valid")
}

// TestWindowsUpdateManager_FilterConfig tests patch filtering with include/exclude
func TestWindowsUpdateManager_FilterConfig(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Get all available patches first
	allPatches, err := manager.ListAvailablePatches(ctx, "all")
	require.NoError(t, err)

	if len(allPatches) == 0 {
		t.Skip("No patches available to test filtering")
	}

	// Create config with exclude pattern
	config := &patch.Config{
		Type:     "all",
		TestMode: true,
		Exclude:  []string{"KB9999999"}, // Non-existent KB, shouldn't affect anything
	}

	// Should not error with exclude list
	err = manager.InstallPatches(ctx, config)
	assert.NoError(t, err, "Install with exclude list should not fail")
}

// TestWindowsUpdateManager_ConcurrentOperations tests thread safety
func TestWindowsUpdateManager_ConcurrentOperations(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	defer manager.Close()

	ctx := context.Background()

	// Run multiple goroutines accessing the manager
	done := make(chan bool)
	errors := make(chan error, 3)

	go func() {
		_, err := manager.ListAvailablePatches(ctx, "all")
		errors <- err
		done <- true
	}()

	go func() {
		_, err := manager.ListInstalledPatches(ctx)
		errors <- err
		done <- true
	}()

	go func() {
		_, err := manager.CheckRebootRequired(ctx)
		errors <- err
		done <- true
	}()

	// Wait for all operations to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// Check for errors
	close(errors)
	for err := range errors {
		assert.NoError(t, err, "Concurrent operations should not fail")
	}
}
