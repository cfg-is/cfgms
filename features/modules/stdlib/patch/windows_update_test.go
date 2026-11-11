//go:build windows
// +build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package patch_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/modules/stdlib/patch"
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
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	// Use a timeout context to avoid hanging on slow Windows Update responses
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

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
		assert.False(t, p.ReleaseDate.IsZero(), "Release date should be set")
	}
}

// TestWindowsUpdateManager_CheckRebootRequired tests reboot status check
func TestWindowsUpdateManager_CheckRebootRequired(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if reboot is required
	rebootRequired, err := manager.CheckRebootRequired(ctx)
	require.NoError(t, err, "Should check reboot status")

	// Result should be a boolean (true or false)
	assert.IsType(t, false, rebootRequired, "Should return boolean")
}

// TestWindowsUpdateManager_GetLastPatchDate tests getting last patch date
func TestWindowsUpdateManager_GetLastPatchDate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get last patch date
	lastDate, err := manager.GetLastPatchDate(ctx)
	require.NoError(t, err, "Should get last patch date")

	// On any Windows system that's been patched, this should not be zero
	// Allow zero time for systems that have never been patched (unlikely but possible)
	assert.True(t, lastDate.IsZero() || lastDate.Before(time.Now()),
		"Last patch date should be in the past or zero")
}

// TestWindowsUpdateManager_FeatureUpdate_ReturnsExplicitError documents the failure contract:
// InstallPatches and ListAvailablePatches with "feature-update" must return an explicit,
// descriptive error (not silently fall through to "install all software") until
// windowsUpgradeCategoryGUID is populated from a confirmed Microsoft source.
func TestWindowsUpdateManager_FeatureUpdate_ReturnsExplicitError(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// InstallPatches must return an explicit error, not silently install all software.
	installErr := manager.InstallPatches(ctx, &patch.Config{PatchType: "feature-update"})
	require.Error(t, installErr,
		"InstallPatches with feature-update must return an error until windowsUpgradeCategoryGUID is confirmed")
	assert.Contains(t, installErr.Error(), "not supported by this implementation",
		"error must be descriptive, not a generic WUA failure")

	// ListAvailablePatches must similarly return an explicit error.
	_, listErr := manager.ListAvailablePatches(ctx, "feature-update")
	require.Error(t, listErr,
		"ListAvailablePatches with feature-update must return an error until windowsUpgradeCategoryGUID is confirmed")
	assert.Contains(t, listErr.Error(), "not supported by this implementation",
		"error must be descriptive, not a generic WUA failure")
}

// TestWindowsUpdateManager_InstallPatches_TestMode tests patch installation in test mode
func TestWindowsUpdateManager_InstallPatches_TestMode(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create config in test mode (won't actually install)
	config := &patch.Config{
		PatchType: "security",
		TestMode:  true,
	}

	// This should not fail even if patches are available
	err = manager.InstallPatches(ctx, config)
	assert.NoError(t, err, "Test mode installation should not fail")
}

// TestWindowsUpdateManager_BuildSearchCriteria tests search criteria building
func TestWindowsUpdateManager_BuildSearchCriteria(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	// This tests the internal search criteria logic indirectly via ListAvailablePatches.

	tests := []struct {
		name          string
		patchType     string
		expectError   bool
		errorContains string
	}{
		{"All patches", "all", false, ""},
		{"Security only", "security", false, ""},
		{"Critical only", "critical", false, ""},
		{"Optional updates", "optional", false, ""},
		// feature-update always returns an error until windowsUpgradeCategoryGUID is confirmed.
		{"Feature update", "feature-update", true, "not supported by this implementation"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := patch.NewWindowsUpdateManager()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, manager.Close()) })

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			patches, err := manager.ListAvailablePatches(ctx, tt.patchType)

			if tt.expectError {
				require.Error(t, err, "patch type %q must return an error", tt.patchType)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
				return
			}

			assert.NoError(t, err, "Should list patches for type: %s", tt.patchType)
			if err != nil {
				return
			}
			// We don't assert length > 0 because the system might be fully patched.
			assert.NotNil(t, patches, "Patches list should not be nil for type: %s", tt.patchType)
		})
	}
}

// TestWindowsUpdateManager_MultipleOperations tests using the manager for multiple operations
func TestWindowsUpdateManager_MultipleOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Get all available patches first
	allPatches, err := manager.ListAvailablePatches(ctx, "all")
	require.NoError(t, err)

	if len(allPatches) == 0 {
		t.Skip("No patches available to test filtering")
	}

	// Create config with exclude pattern
	config := &patch.Config{
		PatchType:      "all",
		TestMode:       true,
		ExcludePatches: []string{"KB9999999"}, // Non-existent KB, shouldn't affect anything
	}

	// Should not error with exclude list
	err = manager.InstallPatches(ctx, config)
	assert.NoError(t, err, "Install with exclude list should not fail")
}

// TestWindowsUpdateManager_ConcurrentOperations tests thread safety
func TestWindowsUpdateManager_ConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Windows Update test in short mode")
	}

	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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

// TestWindowsUpdateManager_ListInstalledPatches_HonoursContext verifies that the
// installed-update search is bounded by the caller's context: an already-cancelled
// context and an already-elapsed deadline each surface as an error wrapping the
// context error instead of being ignored.
func TestWindowsUpdateManager_ListInstalledPatches_HonoursContext(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	const bound = 30 * time.Second

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		patches, err := manager.ListInstalledPatches(ctx)
		require.Error(t, err, "cancelled context must fail the search")
		assert.True(t, errors.Is(err, context.Canceled), "error must wrap context.Canceled, got: %v", err)
		assert.Nil(t, patches)
		assert.Less(t, time.Since(start), bound)
	})

	t.Run("elapsed deadline", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()

		start := time.Now()
		patches, err := manager.ListInstalledPatches(ctx)
		require.Error(t, err, "elapsed deadline must fail the search")
		assert.True(t, errors.Is(err, context.DeadlineExceeded), "error must wrap context.DeadlineExceeded, got: %v", err)
		assert.Nil(t, patches)
		assert.Less(t, time.Since(start), bound)
	})
}

// TestWindowsUpdateManager_ListAvailablePatches_HonoursContext verifies the
// available-updates search is bounded by the caller's context.
func TestWindowsUpdateManager_ListAvailablePatches_HonoursContext(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	patches, err := manager.ListAvailablePatches(ctx, "all")
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "error must wrap context.Canceled, got: %v", err)
	assert.Nil(t, patches)
}

// TestWindowsUpdateManager_InstallPatches_HonoursContext verifies the search
// phase of InstallPatches is bounded by the caller's context.
func TestWindowsUpdateManager_InstallPatches_HonoursContext(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = manager.InstallPatches(ctx, &patch.Config{PatchType: "all", TestMode: true})
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "error must wrap context.Canceled, got: %v", err)
}

// TestWindowsUpdateManager_GetLastPatchDate_HonoursContext verifies the history
// query refuses to start on an already-cancelled context.
func TestWindowsUpdateManager_GetLastPatchDate_HonoursContext(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = manager.GetLastPatchDate(ctx)
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.Canceled), "error must wrap context.Canceled, got: %v", err)
}

// TestWindowsUpdateManager_Search_AcceptsCompletionCallback runs real searches to
// completion. BeginSearch rejects a null completion callback (VT_NULL fails with
// a type mismatch, a null dispatch with an exception), so a successful offline
// and online search proves the in-process callback object is accepted and the
// job completes.
func TestWindowsUpdateManager_Search_AcceptsCompletionCallback(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	installed, err := manager.ListInstalledPatches(ctx)
	require.NoError(t, err, "offline installed-update search must complete")
	assert.NotNil(t, installed)

	available, err := manager.ListAvailablePatches(ctx, "all")
	require.NoError(t, err, "online available-update search must complete")
	assert.NotNil(t, available)
}

// TestWindowsUpdateManager_ListInstalledPatches_DeadlineDuringSearch gives a
// running search a deadline that expires while it is in flight. The search either
// finishes first or is aborted; an abort must surface as an error wrapping
// context.DeadlineExceeded and return promptly, never block.
func TestWindowsUpdateManager_ListInstalledPatches_DeadlineDuringSearch(t *testing.T) {
	manager, err := patch.NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = manager.ListInstalledPatches(ctx)
	if err != nil {
		assert.True(t, errors.Is(err, context.DeadlineExceeded), "error must wrap context.DeadlineExceeded, got: %v", err)
	}
	assert.Less(t, time.Since(start), 30*time.Second, "search must return promptly after the deadline")
}
