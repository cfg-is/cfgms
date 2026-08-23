//go:build windows
// +build windows

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// This file is an in-package test (package patch, matching the rest of this
// package's tests) because TestWindowsUpdateManager_FilterConfig exercises
// filterUpdates and shouldIncludeUpdate directly. Those are the only code paths
// that decide which patches get installed, and they are unreachable from the
// exported API on a fully patched host — the pending-update search returns an
// empty collection, so InstallPatches never enters the filter loop.
//
// No test here is gated on testing.Short(). The //go:build windows constraint
// already means these tests only compile where COM and the Windows Update Agent
// exist, so there is no environment in which they can build but not run — a
// -short gate would be a speed switch that silently drops every behavioural
// assertion in the file, including the feature-update error contract that is the
// only guard on the unpopulated windowsUpgradeCategoryGUID constant. Skips in
// this package are reserved for genuinely absent infrastructure.
package patch

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestWindowsUpdateManager_New tests creating a new Windows Update manager
func TestWindowsUpdateManager_New(t *testing.T) {
	manager, err := NewWindowsUpdateManager()
	require.NoError(t, err, "Should create Windows Update manager")
	require.NotNil(t, manager, "Manager should not be nil")

	// Cleanup
	err = manager.Close()
	assert.NoError(t, err, "Should close manager cleanly")
}

// TestWindowsUpdateManager_ListAvailablePatches tests listing available patches
func TestWindowsUpdateManager_ListAvailablePatches(t *testing.T) {
	manager, err := NewWindowsUpdateManager()
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
	manager, err := NewWindowsUpdateManager()
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
	manager, err := NewWindowsUpdateManager()
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
	manager, err := NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Check if reboot is required
	rebootRequired, err := manager.CheckRebootRequired(ctx)
	require.NoError(t, err, "Should check reboot status")

	// ISystemInformation.RebootRequired is a side-effect-free read of host state,
	// so a second read within the same test must return the same value. This is a
	// value-level check: it fails if the VT_BOOL VARIANT is decoded inconsistently
	// (e.g. reading the raw Val word rather than the boolean conversion), which a
	// type assertion on a statically-typed bool cannot detect.
	rebootRequiredAgain, err := manager.CheckRebootRequired(ctx)
	require.NoError(t, err, "Should check reboot status on a repeat call")
	assert.Equal(t, rebootRequired, rebootRequiredAgain,
		"Reboot status must be stable across consecutive reads")
}

// TestWindowsUpdateManager_GetLastPatchDate tests getting last patch date
func TestWindowsUpdateManager_GetLastPatchDate(t *testing.T) {
	manager, err := NewWindowsUpdateManager()
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
	manager, err := NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// InstallPatches must return an explicit error, not silently install all software.
	installErr := manager.InstallPatches(ctx, &Config{PatchType: "feature-update"})
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
	manager, err := NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create config in test mode (won't actually install)
	config := &Config{
		PatchType: "security",
		TestMode:  true,
	}

	// This should not fail even if patches are available
	err = manager.InstallPatches(ctx, config)
	assert.NoError(t, err, "Test mode installation should not fail")
}

// TestWindowsUpdateManager_BuildSearchCriteria tests search criteria building
func TestWindowsUpdateManager_BuildSearchCriteria(t *testing.T) {
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
			manager, err := NewWindowsUpdateManager()
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
	manager, err := NewWindowsUpdateManager()
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

	// Re-reading the reboot flag after the rest of the sequence proves the shared
	// COM session came through those calls intact: a stable host property must not
	// change value because ListInstalledPatches or QueryHistory ran on the same
	// session. This is the value-level check the sequence is actually about.
	rebootRequiredAfter, err := manager.CheckRebootRequired(ctx)
	require.NoError(t, err, "Fifth operation should succeed")

	// Basic sanity checks
	assert.NotNil(t, available, "Available patches should not be nil")
	assert.NotNil(t, installed, "Installed patches should not be nil")
	assert.Equal(t, rebootRequired, rebootRequiredAfter,
		"Reboot status must be stable across the operation sequence")
	assert.True(t, lastDate.IsZero() || lastDate.Before(time.Now()),
		"Last date should be valid")
}

// TestWindowsUpdateManager_FilterConfig tests patch filtering with include/exclude.
//
// The filter decision (shouldIncludeUpdate) and the collection walk that applies it
// (filterUpdates) are driven here from inputs that exist on every Windows host,
// never from pending updates: a fully patched CI host has zero pending updates, so
// a test driven by ListAvailablePatches would exercise neither. The "should this
// KB be installed" decision is fed real Microsoft.Update.StringColl collections,
// and the collection walk is fed the host's installed-update collection — real WUA
// COM objects in both cases, no substitutes.
func TestWindowsUpdateManager_FilterConfig(t *testing.T) {
	// This test creates COM objects of its own, and COM initialization is
	// per-thread: pinning the goroutine keeps every CreateObject and IDispatch
	// call below on the thread NewWindowsUpdateManager initialized. For the same
	// reason the cases run in a plain loop rather than t.Run subtests — a subtest
	// runs on a fresh goroutine, which may be scheduled onto an uninitialized
	// thread. Unlock is registered before the manager so it runs after Close().
	runtime.LockOSThread()
	t.Cleanup(runtime.UnlockOSThread)

	manager, err := NewWindowsUpdateManager()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, manager.Close()) })

	// Phase 1: the include/exclude decision itself, over real KB article ID
	// collections built for each case.
	{
		tests := []struct {
			name    string
			kbIDs   []string
			config  *Config
			include bool
		}{
			{
				name:    "update with no KB article IDs is kept",
				kbIDs:   nil,
				config:  &Config{PatchType: "all"},
				include: true,
			},
			{
				name:    "empty include and exclude lists keep everything",
				kbIDs:   []string{"5034123"},
				config:  &Config{PatchType: "all"},
				include: true,
			},
			{
				name:    "excluded KB is dropped",
				kbIDs:   []string{"5034123"},
				config:  &Config{PatchType: "all", ExcludePatches: []string{"KB5034123"}},
				include: false,
			},
			{
				name:    "exclude entry for a different KB keeps the update",
				kbIDs:   []string{"5034123"},
				config:  &Config{PatchType: "all", ExcludePatches: []string{"KB9999999"}},
				include: true,
			},
			{
				name:    "include list admits a listed KB",
				kbIDs:   []string{"5034123"},
				config:  &Config{PatchType: "all", IncludePatches: []string{"KB5034123"}},
				include: true,
			},
			{
				name:    "include list drops an unlisted KB",
				kbIDs:   []string{"5034123"},
				config:  &Config{PatchType: "all", IncludePatches: []string{"KB9999999"}},
				include: false,
			},
			{
				name:  "exclude wins over include for the same KB",
				kbIDs: []string{"5034123"},
				config: &Config{
					PatchType:      "all",
					IncludePatches: []string{"KB5034123"},
					ExcludePatches: []string{"KB5034123"},
				},
				include: false,
			},
		}

		for _, tt := range tests {
			kbArticleIDs := newKBArticleIDCollection(t, tt.kbIDs)

			assert.Equal(t, tt.include, manager.shouldIncludeUpdate(kbArticleIDs, tt.config),
				"filter decision for case %q (KB article IDs %v)", tt.name, tt.kbIDs)
		}
	}

	// Phase 2: the collection walk that applies that decision, over the host's
	// own installed-update collection.
	{
		updates := installedUpdatesCollection(t, manager)
		total := updateCollectionCount(t, updates)
		require.Greater(t, total, 0, "Every Windows host has installed updates to filter")

		// Read each update's KB article ID straight off the COM objects. This is an
		// oracle independent of the filter under test, so the expected counts below
		// are exact rather than "fewer than before".
		kbIDs := kbArticleIDPerUpdate(t, updates, total)

		var targetKB string
		for _, kbID := range kbIDs {
			if kbID != "" {
				targetKB = kbID
				break
			}
		}
		require.NotEmpty(t, targetKB, "Expected at least one installed update with a KB article ID")

		carryingTarget, carryingNoKB := 0, 0
		for _, kbID := range kbIDs {
			switch kbID {
			case targetKB:
				carryingTarget++
			case "":
				carryingNoKB++
			}
		}

		unfiltered := filterAndCount(t, manager, updates, &Config{PatchType: "all"})
		assert.Equal(t, total, unfiltered,
			"An empty include/exclude config must pass every update through")

		excluded := filterAndCount(t, manager, updates,
			&Config{PatchType: "all", ExcludePatches: []string{targetKB}})
		assert.Equal(t, total-carryingTarget, excluded,
			"Excluding %s must drop exactly the %d update(s) carrying it", targetKB, carryingTarget)

		// Updates with no KB article ID are kept by design, include list or not.
		included := filterAndCount(t, manager, updates,
			&Config{PatchType: "all", IncludePatches: []string{targetKB}})
		assert.Equal(t, carryingTarget+carryingNoKB, included,
			"An include list naming only %s must keep exactly the updates carrying it "+
				"plus the %d update(s) with no KB article ID", targetKB, carryingNoKB)
	}
}

// newKBArticleIDCollection builds a real WUA IStringCollection holding the given KB
// article IDs, in the same shape IUpdate.KBArticleIDs returns them (bare digits, no
// "KB" prefix). Microsoft.Update.StringColl is a creatable WUA class, so this is the
// production COM type rather than a substitute for it.
func newKBArticleIDCollection(t *testing.T, kbIDs []string) *ole.IDispatch {
	t.Helper()

	unknown, err := oleutil.CreateObject("Microsoft.Update.StringColl")
	require.NoError(t, err, "Should create a WUA string collection")

	collection, err := unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	require.NoError(t, err, "Should query dispatch interface for the string collection")
	t.Cleanup(func() { collection.Release() })

	for _, kbID := range kbIDs {
		result, err := oleutil.CallMethod(collection, "Add", kbID)
		require.NoError(t, err, "Should add KB article ID %q", kbID)
		require.NoError(t, result.Clear())
	}

	return collection
}

// installedUpdatesCollection returns the IUpdateCollection of updates already
// installed on this host. Unlike a search for pending updates, this is non-empty on
// every Windows machine, including a fully patched CI runner.
func installedUpdatesCollection(t *testing.T, manager *WindowsUpdateManager) *ole.IDispatch {
	t.Helper()

	searcher, err := oleutil.CallMethod(manager.session, "CreateUpdateSearcher")
	require.NoError(t, err, "Should create update searcher")
	t.Cleanup(func() { require.NoError(t, searcher.Clear()) })

	searchResult, err := oleutil.CallMethod(searcher.ToIDispatch(), "Search", "IsInstalled=1")
	require.NoError(t, err, "Should search for installed updates")
	t.Cleanup(func() { require.NoError(t, searchResult.Clear()) })

	updates, err := oleutil.GetProperty(searchResult.ToIDispatch(), "Updates")
	require.NoError(t, err, "Should get updates collection")
	t.Cleanup(func() { require.NoError(t, updates.Clear()) })

	return updates.ToIDispatch()
}

// kbArticleIDPerUpdate returns, for each update in the collection, its first KB
// article ID in the "KB<digits>" form the include/exclude lists use, or "" when the
// update carries none.
func kbArticleIDPerUpdate(t *testing.T, collection *ole.IDispatch, count int) []string {
	t.Helper()

	kbIDs := make([]string, 0, count)
	for i := 0; i < count; i++ {
		updateVariant, err := oleutil.GetProperty(collection, "Item", i)
		require.NoError(t, err, "Should read update %d from the collection", i)

		// ToIDispatch does not AddRef, so the interface is released once here and
		// the VARIANT is deliberately not cleared — clearing it as well would be a
		// double release.
		update := updateVariant.ToIDispatch()
		kbIDs = append(kbIDs, firstKBArticleID(t, update))
		update.Release()
	}

	return kbIDs
}

// firstKBArticleID reads one update's first KB article ID. WUA returns the IDs as
// bare digits in a BSTR IStringCollection, so the value comes from Value() (the
// BSTR conversion) and the "KB" prefix is added here.
func firstKBArticleID(t *testing.T, update *ole.IDispatch) string {
	t.Helper()

	kbVariant, err := oleutil.GetProperty(update, "KBArticleIDs")
	require.NoError(t, err, "Should read KBArticleIDs")
	kbArticleIDs := kbVariant.ToIDispatch()
	defer kbArticleIDs.Release()

	countVariant, err := oleutil.GetProperty(kbArticleIDs, "Count")
	require.NoError(t, err, "Should read the KB article ID count")
	if int(countVariant.Val) == 0 {
		return ""
	}

	idVariant, err := oleutil.GetProperty(kbArticleIDs, "Item", 0)
	require.NoError(t, err, "Should read the first KB article ID")
	defer func() { require.NoError(t, idVariant.Clear()) }()

	kbArticleID, ok := idVariant.Value().(string)
	require.True(t, ok, "KB article ID should be a string")

	return "KB" + kbArticleID
}

// updateCollectionCount reads the Count property of a WUA update collection.
func updateCollectionCount(t *testing.T, collection *ole.IDispatch) int {
	t.Helper()

	countVariant, err := oleutil.GetProperty(collection, "Count")
	require.NoError(t, err, "Should get collection count")
	t.Cleanup(func() { require.NoError(t, countVariant.Clear()) })

	return int(countVariant.Val)
}

// filterAndCount runs filterUpdates over the given collection and returns how many
// updates survived the config's include/exclude lists.
func filterAndCount(t *testing.T, manager *WindowsUpdateManager, updates *ole.IDispatch, config *Config) int {
	t.Helper()

	filtered, err := manager.filterUpdates(updates, config)
	require.NoError(t, err, "filterUpdates should not fail")
	defer filtered.Release()

	return updateCollectionCount(t, filtered)
}

// TestWindowsUpdateManager_ConcurrentOperations tests thread safety
func TestWindowsUpdateManager_ConcurrentOperations(t *testing.T) {
	manager, err := NewWindowsUpdateManager()
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
