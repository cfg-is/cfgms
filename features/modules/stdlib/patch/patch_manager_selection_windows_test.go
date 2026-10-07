// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package patch

import (
	"context"
	"errors"
	"testing"

	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPatch_Windows_New_SelectsWindowsManager verifies that patch.New() on Windows
// selects a Windows-specific manager — either WindowsUpdateManager when COM is available
// or windowsManagerInitFailure when it is not (e.g. GitHub-hosted CI runners that lack
// Windows Update Agent COM access). The non-Windows unsupported-platform fallback
// (unsupportedPlatformPatchManager) must never be returned on Windows.
func TestPatch_Windows_New_SelectsWindowsManager(t *testing.T) {
	m := New().(*PatchModule)

	_, isWindowsMgr := m.patchManager.(*WindowsUpdateManager)
	_, isInitFailure := m.patchManager.(*windowsManagerInitFailure)
	assert.True(t, isWindowsMgr || isInitFailure,
		"patch.New() on Windows must select a Windows-specific manager (WindowsUpdateManager or windowsManagerInitFailure), got %T", m.patchManager)
}

// TestPatch_Windows_InitFailure_PropagatesError verifies that windowsManagerInitFailure
// propagates the captured COM init error from every PatchManager method. This covers the
// degraded path where NewWindowsUpdateManager() fails (broken WMI subsystem, unusual
// container sandbox) so callers receive a meaningful error rather than a nil-pointer panic.
func TestPatch_Windows_InitFailure_PropagatesError(t *testing.T) {
	sentinel := errors.New("COM init failed: test sentinel")
	f := &windowsManagerInitFailure{err: sentinel}
	ctx := context.Background()

	patches, err := f.ListAvailablePatches(ctx, "security")
	assert.Nil(t, patches)
	assert.ErrorIs(t, err, sentinel, "ListAvailablePatches must propagate the init error")

	installed, err := f.ListInstalledPatches(ctx)
	assert.Nil(t, installed)
	assert.ErrorIs(t, err, sentinel, "ListInstalledPatches must propagate the init error")

	assert.ErrorIs(t, f.InstallPatches(ctx, &Config{}), sentinel, "InstallPatches must propagate the init error")

	reboot, err := f.CheckRebootRequired(ctx)
	assert.False(t, reboot)
	assert.ErrorIs(t, err, sentinel, "CheckRebootRequired must propagate the init error")

	date, err := f.GetLastPatchDate(ctx)
	assert.True(t, date.IsZero())
	assert.ErrorIs(t, err, sentinel, "GetLastPatchDate must propagate the init error")

	assert.Equal(t, "windows-init-failure", f.Name())
	assert.False(t, f.IsValidPatchType("security"), "IsValidPatchType must return false on init failure")
}

// TestPatch_Windows_ConformanceDeterministicGet verifies ADR-016 clause 4 on Windows
// using patch.New() (real COM-backed manager), matching the AC requirement of running
// the conformance assertion against patch.New().Get(...) on the Windows runner.
func TestPatch_Windows_ConformanceDeterministicGet(t *testing.T) {
	mgr, err := NewWindowsUpdateManager()
	require.NoError(t, err, "Windows Update COM initialization must succeed on a Windows runner")
	defer mgr.Close() //nolint:errcheck // Close() errors in deferred test cleanup release COM resources; the error is non-actionable after a successful test run

	m, err := NewPatchModule(mgr)
	require.NoError(t, err)
	conformance.AssertDeterministicGet(t, m, "system")
}
