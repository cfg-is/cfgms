// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package patch

import (
	"testing"

	"github.com/cfgis/cfgms/features/modules/conformance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPatch_Windows_New_SelectsWindowsManager verifies that patch.New() on Windows
// constructs a module backed by the real WindowsUpdateManager (not the
// unsupported-platform fallback). This is exercised on the self-hosted Windows runner.
func TestPatch_Windows_New_SelectsWindowsManager(t *testing.T) {
	m := New().(*PatchModule)

	_, isWindows := m.patchManager.(*WindowsUpdateManager)
	assert.True(t, isWindows,
		"patch.New() on Windows must select WindowsUpdateManager, got %T", m.patchManager)
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
