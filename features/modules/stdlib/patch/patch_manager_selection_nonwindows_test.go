// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package patch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPatch_NonWindows_New_SelectsUnsupportedPlatformManager verifies that patch.New()
// on non-Windows systems constructs a module backed by the unsupported-platform fallback
// (Name() returns "stub"), not a real backend. Real non-Windows patch managers (apt/yum/
// softwareupdate) are explicitly out of scope per ADR-016 PM Notes.
func TestPatch_NonWindows_New_SelectsUnsupportedPlatformManager(t *testing.T) {
	m := New().(*PatchModule)

	assert.Equal(t, "stub", m.patchManager.Name(),
		"patch.New() on non-Windows must select the unsupported-platform manager (Name()='stub')")
}
