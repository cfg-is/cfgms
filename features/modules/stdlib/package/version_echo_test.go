// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPackageModule_VersionLatestEcho_NoDrift verifies that an installed package
// declared as `version: latest` (update off) reports "latest" on Get rather than
// the concrete installed version — so it does not drift forever ("latest" never
// equals a concrete version). A pinned concrete version is reported as-is so a
// real mismatch still drifts and triggers install/upgrade.
func TestPackageModule_VersionLatestEcho_NoDrift(t *testing.T) {
	mgr := newTestPackageManagerNamed("winget")
	mgr.installed["7zip.7zip"] = "26.02" // already installed at a concrete version
	m, err := NewPackageModule(mgr)
	require.NoError(t, err)

	// version: latest, update off → echo "latest" (compliant, no drift).
	require.NoError(t, m.Configure(&Config{Name: "7zip.7zip", State: "present", Version: "latest"}))
	got, err := m.Get(context.Background(), "7zip.7zip")
	require.NoError(t, err)
	cfg := got.(*Config)
	assert.Equal(t, "present", cfg.State)
	assert.Equal(t, "latest", cfg.Version,
		"an installed unpinned (version: latest) package must echo latest, not the concrete version")

	// Pinned concrete version → report the actual installed version so a mismatch drifts.
	require.NoError(t, m.Configure(&Config{Name: "7zip.7zip", State: "present", Version: "26.02"}))
	got2, err := m.Get(context.Background(), "7zip.7zip")
	require.NoError(t, err)
	assert.Equal(t, "26.02", got2.(*Config).Version,
		"a pinned concrete version reports the actual installed version")

	// version: latest WITH update on → report the concrete version (update mode
	// re-checks against latest; not echoed as compliant).
	require.NoError(t, m.Configure(&Config{Name: "7zip.7zip", State: "present", Version: "latest", Update: true}))
	got3, err := m.Get(context.Background(), "7zip.7zip")
	require.NoError(t, err)
	assert.Equal(t, "26.02", got3.(*Config).Version,
		"with update: true, the concrete version is reported (update mode is not drift-free)")
}
