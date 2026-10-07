// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests exercise the real OS package-manager implementations in linux.go
// (command invocation, output parsing, and the ErrPackageNotFound mapping that
// PackageModule.Get relies on to distinguish an absent package from a genuine
// error). They invoke the actual read-only query binaries (dpkg-query, rpm,
// pacman) — never install/remove — so they are safe to run unprivileged.
//
// When the relevant binary is not present the test is skipped with an
// infrastructure-unavailability justification: the corresponding manager can
// only be validated against its native tooling, which lives on the matching
// distro CI runner (Debian/Ubuntu, Fedora/RHEL, Arch). Skipping is limited to
// this genuine environment gap; the output-detection logic itself is covered
// distro-independently by TestLinux_NotFoundDetectionHelpers.

// requireBinary skips the test with a clear infrastructure-unavailability
// justification when the named package-manager binary is absent.
func requireBinary(t *testing.T, bin, manager string) {
	t.Helper()
	if _, err := exec.LookPath(bin); err != nil {
		t.Skipf("%s not found on PATH: the %s package manager is not installed on this host; "+
			"its command invocation and error mapping can only be validated on a %s runner", bin, manager, manager)
	}
}

func TestAptManager_GetInstalledVersion(t *testing.T) {
	requireBinary(t, "dpkg-query", "apt")
	m := newAptManager()
	ctx := context.Background()

	t.Run("absent package returns ErrPackageNotFound", func(t *testing.T) {
		_, err := m.GetInstalledVersion(ctx, "cfgms-definitely-not-installed-xyz")
		require.ErrorIs(t, err, ErrPackageNotFound,
			"querying an uninstalled package must map dpkg-query's non-zero exit to ErrPackageNotFound "+
				"so PackageModule.Get reports state=absent, not an error")
	})

	t.Run("installed package returns a version", func(t *testing.T) {
		// dpkg is always installed on a dpkg-managed system.
		ver, err := m.GetInstalledVersion(ctx, "dpkg")
		require.NoError(t, err)
		assert.NotEmpty(t, ver, "installed package must report a non-empty version")
	})
}

func TestDnfManager_GetInstalledVersion(t *testing.T) {
	requireBinary(t, "rpm", "dnf")
	m := newDnfManager()
	ctx := context.Background()

	t.Run("absent package returns ErrPackageNotFound", func(t *testing.T) {
		_, err := m.GetInstalledVersion(ctx, "cfgms-definitely-not-installed-xyz")
		require.ErrorIs(t, err, ErrPackageNotFound,
			"rpm -q on an uninstalled package exits non-zero; the error must map to ErrPackageNotFound")
	})
}

func TestYumManager_GetInstalledVersion(t *testing.T) {
	requireBinary(t, "rpm", "yum")
	m := newYumManager()
	ctx := context.Background()

	t.Run("absent package returns ErrPackageNotFound", func(t *testing.T) {
		_, err := m.GetInstalledVersion(ctx, "cfgms-definitely-not-installed-xyz")
		require.ErrorIs(t, err, ErrPackageNotFound,
			"rpm -q on an uninstalled package exits non-zero; the error must map to ErrPackageNotFound")
	})
}

func TestPacmanManager_GetInstalledVersion(t *testing.T) {
	requireBinary(t, "pacman", "pacman")
	m := newPacmanManager()
	ctx := context.Background()

	t.Run("absent package returns ErrPackageNotFound", func(t *testing.T) {
		_, err := m.GetInstalledVersion(ctx, "cfgms-definitely-not-installed-xyz")
		require.ErrorIs(t, err, ErrPackageNotFound,
			"pacman -Q on an uninstalled package exits non-zero; the error must map to ErrPackageNotFound")
	})

	t.Run("installed package version is parsed from pacman -Q output", func(t *testing.T) {
		// pacman itself is always installed on an Arch system; exercises the
		// strings.Fields parse of "pacman <version>".
		ver, err := m.GetInstalledVersion(ctx, "pacman")
		require.NoError(t, err)
		assert.NotEmpty(t, ver, "installed package must report a non-empty version parsed from pacman output")
	})
}

// TestLinuxManagers_RejectLeadingDashName is a defense-in-depth check that the
// argument-injection guard is enforced at the module boundary regardless of
// which Linux manager is active: a name beginning with '-' must never reach the
// exec argv of a root-run package manager.
func TestLinuxManagers_RejectLeadingDashName(t *testing.T) {
	require.ErrorIs(t, validatePackageName("--allow-unauthenticated"), ErrInvalidPackageName)
}
