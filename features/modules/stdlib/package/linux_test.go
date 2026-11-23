// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package package_module

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

func TestInstallArgs_PinnedVersionIsOneArgv(t *testing.T) {
	tests := []struct {
		name    string
		build   func(name, version string, downgrade bool) []string
		version string
		want    []string
	}{
		{"apt latest", aptInstallArgs, "latest", []string{"install", "-y", "--", "curl"}},
		{"apt pinned", aptInstallArgs, "7.88.1-10", []string{"install", "-y", "--", "curl=7.88.1-10"}},
		{"apt pinned epoch", aptInstallArgs, "1:2.3-1", []string{"install", "-y", "--", "curl=1:2.3-1"}},
		{"dnf latest", dnfInstallArgs, "latest", []string{"install", "-y", "--", "curl"}},
		{"dnf pinned", dnfInstallArgs, "7.76.1", []string{"install", "-y", "--", "curl-7.76.1"}},
		{"yum latest", yumInstallArgs, "latest", []string{"install", "-y", "--", "curl"}},
		{"yum pinned", yumInstallArgs, "7.76.1", []string{"install", "-y", "--", "curl-7.76.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.build("curl", tt.version, false))
		})
	}
}

// TestInstallArgs_DowngradeDecision asserts the exact argv each manager runs
// for an absent package, an older installed version, a newer installed version
// (downgrade) and "latest" with a newer installed version (never a downgrade).
func TestInstallArgs_DowngradeDecision(t *testing.T) {
	type manager struct {
		name    string
		compare func(a, b string) (int, error)
		build   func(name, version string, downgrade bool) []string
	}
	apt := manager{"apt", compareDebianVersions, aptInstallArgs}
	dnf := manager{"dnf", compareRPMVersions, dnfInstallArgs}
	yum := manager{"yum", compareRPMVersions, yumInstallArgs}

	tests := []struct {
		name         string
		mgr          manager
		installed    string
		installedErr error
		declared     string
		want         []string
	}{
		{"apt absent", apt, "", ErrPackageNotFound, "8.7.1-1", []string{"install", "-y", "--", "nano=8.7.1-1"}},
		{"apt installed older", apt, "8.7.0-1", nil, "8.7.1-1", []string{"install", "-y", "--", "nano=8.7.1-1"}},
		{"apt installed equal", apt, "8.7.1-1", nil, "8.7.1-1", []string{"install", "-y", "--", "nano=8.7.1-1"}},
		{"apt installed newer", apt, "8.7.1-1ubuntu0.1", nil, "8.7.1-1",
			[]string{"install", "-y", "--allow-downgrades", "--", "nano=8.7.1-1"}},
		{"apt latest newer installed", apt, "8.7.1-1ubuntu0.1", nil, "latest", []string{"install", "-y", "--", "nano"}},
		{"apt unparseable installed", apt, "x:1", nil, "8.7.1-1", []string{"install", "-y", "--", "nano=8.7.1-1"}},
		{"apt query error", apt, "", errors.New("boom"), "8.7.1-1", []string{"install", "-y", "--", "nano=8.7.1-1"}},

		{"dnf absent", dnf, "", ErrPackageNotFound, "7.76.1", []string{"install", "-y", "--", "nano-7.76.1"}},
		{"dnf installed older", dnf, "7.9", nil, "7.76.1", []string{"install", "-y", "--", "nano-7.76.1"}},
		{"dnf installed equal", dnf, "7.76.1", nil, "7.76.1", []string{"install", "-y", "--", "nano-7.76.1"}},
		{"dnf installed newer", dnf, "7.81.0", nil, "7.76.1", []string{"downgrade", "-y", "--", "nano-7.76.1"}},
		{"dnf latest newer installed", dnf, "7.81.0", nil, "latest", []string{"install", "-y", "--", "nano"}},

		{"yum absent", yum, "", ErrPackageNotFound, "7.76.1", []string{"install", "-y", "--", "nano-7.76.1"}},
		{"yum installed older", yum, "7.9", nil, "7.76.1", []string{"install", "-y", "--", "nano-7.76.1"}},
		{"yum installed newer", yum, "7.81.0", nil, "7.76.1", []string{"downgrade", "-y", "--", "nano-7.76.1"}},
		{"yum latest newer installed", yum, "7.81.0", nil, "latest", []string{"install", "-y", "--", "nano"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			downgrade := downgradeNeeded(tt.installed, tt.installedErr, tt.declared, tt.mgr.compare)
			got := tt.mgr.build("nano", tt.declared, downgrade)
			assert.Equal(t, tt.want, got)
			for _, a := range got {
				if a != "--allow-downgrades" {
					assert.NotContains(t, a, "--allow-", "no other --allow-* option may be added")
				}
			}
		})
	}
}

func TestAptSimulateArgs(t *testing.T) {
	assert.Equal(t,
		[]string{"install", "-s", "-y", "--allow-downgrades", "--", "nano=8.7.1-1"},
		aptSimulateArgs("nano", "8.7.1-1"))
}

func TestCheckAptDowngradeSimulation(t *testing.T) {
	t.Run("only the declared package passes", func(t *testing.T) {
		out := "Reading package lists...\n" +
			"The following packages will be DOWNGRADED:\n  nano\n" +
			"Inst nano [8.7.1-1ubuntu0.1] (8.7.1-1 Ubuntu:26.04/resolute [amd64])\n" +
			"Conf nano (8.7.1-1 Ubuntu:26.04/resolute [amd64])\n"
		assert.NoError(t, checkAptDowngradeSimulation("nano", "8.7.1-1", out))
	})

	t.Run("remove of the declared package passes", func(t *testing.T) {
		out := "Remv nano [8.7.1-1ubuntu0.1]\nInst nano (8.7.1-1 Ubuntu [amd64])\n"
		assert.NoError(t, checkAptDowngradeSimulation("nano", "8.7.1-1", out))
	})

	t.Run("a lockstep library fails with a clear error", func(t *testing.T) {
		out := "Inst libjq1 [1.8.1-4] (1.8.0-1 Ubuntu [amd64])\n" +
			"Inst jq [1.8.1-4] (1.8.0-1 Ubuntu [amd64])\n" +
			"Conf libjq1 (1.8.0-1 Ubuntu [amd64])\nConf jq (1.8.0-1 Ubuntu [amd64])\n"
		err := checkAptDowngradeSimulation("jq", "1.8.0-1", out)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrDowngradeNeedsDependency)
		assert.Contains(t, err.Error(), "apt")
		assert.Contains(t, err.Error(), "jq")
		assert.Contains(t, err.Error(), "libjq1")
		assert.Contains(t, err.Error(), "declare the dependency at a matching version")
	})

	t.Run("a removal of another package fails", func(t *testing.T) {
		err := checkAptDowngradeSimulation("nano", "8.7.1-1", "Remv other-pkg [1.0]\nInst nano (8.7.1-1 x [amd64])\n")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "other-pkg")
	})
}

// TestAptInstall_DowngradeGuard drives the real
// aptManager.Install with fixed fake dpkg-query/apt-get executables on PATH
// (shell scripts written to a temp dir) to prove that a failing or
// dependency-changing dry run stops before the real install.
func TestAptInstall_DowngradeGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell-script stand-ins for dpkg-query/apt-get cannot run on Windows; the argv and parser logic is covered by the table tests")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "apt.log")
	write := func(name, body string) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body), 0o700)) // #nosec G306 -- test stand-in in t.TempDir
	}
	write("dpkg-query", "printf '%s' \"$FAKE_INSTALLED\"\n")
	write("apt-get", "echo \"$*\" >> \""+log+"\"\n"+
		"case \"$*\" in *' -s '*) printf '%s\\n' \"$FAKE_SIM_OUT\"; exit \"${FAKE_SIM_RC:-0}\";; esac\nexit 0\n")
	t.Setenv("PATH", dir)
	t.Setenv("FAKE_INSTALLED", "2.0-1")
	ctx := context.Background()
	readLog := func() string {
		b, _ := os.ReadFile(log) // #nosec G304 -- test-owned temp path
		return string(b)
	}

	t.Run("guard pass runs the real downgrade", func(t *testing.T) {
		_ = os.Remove(log)
		t.Setenv("FAKE_SIM_OUT", "Inst pkg [2.0-1] (1.0-1 x [amd64])")
		require.NoError(t, (&aptManager{}).Install(ctx, "pkg", "1.0-1"))
		assert.Equal(t, "install -s -y --allow-downgrades -- pkg=1.0-1\ninstall -y --allow-downgrades -- pkg=1.0-1\n", readLog())
	})

	t.Run("other package in simulation blocks the install", func(t *testing.T) {
		_ = os.Remove(log)
		t.Setenv("FAKE_SIM_OUT", "Inst lib [2.0-1] (1.0-1 x [amd64])\nInst pkg [2.0-1] (1.0-1 x [amd64])")
		err := (&aptManager{}).Install(ctx, "pkg", "1.0-1")
		require.ErrorIs(t, err, ErrDowngradeNeedsDependency)
		assert.Equal(t, "install -s -y --allow-downgrades -- pkg=1.0-1\n", readLog(), "no real install may run")
	})

	t.Run("failed simulation blocks the install and names the provider", func(t *testing.T) {
		_ = os.Remove(log)
		t.Setenv("FAKE_SIM_OUT", "E: Unable to correct problems, you have held broken packages.")
		t.Setenv("FAKE_SIM_RC", "100")
		err := (&aptManager{}).Install(ctx, "pkg", "1.0-1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "apt")
		assert.Contains(t, err.Error(), "pkg")
		assert.Contains(t, err.Error(), "declare the dependency at a matching version")
		assert.Contains(t, err.Error(), "held broken packages")
		assert.Equal(t, "install -s -y --allow-downgrades -- pkg=1.0-1\n", readLog())
	})

	t.Run("equal or older installed version skips the simulation", func(t *testing.T) {
		_ = os.Remove(log)
		t.Setenv("FAKE_INSTALLED", "1.0-1")
		require.NoError(t, (&aptManager{}).Install(ctx, "pkg", "1.0-1"))
		assert.Equal(t, "install -y -- pkg=1.0-1\n", readLog())
	})
}

func TestAptCommand_NonInteractiveEnvKeepsBaseline(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")
	cmd := aptCommand(context.Background(), aptInstallArgs("curl", "7.88.1-10", false)...)
	assert.Contains(t, cmd.Env, "DEBIAN_FRONTEND=noninteractive")
	var hasPath bool
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "PATH=") {
			hasPath = true
		}
	}
	assert.True(t, hasPath, "apt command env must keep the baseline PATH")
	assert.Equal(t, []string{"apt-get", "install", "-y", "--", "curl=7.88.1-10"}, cmd.Args)

	rm := aptCommand(context.Background(), "remove", "-y", "--", "curl")
	assert.Contains(t, rm.Env, "DEBIAN_FRONTEND=noninteractive")
}

func TestInstall_PinUnsupportedProviders(t *testing.T) {
	// An empty PATH means any attempt to start pacman/brew fails with a
	// lookup error, so ErrVersionPinUnsupported proves no command was started.
	t.Setenv("PATH", t.TempDir())
	ctx := context.Background()

	err := (&pacmanManager{}).Install(ctx, "x", "1.0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVersionPinUnsupported)
	assert.Contains(t, err.Error(), "pacman")

	err = (&homebrewManager{}).Install(ctx, "x", "1.0")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVersionPinUnsupported)
	assert.Contains(t, err.Error(), "brew")

	// latest is not rejected as a pin: it reaches exec and fails on lookup.
	err = (&pacmanManager{}).Install(ctx, "x", "latest")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVersionPinUnsupported)
	err = (&homebrewManager{}).Install(ctx, "x", "latest")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrVersionPinUnsupported)
}
