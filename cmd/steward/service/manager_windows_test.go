// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/windows/registry"
)

func TestWindowsManagerInstallPath(t *testing.T) {
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	// Launcher-managed install: the service's exec target is the launcher,
	// so that is the install path Status reports (mirrors linuxLauncherPath).
	assert.Equal(t, windowsLauncherPath, status.InstallPath)
}

func TestWindowsManagerStatusNotInstalled(t *testing.T) {
	// Status must work without Administrator privileges.
	// When the service is not registered it must be reported as not installed.
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsServiceName, status.ServiceName)
	assert.Equal(t, windowsLauncherPath, status.InstallPath)
}

func TestWindowsManagerInstallRequiresElevation(t *testing.T) {
	// Stage a launcher stub next to the steward path so the pre-elevation
	// bundle check passes and Install reaches the elevation gate.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, windowsLauncherBinaryName), []byte("stub"), 0o600))
	m := New(filepath.Join(dir, "cfgms-steward.exe"))
	if m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

// TestWindowsInstallFingerprintMismatch verifies that a mismatched CA fingerprint causes
// Install to return an error before writing the cert or registering the service.
// Runs without Administrator because fingerprint verification is checked before the elevation gate.
func TestWindowsInstallFingerprintMismatch(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping — running as Administrator would proceed past fingerprint check to service ops")
	}
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, _ := generateTestCACert(t)
	err := m.Install("tok_test123", "", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := platformCACertPath()
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestWindowsInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0444 when a correct fingerprint is provided (ADR-013 §3).
func TestWindowsInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, fingerprint := generateTestCACert(t)

	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	destPath := platformCACertPath()
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0444), info.Mode().Perm(), "CA cert must be written with mode 0444 per ADR-013 §3")
}

func TestWindowsManagerUninstallRequiresElevation(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

func TestWindowsManagerNew(t *testing.T) {
	m := New("cfgms-steward.exe")
	require.NotNil(t, m)
	_, ok := m.(*windowsManager)
	assert.True(t, ok, "New() should return a *windowsManager on Windows")
}

// TestSetServiceEnvironmentRoundTrip is the REQUIRED TEST for #2378: the
// registry-write helper round-trips the CFGMS_LOG_DIR Environment value. It
// targets a scratch HKCU key — writing the real HKLM service key requires
// Administrator, which unit tests do not have (the helper's root/keyPath
// parameters exist exactly for this).
func TestSetServiceEnvironmentRoundTrip(t *testing.T) {
	const scratch = `Software\CFGMS-test-svcenv`
	key, _, err := registry.CreateKey(registry.CURRENT_USER, scratch, registry.ALL_ACCESS)
	require.NoError(t, err)
	require.NoError(t, key.Close())
	t.Cleanup(func() { _ = registry.DeleteKey(registry.CURRENT_USER, scratch) })

	logDir := `C:\ProgramData\CFGMS\logs`
	require.NoError(t, setServiceEnvironment(registry.CURRENT_USER, scratch, logDir))

	rk, err := registry.OpenKey(registry.CURRENT_USER, scratch, registry.QUERY_VALUE)
	require.NoError(t, err)
	defer rk.Close()
	vals, valType, err := rk.GetStringsValue("Environment")
	require.NoError(t, err)
	assert.Equal(t, uint32(registry.MULTI_SZ), valType, "Environment must be REG_MULTI_SZ — the only type the SCM accepts")
	assert.Equal(t, []string{
		"CFGMS_LOG_DIR=" + logDir,
		"CFGMS_SECURITY_PROFILE=public-beta",
	}, vals)
}

// TestWindowsLauncherPathParity is the REQUIRED path-parity TEST for #2379:
// windowsLauncherPath must equal the literal path returned by
// features/steward/client's launcherPath() on windows
// (client_transport_upgrade.go) — the compile-time contract push-upgrade
// execs. Drift between install-time and the upgrade runtime path silently
// breaks push-upgrade, so the literal is pinned here.
func TestWindowsLauncherPathParity(t *testing.T) {
	assert.Equal(t, `C:\Program Files\CFGMS\cfgms-steward-launcher.exe`, windowsLauncherPath,
		"windowsLauncherPath must match client_transport_upgrade.go launcherPath() exactly")
	assert.Equal(t, "cfgms-steward-launcher.exe", windowsLauncherBinaryName)
}

// TestWindowsInstallLauncherMissing is the REQUIRED fail-closed TEST for
// #2379: Install must return a clear, actionable error — before any service
// registration — when the launcher binary is not bundled next to the steward
// binary. The check runs before the elevation gate (like fingerprint
// verification), so this asserts an early return without touching privileged
// state.
func TestWindowsInstallLauncherMissing(t *testing.T) {
	dir := t.TempDir() // empty: no launcher next to the (hypothetical) steward binary
	m := New(filepath.Join(dir, "cfgms-steward.exe"))
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), windowsLauncherBinaryName,
		"error must name the missing launcher binary")
	assert.Contains(t, err.Error(), "not found next to the steward binary",
		"error must explain the bundle expectation")
	assert.NotContains(t, err.Error(), "Administrator",
		"launcher presence is checked before the elevation gate")
}

// TestBuildLauncherServiceArgs is the REQUIRED launcher-target TEST for
// #2379: the Windows service must be registered to invoke the launcher
// (`run --root ... --child-args "..."`), never the bare steward binary —
// mirrors TestGenerateSystemdUnit's assertions for Linux.
func TestBuildLauncherServiceArgs(t *testing.T) {
	token := "tok_svc_args_abc123"

	args := buildLauncherServiceArgs(windowsInstallDir, token, "")
	assert.Equal(t, []string{"run", "--root", windowsInstallDir, "--child-args", "--regtoken " + token}, args)

	withURL := buildLauncherServiceArgs(windowsInstallDir, token, "https://ctrl.example.com:8443")
	assert.Equal(t, []string{"run", "--root", windowsInstallDir, "--child-args",
		"--regtoken " + token + " --controller-url https://ctrl.example.com:8443"}, withURL)

	// The service args must never point execution at the bare steward binary.
	joined := strings.Join(withURL, " ")
	assert.NotContains(t, joined, windowsInstallPath+" --regtoken",
		"service must exec the launcher, not the bare steward binary")

	// Token appears exactly once (no duplication across args).
	assert.Equal(t, 1, strings.Count(joined, token), "token should appear exactly once")
}

// TestWindowsLauncherUnderProgramFilesACL is the REQUIRED LPE-hardening TEST
// for #2379: the launcher — a binary a SYSTEM service execs — must be
// installed under the install dir whose default Program Files ACL restricts
// writes to Administrators/SYSTEM. No install-dir ACL is loosened by this
// package (copyBinary sets no Windows ACLs; the directory inherits Program
// Files protection), so the load-bearing guarantee is that the path never
// moves out from under it.
func TestWindowsLauncherUnderProgramFilesACL(t *testing.T) {
	assert.True(t, strings.HasPrefix(windowsLauncherPath, windowsInstallDir+`\`),
		"launcher must live inside the install dir")
	assert.True(t, strings.HasPrefix(windowsInstallDir, `C:\Program Files\`),
		"install dir must be under Program Files (Administrator-only-writable default ACL)")
}

// TestPlatformLogDir verifies the ProgramData-with-fallback resolution mirrors
// platformCACertPath, including CFGMS_INSTALL_PREFIX test isolation.
func TestPlatformLogDir(t *testing.T) {
	t.Setenv("ProgramData", `C:\ProgramData`)
	t.Setenv("CFGMS_INSTALL_PREFIX", "")
	assert.Equal(t, filepath.Join(`C:\ProgramData`, "CFGMS", "logs"), platformLogDir())

	t.Setenv("ProgramData", "")
	assert.Equal(t, filepath.Join(`C:\ProgramData`, "CFGMS", "logs"), platformLogDir(),
		`unset ProgramData falls back to C:\ProgramData`)

	t.Setenv("CFGMS_INSTALL_PREFIX", `D:\scratch`)
	assert.Equal(t, filepath.Join(`D:\scratch`, `ProgramData`, "CFGMS", "logs"), platformLogDir(),
		"CFGMS_INSTALL_PREFIX nests the path under the prefix")
}
