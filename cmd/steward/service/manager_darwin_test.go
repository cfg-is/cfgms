// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build darwin

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinManagerInstallPath(t *testing.T) {
	m := New("/usr/local/bin/cfgms-steward")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, darwinLauncherPath, status.InstallPath)
}

func TestDarwinManagerIsElevated(t *testing.T) {
	m := New("/usr/local/bin/cfgms-steward")
	expected := os.Getuid() == 0
	assert.Equal(t, expected, m.IsElevated())
}

func TestDarwinManagerInstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	dir := t.TempDir()
	// Create both the steward binary and launcher so the check advances past the
	// launcher-present gate and reaches the elevation check.
	binaryPath := filepath.Join(dir, "cfgms-steward")
	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))
	launcherPath := filepath.Join(dir, darwinLauncherBinaryName)
	require.NoError(t, os.WriteFile(launcherPath, []byte("launcher"), 0755))

	m := New(binaryPath)
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

// TestDarwinInstallFingerprintMismatch verifies that a mismatched CA fingerprint causes
// Install to return an error before writing the cert or registering the daemon.
// verifyCACertFingerprint is called before IsElevated(), so the error is returned
// regardless of whether the caller is root.
func TestDarwinInstallFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, _ := generateTestCACert(t)
	m := New("/usr/local/bin/cfgms-steward")
	err := m.Install("tok_test123", "", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestDarwinInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0444 when a correct fingerprint is provided (ADR-013 §3).
func TestDarwinInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	certPEM, fingerprint := generateTestCACert(t)

	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	destPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0444), info.Mode().Perm(), "CA cert must be written with mode 0444 per ADR-013 §3")
}

// TestDarwinInstallMissingLauncher is the REQUIRED TEST for fail-closed behaviour:
// Install() must return a clear, actionable error and perform no daemon registration
// when the launcher binary is absent next to binaryPath.
func TestDarwinInstallMissingLauncher(t *testing.T) {
	dir := t.TempDir()
	// Write only the steward binary — deliberately omit the launcher binary.
	binaryPath := filepath.Join(dir, "cfgms-steward")
	require.NoError(t, os.WriteFile(binaryPath, []byte("binary"), 0755))

	m := New(binaryPath)
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	// Error must name the missing binary and the bundle requirement.
	assert.Contains(t, err.Error(), "launcher binary")
	assert.Contains(t, err.Error(), darwinLauncherBinaryName)
}

func TestDarwinManagerUninstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/local/bin/cfgms-steward")
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestDarwinManagerStatusNotInstalled(t *testing.T) {
	m := New("/usr/local/bin/cfgms-steward")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, darwinServiceName, status.ServiceName)
	assert.Equal(t, darwinLauncherPath, status.InstallPath)
	if _, statErr := os.Stat(darwinPlistPath); os.IsNotExist(statErr) {
		assert.False(t, status.Installed)
		assert.False(t, status.Running)
	}
}

func TestGenerateLaunchdPlist(t *testing.T) {
	token := "tok_plist_test_abc123"
	tokenPath := "/etc/cfgms/registration-token"
	plist := generateLaunchdPlist(tokenPath, "")

	assert.Contains(t, plist, "<?xml")
	assert.Contains(t, plist, darwinServiceName)
	// Launcher-managed: ProgramArguments runs the launcher, which supervises the
	// steward and forwards the token via --child-args. This is what makes the
	// steward push-upgradeable.
	assert.Contains(t, plist, darwinLauncherPath)
	assert.Contains(t, plist, "run")
	assert.Contains(t, plist, "--root")
	assert.Contains(t, plist, darwinLauncherRoot)
	assert.Contains(t, plist, "--child-args")
	assert.NotContains(t, plist, darwinInstallPath+" --regtoken", "ProgramArguments must run the launcher, not the bare steward")
	assert.Contains(t, plist, "--regtoken-file "+tokenPath)
	assert.NotContains(t, plist, "--regtoken ")
	assert.NotContains(t, plist, token)
	assert.Contains(t, plist, "<key>KeepAlive</key>")
	assert.Contains(t, plist, "<key>RunAtLoad</key>")
	assert.Contains(t, plist, "<true/>")
	// Without URL: --controller-url must not appear.
	assert.NotContains(t, plist, "--controller-url")
	assert.Equal(t, 1, strings.Count(plist, tokenPath), "token file path should appear exactly once")
}

func TestGenerateLaunchdPlistKeepAliveRequired(t *testing.T) {
	plist := generateLaunchdPlist("/etc/cfgms/registration-token", "")
	assert.Contains(t, plist, "<key>KeepAlive</key>", "KeepAlive required by acceptance criteria")
	assert.Contains(t, plist, "<key>RunAtLoad</key>", "RunAtLoad required by acceptance criteria")
}

func TestGenerateLaunchdPlistWithControllerURL(t *testing.T) {
	tokenPath := "/etc/cfgms/registration-token"
	controllerURL := "https://ctrl.example.com"
	plist := generateLaunchdPlist(tokenPath, controllerURL)

	assert.Contains(t, plist, "--controller-url")
	assert.Contains(t, plist, controllerURL)
	assert.Contains(t, plist, "--regtoken-file")
	assert.Equal(t, 1, strings.Count(plist, tokenPath), "token file path should appear exactly once")
	assert.Equal(t, 1, strings.Count(plist, controllerURL), "controller URL should appear exactly once")
}

func TestDarwinManagerNew(t *testing.T) {
	m := New("/path/to/binary")
	require.NotNil(t, m)
	_, ok := m.(*darwinManager)
	assert.True(t, ok, "New() should return a *darwinManager on macOS")
}

// TestGenerateLaunchdPlistSetsLogDir: the installer-managed steward must log to
// the platform-conventional path (#2378) — never the /tmp/cfgms fallback.
func TestGenerateLaunchdPlistSetsLogDir(t *testing.T) {
	plist := generateLaunchdPlist("/etc/cfgms/registration-token", "")
	assert.Contains(t, plist, "<key>EnvironmentVariables</key>")
	assert.Contains(t, plist, "<key>CFGMS_LOG_DIR</key>")
	assert.Contains(t, plist, "<string>/usr/local/var/log/cfgms</string>",
		"launchd plist must set the platform-conventional log directory")
	assert.Contains(t, plist, "<key>CFGMS_SECURITY_PROFILE</key>")
	assert.Contains(t, plist, "<string>public-beta</string>",
		"installer-managed connected stewards must select the fail-closed public-beta profile")
}

// TestDarwinLauncherPathParity is the REQUIRED TEST for path parity: darwinLauncherPath
// must equal the literal non-Windows-default path in client_transport_upgrade.go's
// launcherPath(), guarding against silent drift between install-time and push-upgrade
// runtime.
func TestDarwinLauncherPathParity(t *testing.T) {
	assert.Equal(t, "/usr/local/bin/cfgms-launcher", darwinLauncherPath,
		"darwinLauncherPath must match the non-Windows default used by push-upgrade (client_transport_upgrade.go launcherPath())")
}

// TestDarwinLauncherBinaryPermissions is the REQUIRED TEST for LPE hardening:
// the launcher binary is installed via copyBinary which sets root-owned 0750
// (owner rwx, group rx, no world access) — a standard user cannot replace the
// binary a root daemon execs.
func TestDarwinLauncherBinaryPermissions(t *testing.T) {
	src := filepath.Join(t.TempDir(), "cfgms-steward-launcher-src")
	require.NoError(t, os.WriteFile(src, []byte("launcher content"), 0600))

	dst := filepath.Join(t.TempDir(), "cfgms-launcher")
	require.NoError(t, copyBinary(src, dst))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	// 0750: owner rwx (service binary), group rx (service group), no world access
	assert.Equal(t, os.FileMode(0750), info.Mode().Perm(),
		"launcher binary must be installed with 0750 to prevent standard-user replacement")
}

// TestDarwinInstallFilesKeepTokenOutOfPlist is the REQUIRED TEST for the token
// file contract: the token lives only in a 0600 file, and the plist (also 0600)
// references that file instead of embedding the token.
func TestDarwinInstallFilesKeepTokenOutOfPlist(t *testing.T) {
	prefix := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", prefix)
	token := "tok_install_files_secret"
	plistPath := filepath.Join(t.TempDir(), "com.cfgms.steward.plist")

	// A pre-existing world-readable plist must be tightened, not inherited.
	require.NoError(t, os.WriteFile(plistPath, []byte("old"), 0644))

	require.NoError(t, writeDaemonFiles(token, "https://ctrl.example.com", plistPath))

	tokenPath := filepath.Join(prefix, "etc", "cfgms", tokenFileName)
	assert.Equal(t, tokenPath, platformTokenFilePath())

	tokenInfo, err := os.Stat(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), tokenInfo.Mode().Perm())
	got, err := ReadTokenFile(tokenPath)
	require.NoError(t, err)
	assert.Equal(t, token, got)

	plistInfo, err := os.Stat(plistPath)
	require.NoError(t, err)
	assert.Zero(t, plistInfo.Mode().Perm()&0077, "plist must have no group or other permission bit")

	plist, err := os.ReadFile(plistPath)
	require.NoError(t, err)
	assert.NotContains(t, string(plist), token)
	assert.Contains(t, string(plist), "--regtoken-file "+tokenPath)
}

func TestDarwinInstallFilesRejectsInvalidToken(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", t.TempDir())
	plistPath := filepath.Join(t.TempDir(), "p.plist")
	require.Error(t, writeDaemonFiles("bad token", "", plistPath))
	_, err := os.Stat(plistPath)
	assert.True(t, os.IsNotExist(err), "plist must not be written when the token is invalid")
}
