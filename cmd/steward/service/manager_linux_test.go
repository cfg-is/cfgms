// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var _ Manager = New("")

// TestLinuxInstallFingerprintMismatch verifies that a mismatched CA fingerprint causes
// Install to return an error before writing the cert or registering the service.
// Runs without root because fingerprint verification is checked before the elevation gate.
func TestLinuxInstallFingerprintMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, _ := generateTestCACert(t)
	m := New("/usr/bin/cfgms-steward")
	err := m.Install("tok_test123", "", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestLinuxInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0444 (ADR-013 §3: immutable to non-root, tamper-evident).
func TestLinuxInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	certPEM, fingerprint := generateTestCACert(t)

	// Fingerprint verification must pass for the cert we generated.
	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	// Write cert using the same logic Install uses, with an explicit prefix path.
	destPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0444), info.Mode().Perm(), "CA cert must be written with mode 0444 per ADR-013 §3")
}

func TestLinuxManagerIsElevated(t *testing.T) {
	m := New("/usr/bin/cfgms-steward")
	// In most CI environments the test process is not root.
	// We validate that IsElevated() reflects os.Getuid() correctly.
	expected := os.Getuid() == 0
	assert.Equal(t, expected, m.IsElevated())
}

func TestLinuxManagerInstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/bin/cfgms-steward")
	err := m.Install("tok_test123", "", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestLinuxManagerUninstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/bin/cfgms-steward")
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestLinuxManagerStatusNotInstalled(t *testing.T) {
	// Status must work without root; when the unit file does not exist the
	// service is reported as not installed.
	m := New("/usr/bin/cfgms-steward")
	status, err := m.Status()
	require.NoError(t, err)
	// If the unit file is missing, service must be reported as not installed.
	if _, statErr := os.Stat(linuxSystemdUnit); os.IsNotExist(statErr) {
		assert.False(t, status.Installed, "should not be installed when unit file is absent")
		assert.False(t, status.Running, "should not be running when unit file is absent")
	}
	assert.Equal(t, linuxServiceName, status.ServiceName)
	assert.Equal(t, linuxLauncherPath, status.InstallPath)
}

func TestGenerateSystemdUnit(t *testing.T) {
	token := "tok_unit_test_abc123"
	unit := generateSystemdUnit(token, "")

	assert.Contains(t, unit, "[Unit]")
	assert.Contains(t, unit, "[Service]")
	assert.Contains(t, unit, "[Install]")
	assert.Contains(t, unit, "Restart=always")
	assert.Contains(t, unit, "RestartSec=10")
	assert.Contains(t, unit, "--regtoken "+token)
	// Launcher-managed: ExecStart runs the launcher, which supervises the steward
	// and forwards the token via --child-args. This is what makes the steward
	// push-upgradeable.
	assert.Contains(t, unit, linuxLauncherPath+" run ")
	assert.Contains(t, unit, "--child-args")
	assert.NotContains(t, unit, linuxInstallPath+" --regtoken", "ExecStart must run the launcher, not the bare steward")
	assert.Contains(t, unit, "WantedBy=multi-user.target")

	// Verify token appears exactly once (no duplication).
	count := strings.Count(unit, token)
	assert.Equal(t, 1, count, "token should appear exactly once in unit file")
}

func TestGenerateSystemdUnitContainsRestartPolicy(t *testing.T) {
	unit := generateSystemdUnit("tok_test", "")
	assert.Contains(t, unit, "Restart=always", "Restart=always required by acceptance criteria")
	assert.Contains(t, unit, "RestartSec=10", "RestartSec=10 required by acceptance criteria")
}

// TestGenerateSystemdUnitWithControllerURL verifies that generateSystemdUnit embeds
// --controller-url in ExecStart when a non-empty URL is provided (ADR-013 §3, Issue #1517).
func TestGenerateSystemdUnitWithControllerURL(t *testing.T) {
	token := "tok_test_url"
	controllerURL := "https://ctrl.example.com"
	unit := generateSystemdUnit(token, controllerURL)

	assert.Contains(t, unit, "--controller-url "+controllerURL)
	assert.Contains(t, unit, "--regtoken "+token)
	assert.Contains(t, unit, linuxLauncherPath)

	// Verify token and URL each appear exactly once.
	assert.Equal(t, 1, strings.Count(unit, token), "token should appear exactly once")
	assert.Equal(t, 1, strings.Count(unit, controllerURL), "controller URL should appear exactly once")

	// Without URL: --controller-url must not appear.
	unitNoURL := generateSystemdUnit(token, "")
	assert.NotContains(t, unitNoURL, "--controller-url")
}

func TestCopyBinaryPermissions(t *testing.T) {
	src := filepath.Join(t.TempDir(), "cfgms-steward-src")
	require.NoError(t, os.WriteFile(src, []byte("binary content"), 0600))

	dst := filepath.Join(t.TempDir(), "cfgms-steward")
	require.NoError(t, copyBinary(src, dst))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	// 0750: owner rwx (service binary), group rx (service group), no world access
	assert.Equal(t, os.FileMode(0750), info.Mode().Perm())
}

func TestSystemdUnitFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms-steward.service")
	content := generateSystemdUnit("tok_test", "")
	require.NoError(t, writeSystemdUnit(path, []byte(content)))

	info, err := os.Stat(path)
	require.NoError(t, err)
	// 0600: owner rw (root only); systemd reads as root, group read exposes the token
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// TestGenerateSystemdUnitSetsLogDir: the installer-managed steward must log to
// the platform-conventional path (#2378) — never the /tmp/cfgms fallback.
func TestGenerateSystemdUnitSetsLogDir(t *testing.T) {
	unit := generateSystemdUnit("tok_test", "")
	assert.Contains(t, unit, "Environment=CFGMS_LOG_DIR=/var/log/cfgms",
		"systemd unit must set the platform-conventional log directory")
}

// TestLinuxInstallCreatesLogDir is the required acceptance test for Issue #2483:
// cfgms-steward install must create /var/log/cfgms (mode 0750, owned by the service
// user) before writing and starting the systemd unit. createLogDir is exercised
// directly here because the full Install path requires root and a launcher binary;
// the directory-creation logic is self-contained and this is the pattern used by
// the analogous TestLinuxInstallCACertWritten.
func TestLinuxInstallCreatesLogDir(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "var", "log", "cfgms")

	uid := os.Getuid()
	gid := os.Getgid()

	require.NoError(t, createLogDir(logDir, uid, gid))

	info, err := os.Stat(logDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "log path must be a directory")
	assert.Equal(t, os.FileMode(0750), info.Mode().Perm(),
		"log directory must have mode 0750 (owner rwx, group rx, no world access)")

	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "expected *syscall.Stat_t from FileInfo.Sys()")
	assert.Equal(t, uint32(uid), stat.Uid, "log directory must be owned by the service user uid")
	assert.Equal(t, uint32(gid), stat.Gid, "log directory must be owned by the service group gid")
}

// TestLinuxInstallCreatesLogDirIdempotent verifies that createLogDir corrects the
// directory mode even when the directory already exists with wrong permissions.
func TestLinuxInstallCreatesLogDirIdempotent(t *testing.T) {
	dir := t.TempDir()
	logDir := filepath.Join(dir, "var", "log", "cfgms")
	require.NoError(t, os.MkdirAll(logDir, 0777))

	uid := os.Getuid()
	gid := os.Getgid()
	require.NoError(t, createLogDir(logDir, uid, gid))

	info, err := os.Stat(logDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0750), info.Mode().Perm(),
		"createLogDir must enforce mode 0750 even when directory already exists")
}

// TestPlatformLogDirPrefix verifies that platformLogDir respects CFGMS_INSTALL_PREFIX
// for test isolation, mirroring the platformCACertPath pattern.
func TestPlatformLogDirPrefix(t *testing.T) {
	prefix := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", prefix)
	assert.Equal(t, filepath.Join(prefix, linuxLogDir), platformLogDir())
}

func TestPlatformLogDirNoPrefix(t *testing.T) {
	t.Setenv("CFGMS_INSTALL_PREFIX", "")
	assert.Equal(t, linuxLogDir, platformLogDir())
}

// TestServiceUserIDs verifies that serviceUserIDs returns the correct uid/gid.
// Uses the current process user (always exists) rather than the cfgms service user
// which may not be present in test environments.
func TestServiceUserIDs(t *testing.T) {
	cur, err := user.Current()
	require.NoError(t, err)

	uid, gid, err := serviceUserIDs(cur.Username)
	require.NoError(t, err)
	assert.Equal(t, os.Getuid(), uid)
	assert.Equal(t, os.Getgid(), gid)
}

func TestServiceUserIDsNotFound(t *testing.T) {
	_, _, err := serviceUserIDs("cfgms-nonexistent-test-user-xyzzy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
