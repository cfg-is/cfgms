// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"os"
	"path/filepath"
	"strings"
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
	err := m.Install("tok_test123", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestLinuxInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0644 when a correct fingerprint is provided.
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
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "CA cert must be written with mode 0644")
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
	err := m.Install("tok_test123", "", "")
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
	assert.Equal(t, linuxInstallPath, status.InstallPath)
}

func TestGenerateSystemdUnit(t *testing.T) {
	token := "tok_unit_test_abc123"
	unit := generateSystemdUnit(token)

	assert.Contains(t, unit, "[Unit]")
	assert.Contains(t, unit, "[Service]")
	assert.Contains(t, unit, "[Install]")
	assert.Contains(t, unit, "Restart=always")
	assert.Contains(t, unit, "RestartSec=10")
	assert.Contains(t, unit, `--regtoken "`+token+`"`)
	assert.Contains(t, unit, linuxInstallPath)
	assert.Contains(t, unit, "WantedBy=multi-user.target")

	// Verify token appears exactly once (no duplication).
	count := strings.Count(unit, token)
	assert.Equal(t, 1, count, "token should appear exactly once in unit file")
}

func TestGenerateSystemdUnitContainsRestartPolicy(t *testing.T) {
	unit := generateSystemdUnit("tok_test")
	assert.Contains(t, unit, "Restart=always", "Restart=always required by acceptance criteria")
	assert.Contains(t, unit, "RestartSec=10", "RestartSec=10 required by acceptance criteria")
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
	content := generateSystemdUnit("tok_test")
	require.NoError(t, writeSystemdUnit(path, []byte(content)))

	info, err := os.Stat(path)
	require.NoError(t, err)
	// 0600: owner rw (root only); systemd reads as root, group read exposes the token
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
