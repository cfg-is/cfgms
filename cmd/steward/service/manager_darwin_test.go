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
	assert.Equal(t, darwinInstallPath, status.InstallPath)
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
	m := New("/usr/local/bin/cfgms-steward")
	err := m.Install("tok_test123", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

// TestDarwinInstallFingerprintMismatch verifies that a mismatched CA fingerprint causes
// Install to return an error before writing the cert or registering the daemon.
// Runs without root because fingerprint verification is checked before the elevation gate.
func TestDarwinInstallFingerprintMismatch(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping — running as root would proceed past fingerprint check to service ops")
	}
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, _ := generateTestCACert(t)
	m := New("/usr/local/bin/cfgms-steward")
	err := m.Install("tok_test123", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestDarwinInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0644 when a correct fingerprint is provided.
func TestDarwinInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	certPEM, fingerprint := generateTestCACert(t)

	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	destPath := filepath.Join(dir, "etc", "cfgms", "controller-ca.crt")
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "CA cert must be written with mode 0644")
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
	assert.Equal(t, darwinInstallPath, status.InstallPath)
	if _, statErr := os.Stat(darwinPlistPath); os.IsNotExist(statErr) {
		assert.False(t, status.Installed)
		assert.False(t, status.Running)
	}
}

func TestGenerateLaunchdPlist(t *testing.T) {
	token := "tok_plist_test_abc123"
	plist := generateLaunchdPlist(token)

	assert.Contains(t, plist, "<?xml")
	assert.Contains(t, plist, darwinServiceName)
	assert.Contains(t, plist, darwinInstallPath)
	assert.Contains(t, plist, "--regtoken")
	assert.Contains(t, plist, token)
	assert.Contains(t, plist, "<key>KeepAlive</key>")
	assert.Contains(t, plist, "<key>RunAtLoad</key>")
	assert.Contains(t, plist, "<true/>")

	// Token appears exactly once (no duplication).
	count := strings.Count(plist, token)
	assert.Equal(t, 1, count, "token should appear exactly once in plist")
}

func TestGenerateLaunchdPlistKeepAliveRequired(t *testing.T) {
	plist := generateLaunchdPlist("tok_test")
	assert.Contains(t, plist, "<key>KeepAlive</key>", "KeepAlive required by acceptance criteria")
	assert.Contains(t, plist, "<key>RunAtLoad</key>", "RunAtLoad required by acceptance criteria")
}

func TestDarwinManagerNew(t *testing.T) {
	m := New("/path/to/binary")
	require.NotNil(t, m)
	_, ok := m.(*darwinManager)
	assert.True(t, ok, "New() should return a *darwinManager on macOS")
}
