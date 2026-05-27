// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsManagerInstallPath(t *testing.T) {
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsInstallPath, status.InstallPath)
}

func TestWindowsManagerStatusNotInstalled(t *testing.T) {
	// Status must work without Administrator privileges.
	// When the service is not registered it must be reported as not installed.
	m := New("cfgms-steward.exe")
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsServiceName, status.ServiceName)
	assert.Equal(t, windowsInstallPath, status.InstallPath)
}

func TestWindowsManagerInstallRequiresElevation(t *testing.T) {
	m := New("cfgms-steward.exe")
	if m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	err := m.Install("tok_test123", "", "")
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
	err := m.Install("tok_test123", certPEM, "deadbeefdeadbeefdeadbeef")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fingerprint mismatch")

	// Cert must NOT be written on fingerprint mismatch.
	certPath := platformCACertPath()
	_, statErr := os.Stat(certPath)
	assert.True(t, os.IsNotExist(statErr), "cert file must not exist after fingerprint mismatch")
}

// TestWindowsInstallCACertWritten verifies that the CA cert is written to the prefixed
// platform path with mode 0644 when a correct fingerprint is provided.
func TestWindowsInstallCACertWritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CFGMS_INSTALL_PREFIX", dir)

	certPEM, fingerprint := generateTestCACert(t)

	require.NoError(t, verifyCACertFingerprint(certPEM, fingerprint))

	destPath := platformCACertPath()
	require.NoError(t, writeCACert(certPEM, destPath))

	info, err := os.Stat(destPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "CA cert must be written with mode 0644")
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
