// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/windows/registry"
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
	assert.Equal(t, []string{"CFGMS_LOG_DIR=" + logDir}, vals)
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
