// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsRootedPath_POSIXAbsoluteIsRootedOnEveryPlatform pins the cross-platform half of
// the contract. Deployment configs are authored with POSIX paths and are parsed on every
// platform the controller builds for, so a leading slash must count as rooted even where
// filepath.IsAbs disagrees (Windows requires a volume name).
func TestIsRootedPath_POSIXAbsoluteIsRootedOnEveryPlatform(t *testing.T) {
	for _, p := range []string{"/var/lib/cfgms/certs", "/etc/cfgms", "/"} {
		assert.True(t, IsRootedPath(p), "%q must be treated as rooted on %s", p, runtime.GOOS)
	}
}

// TestIsRootedPath_RelativeIsNotRooted keeps the #3197 behaviour intact: a genuinely
// relative cert_path is still anchored to the config file's directory.
func TestIsRootedPath_RelativeIsNotRooted(t *testing.T) {
	for _, p := range []string{"certs/", "certs", "./certs", "../certs", ""} {
		assert.False(t, IsRootedPath(p), "%q must be treated as relative", p)
	}
}

// TestIsRootedPath_WindowsSpellings covers the separator and volume forms that only
// exist on Windows.
func TestIsRootedPath_WindowsSpellings(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("volume-qualified and backslash-rooted paths are only meaningful on Windows")
	}
	for _, p := range []string{`C:\ProgramData\cfgms\certs`, `\cfgms\certs`, `\\server\share\certs`} {
		assert.True(t, IsRootedPath(p), "%q must be treated as rooted", p)
	}
}

// TestLoadWithPath_KeepsPOSIXAbsoluteCertPath is the end-to-end regression: a reviewed
// deployment config that names an absolute POSIX cert_path must survive Load unchanged,
// rather than being rewritten beneath the config file's directory.
func TestLoadWithPath_KeepsPOSIXAbsoluteCertPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(configPath, []byte("cert_path: /var/lib/cfgms/certs\n"), 0o600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	assert.Equal(t, "/var/lib/cfgms/certs", cfg.CertPath)
}

// TestLoadWithPath_AnchorsRelativeCertPath is the paired negative case, so a change that
// made every path "rooted" could not pass the test above for the wrong reason.
func TestLoadWithPath_AnchorsRelativeCertPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(configPath, []byte("cert_path: certs/\n"), 0o600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, "certs"), cfg.CertPath)
}
