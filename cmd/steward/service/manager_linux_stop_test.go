// SPDX-License-Identifier: AGPL-3.0-only
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

// installFakeSystemctl puts a real executable named systemctl first on PATH.
// It appends its arguments to a log file and exits with exitCode, so the stop
// path runs the real exec.Command code against a real process.
func installFakeSystemctl(t *testing.T, exitCode int) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + logPath + "\nexit " + string(rune('0'+exitCode)) + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0700)) //#nosec G306 -- test helper must be executable
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

func TestStop_RequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("covered by TestStop_NotInstalled when running as root")
	}
	err := New("/usr/bin/cfgms-steward").Stop()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root privileges")
}

func TestStop_NotInstalled(t *testing.T) {
	logPath := installFakeSystemctl(t, 0)
	err := stopSystemdUnit(filepath.Join(t.TempDir(), "absent.service"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not installed")
	_, statErr := os.Stat(logPath)
	assert.True(t, os.IsNotExist(statErr), "systemctl must not be invoked for a missing unit")
}

func TestStop_StopsInstalledUnit(t *testing.T) {
	logPath := installFakeSystemctl(t, 0)
	unit := filepath.Join(t.TempDir(), "cfgms-steward.service")
	require.NoError(t, os.WriteFile(unit, []byte("[Unit]\n"), 0600))

	require.NoError(t, stopSystemdUnit(unit))

	data, err := os.ReadFile(logPath) //#nosec G304 -- test-owned temp path
	require.NoError(t, err)
	assert.Equal(t, "stop cfgms-steward", strings.TrimSpace(string(data)))
	assert.NotContains(t, string(data), "disable", "Stop must leave the service enabled")
}

func TestStop_SystemctlFailureIsReported(t *testing.T) {
	installFakeSystemctl(t, 1)
	unit := filepath.Join(t.TempDir(), "cfgms-steward.service")
	require.NoError(t, os.WriteFile(unit, []byte("[Unit]\n"), 0600))

	err := stopSystemdUnit(unit)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "systemctl stop")
}

func TestLinuxRegistrationTokenConfiguredFalseWithoutUnit(t *testing.T) {
	if _, err := os.Stat(linuxSystemdUnit); err == nil {
		t.Skip("a real cfgms-steward unit is installed on this host")
	}
	ok, err := New("/usr/bin/cfgms-steward").RegistrationTokenConfigured()
	require.NoError(t, err)
	assert.False(t, ok)
}
