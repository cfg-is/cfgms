// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build linux

package service

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinuxManagerInstallPath(t *testing.T) {
	m := New("/usr/bin/cfgms-steward")
	assert.Equal(t, linuxInstallPath, m.InstallPath())
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
	err := m.Install("tok_test123")
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
	assert.Contains(t, unit, "--regtoken "+token)
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

func TestLinuxManagerNew(t *testing.T) {
	m := New("/path/to/binary")
	require.NotNil(t, m)
	_, ok := m.(*linuxManager)
	assert.True(t, ok, "New() should return a *linuxManager on Linux")
}
