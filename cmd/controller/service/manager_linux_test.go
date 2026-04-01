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
	m := New("/usr/bin/cfgms-controller")
	assert.Equal(t, linuxInstallPath, m.InstallPath())
}

func TestLinuxManagerIsElevated(t *testing.T) {
	m := New("/usr/bin/cfgms-controller")
	expected := os.Getuid() == 0
	assert.Equal(t, expected, m.IsElevated())
}

func TestLinuxManagerInstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/bin/cfgms-controller")
	err := m.Install("/etc/cfgms/controller.cfg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestLinuxManagerInstallRejectsEmptyConfigPath(t *testing.T) {
	m := New("/usr/bin/cfgms-controller")
	err := m.Install("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestLinuxManagerUninstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/bin/cfgms-controller")
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestLinuxManagerStatusNotInstalled(t *testing.T) {
	// Status must work without root; when the unit file does not exist the
	// service is reported as not installed.
	m := New("/usr/bin/cfgms-controller")
	status, err := m.Status()
	require.NoError(t, err)
	if _, statErr := os.Stat(linuxSystemdUnit); os.IsNotExist(statErr) {
		assert.False(t, status.Installed, "should not be installed when unit file is absent")
		assert.False(t, status.Running, "should not be running when unit file is absent")
	}
	assert.Equal(t, linuxServiceName, status.ServiceName)
	assert.Equal(t, linuxInstallPath, status.InstallPath)
}

func TestGenerateSystemdUnit(t *testing.T) {
	configPath := "/etc/cfgms/controller.cfg"
	unit := generateSystemdUnit(configPath)

	assert.Contains(t, unit, "[Unit]")
	assert.Contains(t, unit, "[Service]")
	assert.Contains(t, unit, "[Install]")
	assert.Contains(t, unit, "Restart=always")
	assert.Contains(t, unit, "RestartSec=10")
	assert.Contains(t, unit, `--config "`+configPath+`"`)
	assert.Contains(t, unit, linuxInstallPath)
	assert.Contains(t, unit, "WantedBy=multi-user.target")
	assert.Contains(t, unit, "Description=CFGMS Controller")

	// Config path appears exactly once (no duplication).
	count := strings.Count(unit, configPath)
	assert.Equal(t, 1, count, "config path should appear exactly once in unit file")
}

func TestGenerateSystemdUnitContainsRestartPolicy(t *testing.T) {
	unit := generateSystemdUnit("/etc/cfgms/controller.cfg")
	assert.Contains(t, unit, "Restart=always", "Restart=always required")
	assert.Contains(t, unit, "RestartSec=10", "RestartSec=10 required")
}

func TestConfigPathFromUnit(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "valid unit with config",
			content:  generateSystemdUnit("/etc/cfgms/controller.cfg"),
			expected: "/etc/cfgms/controller.cfg",
		},
		{
			name:     "unit without config",
			content:  "[Service]\nExecStart=/usr/local/bin/cfgms-controller\n",
			expected: "",
		},
		{
			name:     "empty content",
			content:  "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := configPathFromUnit(tc.content)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestLinuxManagerNew(t *testing.T) {
	m := New("/path/to/binary")
	require.NotNil(t, m)
	_, ok := m.(*linuxManager)
	assert.True(t, ok, "New() should return a *linuxManager on Linux")
}
