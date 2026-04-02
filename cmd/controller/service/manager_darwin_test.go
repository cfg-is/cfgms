// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build darwin

package service

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDarwinManagerInstallPath(t *testing.T) {
	m := New("/usr/local/bin/cfgms-controller")
	assert.Equal(t, darwinInstallPath, m.InstallPath())
}

func TestDarwinManagerIsElevated(t *testing.T) {
	m := New("/usr/local/bin/cfgms-controller")
	expected := os.Getuid() == 0
	assert.Equal(t, expected, m.IsElevated())
}

func TestDarwinManagerInstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/local/bin/cfgms-controller")
	err := m.Install("/etc/cfgms/controller.cfg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestDarwinManagerInstallRejectsEmptyConfigPath(t *testing.T) {
	m := New("/usr/local/bin/cfgms-controller")
	err := m.Install("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestDarwinManagerUninstallRequiresElevation(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("skipping elevation check — running as root")
	}
	m := New("/usr/local/bin/cfgms-controller")
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
}

func TestDarwinManagerStatusNotInstalled(t *testing.T) {
	m := New("/usr/local/bin/cfgms-controller")
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
	configPath := "/etc/cfgms/controller.cfg"
	plist := generateLaunchdPlist(configPath)

	assert.Contains(t, plist, "<?xml")
	assert.Contains(t, plist, darwinServiceName)
	assert.Contains(t, plist, darwinInstallPath)
	assert.Contains(t, plist, "<string>--config</string>")
	assert.Contains(t, plist, configPath)
	assert.Contains(t, plist, "<key>KeepAlive</key>")
	assert.Contains(t, plist, "<key>RunAtLoad</key>")
	assert.Contains(t, plist, "<true/>")

	// Config path appears exactly once.
	count := strings.Count(plist, configPath)
	assert.Equal(t, 1, count, "config path should appear exactly once in plist")
}

func TestGenerateLaunchdPlistKeepAliveRequired(t *testing.T) {
	plist := generateLaunchdPlist("/etc/cfgms/controller.cfg")
	assert.Contains(t, plist, "<key>KeepAlive</key>", "KeepAlive required")
	assert.Contains(t, plist, "<key>RunAtLoad</key>", "RunAtLoad required")
}

func TestConfigPathFromPlist(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "valid plist with config",
			content:  generateLaunchdPlist("/etc/cfgms/controller.cfg"),
			expected: "/etc/cfgms/controller.cfg",
		},
		{
			name:     "plist without config",
			content:  "<plist><dict><key>Label</key><string>com.cfgms.controller</string></dict></plist>",
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
			got := configPathFromPlist(tc.content)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestDarwinManagerNew(t *testing.T) {
	m := New("/path/to/binary")
	require.NotNil(t, m)
	_, ok := m.(*darwinManager)
	assert.True(t, ok, "New() should return a *darwinManager on macOS")
}
