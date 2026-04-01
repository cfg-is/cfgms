// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

//go:build windows

package service

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsManagerInstallPath(t *testing.T) {
	m := New(`C:\cfgms-controller.exe`)
	assert.Equal(t, windowsInstallPath, m.InstallPath())
}

func TestWindowsManagerInstallRequiresElevation(t *testing.T) {
	if m := New(`C:\cfgms-controller.exe`); m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	m := New(`C:\cfgms-controller.exe`)
	err := m.Install(`C:\cfgms\controller.cfg`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

func TestWindowsManagerInstallRejectsEmptyConfigPath(t *testing.T) {
	m := New(`C:\cfgms-controller.exe`)
	err := m.Install("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestWindowsManagerUninstallRequiresElevation(t *testing.T) {
	if m := New(`C:\cfgms-controller.exe`); m.IsElevated() {
		t.Skip("skipping elevation check — running as Administrator")
	}
	m := New(`C:\cfgms-controller.exe`)
	err := m.Uninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Administrator")
}

func TestWindowsManagerStatusNotInstalled(t *testing.T) {
	m := New(`C:\cfgms-controller.exe`)
	status, err := m.Status()
	require.NoError(t, err)
	assert.Equal(t, windowsServiceName, status.ServiceName)
	assert.Equal(t, windowsInstallPath, status.InstallPath)
}

func TestConfigPathFromBinaryPath(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "unquoted config path",
			input:    `C:\Program Files\CFGMS\cfgms-controller.exe --config C:\cfgms\controller.cfg`,
			expected: `C:\cfgms\controller.cfg`,
		},
		{
			name:     "quoted config path",
			input:    `"C:\Program Files\CFGMS\cfgms-controller.exe" --config "C:\cfgms\controller.cfg"`,
			expected: `C:\cfgms\controller.cfg`,
		},
		{
			name:     "no config argument",
			input:    `C:\Program Files\CFGMS\cfgms-controller.exe`,
			expected: "",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := configPathFromBinaryPath(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestWindowsManagerNew(t *testing.T) {
	m := New(`C:\path\to\binary`)
	require.NotNil(t, m)
	_, ok := m.(*windowsManager)
	assert.True(t, ok, "New() should return a *windowsManager on Windows")
}
