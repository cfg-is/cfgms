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
	m := New("/usr/local/bin/cfgms-steward")
	assert.Equal(t, darwinInstallPath, m.InstallPath())
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
	err := m.Install("tok_test123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "root")
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
