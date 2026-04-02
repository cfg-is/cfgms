// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"testing"

	"github.com/cfgis/cfgms/cmd/controller/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// isElevated returns true if the test process has elevated privileges,
// using the platform-specific check from the service package.
func isElevated() bool {
	return service.New("").IsElevated()
}

func TestBuildRootCommand(t *testing.T) {
	cmd := buildRootCommand()
	require.NotNil(t, cmd)
	assert.Equal(t, "cfgms-controller", cmd.Use)

	// Verify subcommands are registered.
	names := make([]string, 0, len(cmd.Commands()))
	for _, sub := range cmd.Commands() {
		names = append(names, sub.Name())
	}
	assert.Contains(t, names, "install")
	assert.Contains(t, names, "uninstall")
	assert.Contains(t, names, "status")
}

func TestBuildRootCommandFlags(t *testing.T) {
	cmd := buildRootCommand()

	for _, name := range []string{"config", "init"} {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "expected flag %q to be registered", name)
	}
}

func TestRunInstallRequiresConfig(t *testing.T) {
	err := runInstall("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--config is required")
}

func TestRunInstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runInstall("/etc/cfgms/controller.cfg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated privileges")
}

func TestRunUninstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runUninstall(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated privileges")
}

func TestRunStatusNotInstalled(t *testing.T) {
	// status should succeed even when the service is not installed.
	err := runStatus()
	assert.NoError(t, err)
}

func TestInstallCommandFlagRequired(t *testing.T) {
	cmd := buildInstallCommand()
	// Verify --config flag exists.
	flag := cmd.Flags().Lookup("config")
	require.NotNil(t, flag, "install command must have --config flag")

	// Verify it is marked required: executing without --config returns an error.
	cmd.SetArgs([]string{})
	err := cmd.Execute()
	require.Error(t, err, "install command should fail when --config is not provided")
}

func TestUninstallCommandHasPurgeFlag(t *testing.T) {
	cmd := buildUninstallCommand()
	flag := cmd.Flags().Lookup("purge")
	require.NotNil(t, flag, "uninstall command must have --purge flag")
	assert.Equal(t, "false", flag.DefValue)
}

// TestSignalHandling is implemented in platform-specific files:
// - main_test_unix.go for Unix systems (uses syscall.Kill)
// - main_test_windows.go for Windows (uses channel-based simulation)
