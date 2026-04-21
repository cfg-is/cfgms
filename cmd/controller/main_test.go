// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"io"
	"os"
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

// TestRunControllerNoDebugPrints asserts that no "[DEBUG] main.go:" lines exist
// in the main.go source file, preventing debug scaffolding from being re-introduced.
func TestRunControllerNoDebugPrints(t *testing.T) {
	src, err := os.ReadFile("main.go")
	require.NoError(t, err, "should be able to read main.go source")
	assert.NotContains(t, string(src), "[DEBUG] main.go:",
		"main.go must not contain debug fmt.Printf lines with [DEBUG] main.go: prefix")
}

// TestRunControllerNoDebugOutput verifies that runController does not write any
// [DEBUG] text to stdout. runController fails fast on a missing config path,
// which is sufficient to cover the early-path debug prints that were removed.
func TestRunControllerNoDebugOutput(t *testing.T) {
	r, w, err := os.Pipe()
	require.NoError(t, err)

	old := os.Stdout
	os.Stdout = w

	// Fails immediately at config load — no server is started.
	err = runController("/nonexistent/config/path/does-not-exist", false)
	require.Error(t, err, "runController must fail when config path does not exist")

	require.NoError(t, w.Close())
	os.Stdout = old

	var buf bytes.Buffer
	_, err = io.Copy(&buf, r)
	require.NoError(t, err)

	assert.NotContains(t, buf.String(), "[DEBUG]",
		"runController must not write [DEBUG] output to stdout")
}

// TestSignalHandling is implemented in platform-specific files:
// - main_test_unix.go for Unix systems (uses syscall.Kill)
// - main_test_windows.go for Windows (uses channel-based simulation)
