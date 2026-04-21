// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/cfgis/cfgms/cmd/controller/service"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
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

// TestGetLogProviderConfigTimescaleMissingPassword verifies that getLogProviderConfig
// returns a non-nil error when the timescale provider is configured but
// CFGMS_TIMESCALE_PASSWORD is not set.
func TestGetLogProviderConfigTimescaleMissingPassword(t *testing.T) {
	t.Setenv("CFGMS_TIMESCALE_PASSWORD", "")
	cfg := &config.Config{
		Logging: &config.LoggingConfig{
			Provider: "timescale",
		},
	}
	result, err := getLogProviderConfig(cfg)
	require.Error(t, err, "expected error when CFGMS_TIMESCALE_PASSWORD is unset")
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "CFGMS_TIMESCALE_PASSWORD")
}

// TestGetLogProviderConfigTimescaleWithPassword verifies that getLogProviderConfig
// returns a nil error and a map containing the "password" key when
// CFGMS_TIMESCALE_PASSWORD is set.
func TestGetLogProviderConfigTimescaleWithPassword(t *testing.T) {
	t.Setenv("CFGMS_TIMESCALE_PASSWORD", "secret123")
	cfg := &config.Config{
		Logging: &config.LoggingConfig{
			Provider: "timescale",
		},
	}
	result, err := getLogProviderConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "secret123", result["password"])
}

// TestSignalHandling is implemented in platform-specific files:
// - main_test_unix.go for Unix systems (uses syscall.Kill)
// - main_test_windows.go for Windows (uses channel-based simulation)

// fakeServer is a test stub satisfying the Server interface.
type fakeServer struct {
	startErr  error
	stopErr   error
	mu        sync.Mutex
	stopCalls int
}

func (f *fakeServer) Start() error { return f.startErr }

func (f *fakeServer) Stop() error {
	f.mu.Lock()
	f.stopCalls++
	f.mu.Unlock()
	return f.stopErr
}

func (f *fakeServer) StopCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stopCalls
}

// TestRunControllerStartFailureCallsStop verifies that when srv.Start() returns
// an error, runControllerServer calls srv.Stop() before returning a non-nil error.
func TestRunControllerStartFailureCallsStop(t *testing.T) {
	startErr := errors.New("start failed")
	stub := &fakeServer{startErr: startErr}
	logger := logging.NewNoopLogger()
	sigChan := make(chan os.Signal, 1)

	err := runControllerServer(stub, logger, sigChan)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "start failed")
	assert.Equal(t, 1, stub.StopCallCount(), "srv.Stop() must be called exactly once after Start() error")
}

// TestRunControllerCleanExitCallsStop verifies that when srv.Start() returns nil
// (clean exit), runControllerServer still calls srv.Stop() and returns nil.
func TestRunControllerCleanExitCallsStop(t *testing.T) {
	stub := &fakeServer{startErr: nil}
	logger := logging.NewNoopLogger()
	sigChan := make(chan os.Signal, 1)

	err := runControllerServer(stub, logger, sigChan)

	require.NoError(t, err)
	assert.Equal(t, 1, stub.StopCallCount(), "srv.Stop() must be called exactly once after clean Start() exit")
}
