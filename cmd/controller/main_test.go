// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cfgis/cfgms/cmd/controller/service"
	"github.com/cfgis/cfgms/features/controller/config"
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

// TestBuildLoggingConfigFieldsComplete asserts that buildLoggingConfig populates
// all required fields for a config with LogLevel = "debug" and no timescale provider.
func TestBuildLoggingConfigFieldsComplete(t *testing.T) {
	cfg := &config.Config{
		LogLevel: "debug",
	}
	lc, err := buildLoggingConfig(cfg, "test")
	require.NoError(t, err)
	require.NotNil(t, lc)

	assert.Equal(t, "DEBUG", lc.Level, "Level must be uppercased from cfg.LogLevel")
	assert.True(t, lc.TenantIsolation, "TenantIsolation must be true")
	assert.True(t, lc.EnableCorrelation, "EnableCorrelation must be true")
	assert.True(t, lc.EnableTracing, "EnableTracing must be true")
	assert.True(t, lc.AsyncWrites, "AsyncWrites must be true")
	assert.Equal(t, 100, lc.BatchSize, "BatchSize must be 100")
	assert.Equal(t, 5*time.Second, lc.FlushInterval, "FlushInterval must be 5s")
	assert.Equal(t, 90, lc.RetentionDays, "RetentionDays must be 90")
	assert.Equal(t, "test", lc.Component, "Component must match argument")
}

// TestRunInstallLoggingConfigMatchesRunController asserts that buildLoggingConfig
// produces equivalent field values for install and main paths given identical config.
func TestRunInstallLoggingConfigMatchesRunController(t *testing.T) {
	cfg := &config.Config{
		LogLevel: "info",
	}

	mainCfg, err := buildLoggingConfig(cfg, "main")
	require.NoError(t, err)

	installCfg, err := buildLoggingConfig(cfg, "install")
	require.NoError(t, err)

	assert.Equal(t, mainCfg.Level, installCfg.Level)
	assert.Equal(t, mainCfg.TenantIsolation, installCfg.TenantIsolation)
	assert.Equal(t, mainCfg.EnableCorrelation, installCfg.EnableCorrelation)
	assert.Equal(t, mainCfg.EnableTracing, installCfg.EnableTracing)
	assert.Equal(t, mainCfg.AsyncWrites, installCfg.AsyncWrites)
	assert.Equal(t, mainCfg.BatchSize, installCfg.BatchSize)
	assert.Equal(t, mainCfg.FlushInterval, installCfg.FlushInterval)
	assert.Equal(t, mainCfg.RetentionDays, installCfg.RetentionDays)
}

// TestResolveInstallCAPathNilCertificateErrors asserts that resolveInstallCAPath
// returns a clear error when cfg.Certificate is nil and initialization is needed.
func TestResolveInstallCAPathNilCertificateErrors(t *testing.T) {
	cfg := &config.Config{}
	_, err := resolveInstallCAPath(cfg, "/etc/cfgms/controller.cfg")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate configuration is required for initialization")
	assert.Contains(t, err.Error(), "/etc/cfgms/controller.cfg")
}

// TestResolveInstallCAPathWithCertificate asserts that resolveInstallCAPath
// returns the CA path without error when cfg.Certificate is set.
func TestResolveInstallCAPathWithCertificate(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			CAPath: dir,
		},
	}
	caPath, err := resolveInstallCAPath(cfg, "/etc/cfgms/controller.cfg")
	require.NoError(t, err)
	assert.Equal(t, dir, caPath)
}

// TestSignalHandling is implemented in platform-specific files:
// - main_test_unix.go for Unix systems (uses syscall.Kill)
// - main_test_windows.go for Windows (uses channel-based simulation)

// fakeServer is a test double for the controllerServer interface defined in
// main.go. It does NOT mock any CFGMS business-logic component; it models
// the OS-process lifecycle boundary (Start/Stop) with controllable return
// values so that runControllerServer's goroutine-supervision logic can be
// tested without requiring a full TLS+storage+gRPC stack.
type fakeServer struct {
	startErr   error
	stopErr    error
	startBlock chan struct{} // nil means return immediately
	startDone  chan struct{} // closed when Start() returns
	stopCalled chan struct{}
}

func newFakeServer(startErr error, block bool) *fakeServer {
	f := &fakeServer{
		startErr:   startErr,
		startDone:  make(chan struct{}),
		stopCalled: make(chan struct{}, 1),
	}
	if block {
		f.startBlock = make(chan struct{})
	}
	return f
}

func (f *fakeServer) Start() error {
	defer close(f.startDone)
	if f.startBlock != nil {
		<-f.startBlock
	}
	return f.startErr
}

func (f *fakeServer) Stop() error {
	f.stopCalled <- struct{}{}
	return f.stopErr
}

// TestRunControllerStartFailureCallsStop verifies that when Start() returns an
// error, runControllerServer calls Stop() and returns a wrapped non-nil error.
func TestRunControllerStartFailureCallsStop(t *testing.T) {
	srv := newFakeServer(fmt.Errorf("boom"), false)
	sigChan := make(chan os.Signal, 1)

	err := runControllerServer(srv, sigChan)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
	assert.Len(t, srv.stopCalled, 1, "Stop() must be called exactly once on Start() error")
}

// TestRunControllerServerIgnoresNilStart is the regression test for PR #815:
// when Start() returns nil (non-blocking success), runControllerServer must NOT
// return — it must keep waiting for sigChan. We verify this by confirming the
// function is still blocked after a short delay, then unblock it via sigChan.
func TestRunControllerServerIgnoresNilStart(t *testing.T) {
	srv := newFakeServer(nil, false) // Start() returns nil immediately
	sigChan := make(chan os.Signal, 1)

	done := make(chan error, 1)
	go func() {
		done <- runControllerServer(srv, sigChan)
	}()

	// Confirm runControllerServer has NOT returned ~50 ms after Start() returned nil.
	select {
	case got := <-done:
		t.Fatalf("runControllerServer returned early (runErr=%v) — nil Start() must not unblock it", got)
	case <-time.After(50 * time.Millisecond):
		// Still blocked — correct behaviour.
	}

	// Now send a signal to trigger clean shutdown.
	sigChan <- os.Interrupt

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("runControllerServer did not unblock after signal")
	}
	assert.Len(t, srv.stopCalled, 1, "Stop() must be called exactly once")
}

// TestRunControllerSignalPath verifies that a signal on sigChan causes
// runControllerServer to call Stop() and return nil.
func TestRunControllerSignalPath(t *testing.T) {
	srv := newFakeServer(nil, true) // Start() blocks until Stop path closes startBlock
	sigChan := make(chan os.Signal, 1)

	done := make(chan error, 1)
	go func() {
		done <- runControllerServer(srv, sigChan)
	}()

	// Unblock Start() so it can return nil; then wait for the goroutine to
	// actually return before sending the signal — no sleep needed.
	close(srv.startBlock)
	select {
	case <-srv.startDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Start() goroutine did not return within timeout")
	}

	sigChan <- syscall.SIGTERM

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("runControllerServer did not return after signal")
	}
	assert.Len(t, srv.stopCalled, 1, "Stop() must be called exactly once")
}
