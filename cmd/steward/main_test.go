// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cfgis/cfgms/cmd/steward/service"
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
	assert.Equal(t, "cfgms-steward", cmd.Use)

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

	for _, name := range []string{"config", "mode", "regtoken"} {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "expected flag %q to be registered", name)
	}

	// log-level and log-provider must not be registered as CLI flags.
	assert.Nil(t, cmd.Flags().Lookup("log-level"), "log-level flag must not be registered")
	assert.Nil(t, cmd.Flags().Lookup("log-provider"), "log-provider flag must not be registered")
}

func TestRunInstallRequiresToken(t *testing.T) {
	err := runInstall("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--regtoken is required")
}

func TestRunInstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runInstall("tok_test_abc123")
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

func TestBuildHTTPConfig(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("empty CFGMS_HTTP_CA_CERT_PATH produces empty CACertPath", func(t *testing.T) {
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")
		cfg := buildHTTPConfig("https://controller.example.com", 30*time.Second, logger)
		require.NotNil(t, cfg)
		assert.Equal(t, "https://controller.example.com", cfg.ControllerURL)
		assert.Equal(t, "", cfg.CACertPath)
	})

	t.Run("CFGMS_HTTP_CA_CERT_PATH is forwarded to HTTPConfig.CACertPath", func(t *testing.T) {
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "/etc/cfgms/ca.crt")
		cfg := buildHTTPConfig("https://controller.example.com", 30*time.Second, logger)
		require.NotNil(t, cfg)
		assert.Equal(t, "/etc/cfgms/ca.crt", cfg.CACertPath)
	})
}

func TestControllerURLOrUnknown(t *testing.T) {
	// When ControllerURL is empty (default in test builds).
	original := ControllerURL
	defer func() { ControllerURL = original }()

	ControllerURL = ""
	assert.Contains(t, controllerURLOrUnknown(), "not set")

	ControllerURL = "https://ctrl.example.com"
	assert.Equal(t, "https://ctrl.example.com", controllerURLOrUnknown())
}

func TestLogLevelFromEnv(t *testing.T) {
	tests := []struct {
		env      string
		expected string
	}{
		{"", "INFO"},
		{"invalid", "INFO"},
		{"info", "INFO"},
		{"INFO", "INFO"},
		{"debug", "DEBUG"},
		{"DEBUG", "DEBUG"},
		{"warn", "WARN"},
		{"WARN", "WARN"},
		{"error", "ERROR"},
		{"ERROR", "ERROR"},
		{"verbose", "INFO"},
	}

	for _, tc := range tests {
		t.Run("env="+tc.env, func(t *testing.T) {
			t.Setenv("CFGMS_LOG_LEVEL", tc.env)
			assert.Equal(t, tc.expected, logLevelFromEnv())
		})
	}
}

// TestStandaloneStartErrorPropagatesToRunSteward verifies that setup failures
// in standalone mode are returned as errors rather than triggering os.Exit via
// logger.Fatal. The errCh pattern ensures errors from s.Start are returned to
// the cobra RunE handler for a clean process exit.
func TestStandaloneStartErrorPropagatesToRunSteward(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := runSteward(ctx, "", "/nonexistent/path/steward.cfg", "standalone")
	require.Error(t, err, "runSteward must return an error when standalone setup fails")
	assert.Contains(t, err.Error(), "failed to create standalone steward",
		"error must propagate from NewStandalone rather than being swallowed")
}

// TestStandaloneContextCanceledIsNotError verifies that a context.Canceled
// error from s.Start is filtered and does not cause runSteward to return an
// error. Cancellation is the normal shutdown path triggered by OS signals.
func TestStandaloneContextCanceledIsNotError(t *testing.T) {
	logDir := t.TempDir()
	t.Setenv("CFGMS_LOG_DIR", logDir)

	// Write a minimal valid standalone config so NewStandalone succeeds.
	configFile := filepath.Join(t.TempDir(), "steward.cfg")
	configData := `steward:
  id: test-steward-shutdown
  mode: standalone

resources: []
`
	require.NoError(t, os.WriteFile(configFile, []byte(configData), 0644))

	// Cancel the context immediately so s.Start returns context.Canceled right away.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := runSteward(ctx, "", configFile, "standalone")
	assert.NoError(t, err, "context.Canceled from s.Start must not be returned as an error from runSteward")
}
