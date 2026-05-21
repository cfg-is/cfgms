// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package main

import (
	"context"
	"io"
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

	for _, name := range []string{"config", "regtoken"} {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "expected flag %q to be registered", name)
	}

	// log-level and log-provider must not be registered as CLI flags.
	assert.Nil(t, cmd.Flags().Lookup("log-level"), "log-level flag must not be registered")
	assert.Nil(t, cmd.Flags().Lookup("log-provider"), "log-provider flag must not be registered")
}

func TestBuildRootCommandNoModeFlag(t *testing.T) {
	cmd := buildRootCommand()
	assert.Nil(t, cmd.Flags().Lookup("mode"), "mode flag must not be registered")
}

func TestInstallCommandEnforcesRequiredRegtoken(t *testing.T) {
	// Verify cobra's MarkFlagRequired("regtoken") rejects the install subcommand
	// when --regtoken is absent. This is the cobra-level guard that supersedes
	// any manual empty-token check in runInstall — runInstall is never reached
	// without a non-empty token value.
	root := buildRootCommand()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"install"})
	err := root.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regtoken")
}

func TestRunInstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runInstall("tok_test_abc123", "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "elevated privileges")
}

func TestRunInstallCACertFileNotFound(t *testing.T) {
	// Verify runInstall returns an error that includes the filename when --ca-cert
	// names a path that does not exist.
	missing := filepath.Join(t.TempDir(), "nonexistent-ca.crt")
	err := runInstall("tok_test_abc123", missing, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-ca.crt")
}

func TestBuildInstallCommandFlags(t *testing.T) {
	cmd := buildInstallCommand()
	require.NotNil(t, cmd)

	for _, name := range []string{"regtoken", "ca-cert", "fingerprint"} {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "expected flag %q to be registered on install subcommand", name)
	}
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
		// CACertPath is "" when no env var is set and platform-standard cert does not exist.
		// In test environments the platform cert is absent, so this holds.
		assert.Equal(t, "", cfg.CACertPath)
	})

	t.Run("CFGMS_HTTP_CA_CERT_PATH with existing file is forwarded to HTTPConfig.CACertPath", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "ca.crt")
		require.NoError(t, os.WriteFile(certFile, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", certFile)
		cfg := buildHTTPConfig("https://controller.example.com", 30*time.Second, logger)
		require.NotNil(t, cfg)
		assert.Equal(t, certFile, cfg.CACertPath)
	})
}

func TestResolveRegistrationCACertPath(t *testing.T) {
	logger := logging.NewLogger("debug")

	t.Run("priority 1: env var set and file exists", func(t *testing.T) {
		dir := t.TempDir()
		certFile := filepath.Join(dir, "ca.crt")
		require.NoError(t, os.WriteFile(certFile, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", certFile)

		result := doResolveRegistrationCACertPath(logger, filepath.Join(dir, "platform-ca.crt"))
		assert.Equal(t, certFile, result)
	})

	t.Run("priority 1 fallthrough: env var set but file missing; platform path used", func(t *testing.T) {
		dir := t.TempDir()
		platformCert := filepath.Join(dir, "platform-ca.crt")
		require.NoError(t, os.WriteFile(platformCert, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", filepath.Join(dir, "nonexistent.crt"))

		result := doResolveRegistrationCACertPath(logger, platformCert)
		assert.Equal(t, platformCert, result)
	})

	t.Run("priority 2: platform-standard path exists when env var is empty", func(t *testing.T) {
		dir := t.TempDir()
		platformCert := filepath.Join(dir, "controller-ca.crt")
		require.NoError(t, os.WriteFile(platformCert, []byte("fake-cert"), 0600))
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")

		result := doResolveRegistrationCACertPath(logger, platformCert)
		assert.Equal(t, platformCert, result)
	})

	t.Run("priority 3: neither env var nor platform path exists returns empty string", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv("CFGMS_HTTP_CA_CERT_PATH", "")

		result := doResolveRegistrationCACertPath(logger, filepath.Join(dir, "nonexistent.crt"))
		assert.Equal(t, "", result)
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

// TestStandaloneStartErrorPropagatesToRunSteward verifies that startup errors in
// standalone mode are returned as errors from runSteward rather than terminating
// the process via logger.Fatal / os.Exit. Uses a non-existent config path to
// trigger a known-bad startup error from steward.NewStandalone.
func TestStandaloneStartErrorPropagatesToRunSteward(t *testing.T) {
	t.Setenv("CFGMS_LOG_DIR", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := runSteward(ctx, "", "/nonexistent/cfgms-config-does-not-exist.yaml")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create standalone steward")
}
