// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

package main

import (
	"testing"
	"time"

	"github.com/cfgis/cfgms/cmd/steward/service"
	"github.com/cfgis/cfgms/features/steward/registration"
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

	for _, name := range []string{"config", "mode", "log-level", "log-provider", "regtoken"} {
		flag := cmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "expected flag %q to be registered", name)
	}

	// Verify defaults.
	assert.Equal(t, "info", cmd.Flags().Lookup("log-level").DefValue)
	assert.Equal(t, "file", cmd.Flags().Lookup("log-provider").DefValue)
}

func TestRunInstallRequiresToken(t *testing.T) {
	err := runInstall("", "info", "file")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "--regtoken is required")
}

func TestRunInstallRequiresElevation(t *testing.T) {
	if isElevated() {
		t.Skip("test requires non-elevated process — running as root")
	}
	err := runInstall("tok_test_abc123", "info", "file")
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

// TestRegisterAndConnectIgnoresInsecureEnvVar asserts that setting
// CFGMS_HTTP_INSECURE_SKIP_VERIFY=true has no observable effect on the HTTP
// registration client. The env var was removed from registerAndConnect; this
// test documents that guarantee. TLS enforcement is verified structurally:
// HTTPConfig has no InsecureSkipVerify field, so the env var cannot be wired in.
func TestRegisterAndConnectIgnoresInsecureEnvVar(t *testing.T) {
	t.Setenv("CFGMS_HTTP_INSECURE_SKIP_VERIFY", "true")

	logger := logging.NewLogger("info")

	// Construct a client the same way registerAndConnect does after the fix.
	// HTTPConfig has no InsecureSkipVerify field — the env var cannot influence it.
	client, err := registration.NewHTTPClient(&registration.HTTPConfig{
		ControllerURL: "https://controller.example.com",
		Timeout:       30 * time.Second,
		Logger:        logger,
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	// The env var is set to "true" but must have no effect on TLS enforcement.
	// TransportInsecureSkipVerify() reads the underlying transport's TLSClientConfig
	// and returns false when TLSClientConfig is nil (Go default: always verify).
	assert.False(t, client.TransportInsecureSkipVerify(),
		"CFGMS_HTTP_INSECURE_SKIP_VERIFY=true must have no effect — TLS is always enforced")
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
