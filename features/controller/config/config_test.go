// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestDefaultConfig_TransportPopulated verifies DefaultConfig returns a Transport section with sensible defaults.
func TestDefaultConfig_TransportPopulated(t *testing.T) {
	cfg := DefaultConfig()
	require.NotNil(t, cfg.Transport, "Transport must be populated in DefaultConfig")

	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr)
	assert.True(t, cfg.Transport.UseCertManager)
	assert.Equal(t, 50000, cfg.Transport.MaxConnections)
	assert.Equal(t, 30*time.Second, cfg.Transport.KeepalivePeriod.AsDuration())
	assert.Equal(t, 5*time.Minute, cfg.Transport.IdleTimeout.AsDuration())
}

// TestTransportConfig_Validate_Valid verifies that a valid TransportConfig passes validation.
func TestTransportConfig_Validate_Valid(t *testing.T) {
	tc := &TransportConfig{
		ListenAddr:      "0.0.0.0:4433",
		UseCertManager:  true,
		MaxConnections:  1000,
		KeepalivePeriod: Duration(30 * time.Second),
		IdleTimeout:     Duration(5 * time.Minute),
	}
	assert.NoError(t, tc.Validate())
}

// TestTransportConfig_Validate_RejectsEmptyListenAddr verifies validation rejects empty listen_addr.
func TestTransportConfig_Validate_RejectsEmptyListenAddr(t *testing.T) {
	tc := &TransportConfig{
		ListenAddr:      "",
		MaxConnections:  1000,
		KeepalivePeriod: Duration(30 * time.Second),
	}
	err := tc.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen_addr")
}

// TestTransportConfig_Validate_RejectsZeroMaxConnections verifies validation rejects max_connections < 1.
func TestTransportConfig_Validate_RejectsZeroMaxConnections(t *testing.T) {
	tests := []struct {
		name string
		val  int
	}{
		{name: "zero", val: 0},
		{name: "negative", val: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TransportConfig{
				ListenAddr:      "0.0.0.0:4433",
				MaxConnections:  tt.val,
				KeepalivePeriod: Duration(30 * time.Second),
			}
			err := tc.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "max_connections")
		})
	}
}

// TestTransportConfig_Validate_RejectsShortKeepalive verifies validation rejects keepalive_period < 1s.
func TestTransportConfig_Validate_RejectsShortKeepalive(t *testing.T) {
	tests := []struct {
		name string
		dur  time.Duration
	}{
		{name: "zero", dur: 0},
		{name: "500ms", dur: 500 * time.Millisecond},
		{name: "999ms", dur: 999 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tc := &TransportConfig{
				ListenAddr:      "0.0.0.0:4433",
				MaxConnections:  1000,
				KeepalivePeriod: Duration(tt.dur),
			}
			err := tc.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "keepalive_period")
		})
	}
}

// TestTransportConfig_Validate_AcceptsExactlyOneSecondKeepalive verifies exactly 1s keepalive is valid.
func TestTransportConfig_Validate_AcceptsExactlyOneSecondKeepalive(t *testing.T) {
	tc := &TransportConfig{
		ListenAddr:      "0.0.0.0:4433",
		MaxConnections:  1,
		KeepalivePeriod: Duration(time.Second),
	}
	assert.NoError(t, tc.Validate())
}

// TestLoadWithPath_TransportSectionLoaded verifies the transport: YAML section is loaded correctly.
func TestLoadWithPath_TransportSectionLoaded(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
transport:
  listen_addr: "0.0.0.0:5555"
  use_cert_manager: true
  max_connections: 25000
  keepalive_period: 1m
  idle_timeout: 10m
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)

	assert.Equal(t, "0.0.0.0:5555", cfg.Transport.ListenAddr)
	assert.True(t, cfg.Transport.UseCertManager)
	assert.Equal(t, 25000, cfg.Transport.MaxConnections)
	assert.Equal(t, time.Minute, cfg.Transport.KeepalivePeriod.AsDuration())
	assert.Equal(t, 10*time.Minute, cfg.Transport.IdleTimeout.AsDuration())
}

// TestLoadWithPath_TransportSectionFromYAML verifies transport: section is loaded from YAML.
func TestLoadWithPath_TransportSectionFromYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
transport:
  listen_addr: "0.0.0.0:4433"
  use_cert_manager: true
  max_connections: 50000
  keepalive_period: 30s
  idle_timeout: 5m
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)

	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr)
	assert.True(t, cfg.Transport.UseCertManager)
}

// TestLoadWithPath_TransportEnvVar verifies CFGMS_TRANSPORT_LISTEN_ADDR overrides config.
func TestLoadWithPath_TransportEnvVar(t *testing.T) {
	t.Setenv("CFGMS_TRANSPORT_LISTEN_ADDR", "0.0.0.0:7777")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)
	assert.Equal(t, "0.0.0.0:7777", cfg.Transport.ListenAddr)
}

// TestLoadWithPath_TransportMaxConnectionsEnvVar verifies CFGMS_TRANSPORT_MAX_CONNECTIONS env var.
func TestLoadWithPath_TransportMaxConnectionsEnvVar(t *testing.T) {
	t.Setenv("CFGMS_TRANSPORT_MAX_CONNECTIONS", "12345")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)
	assert.Equal(t, 12345, cfg.Transport.MaxConnections)
}

// TestLoadWithPath_TransportKeepaliveEnvVar verifies CFGMS_TRANSPORT_KEEPALIVE_PERIOD env var.
func TestLoadWithPath_TransportKeepaliveEnvVar(t *testing.T) {
	t.Setenv("CFGMS_TRANSPORT_KEEPALIVE_PERIOD", "2m")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)
	assert.Equal(t, 2*time.Minute, cfg.Transport.KeepalivePeriod.AsDuration())
}

// TestLoadWithPath_TransportListenAddrEnvVar verifies CFGMS_TRANSPORT_LISTEN_ADDR overrides config.
func TestLoadWithPath_TransportListenAddrEnvVar(t *testing.T) {
	t.Setenv("CFGMS_TRANSPORT_LISTEN_ADDR", "0.0.0.0:4433")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)
	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr,
		"CFGMS_TRANSPORT_LISTEN_ADDR must override transport.listen_addr")
}

// TestDuration_UnmarshalYAML verifies Duration type parses human-readable strings from YAML.
func TestDuration_UnmarshalYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
transport:
  listen_addr: "0.0.0.0:4433"
  use_cert_manager: true
  max_connections: 1000
  keepalive_period: 45s
  idle_timeout: 15m
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)

	assert.Equal(t, 45*time.Second, cfg.Transport.KeepalivePeriod.AsDuration())
	assert.Equal(t, 15*time.Minute, cfg.Transport.IdleTimeout.AsDuration())
}

// TestDuration_AsDuration verifies AsDuration returns the underlying time.Duration.
func TestDuration_AsDuration(t *testing.T) {
	d := Duration(30 * time.Second)
	assert.Equal(t, 30*time.Second, d.AsDuration())
}

// TestLoadWithPath_DefaultConfigHasTransport verifies Config has Transport section.
func TestLoadWithPath_DefaultConfigHasTransport(t *testing.T) {
	cfg := DefaultConfig()

	require.NotNil(t, cfg.Transport, "Transport must be present as unified section")
}

// TestLoadWithPath_NoConfigFileUsesDefaults verifies defaults are used when no config file exists.
func TestLoadWithPath_NoConfigFileUsesDefaults(t *testing.T) {
	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)

	// Should have the same defaults as DefaultConfig
	defaults := DefaultConfig()
	assert.Equal(t, defaults.Transport.ListenAddr, cfg.Transport.ListenAddr)
	assert.Equal(t, defaults.Transport.MaxConnections, cfg.Transport.MaxConnections)
	assert.Equal(t, defaults.Transport.KeepalivePeriod, cfg.Transport.KeepalivePeriod)
	assert.Equal(t, defaults.Transport.IdleTimeout, cfg.Transport.IdleTimeout)
}

// TestRegistrationConfigDefaults verifies that a config YAML with no registration block
// leaves Registration nil, signalling the server to seed the auto-approve workflow (Issue #1527).
func TestRegistrationConfigDefaults(t *testing.T) {
	yamlInput := `listen_addr: "127.0.0.1:8080"` + "\n"

	cfg := &Config{}
	err := yaml.Unmarshal([]byte(yamlInput), cfg)
	require.NoError(t, err)

	assert.Nil(t, cfg.Registration, "Registration should be nil when no registration block is present")
}

// TestRegistrationConfigManualReview verifies that a config YAML with registration.workflow: manual-review
// is parsed correctly (Issue #1527).
func TestRegistrationConfigManualReview(t *testing.T) {
	yamlInput := "registration:\n  workflow: manual-review\n"

	cfg := &Config{}
	err := yaml.Unmarshal([]byte(yamlInput), cfg)
	require.NoError(t, err)

	require.NotNil(t, cfg.Registration)
	assert.Equal(t, "manual-review", cfg.Registration.Workflow)
}

// TestRegistrationConfigAutoApprove verifies that an explicit auto-approve workflow value is parsed (Issue #1527).
func TestRegistrationConfigAutoApprove(t *testing.T) {
	yamlInput := "registration:\n  workflow: auto-approve\n"

	cfg := &Config{}
	err := yaml.Unmarshal([]byte(yamlInput), cfg)
	require.NoError(t, err)

	require.NotNil(t, cfg.Registration)
	assert.Equal(t, "auto-approve", cfg.Registration.Workflow)
}

// TestLoadWithPath_RegistrationWorkflowEnvVar verifies CFGMS_REGISTRATION_WORKFLOW
// creates the Registration section when absent and sets the workflow (Issue #1695).
func TestLoadWithPath_RegistrationWorkflowEnvVar(t *testing.T) {
	t.Setenv("CFGMS_REGISTRATION_WORKFLOW", "auto-approve")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Registration,
		"CFGMS_REGISTRATION_WORKFLOW must create the Registration section when absent")
	assert.Equal(t, "auto-approve", cfg.Registration.Workflow)
}

// TestLoadWithPath_RegistrationWorkflowEnvVarOverridesFile verifies the env var
// overrides a workflow value loaded from the config file (Issue #1695).
func TestLoadWithPath_RegistrationWorkflowEnvVarOverridesFile(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")
	require.NoError(t, os.WriteFile(configPath,
		[]byte("registration:\n  workflow: manual-review\n"), 0600))

	t.Setenv("CFGMS_REGISTRATION_WORKFLOW", "auto-approve")

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Registration)
	assert.Equal(t, "auto-approve", cfg.Registration.Workflow,
		"CFGMS_REGISTRATION_WORKFLOW must override registration.workflow from the config file")
}

// TestLoadWithPath_RegistrationWorkflowUnsetLeavesDefault verifies an unset
// env var does not create or mutate the Registration section (Issue #1695).
func TestLoadWithPath_RegistrationWorkflowUnsetLeavesDefault(t *testing.T) {
	// Explicitly clear the env var so the test is deterministic even if a CI
	// runner sets CFGMS_REGISTRATION_WORKFLOW in its ambient environment.
	t.Setenv("CFGMS_REGISTRATION_WORKFLOW", "")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Nil(t, cfg.Registration,
		"Registration must stay nil when CFGMS_REGISTRATION_WORKFLOW is unset and no config file is present")
}

// TestRegistrationConfig_GetIPTrustThreshold verifies the IP-trust threshold
// getter covers all three cases: nil receiver, zero value, and configured value
// (Issue #1694).
func TestRegistrationConfig_GetIPTrustThreshold(t *testing.T) {
	// Nil receiver returns the 30-minute default.
	var rc *RegistrationConfig
	assert.Equal(t, 30*time.Minute, rc.GetIPTrustThreshold(),
		"nil RegistrationConfig must default to 30 minutes")

	// Zero value returns the 30-minute default.
	zero := &RegistrationConfig{}
	assert.Equal(t, 30*time.Minute, zero.GetIPTrustThreshold(),
		"zero IPTrustThreshold must default to 30 minutes")

	// Configured value is returned as-is.
	configured := &RegistrationConfig{IPTrustThreshold: Duration(45 * time.Minute)}
	assert.Equal(t, 45*time.Minute, configured.GetIPTrustThreshold(),
		"configured threshold must be returned unchanged")
}

// TestRegistrationConfig_IPTrustThreshold_YAML verifies that the ip_trust_threshold
// field is correctly parsed from YAML (Issue #1694).
func TestRegistrationConfig_IPTrustThreshold_YAML(t *testing.T) {
	yamlInput := "registration:\n  workflow: manual-review\n  ip_trust_threshold: 45m\n"

	cfg := &Config{}
	err := yaml.Unmarshal([]byte(yamlInput), cfg)
	require.NoError(t, err)

	require.NotNil(t, cfg.Registration)
	assert.Equal(t, 45*time.Minute, cfg.Registration.GetIPTrustThreshold(),
		"ip_trust_threshold must be parsed from YAML duration string")
}
