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

// TestLoadWithPath_MigrationFromMQTT verifies deprecated mqtt: section is migrated to transport:.
func TestLoadWithPath_MigrationFromMQTT(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
mqtt:
  listen_addr: "0.0.0.0:1883"
  use_cert_manager: false
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport, "Transport must be populated after MQTT migration")

	assert.Equal(t, "0.0.0.0:1883", cfg.Transport.ListenAddr,
		"mqtt.listen_addr must be migrated to transport.listen_addr")
	assert.False(t, cfg.Transport.UseCertManager,
		"mqtt.use_cert_manager must be migrated to transport.use_cert_manager")
}

// TestLoadWithPath_MigrationFromQUIC verifies deprecated quic: section is migrated to transport:.
func TestLoadWithPath_MigrationFromQUIC(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
quic:
  listen_addr: "0.0.0.0:9999"
  use_cert_manager: true
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport, "Transport must be populated after QUIC migration")

	assert.Equal(t, "0.0.0.0:9999", cfg.Transport.ListenAddr,
		"quic.listen_addr must be migrated to transport.listen_addr")
	assert.True(t, cfg.Transport.UseCertManager,
		"quic.use_cert_manager must be migrated to transport.use_cert_manager")
}

// TestLoadWithPath_QUICOverridesMQTTInMigration verifies that quic: takes priority over mqtt: when both present.
func TestLoadWithPath_QUICOverridesMQTTInMigration(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
mqtt:
  listen_addr: "0.0.0.0:1883"
  use_cert_manager: false
quic:
  listen_addr: "0.0.0.0:4433"
  use_cert_manager: true
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)

	// QUIC takes priority when both old sections are present
	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr,
		"quic.listen_addr must take priority over mqtt.listen_addr")
	assert.True(t, cfg.Transport.UseCertManager,
		"quic.use_cert_manager must take priority over mqtt.use_cert_manager")
}

// TestLoadWithPath_NewSectionOverridesOld verifies transport: wins when both old and new sections present.
func TestLoadWithPath_NewSectionOverridesOld(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
mqtt:
  listen_addr: "0.0.0.0:1883"
  use_cert_manager: false
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

	// transport: section wins
	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr,
		"transport: section must win over mqtt: section")
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

// TestLoadWithPath_MQTTListenAddrDeprecatedEnvVar verifies CFGMS_MQTT_LISTEN_ADDR maps to transport with deprecation.
func TestLoadWithPath_MQTTListenAddrDeprecatedEnvVar(t *testing.T) {
	// Ensure the new transport env var is not set
	t.Setenv("CFGMS_MQTT_LISTEN_ADDR", "0.0.0.0:9876")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)
	// Deprecated CFGMS_MQTT_LISTEN_ADDR should propagate to Transport when CFGMS_TRANSPORT_LISTEN_ADDR is not set
	assert.Equal(t, "0.0.0.0:9876", cfg.Transport.ListenAddr,
		"deprecated CFGMS_MQTT_LISTEN_ADDR must propagate to transport.listen_addr")
}

// TestLoadWithPath_TransportEnvVarWinsOverMQTTDeprecated verifies CFGMS_TRANSPORT_LISTEN_ADDR takes priority.
func TestLoadWithPath_TransportEnvVarWinsOverMQTTDeprecated(t *testing.T) {
	t.Setenv("CFGMS_MQTT_LISTEN_ADDR", "0.0.0.0:9876")
	t.Setenv("CFGMS_TRANSPORT_LISTEN_ADDR", "0.0.0.0:4433")

	cfg, err := Load()
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport)
	assert.Equal(t, "0.0.0.0:4433", cfg.Transport.ListenAddr,
		"CFGMS_TRANSPORT_LISTEN_ADDR must win over deprecated CFGMS_MQTT_LISTEN_ADDR")
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

// TestLoadWithPath_DefaultConfigHasTransportAlongsideLegacy verifies Config has Transport alongside MQTT.
func TestLoadWithPath_DefaultConfigHasTransportAlongsideLegacy(t *testing.T) {
	cfg := DefaultConfig()

	// Both sections must exist during Phase 10 transition
	require.NotNil(t, cfg.MQTT, "MQTT must remain for backward compat during Phase 10")
	require.NotNil(t, cfg.Transport, "Transport must be present as new unified section")
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
