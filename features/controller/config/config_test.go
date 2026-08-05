// SPDX-License-Identifier: AGPL-3.0-only
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

// TestLoadWithPath_TransportEnvVarAppliesWhenSectionMissing was added in
// the Story #1919 fix-up after review feedback. The previous behaviour
// was to silently drop CFGMS_TRANSPORT_* env vars when the YAML config
// file omitted the `transport:` section entirely (cfg.Transport was nil
// at env-var application time and each env block was guarded by
// `&& cfg.Transport != nil`). The documented precedence is env > cfg >
// default, so an env-var set by the operator must always apply.
func TestLoadWithPath_TransportEnvVarAppliesWhenSectionMissing(t *testing.T) {
	// A minimal config YAML with NO transport: block. Mimics a
	// production config that wants to opt out of the canonical defaults
	// and configure the transport entirely via env vars (e.g. a green
	// controller standing up next to a blue one with shared cfg).
	dir := t.TempDir()
	cfgPath := dir + "/controller.cfg"
	require.NoError(t, os.WriteFile(cfgPath, []byte(`
listen_addr: ":9080"
external_url: "https://localhost:9080"
data_dir: "/tmp/cfgms-data"
log_level: "info"
`), 0o600))

	t.Setenv("CFGMS_TRANSPORT_LISTEN_ADDR", "0.0.0.0:4434")
	t.Setenv("CFGMS_TRANSPORT_MAX_CONNECTIONS", "9999")

	cfg, err := LoadWithPath(cfgPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Transport,
		"Transport must be materialised when env var is set, even if YAML omits the section")
	assert.Equal(t, "0.0.0.0:4434", cfg.Transport.ListenAddr,
		"CFGMS_TRANSPORT_LISTEN_ADDR must apply even when transport: section is omitted from YAML")
	assert.Equal(t, 9999, cfg.Transport.MaxConnections,
		"CFGMS_TRANSPORT_MAX_CONNECTIONS must apply even when transport: section is omitted from YAML")
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

// TestRegistrationConfig_GetIPTrustDarkWindow verifies the dark-window getter
// covers nil receiver, zero value, and configured value (Issue #1697).
func TestRegistrationConfig_GetIPTrustDarkWindow(t *testing.T) {
	var rc *RegistrationConfig
	assert.Equal(t, 30*24*time.Hour, rc.GetIPTrustDarkWindow(),
		"nil RegistrationConfig must default to 30 days")

	zero := &RegistrationConfig{}
	assert.Equal(t, 30*24*time.Hour, zero.GetIPTrustDarkWindow(),
		"zero IPTrustDarkWindow must default to 30 days")

	configured := &RegistrationConfig{IPTrustDarkWindow: Duration(7 * 24 * time.Hour)}
	assert.Equal(t, 7*24*time.Hour, configured.GetIPTrustDarkWindow(),
		"configured dark window must be returned unchanged")
}

// TestRegistrationConfig_GetPendingReviewTimeout verifies the pending timeout
// getter covers nil receiver, zero value, and configured value (Issue #1697).
func TestRegistrationConfig_GetPendingReviewTimeout(t *testing.T) {
	var rc *RegistrationConfig
	assert.Equal(t, 5*24*time.Hour, rc.GetPendingReviewTimeout(),
		"nil RegistrationConfig must default to 5 days")

	zero := &RegistrationConfig{}
	assert.Equal(t, 5*24*time.Hour, zero.GetPendingReviewTimeout(),
		"zero PendingReviewTimeout must default to 5 days")

	configured := &RegistrationConfig{PendingReviewTimeout: Duration(3 * 24 * time.Hour)}
	assert.Equal(t, 3*24*time.Hour, configured.GetPendingReviewTimeout(),
		"configured timeout must be returned unchanged")
}

// TestRegistrationConfig_DarkWindowAndTimeout_YAML verifies that
// ip_trust_dark_window and pending_review_timeout parse from YAML (Issue #1697).
// Uses non-default values (14 days / 3 days) so the assertion only passes when
// YAML unmarshaling actually populated the fields.
func TestRegistrationConfig_DarkWindowAndTimeout_YAML(t *testing.T) {
	yamlInput := "registration:\n  ip_trust_dark_window: 336h\n  pending_review_timeout: 72h\n"

	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))
	require.NotNil(t, cfg.Registration)

	assert.Equal(t, 14*24*time.Hour, cfg.Registration.GetIPTrustDarkWindow(),
		"336h must parse to 14 days")
	assert.Equal(t, 3*24*time.Hour, cfg.Registration.GetPendingReviewTimeout(),
		"72h must parse to 3 days")
}

// TestHAMode_YAML verifies that ha.mode: cluster is parsed correctly (Issue #2119).
func TestHAMode_YAML(t *testing.T) {
	yamlInput := "ha:\n  mode: cluster\n"

	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))

	require.NotNil(t, cfg.HA, "HA config must be populated when ha block is present")
	assert.Equal(t, "cluster", cfg.HA.Mode,
		"ha.mode: cluster must parse to the string \"cluster\"")
	assert.True(t, cfg.HA.IsClusterMode(), "IsClusterMode() must return true for mode=cluster")
}

// TestHAMode_YAML_Single verifies that ha.mode: single is parsed correctly.
func TestHAMode_YAML_Single(t *testing.T) {
	yamlInput := "ha:\n  mode: single\n"

	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))

	require.NotNil(t, cfg.HA)
	assert.Equal(t, "single", cfg.HA.Mode)
	assert.False(t, cfg.HA.IsClusterMode())
}

// TestHAMode_YAML_Absent verifies that omitting ha block leaves HA nil.
func TestHAMode_YAML_Absent(t *testing.T) {
	yamlInput := "listen_addr: \"127.0.0.1:8080\"\n"

	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))

	assert.Nil(t, cfg.HA, "HA config must be nil when the ha block is absent")
}

// TestHAModeEnvVar verifies that CFGMS_HA_MODE overrides ha.mode from YAML (Issue #2119).
func TestHAModeEnvVar(t *testing.T) {
	t.Setenv("CFGMS_HA_MODE", "cluster")
	// Clear CFGMS_STORAGE_CLUSTER_POSTGRES_DSN so it doesn't interfere.
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "")

	cfg, err := Load()
	require.NoError(t, err)

	require.NotNil(t, cfg.HA, "CFGMS_HA_MODE must materialise the HA config section")
	assert.Equal(t, "cluster", cfg.HA.Mode,
		"CFGMS_HA_MODE=cluster must set ha.Mode to \"cluster\"")
	assert.True(t, cfg.HA.IsClusterMode())
}

// TestClusterStorageConfig_YAML verifies that storage.cluster.postgres_dsn and
// storage.cluster.session_hmac_key are parsed (Issues #2119, #3127).
func TestClusterStorageConfig_YAML(t *testing.T) {
	yamlInput := `
storage:
  cluster:
    postgres_dsn: "host=pg.example.com port=5432 dbname=cfgms user=cfgms password=secret sslmode=require"
    session_hmac_key: "yaml-session-hmac-key"
    s3:
      bucket: "cfgms-installers"
      region: "us-east-1"
`
	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))

	require.NotNil(t, cfg.Storage.Cluster, "storage.cluster must be populated")
	assert.Equal(t,
		"host=pg.example.com port=5432 dbname=cfgms user=cfgms password=secret sslmode=require",
		cfg.Storage.Cluster.PostgresDSN)
	assert.Equal(t, "yaml-session-hmac-key", cfg.Storage.Cluster.SessionHMACKey,
		"storage.cluster.session_hmac_key must be parsed from YAML")
	require.NotNil(t, cfg.Storage.Cluster.S3)
	assert.Equal(t, "cfgms-installers", cfg.Storage.Cluster.S3["bucket"])
	assert.Equal(t, "us-east-1", cfg.Storage.Cluster.S3["region"])
}

// TestClusterStorageDSNEnvVar verifies that CFGMS_STORAGE_CLUSTER_POSTGRES_DSN overrides
// storage.cluster.postgres_dsn (Issue #2119).
func TestClusterStorageDSNEnvVar(t *testing.T) {
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "host=override.pg port=5432 dbname=cfgms user=cfgms password=test sslmode=disable")
	t.Setenv("CFGMS_HA_MODE", "") // clear so HA mode is not set by env

	cfg, err := Load()
	require.NoError(t, err)

	require.NotNil(t, cfg.Storage.Cluster,
		"CFGMS_STORAGE_CLUSTER_POSTGRES_DSN must materialise storage.cluster")
	assert.Equal(t,
		"host=override.pg port=5432 dbname=cfgms user=cfgms password=test sslmode=disable",
		cfg.Storage.Cluster.PostgresDSN)
}

// TestClusterStorageSessionHMACKeyEnvVar verifies that
// CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY materialises storage.cluster and populates
// storage.cluster.session_hmac_key when no config file supplies it (Issue #3127).
func TestClusterStorageSessionHMACKeyEnvVar(t *testing.T) {
	t.Setenv("CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY", "env-session-hmac-key")
	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "") // clear so only the HMAC key is set by env
	t.Setenv("CFGMS_HA_MODE", "")                      // clear so HA mode is not set by env

	cfg, err := Load()
	require.NoError(t, err)

	require.NotNil(t, cfg.Storage.Cluster,
		"CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY must materialise storage.cluster")
	assert.Equal(t, "env-session-hmac-key", cfg.Storage.Cluster.SessionHMACKey)
}

// TestClusterStorageSessionHMACKeyEnvVarOverridesYAML verifies that
// CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY takes precedence over a session_hmac_key
// supplied by the config file, and that an unset env var leaves the YAML value intact
// (Issue #3127). The key backs bearer-token hashing, so operators must be able to keep
// it out of the on-disk config.
func TestClusterStorageSessionHMACKeyEnvVarOverridesYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
storage:
  cluster:
    postgres_dsn: "host=pg.example.com port=5432 dbname=cfgms user=cfgms sslmode=require"
    session_hmac_key: "from-yaml"
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	t.Setenv("CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "") // clear so the YAML DSN is not overridden
	t.Setenv("CFGMS_HA_MODE", "")                      // clear so HA mode is not set by env

	// Env var unset: the YAML value survives.
	t.Setenv("CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY", "")
	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Storage.Cluster)
	assert.Equal(t, "from-yaml", cfg.Storage.Cluster.SessionHMACKey,
		"an empty env var must not clobber the config-file session_hmac_key")

	// Env var set: it wins over the YAML value.
	t.Setenv("CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY", "from-env")
	cfg, err = LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.Storage.Cluster)
	assert.Equal(t, "from-env", cfg.Storage.Cluster.SessionHMACKey,
		"CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY must override storage.cluster.session_hmac_key")
	assert.Equal(t, "host=pg.example.com port=5432 dbname=cfgms user=cfgms sslmode=require",
		cfg.Storage.Cluster.PostgresDSN,
		"overriding the HMAC key must not disturb the sibling postgres_dsn")
}

// --- Deployment Ring Config tests (Issue #2271) ---

// TestDeploymentRings_YAML_ParsesCorrectly verifies the deployment_rings section
// is parsed from YAML with all fields populated.
func TestDeploymentRings_YAML_ParsesCorrectly(t *testing.T) {
	yamlInput := `
deployment_rings:
  fallback_ring: early
  rings:
    - name: pre-release
      desired_version: "v0.6.0-rc1"
    - name: early
      desired_version: "v0.5.21"
      soak: 24h
      halt_threshold: 0.05
      concurrency_limit: 10
    - name: default
      desired_version: "v0.5.20"
    - name: stable
      desired_version: "v0.5.19"
`
	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))

	require.NotNil(t, cfg.DeploymentRings, "deployment_rings must be populated")
	assert.Equal(t, "early", cfg.DeploymentRings.FallbackRing)
	require.Len(t, cfg.DeploymentRings.Rings, 4)
	assert.Equal(t, "pre-release", cfg.DeploymentRings.Rings[0].Name)
	assert.Equal(t, "v0.6.0-rc1", cfg.DeploymentRings.Rings[0].DesiredVersion)
	assert.Equal(t, "early", cfg.DeploymentRings.Rings[1].Name)
	assert.Equal(t, "v0.5.21", cfg.DeploymentRings.Rings[1].DesiredVersion)
	assert.Equal(t, 24*time.Hour, cfg.DeploymentRings.Rings[1].Soak.AsDuration())
	assert.InDelta(t, 0.05, cfg.DeploymentRings.Rings[1].HaltThreshold, 1e-9)
	assert.Equal(t, 10, cfg.DeploymentRings.Rings[1].ConcurrencyLimit)
}

// TestDeploymentRings_Absent_LeavesNil verifies that omitting deployment_rings leaves the
// field nil, signalling use of the default ring set.
func TestDeploymentRings_Absent_LeavesNil(t *testing.T) {
	yamlInput := `listen_addr: "127.0.0.1:8080"` + "\n"

	cfg := &Config{}
	require.NoError(t, yaml.Unmarshal([]byte(yamlInput), cfg))

	assert.Nil(t, cfg.DeploymentRings, "deployment_rings must be nil when absent")
}

// TestValidateDeploymentRingConfig_Valid verifies that a well-formed ring config passes.
func TestValidateDeploymentRingConfig_Valid(t *testing.T) {
	rc := DeploymentRingConfig{
		FallbackRing: "default",
		Rings: []RingSpec{
			{Name: "pre-release"},
			{Name: "early"},
			{Name: "default", DesiredVersion: "v0.5.21"},
			{Name: "stable"},
		},
	}
	assert.NoError(t, ValidateDeploymentRingConfig(rc))
}

// TestValidateDeploymentRingConfig_RejectsDuplicateNames verifies that duplicate ring
// names are rejected at startup.
func TestValidateDeploymentRingConfig_RejectsDuplicateNames(t *testing.T) {
	rc := DeploymentRingConfig{
		FallbackRing: "early",
		Rings: []RingSpec{
			{Name: "early"},
			{Name: "default"},
			{Name: "early"}, // duplicate
		},
	}
	err := ValidateDeploymentRingConfig(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate ring name")
	assert.Contains(t, err.Error(), "early")
}

// TestValidateDeploymentRingConfig_RejectsUnknownFallbackRing verifies that a
// fallback_ring not in the declared set is rejected at startup.
func TestValidateDeploymentRingConfig_RejectsUnknownFallbackRing(t *testing.T) {
	rc := DeploymentRingConfig{
		FallbackRing: "canary",
		Rings: []RingSpec{
			{Name: "pre-release"},
			{Name: "default"},
		},
	}
	err := ValidateDeploymentRingConfig(rc)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fallback_ring")
	assert.Contains(t, err.Error(), "canary")
}

// TestValidateDeploymentRingConfig_RejectsInvalidName verifies that ring names not
// matching ^[a-z][a-z0-9-]{0,31}$ are rejected.
func TestValidateDeploymentRingConfig_RejectsInvalidName(t *testing.T) {
	tests := []struct {
		name    string
		invalid string
	}{
		{"uppercase", "Early"},
		{"starts-with-digit", "1early"},
		{"has-underscore", "early_ring"},
		{"too-long", "a" + "b0123456789012345678901234567890"}, // 33 chars
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rc := DeploymentRingConfig{
				Rings: []RingSpec{{Name: tt.invalid}},
			}
			err := ValidateDeploymentRingConfig(rc)
			require.Error(t, err, "ring name %q must be rejected", tt.invalid)
		})
	}
}

// TestConfig_ValidateDeploymentRings_AbsentIsNil verifies nil DeploymentRings is always valid.
func TestConfig_ValidateDeploymentRings_AbsentIsNil(t *testing.T) {
	cfg := &Config{}
	assert.NoError(t, cfg.ValidateDeploymentRings(),
		"nil DeploymentRings must be valid (defaults apply)")
}

// TestConfig_EffectiveRings_DefaultsApplied verifies EffectiveRings returns the four
// default rings when DeploymentRings is nil.
func TestConfig_EffectiveRings_DefaultsApplied(t *testing.T) {
	cfg := &Config{}
	rings := cfg.EffectiveRings()

	require.Len(t, rings.Rings, 4, "must return the four default rings")
	assert.Equal(t, "pre-release", rings.Rings[0].Name)
	assert.Equal(t, "early", rings.Rings[1].Name)
	assert.Equal(t, "default", rings.Rings[2].Name)
	assert.Equal(t, "stable", rings.Rings[3].Name)
	assert.Equal(t, "default", rings.FallbackRing)
}

// TestConfig_EffectiveRings_ConfigOverride verifies EffectiveRings returns the
// operator-configured rings when present, with fallback_ring defaulted to "default".
func TestConfig_EffectiveRings_ConfigOverride(t *testing.T) {
	cfg := &Config{
		DeploymentRings: &DeploymentRingConfig{
			Rings: []RingSpec{
				{Name: "beta", DesiredVersion: "v0.6.0"},
				{Name: "stable", DesiredVersion: "v0.5.21"},
			},
		},
		// FallbackRing deliberately left empty — should default to "default"
	}
	rings := cfg.EffectiveRings()

	require.Len(t, rings.Rings, 2)
	assert.Equal(t, "beta", rings.Rings[0].Name)
	assert.Equal(t, DefaultFallbackRing, rings.FallbackRing,
		"empty fallback_ring must default to the constant DefaultFallbackRing")
}

// TestDeploymentRings_LoadWithPath verifies deployment_rings is loaded from a config file.
func TestDeploymentRings_LoadWithPath(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "controller.cfg")

	content := `
deployment_rings:
  fallback_ring: default
  rings:
    - name: pre-release
      desired_version: "v0.6.0"
    - name: early
      desired_version: "v0.5.21"
    - name: default
      desired_version: "v0.5.20"
    - name: stable
      desired_version: "v0.5.19"
`
	require.NoError(t, os.WriteFile(configPath, []byte(content), 0600))

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	require.NotNil(t, cfg.DeploymentRings)
	assert.Len(t, cfg.DeploymentRings.Rings, 4)
	assert.Equal(t, "v0.6.0", cfg.DeploymentRings.Rings[0].DesiredVersion)
	assert.Equal(t, "default", cfg.DeploymentRings.FallbackRing)
}
