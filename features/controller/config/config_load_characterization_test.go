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
)

// Characterization tests for LoadWithPath (Issue #5820). They pin the current
// behavior of the file stage, the stage order and every environment override so
// the function can be decomposed without changing behavior.

var configloadCharEnvVars = []string{
	"CFGMS_SECURITY_PROFILE", "CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC", "CFGMS_LISTEN_ADDR",
	"CFGMS_METRICS_LISTEN_ADDR", "CFGMS_EXTERNAL_URL", "CFGMS_CERT_PATH", "CFGMS_DATA_DIR",
	"CFGMS_LOG_LEVEL", "CFGMS_CERT_ENABLE_MANAGEMENT", "CFGMS_CERT_CA_PATH",
	"CFGMS_CERT_RENEWAL_THRESHOLD_DAYS", "CFGMS_CERT_SERVER_VALIDITY_DAYS",
	"CFGMS_CERT_CLIENT_VALIDITY_DAYS", "CFGMS_CERT_SERVER_COMMON_NAME",
	"CFGMS_CERT_SERVER_ORGANIZATION", "CFGMS_CERT_ARCHITECTURE", "CFGMS_CERT_SIGNING_VALIDITY_DAYS",
	"CFGMS_CERT_PUBLIC_API_SOURCE", "CFGMS_CERT_PUBLIC_API_CERT_PATH", "CFGMS_CERT_PUBLIC_API_KEY_PATH",
	"CFGMS_STORAGE_PROVIDER", "CFGMS_STORAGE_DATABASE_HOST", "CFGMS_DB_HOST",
	"CFGMS_STORAGE_DATABASE_PORT", "CFGMS_DB_PORT", "CFGMS_STORAGE_DATABASE_NAME", "CFGMS_DB_NAME",
	"CFGMS_STORAGE_DATABASE_USER", "CFGMS_DB_USER", "CFGMS_STORAGE_DATABASE_PASSWORD", "CFGMS_DB_PASSWORD",
	"CFGMS_STORAGE_DATABASE_SSLMODE", "CFGMS_DB_SSLMODE", "CFGMS_STORAGE_GIT_PATH", "CFGMS_STORAGE_GIT_URL",
	"CFGMS_STORAGE_GIT_BRANCH", "CFGMS_STORAGE_GIT_USERNAME", "CFGMS_STORAGE_GIT_PASSWORD",
	"CFGMS_STORAGE_GIT_TOKEN", "CFGMS_LOGGING_PROVIDER", "CFGMS_LOGGING_SERVICE_NAME",
	"CFGMS_LOGGING_COMPONENT", "CFGMS_TRANSPORT_LISTEN_ADDR", "CFGMS_TRANSPORT_USE_CERT_MANAGER",
	"CFGMS_TRANSPORT_MAX_CONNECTIONS", "CFGMS_TRANSPORT_KEEPALIVE_PERIOD", "CFGMS_TRANSPORT_IDLE_TIMEOUT",
	"CFGMS_HTTP_LISTEN_ADDR", "CFGMS_REGISTRATION_WORKFLOW", "CFGMS_HA_MODE",
	"CFGMS_STORAGE_CLUSTER_POSTGRES_DSN", "CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY", "CFGMS_AUDIT_SINK",
	"CFGMS_CLUSTER_CA_VAULT_ADDRESS", "CFGMS_CLUSTER_CA_VAULT_KEY_PATH", "CFGMS_CONTROLLER_CONFIG",
}

// configloadCharLoad clears every override variable, applies env, writes yaml
// under t.TempDir() and loads it.
func configloadCharLoad(t *testing.T, yamlText string, env map[string]string) (*Config, error) {
	t.Helper()
	for _, k := range configloadCharEnvVars {
		t.Setenv(k, "")
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	path := filepath.Join(t.TempDir(), "controller.cfg")
	require.NoError(t, os.WriteFile(path, []byte(yamlText), 0600))
	return LoadWithPath(path)
}

func TestConfigloadChar_EnvOverrides(t *testing.T) {
	cases := []struct {
		name  string
		env   map[string]string
		check func(t *testing.T, c *Config)
	}{
		{"listen addr", map[string]string{"CFGMS_LISTEN_ADDR": "127.0.0.1:1"}, func(t *testing.T, c *Config) { assert.Equal(t, "127.0.0.1:1", c.ListenAddr) }},
		{"http listen addr wins over listen addr", map[string]string{"CFGMS_LISTEN_ADDR": "127.0.0.1:1", "CFGMS_HTTP_LISTEN_ADDR": "127.0.0.1:2"}, func(t *testing.T, c *Config) { assert.Equal(t, "127.0.0.1:2", c.ListenAddr) }},
		{"metrics addr", map[string]string{"CFGMS_METRICS_LISTEN_ADDR": "127.0.0.1:3"}, func(t *testing.T, c *Config) { assert.Equal(t, "127.0.0.1:3", c.MetricsListenAddr) }},
		{"external url", map[string]string{"CFGMS_EXTERNAL_URL": "https://x.example"}, func(t *testing.T, c *Config) { assert.Equal(t, "https://x.example", c.ExternalURL) }},
		{"cert path", map[string]string{"CFGMS_CERT_PATH": "/abs/certs"}, func(t *testing.T, c *Config) { assert.Equal(t, "/abs/certs", c.CertPath) }},
		{"data dir", map[string]string{"CFGMS_DATA_DIR": "/abs/data"}, func(t *testing.T, c *Config) { assert.Equal(t, "/abs/data", c.DataDir) }},
		{"log level sets both", map[string]string{"CFGMS_LOG_LEVEL": "debug"}, func(t *testing.T, c *Config) {
			assert.Equal(t, "debug", c.LogLevel)
			assert.Equal(t, "debug", c.Logging.Level)
		}},
		{"signed adhoc", map[string]string{"CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC": " true "}, func(t *testing.T, c *Config) { assert.True(t, c.Execution.RequireSignedAdhoc) }},
		{"cert mgmt disable", map[string]string{"CFGMS_CERT_ENABLE_MANAGEMENT": "false"}, func(t *testing.T, c *Config) { assert.False(t, c.Certificate.EnableCertManagement) }},
		{"cert mgmt invalid ignored", map[string]string{"CFGMS_CERT_ENABLE_MANAGEMENT": "zzz"}, func(t *testing.T, c *Config) { assert.True(t, c.Certificate.EnableCertManagement) }},
		{"ca path", map[string]string{"CFGMS_CERT_CA_PATH": "/x/ca"}, func(t *testing.T, c *Config) { assert.Equal(t, "/x/ca", c.Certificate.CAPath) }},
		{"renewal days", map[string]string{"CFGMS_CERT_RENEWAL_THRESHOLD_DAYS": "7"}, func(t *testing.T, c *Config) { assert.Equal(t, 7, c.Certificate.RenewalThresholdDays) }},
		{"renewal days invalid ignored", map[string]string{"CFGMS_CERT_RENEWAL_THRESHOLD_DAYS": "x"}, func(t *testing.T, c *Config) {
			assert.Equal(t, DefaultConfig().Certificate.RenewalThresholdDays, c.Certificate.RenewalThresholdDays)
		}},
		{"server validity", map[string]string{"CFGMS_CERT_SERVER_VALIDITY_DAYS": "11"}, func(t *testing.T, c *Config) { assert.Equal(t, 11, c.Certificate.ServerCertValidityDays) }},
		{"client validity", map[string]string{"CFGMS_CERT_CLIENT_VALIDITY_DAYS": "12"}, func(t *testing.T, c *Config) { assert.Equal(t, 12, c.Certificate.ClientCertValidityDays) }},
		{"signing validity", map[string]string{"CFGMS_CERT_SIGNING_VALIDITY_DAYS": "13"}, func(t *testing.T, c *Config) { assert.Equal(t, 13, c.Certificate.SigningCertValidityDays) }},
		{"server cn", map[string]string{"CFGMS_CERT_SERVER_COMMON_NAME": "cn-a"}, func(t *testing.T, c *Config) { assert.Equal(t, "cn-a", c.Certificate.Server.CommonName) }},
		{"server org", map[string]string{"CFGMS_CERT_SERVER_ORGANIZATION": "org-a"}, func(t *testing.T, c *Config) { assert.Equal(t, "org-a", c.Certificate.Server.Organization) }},
		{"cert architecture", map[string]string{"CFGMS_CERT_ARCHITECTURE": "unified"}, func(t *testing.T, c *Config) { assert.Equal(t, "unified", c.Certificate.Architecture) }},
		{"public api source", map[string]string{"CFGMS_CERT_PUBLIC_API_SOURCE": "file"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Certificate.PublicAPI)
			assert.Equal(t, "file", c.Certificate.PublicAPI.Source)
		}},
		{"public api cert and key", map[string]string{"CFGMS_CERT_PUBLIC_API_CERT_PATH": "/p/c.pem", "CFGMS_CERT_PUBLIC_API_KEY_PATH": "/p/k.pem"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Certificate.PublicAPI)
			assert.Equal(t, "/p/c.pem", c.Certificate.PublicAPI.CertPath)
			assert.Equal(t, "/p/k.pem", c.Certificate.PublicAPI.KeyPath)
		}},
		{"database primary vars", map[string]string{
			"CFGMS_STORAGE_PROVIDER": "database", "CFGMS_STORAGE_DATABASE_HOST": "h1", "CFGMS_STORAGE_DATABASE_PORT": "5433",
			"CFGMS_STORAGE_DATABASE_NAME": "n1", "CFGMS_STORAGE_DATABASE_USER": "u1", "CFGMS_STORAGE_DATABASE_PASSWORD": "p1",
			"CFGMS_STORAGE_DATABASE_SSLMODE": "require",
			"CFGMS_DB_HOST":                  "h2", "CFGMS_DB_PORT": "1", "CFGMS_DB_NAME": "n2", "CFGMS_DB_USER": "u2", "CFGMS_DB_PASSWORD": "p2", "CFGMS_DB_SSLMODE": "disable",
		}, func(t *testing.T, c *Config) {
			assert.Equal(t, "database", c.Storage.Provider)
			assert.Equal(t, map[string]interface{}{"host": "h1", "port": 5433, "database": "n1", "username": "u1", "password": "p1", "sslmode": "require"}, c.Storage.Config)
		}},
		{"database fallback vars", map[string]string{
			"CFGMS_STORAGE_PROVIDER": "database", "CFGMS_DB_HOST": "h2", "CFGMS_DB_PORT": "6543", "CFGMS_DB_NAME": "n2",
			"CFGMS_DB_USER": "u2", "CFGMS_DB_PASSWORD": "p2", "CFGMS_DB_SSLMODE": "disable",
		}, func(t *testing.T, c *Config) {
			assert.Equal(t, map[string]interface{}{"host": "h2", "port": 6543, "database": "n2", "username": "u2", "password": "p2", "sslmode": "disable"}, c.Storage.Config)
		}},
		{"database invalid primary port does not fall back", map[string]string{
			"CFGMS_STORAGE_PROVIDER": "database", "CFGMS_STORAGE_DATABASE_PORT": "bad", "CFGMS_DB_PORT": "6543",
		}, func(t *testing.T, c *Config) { assert.NotContains(t, c.Storage.Config, "port") }},
		{"database invalid fallback port ignored", map[string]string{
			"CFGMS_STORAGE_PROVIDER": "database", "CFGMS_DB_PORT": "bad",
		}, func(t *testing.T, c *Config) { assert.NotContains(t, c.Storage.Config, "port") }},
		{"git vars", map[string]string{
			"CFGMS_STORAGE_PROVIDER": "git", "CFGMS_STORAGE_GIT_PATH": "/g", "CFGMS_STORAGE_GIT_URL": "https://g.example/r.git",
			"CFGMS_STORAGE_GIT_BRANCH": "main", "CFGMS_STORAGE_GIT_USERNAME": "gu", "CFGMS_STORAGE_GIT_PASSWORD": "gp", "CFGMS_STORAGE_GIT_TOKEN": "gt",
		}, func(t *testing.T, c *Config) {
			assert.Equal(t, map[string]interface{}{"path": "/g", "url": "https://g.example/r.git", "branch": "main", "username": "gu", "password": "gp", "token": "gt"}, c.Storage.Config)
		}},
		{"other provider ignores db vars", map[string]string{"CFGMS_STORAGE_PROVIDER": "other", "CFGMS_DB_HOST": "h"}, func(t *testing.T, c *Config) {
			assert.Equal(t, "other", c.Storage.Provider)
			assert.NotNil(t, c.Storage.Config)
			assert.NotContains(t, c.Storage.Config, "host")
		}},
		{"logging", map[string]string{"CFGMS_LOGGING_PROVIDER": "lp", "CFGMS_LOGGING_SERVICE_NAME": "svc", "CFGMS_LOGGING_COMPONENT": "cmp"}, func(t *testing.T, c *Config) {
			assert.Equal(t, "lp", c.Logging.Provider)
			assert.Equal(t, "svc", c.Logging.ServiceName)
			assert.Equal(t, "cmp", c.Logging.Component)
		}},
		{"transport all", map[string]string{
			"CFGMS_TRANSPORT_LISTEN_ADDR": "127.0.0.1:4", "CFGMS_TRANSPORT_USE_CERT_MANAGER": "true", "CFGMS_TRANSPORT_MAX_CONNECTIONS": "9",
			"CFGMS_TRANSPORT_KEEPALIVE_PERIOD": "5s", "CFGMS_TRANSPORT_IDLE_TIMEOUT": "7m",
		}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Transport)
			assert.Equal(t, "127.0.0.1:4", c.Transport.ListenAddr)
			assert.True(t, c.Transport.UseCertManager)
			assert.Equal(t, 9, c.Transport.MaxConnections)
			assert.Equal(t, 5*time.Second, c.Transport.KeepalivePeriod.AsDuration())
			assert.Equal(t, 7*time.Minute, c.Transport.IdleTimeout.AsDuration())
		}},
		{"transport invalid values ignored", map[string]string{
			"CFGMS_TRANSPORT_USE_CERT_MANAGER": "x", "CFGMS_TRANSPORT_MAX_CONNECTIONS": "x", "CFGMS_TRANSPORT_KEEPALIVE_PERIOD": "x", "CFGMS_TRANSPORT_IDLE_TIMEOUT": "x",
		}, func(t *testing.T, c *Config) {
			assert.Equal(t, DefaultConfig().Transport, c.Transport)
		}},
		{"registration workflow", map[string]string{"CFGMS_REGISTRATION_WORKFLOW": "auto-approve"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Registration)
			assert.Equal(t, "auto-approve", c.Registration.Workflow)
		}},
		{"ha mode lowercased", map[string]string{"CFGMS_HA_MODE": "Blue-Green"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.HA)
			assert.Equal(t, "blue-green", c.HA.Mode)
		}},
		{"cluster storage", map[string]string{"CFGMS_STORAGE_CLUSTER_POSTGRES_DSN": "postgres://x/y", "CFGMS_STORAGE_CLUSTER_SESSION_HMAC_KEY": "k"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Storage.Cluster)
			assert.Equal(t, "postgres://x/y", c.Storage.Cluster.PostgresDSN)
			assert.Equal(t, "k", c.Storage.Cluster.SessionHMACKey)
		}},
		{"audit sink lowercased", map[string]string{"CFGMS_AUDIT_SINK": "LOCAL"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Audit)
			assert.Equal(t, "local", c.Audit.Sink)
		}},
		{"cluster ca vault", map[string]string{"CFGMS_CLUSTER_CA_VAULT_ADDRESS": "https://v:8200", "CFGMS_CLUSTER_CA_VAULT_KEY_PATH": "transit/k"}, func(t *testing.T, c *Config) {
			require.NotNil(t, c.Certificate.ClusterCA)
			assert.Equal(t, "https://v:8200", c.Certificate.ClusterCA.VaultAddress)
			assert.Equal(t, "transit/k", c.Certificate.ClusterCA.VaultKeyPath)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", tc.env)
			require.NoError(t, err)
			tc.check(t, cfg)
		})
	}
}

func TestConfigloadChar_EnvOverridesWinOverFile(t *testing.T) {
	cfg, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:1\"\ndata_dir: /file/data\n",
		map[string]string{"CFGMS_DATA_DIR": "/env/data"})
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1:1", cfg.ListenAddr)
	assert.Equal(t, "/env/data", cfg.DataDir)
}

func TestConfigloadChar_StageOrderAndErrors(t *testing.T) {
	t.Run("missing explicit path", func(t *testing.T) {
		_, err := LoadWithPath(filepath.Join(t.TempDir(), "absent.cfg"))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "config file not found at specified path")
	})
	t.Run("unreadable path is a directory", func(t *testing.T) {
		_, err := LoadWithPath(t.TempDir())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read config file")
	})
	t.Run("literal secret refused before expansion", func(t *testing.T) {
		// The referenced variable is unset, which would fail the env check; the
		// literal-secret refusal must come first.
		_, err := configloadCharLoad(t, "storage:\n  cluster:\n    session_hmac_key: literal-secret\n    postgres_dsn: ${CONFIGLOAD_CHAR_UNSET}\n", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configuration validation failed in")
		assert.Contains(t, err.Error(), "literal secret refused in storage.cluster.session_hmac_key")
		assert.NotContains(t, err.Error(), "literal-secret\"")
	})
	t.Run("unset referenced env var refused", func(t *testing.T) {
		_, err := configloadCharLoad(t, "data_dir: ${CONFIGLOAD_CHAR_UNSET}\n", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "configuration validation failed in")
		assert.Contains(t, err.Error(), "CONFIGLOAD_CHAR_UNSET")
	})
	t.Run("env reference expanded", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "data_dir: ${CONFIGLOAD_CHAR_SET}\n", map[string]string{"CONFIGLOAD_CHAR_SET": "/expanded"})
		require.NoError(t, err)
		assert.Equal(t, "/expanded", cfg.DataDir)
	})
	t.Run("default expanded", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "data_dir: ${CONFIGLOAD_CHAR_UNSET:-/fallback}\n", nil)
		require.NoError(t, err)
		assert.Equal(t, "/fallback", cfg.DataDir)
	})
	t.Run("parse error", func(t *testing.T) {
		_, err := configloadCharLoad(t, "listen_addr: [unterminated\n", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse config file")
	})
	t.Run("relative cert_path anchored to config dir", func(t *testing.T) {
		for _, k := range configloadCharEnvVars {
			t.Setenv(k, "")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "controller.cfg")
		require.NoError(t, os.WriteFile(path, []byte("cert_path: certs\n"), 0600))
		cfg, err := LoadWithPath(path)
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(dir, "certs"), cfg.CertPath)
	})
	t.Run("env cert path not anchored", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "cert_path: certs\n", map[string]string{"CFGMS_CERT_PATH": "rel/certs"})
		require.NoError(t, err)
		assert.Equal(t, "rel/certs", cfg.CertPath)
	})
	t.Run("invalid signed adhoc value", func(t *testing.T) {
		_, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", map[string]string{"CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC": "maybe"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `invalid CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC value "maybe"`)
	})
}

func TestConfigloadChar_SecurityProfileOrder(t *testing.T) {
	const publicBetaFile = "security_profile: public-beta\nexecution:\n  require_signed_adhoc: true\ntransport:\n  listen_addr: \"127.0.0.1:4433\"\n  use_cert_manager: true\n  max_connections: 10\n  keepalive_period: 30s\n  idle_timeout: 5m\n"

	t.Run("env tightens development to public-beta", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "security_profile: development\n", map[string]string{
			"CFGMS_SECURITY_PROFILE":               "public-beta",
			"CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC": "true",
			"CFGMS_TRANSPORT_LISTEN_ADDR":          "127.0.0.1:4433",
			"CFGMS_TRANSPORT_USE_CERT_MANAGER":     "true",
		})
		require.NoError(t, err)
		assert.Equal(t, SecurityProfilePublicBeta, cfg.SecurityProfile)
	})
	t.Run("tightened profile is validated after later overrides", func(t *testing.T) {
		_, err := configloadCharLoad(t, "security_profile: development\n", map[string]string{"CFGMS_SECURITY_PROFILE": "public-beta"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "public-beta security profile requires")
	})
	t.Run("env cannot downgrade public-beta file", func(t *testing.T) {
		for _, p := range []string{"development", "test"} {
			_, err := configloadCharLoad(t, publicBetaFile, map[string]string{"CFGMS_SECURITY_PROFILE": p})
			require.Error(t, err)
			assert.Contains(t, err.Error(), "CFGMS_SECURITY_PROFILE cannot downgrade configured public-beta security profile to")
		}
	})
	t.Run("same profile from env is accepted", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, publicBetaFile, map[string]string{"CFGMS_SECURITY_PROFILE": " public-beta "})
		require.NoError(t, err)
		assert.Equal(t, SecurityProfilePublicBeta, cfg.SecurityProfile)
	})
	t.Run("env sets test profile", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", map[string]string{"CFGMS_SECURITY_PROFILE": "test"})
		require.NoError(t, err)
		assert.Equal(t, SecurityProfileTest, cfg.SecurityProfile)
	})
	t.Run("invalid profile refused", func(t *testing.T) {
		_, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", map[string]string{"CFGMS_SECURITY_PROFILE": "bogus"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid security_profile")
	})
}

func TestConfigloadChar_PostOverrideValidation(t *testing.T) {
	t.Run("ca path must end in ca", func(t *testing.T) {
		_, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", map[string]string{"CFGMS_CERT_CA_PATH": "/x/notca"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid certificate.ca_path")
	})
	t.Run("defaults without any config file", func(t *testing.T) {
		for _, k := range configloadCharEnvVars {
			t.Setenv(k, "")
		}
		t.Chdir(t.TempDir())
		if _, statErr := os.Stat("/etc/cfgms/controller.cfg"); statErr == nil {
			t.Fatal("unexpected production config present in test environment")
		}
		cfg, err := LoadWithPath("")
		require.NoError(t, err)
		assert.Equal(t, DefaultConfig(), cfg)
	})
}

func TestConfigloadChar_ValidationOrderAndNilSections(t *testing.T) {
	t.Run("webauthn validated", func(t *testing.T) {
		_, err := configloadCharLoad(t, "webauthn:\n  rp_origins: [\"https://a.example\"]\n", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "webauthn.rp_id must be set")
	})
	t.Run("notifications validated", func(t *testing.T) {
		_, err := configloadCharLoad(t, "notifications:\n  email:\n    tls_mode: bogus\n", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "notifications.email.tls_mode")
	})
	t.Run("module sources validated", func(t *testing.T) {
		_, err := configloadCharLoad(t, "module_sources:\n  acme-corp:\n    base: \"not a valid base\"\n", nil)
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrModuleSourceBadBase)
	})
	t.Run("public api key path alone materialises section", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", map[string]string{"CFGMS_CERT_PUBLIC_API_KEY_PATH": "/p/k.pem"})
		require.NoError(t, err)
		require.NotNil(t, cfg.Certificate.PublicAPI)
		assert.Equal(t, "/p/k.pem", cfg.Certificate.PublicAPI.KeyPath)
	})
	t.Run("vault key path alone materialises section", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "listen_addr: \"127.0.0.1:8080\"\n", map[string]string{"CFGMS_CLUSTER_CA_VAULT_KEY_PATH": "transit/k"})
		require.NoError(t, err)
		require.NotNil(t, cfg.Certificate.ClusterCA)
		assert.Equal(t, "transit/k", cfg.Certificate.ClusterCA.VaultKeyPath)
	})
	t.Run("transport env applies when file nulls the section", func(t *testing.T) {
		cfg, err := configloadCharLoad(t, "transport: null\n", map[string]string{"CFGMS_TRANSPORT_LISTEN_ADDR": "127.0.0.1:4"})
		require.NoError(t, err)
		require.NotNil(t, cfg.Transport)
		assert.Equal(t, "127.0.0.1:4", cfg.Transport.ListenAddr)
	})
}

// A file may null out pointer sections; with no override variable set, loading
// must not dereference them.
func TestConfigloadChar_NilSectionsWithoutEnv(t *testing.T) {
	for _, section := range []string{"certificate", "logging"} {
		t.Run(section+" null", func(t *testing.T) {
			require.NotPanics(t, func() {
				_, err := configloadCharLoad(t, section+": null\n", nil)
				require.NoError(t, err)
			})
		})
	}
}
