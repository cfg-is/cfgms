// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestClusterModeWithoutClusterCANamesMissingSetting: a cluster-mode controller
// with no cluster signing-key custody must be told which setting is missing.
func TestClusterModeWithoutClusterCANamesMissingSetting(t *testing.T) {
	cfg := &config.Config{
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               filepath.Join(t.TempDir(), "ca"),
		},
		HA: &config.HAConfig{Mode: "cluster"},
	}

	_, err := loadExistingCertificateManager(cfg, nil, logging.NewNoopLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate.cluster_ca")
	assert.NotContains(t, err.Error(), "single-node signing key store cannot be used in cluster mode")
}

// TestHAFixtureSelectsClusterCertPath parses the HA compose fixture through the
// controller config loader and asserts a cluster-mode config built from it takes
// the cluster certificate path, not the single-node branch.
func TestHAFixtureSelectsClusterCertPath(t *testing.T) {
	t.Setenv("CFGMS_HA_INTERNAL_IP", "172.20.0.11")
	t.Setenv("CFGMS_HA_MODE", "cluster")
	t.Setenv("CFGMS_HA_ENABLED", "true")

	cfg, err := config.LoadWithPath(filepath.Join("..", "..", "..", "test", "fixtures", "ha", "controller-ha.cfg"))
	require.NoError(t, err)
	require.NotNil(t, cfg.HA)
	require.True(t, cfg.HA.IsClusterMode(), "fixture settings plus the compose HA env select cluster mode")

	require.NotNil(t, cfg.Certificate.ClusterCA, "fixture must configure certificate.cluster_ca")
	assert.NotEmpty(t, cfg.Certificate.ClusterCA.VaultAddress)
	assert.NotEmpty(t, cfg.Certificate.ClusterCA.VaultKeyPath)
	require.NoError(t, initialization.RequireClusterCAConfig(cfg))
	assert.True(t, initialization.UsesClusterCA(cfg))
}

// TestOpenBaoTestHealthcheckTargetsBoundAddress parses the compose file and
// asserts the openbao-test healthcheck probes the IPv4 address the dev listener
// binds. "localhost" resolves to ::1 first in the image, where nothing listens,
// so the service never reports healthy and the HA controllers never start.
func TestOpenBaoTestHealthcheckTargetsBoundAddress(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docker-compose.test.yml"))
	require.NoError(t, err)

	var compose struct {
		Services struct {
			OpenBao struct {
				Environment map[string]string `yaml:"environment"`
				Healthcheck struct {
					Test []string `yaml:"test"`
				} `yaml:"healthcheck"`
			} `yaml:"openbao-test"`
		} `yaml:"services"`
	}
	require.NoError(t, yaml.Unmarshal(data, &compose))

	svc := compose.Services.OpenBao
	require.NotEmpty(t, svc.Healthcheck.Test, "openbao-test service must define a healthcheck")

	listen := svc.Environment["BAO_DEV_LISTEN_ADDRESS"]
	require.Equal(t, "0.0.0.0:8200", listen, "listener binds IPv4 only")

	probe := strings.Join(svc.Healthcheck.Test, " ")
	assert.Contains(t, probe, "http://127.0.0.1:8200/v1/sys/health")
	assert.NotContains(t, probe, "localhost", "localhost resolves to ::1 first, which the IPv4 listener does not serve")
}
