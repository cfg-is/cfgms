// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	composePath         = "../../docker-compose.test.yml"
	compatServiceName   = "compat-controller"
	controllerCfgTarget = "/app/controller.cfg"
)

// composeFile is the subset of the compose schema this test reads.
type composeFile struct {
	Services map[string]struct {
		Environment yaml.Node `yaml:"environment"`
		Volumes     []string  `yaml:"volumes"`
	} `yaml:"services"`
}

// controllerCfg is the subset of controller.cfg this test reads.
type controllerCfg struct {
	Certificate struct {
		Server struct {
			DNSNames []string `yaml:"dns_names"`
		} `yaml:"server"`
	} `yaml:"certificate"`
}

// composeEnv returns the service's environment as a map, accepting both the
// mapping and the "KEY=value" list forms.
func composeEnv(t *testing.T, node yaml.Node) map[string]string {
	t.Helper()
	env := map[string]string{}
	switch node.Kind {
	case yaml.MappingNode:
		require.NoError(t, node.Decode(&env))
	case yaml.SequenceNode:
		var items []string
		require.NoError(t, node.Decode(&items))
		for _, item := range items {
			k, v, _ := strings.Cut(item, "=")
			env[k] = v
		}
	}
	return env
}

// mountedHostPath returns the host side of the volume mounted at target.
func mountedHostPath(volumes []string, target string) (string, bool) {
	for _, v := range volumes {
		parts := strings.Split(v, ":")
		if len(parts) >= 2 && parts[1] == target {
			return parts[0], true
		}
	}
	return "", false
}

// TestCompatControllerCertCoversExternalURL fails when the controller config
// that compat-controller mounts does not list the host of its
// CFGMS_EXTERNAL_URL in certificate.server.dns_names. The controller mints its
// public API certificate from those names and refuses to start when the
// external URL host is not covered, so this catches the drift without Docker.
func TestCompatControllerCertCoversExternalURL(t *testing.T) {
	raw, err := os.ReadFile(composePath)
	require.NoError(t, err)
	var compose composeFile
	require.NoError(t, yaml.Unmarshal(raw, &compose))

	svc, ok := compose.Services[compatServiceName]
	require.True(t, ok, "service %q missing from %s", compatServiceName, composePath)

	externalURL := composeEnv(t, svc.Environment)["CFGMS_EXTERNAL_URL"]
	require.NotEmpty(t, externalURL, "%s sets no CFGMS_EXTERNAL_URL", compatServiceName)
	parsed, err := url.Parse(externalURL)
	require.NoError(t, err)
	host := parsed.Hostname()
	require.NotEmpty(t, host, "CFGMS_EXTERNAL_URL %q has no hostname", externalURL)

	hostPath, ok := mountedHostPath(svc.Volumes, controllerCfgTarget)
	require.True(t, ok, "%s mounts nothing at %s", compatServiceName, controllerCfgTarget)

	cfgRaw, err := os.ReadFile(filepath.Join(filepath.Dir(composePath), hostPath))
	require.NoError(t, err)
	var cfg controllerCfg
	require.NoError(t, yaml.Unmarshal(cfgRaw, &cfg))

	assert.Contains(t, cfg.Certificate.Server.DNSNames, host,
		"%s (mounted at %s) must list the CFGMS_EXTERNAL_URL host in certificate.server.dns_names",
		hostPath, controllerCfgTarget)
}

// TestCompatControllerCertHelpers covers the parsing helpers' error paths.
func TestCompatControllerCertHelpers(t *testing.T) {
	t.Run("mount lookup misses an unmounted target", func(t *testing.T) {
		_, ok := mountedHostPath([]string{"./a:/app/other:ro"}, controllerCfgTarget)
		assert.False(t, ok)
	})
	t.Run("mount lookup returns the host path", func(t *testing.T) {
		p, ok := mountedHostPath([]string{"vol:/app/data", "./x.cfg:/app/controller.cfg:ro"}, controllerCfgTarget)
		assert.True(t, ok)
		assert.Equal(t, "./x.cfg", p)
	})
	t.Run("environment list form", func(t *testing.T) {
		var n yaml.Node
		require.NoError(t, yaml.Unmarshal([]byte("[\"A=b=c\", \"D=e\"]"), &n))
		env := composeEnv(t, *n.Content[0])
		assert.Equal(t, "b=c", env["A"])
		assert.Equal(t, "e", env["D"])
	})
}
