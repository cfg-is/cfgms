// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func deploymentRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must locate deployment contract test")
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
}

func readDeploymentFile(t *testing.T, relativePath string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(deploymentRepoRoot(t), relativePath))
	require.NoError(t, err)
	return string(content)
}

func TestSystemdDeploymentUsesDedicatedLoopbackMetricsListener(t *testing.T) {
	t.Setenv("CFGMS_LISTEN_ADDR", "")
	t.Setenv("CFGMS_HTTP_LISTEN_ADDR", "")
	t.Setenv("CFGMS_METRICS_LISTEN_ADDR", "")
	root := deploymentRepoRoot(t)
	configPath := filepath.Join(root, "docs", "deployment", "controller.cfg")

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	assert.Equal(t, SecurityProfilePublicBeta, cfg.SecurityProfile)
	assert.True(t, cfg.Execution.RequireSignedAdhoc)
	assert.Equal(t, "0.0.0.0:9080", cfg.ListenAddr, "product API remains the public listener")
	assert.Equal(t, "/var/lib/cfgms/certs", cfg.CertPath,
		"systemd certificates must be written beneath the writable state directory")
	assert.Equal(t, "127.0.0.1:9090", cfg.MetricsListenAddr,
		"systemd metrics listener must bind only to host loopback")
	require.NoError(t, ValidatePrivateListenerAddress(cfg.MetricsListenAddr))
	assert.NotEqual(t, cfg.ListenAddr, cfg.MetricsListenAddr)

	unit := readDeploymentFile(t, "docs/deployment/single-controller/cfgms-controller.service")
	assert.Contains(t, unit, "ExecStart=/usr/local/bin/cfgms-controller --config /etc/cfgms/controller.cfg")
	assert.Contains(t, unit, "Environment=CFGMS_SECURITY_PROFILE=public-beta")
	assert.Contains(t, unit, "Environment=CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC=true")
	assert.NotContains(t, unit, "CFGMS_METRICS_LISTEN_ADDR",
		"unit must not override the reviewed loopback metrics address")
}

func TestContainerDeploymentPublishesMetricsOnlyOnHostLoopback(t *testing.T) {
	t.Setenv("CFGMS_LISTEN_ADDR", "")
	t.Setenv("CFGMS_HTTP_LISTEN_ADDR", "")
	t.Setenv("CFGMS_METRICS_LISTEN_ADDR", "")
	root := deploymentRepoRoot(t)
	configPath := filepath.Join(root, "docs", "deployment", "container", "controller.cfg")

	cfg, err := LoadWithPath(configPath)
	require.NoError(t, err)
	assert.Equal(t, SecurityProfilePublicBeta, cfg.SecurityProfile)
	assert.True(t, cfg.Execution.RequireSignedAdhoc)
	assert.Equal(t, "0.0.0.0:9080", cfg.ListenAddr, "product API remains the public listener")
	assert.Equal(t, "/var/lib/cfgms/certs", cfg.CertPath,
		"container certificates must be written beneath the writable state volume")
	assert.Equal(t, "172.30.0.10:9090", cfg.MetricsListenAddr,
		"container metrics listener must bind the fixed private bridge address")
	require.NoError(t, ValidatePrivateListenerAddress(cfg.MetricsListenAddr))
	assert.NotEqual(t, cfg.ListenAddr, cfg.MetricsListenAddr)

	compose := readDeploymentFile(t, "docs/deployment/container/compose.yaml")
	assert.Equal(t, 2, strings.Count(compose, "CFGMS_SECURITY_PROFILE: public-beta"),
		"both container initialization and runtime must select public-beta")
	assert.Equal(t, 2, strings.Count(compose, `CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC: "true"`),
		"both container initialization and runtime must require signed ad-hoc execution")
	assert.NotContains(t, compose, "CFGMS_EXECUTION_REQUIRE_SIGNED_ADHOC: \"false\"")
	assert.Contains(t, compose, `"127.0.0.1:${CFGMS_METRICS_PORT:-9090}:9090/tcp"`,
		"metrics may be published only on host loopback")
	assert.NotContains(t, compose, "CFGMS_METRICS_BIND_IP",
		"deployment must not provide an environment switch that widens metrics exposure")
	assert.Contains(t, compose, "ipv4_address: 172.30.0.10")
	assert.Contains(t, compose, "controller-private:")
	assert.NotContains(t, compose, "controller-public:",
		"published ports, not a second container network, define the public surface")

	dockerfile := readDeploymentFile(t, "cmd/controller/Dockerfile")
	for _, line := range strings.Split(dockerfile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "EXPOSE ") {
			assert.NotContains(t, line, "9090",
				"private metrics port must not be exposed through image metadata")
		}
	}
}

func TestContainerHealthcheckHasVerifiedTLSClient(t *testing.T) {
	dockerfile := readDeploymentFile(t, "cmd/controller/Dockerfile")
	compose := readDeploymentFile(t, "docs/deployment/container/compose.yaml")

	assert.Contains(t, dockerfile, "apk add --no-cache ca-certificates wget",
		"the image must install full wget because BusyBox wget lacks --ca-certificate")
	assert.Contains(t, dockerfile, "--output-document=/dev/null",
		"the image healthcheck must issue GET because the health route is GET-only")
	assert.Contains(t, compose, "--output-document=/dev/null")
	assert.NotContains(t, dockerfile, "--spider")
	assert.NotContains(t, compose, "--spider")
	assert.Contains(t, dockerfile, "--ca-certificate=/var/lib/cfgms/certs/ca/ca.crt")
	assert.Contains(t, compose, "--ca-certificate=/var/lib/cfgms/certs/ca/ca.crt")
	assert.NotContains(t, dockerfile, "--no-check-certificate")
	assert.NotContains(t, compose, "--no-check-certificate")
}

// TestRuntimeImagesApplyPendingAlpineSecurityUpdates locks in the fix for the
// controller image's Trivy failure (Issue #3627). Pinning the runtime base by
// digest bounds what a release build starts from, but it cannot deliver a
// package fix that upstream has not rebuilt the image with — alpine:3.24 still
// resolves to a digest shipping libssl3/libcrypto3 3.5.7-r0 (CVE-2026-14456,
// HIGH), fixed in 3.5.8-r0 (Issue #3842). The steward image has always run
// `apk upgrade` and scanned clean while the controller image, which did not,
// failed. Both runtime stages must upgrade.
func TestRuntimeImagesApplyPendingAlpineSecurityUpdates(t *testing.T) {
	for _, path := range []string{"cmd/controller/Dockerfile", "cmd/steward/Dockerfile"} {
		t.Run(path, func(t *testing.T) {
			dockerfile := readDeploymentFile(t, path)

			// Scope the assertion to the runtime stage: an upgrade in a builder
			// stage is discarded and would not patch the shipped image.
			lastFrom := strings.LastIndex(dockerfile, "\nFROM ")
			require.GreaterOrEqual(t, lastFrom, 0, "Dockerfile must declare a runtime stage")

			assert.Contains(t, dockerfile[lastFrom:], "apk --no-cache upgrade",
				"the runtime stage must apply pending Alpine security updates at build time, "+
					"because a pinned base digest cannot carry a fix upstream has not rebuilt")
		})
	}
}
