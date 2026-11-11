// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestUnattendedRolloutStoreWiredAtStartup starts a real controller and reads the
// setting through the store New() wired into the API server: it is off, and a
// change made through that store is read back.
func TestUnattendedRolloutStoreWiredAtStartup(t *testing.T) {
	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Unattended Rollout Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               caDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "unattended-wiring-controller",
				Organization: "Unattended Rollout Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "unattended-wiring"),
	}
	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop() })

	st := srv.httpServer.UnattendedRolloutStore()
	require.NotNil(t, st, "the unattended rollout store must be wired at startup (else the setting routes 503)")
	got, err := st.Get(t.Context())
	require.NoError(t, err)
	assert.False(t, got.Enabled)

	_, err = st.Set(t.Context(), true, "operator-1")
	require.NoError(t, err)
	got, err = st.Get(t.Context())
	require.NoError(t, err)
	assert.True(t, got.Enabled)
}
