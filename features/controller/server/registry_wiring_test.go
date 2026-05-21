// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestServer_New_WiresSharedConnectionRegistry verifies that when transport is
// configured, New() creates a single steward connection registry and shares it
// between the gRPC control-plane provider (which registers ControlChannel
// connections) and the HTTP API server (which reads connection_state for
// GET /api/v1/stewards/{id}).
//
// Regression guard for Issue #1572: previously SetRegistry was never called, so
// the API server held a nil registry and every steward — even a connected one —
// reported connection_state "disconnected", which broke the fleet E2E
// VanillaState scenario.
func TestServer_New_WiresSharedConnectionRegistry(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	certDir := tempDir + "/ca"

	// Create the CA up front so EnableCertManagement startup succeeds without
	// the init guard rejecting the boot.
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: certDir,
		CAConfig: &cert.CAConfig{
			Organization: "Registry Wiring Test",
			Country:      "US",
			ValidityDays: 3650,
			StoragePath:  certDir,
		},
		LoadExistingCA: false,
	})
	require.NoError(t, err, "failed to create test CA")

	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		CertPath:   certDir,
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               certDir,
			Server: &config.ServerCertificateConfig{
				CommonName:   "registry-wiring-controller",
				Organization: "Registry Wiring Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "registry-wiring"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	// A registry must have been created for the transport-enabled controller.
	require.NotNil(t, srv.connRegistry, "transport-enabled controller must create a connection registry")

	// The API server must hold that exact registry instance, not nil and not a
	// different one — otherwise connection_state is always "disconnected".
	require.NotNil(t, srv.httpServer, "API server must be initialized")
	assert.Same(t, srv.connRegistry, srv.httpServer.Registry(),
		"API server registry must be the shared connection registry")

	// The gRPC control-plane provider must register ControlChannel connections
	// into the same registry the API server reads.
	cpProvider, ok := srv.controlPlane.(*grpcCP.Provider)
	require.True(t, ok, "control plane must be the gRPC provider")
	assert.Same(t, srv.connRegistry, cpProvider.Registry(),
		"CP provider registry must be the shared connection registry")
}

// TestServer_New_NoTransport_NoRegistry verifies that an OSS single-node
// controller without transport configured leaves the connection registry unset
// — there is no transport server registering connections, so wiring one would
// be misleading.
func TestServer_New_NoTransport_NoRegistry(t *testing.T) {
	t.Setenv("CFGMS_SEED_TEST_TOKENS", "")

	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: createTestStorageConfig(tempDir, "no-transport"),
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	assert.Nil(t, srv.connRegistry, "controller without transport must not create a connection registry")
	assert.Nil(t, srv.httpServer.Registry(), "API server registry must remain unset without transport")
}
