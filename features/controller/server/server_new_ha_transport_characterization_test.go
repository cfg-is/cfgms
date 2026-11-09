// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Characterization tests for the HA, registration token, transport and control
// plane region of New (Issue #5863). They pin the observable behavior of that
// region (error text, check order, what the returned Server holds, and the
// Issue #4058 close-once contract) so the region can be split into helpers
// without changing it. They reuse the servernewChar helpers of the sibling
// characterization file; every new helper and test carries the
// servernewhatransportChar prefix.

// servernewhatransportCharTransportConfig returns a config with certificate
// management on a real CA and the gRPC control plane enabled on an ephemeral
// port.
func servernewhatransportCharTransportConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := servernewCharCertConfig(t)
	cfg.Transport = &config.TransportConfig{
		ListenAddr:     "127.0.0.1:0",
		UseCertManager: true,
		MaxConnections: 10,
	}
	return cfg
}

func TestServernewhatransportChar_HAWiring(t *testing.T) {
	t.Run("default config builds a single-server HA manager", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		require.NotNil(t, srv.haManager)
		assert.Equal(t, ha.SingleServerMode, srv.haManager.GetDeploymentMode())
		assert.True(t, logger.containsAny("Initializing HA manager..."))
		assert.True(t, logger.containsAny("HA manager initialized successfully"))
		assert.False(t, logger.containsAny("HA mode has no shared lease substrate"))
	})

	t.Run("explicit single mode is the same as the default", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "single"}
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		require.NotNil(t, srv.haManager)
		assert.Equal(t, ha.SingleServerMode, srv.haManager.GetDeploymentMode())
	})

	t.Run("blue-green mode without a node id is refused by the HA manager and closes the stores once", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "blue-green"}
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize HA manager: failed to create HA manager:")
		assert.Contains(t, err.Error(), "node ID is required for cluster/blue-green modes")
		assert.False(t, logger.containsAny("HA manager initialized successfully"))
		assert.Equal(t, 1, counting.auditCloses)
	})

	t.Run("the DNA maintenance lease is claimed from the HA manager", func(t *testing.T) {
		srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())

		require.NotNil(t, srv.dnaStorageManager)
		require.NotNil(t, srv.haManager)
		// The lease job the region installs is a real singleton job of the
		// same manager; asking the manager for it again must succeed.
		job, err := srv.haManager.NewBackgroundLoopLease("controller-dna-storage-maintenance", logging.NewNoopLogger())
		require.NoError(t, err)
		assert.NotNil(t, job)
	})

	t.Run("an invalid ha.mode is refused with the wrapped message and closes the stores once", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "not-a-real-mode"}
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize HA manager: invalid ha.mode in config:")
		assert.True(t, logger.containsAny("Initializing HA manager..."))
		assert.False(t, logger.containsAny("HA manager initialized successfully"))
		assert.Equal(t, 1, counting.auditCloses)
	})

	t.Run("cluster mode requires a node-shared lease store", func(t *testing.T) {
		// New cannot reach this stage in cluster mode without a Postgres
		// server (the storage stage refuses first), so the stage function is
		// exercised against a real single-node storage manager.
		srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())
		cfg := servernewCharConfig(t)
		cfg.HA = &config.HAConfig{Mode: "cluster"}

		mgr, err := initializeHAManager(cfg, logging.NewNoopLogger(), srv.storageManager)
		assert.Nil(t, mgr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), `ha.mode "cluster" requires a leadership lease`)
	})

	t.Run("outside cluster mode no cluster-aware dispatch fallback is built", func(t *testing.T) {
		srv := servernewCharNewServer(t, servernewhatransportCharTransportConfig(t), logging.NewNoopLogger())

		assert.Nil(t, srv.clusterAwareSender)
	})

	t.Run("cluster dispatch fallback needs an internal delivery address", func(t *testing.T) {
		cfg := servernewhatransportCharTransportConfig(t)
		cfg.InternalDeliveryListenAddr = "127.0.0.1:0"
		srv := servernewCharNewServer(t, cfg, logging.NewNoopLogger())

		assert.Nil(t, srv.clusterAwareSender, "a single-node deployment never builds the cluster-aware sender")
	})
}

func TestServernewhatransportChar_RegistrationTokenStore(t *testing.T) {
	t.Run("the store is initialized and handed to the Server", func(t *testing.T) {
		t.Setenv("CFGMS_SEED_TEST_TOKENS", "")
		srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())

		require.NotNil(t, srv.registrationTokenStore)
		require.NotNil(t, srv.storageManager.GetRegistrationTokenStore())
		_, err := srv.registrationTokenStore.GetToken(context.Background(), "dockertest_standalone")
		assert.Error(t, err, "no token is seeded unless explicitly requested")
	})

	t.Run("a value other than 1 does not seed", func(t *testing.T) {
		t.Setenv("CFGMS_SEED_TEST_TOKENS", "true")
		srv := servernewCharNewServer(t, servernewCharConfig(t), logging.NewNoopLogger())

		_, err := srv.registrationTokenStore.GetToken(context.Background(), "dockertest_standalone")
		assert.Error(t, err)
	})

	t.Run("CFGMS_SEED_TEST_TOKENS=1 seeds the test tokens and the fleet hierarchy", func(t *testing.T) {
		t.Setenv("CFGMS_SEED_TEST_TOKENS", "1")
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)
		ctx := context.Background()

		standalone, err := srv.registrationTokenStore.GetToken(ctx, "dockertest_standalone")
		require.NoError(t, err)
		assert.Equal(t, "test-tenant", standalone.TenantID)
		assert.Equal(t, "tcp://controller-standalone:1883", standalone.ControllerURL)
		assert.Equal(t, "test-group", standalone.Group)
		assert.False(t, standalone.Revoked)
		assert.Nil(t, standalone.ExpiresAt)

		expired, err := srv.registrationTokenStore.GetToken(ctx, "integration_expired")
		require.NoError(t, err)
		require.NotNil(t, expired.ExpiresAt)
		assert.True(t, expired.ExpiresAt.Before(time.Now()), "the expired token is already past its expiry")

		revoked, err := srv.registrationTokenStore.GetToken(ctx, "integration_revoked")
		require.NoError(t, err)
		assert.True(t, revoked.Revoked)
		assert.NotNil(t, revoked.RevokedAt)

		for _, tok := range []string{
			"dockertest_standalone", "integration_reusable", "integration_expired",
			"integration_revoked", "dockertest_fleet", "dockertest_fleet_child_a", "dockertest_fleet_child_b",
		} {
			_, getErr := srv.registrationTokenStore.GetToken(ctx, tok)
			assert.NoError(t, getErr, "token %s must be seeded", tok)
			assert.False(t, logger.containsAny(tok), "the plaintext token %s must not reach the log", tok)
		}
		assert.True(t, logger.containsAny("Seeded test registration token"))

		for _, id := range []string{"fleet-root", "fleet-root/fleet-child-a", "fleet-root/fleet-child-b"} {
			td, tenantErr := srv.storageManager.GetTenantStore().GetTenant(ctx, id)
			require.NoError(t, tenantErr, "fleet cascade tenant %s must be seeded", id)
			assert.Equal(t, id, td.ID)
		}
	})
}

func TestServernewhatransportChar_RegistrationTokenReseed(t *testing.T) {
	t.Setenv("CFGMS_SEED_TEST_TOKENS", "1")
	cfg := servernewCharConfig(t)
	first, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, first.Stop())

	// A second start over the same durable data seeds again and succeeds: the
	// save is an upsert, so no warning is logged.
	logger := &recordingLogger{}
	second := servernewCharNewServer(t, cfg, logger)

	_, err = second.registrationTokenStore.GetToken(context.Background(), "dockertest_standalone")
	assert.NoError(t, err)
	assert.True(t, logger.containsAny("Seeded test registration token"))
	assert.False(t, logger.containsAny("Failed to seed test token"))
}

func TestServernewhatransportChar_Transport(t *testing.T) {
	t.Run("no transport section leaves the control plane disabled", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewCharConfig(t), logger)

		assert.Nil(t, srv.controlPlane)
		assert.Nil(t, srv.connRegistry)
		assert.Nil(t, srv.lockdown)
		assert.Nil(t, srv.commandPublisher)
		assert.Nil(t, srv.heartbeatService)
		assert.Nil(t, srv.jobDispatcher)
		assert.Nil(t, srv.executionQueue)
		assert.Nil(t, srv.dataPlaneProvider)
		assert.True(t, logger.containsAny("Transport config not set — gRPC control plane disabled"))
	})

	t.Run("a transport section without certificate management leaves it disabled", func(t *testing.T) {
		cfg := servernewCharConfig(t)
		cfg.Transport = &config.TransportConfig{ListenAddr: "127.0.0.1:0", MaxConnections: 10}
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, cfg, logger)

		assert.Nil(t, srv.controlPlane)
		assert.Nil(t, srv.connRegistry)
		assert.True(t, logger.containsAny("Transport config not set — gRPC control plane disabled"))
		assert.False(t, logger.containsAny("Initializing gRPC control plane provider..."))
	})

	t.Run("transport with certificate management builds the control plane and its services", func(t *testing.T) {
		logger := &recordingLogger{}
		srv := servernewCharNewServer(t, servernewhatransportCharTransportConfig(t), logger)

		provider, ok := srv.controlPlane.(*grpcCP.Provider)
		require.True(t, ok, "control plane must be the gRPC provider")
		require.NotNil(t, srv.connRegistry)
		assert.Same(t, srv.connRegistry, provider.Registry())
		assert.NotNil(t, srv.lockdown)
		assert.NotNil(t, srv.commandPublisher)
		assert.NotNil(t, srv.heartbeatService)
		assert.NotNil(t, srv.jobDispatcher)
		assert.NotNil(t, srv.executionQueue)
		assert.NotNil(t, srv.admissionQueues)
		assert.NotNil(t, srv.signingMigrationSvc)
		assert.NotNil(t, srv.stewardMigrationSvc)
		assert.NotNil(t, srv.dataPlaneProvider, "the data plane stage follows a built control plane")
		assert.NotEmpty(t, srv.signerCertSerial, "the config signer is hoisted from the signing certificate")
		assert.Nil(t, srv.clusterAwareSender)

		for _, msg := range []string{
			"Initializing gRPC control plane provider...",
			"gRPC control plane provider initialized",
			"Config signer initialized successfully",
			"Initializing execution queue and job dispatcher...",
			"Execution queue and job dispatcher initialized",
			"Initializing heartbeat monitoring service...",
			"Heartbeat monitoring service initialized successfully",
			"Steward-registry heartbeat bridge registered (Issue #1986)",
			"Initializing command publisher...",
			"Command publisher initialized successfully",
			"Signing rotation service wired (refresh-on-connect enabled)",
			"DNA hash mismatch detection wired (Issue #2524)",
			"Post-DNA-sync hook wired (Issue #2524)",
			"Expected DNA hashes warmed from durable storage (Issue #2524)",
		} {
			assert.True(t, logger.containsAny(msg), "missing log line %q", msg)
		}
		assert.False(t, logger.containsAny("Transport config not set"))
	})

	t.Run("transport log lines keep their order", func(t *testing.T) {
		logger := &recordingLogger{}
		servernewCharNewServer(t, servernewhatransportCharTransportConfig(t), logger)

		order := []string{
			"Initializing HA manager...",
			"HA manager initialized successfully",
			"Initializing gRPC control plane provider...",
			"gRPC control plane provider initialized",
			"Initializing execution queue and job dispatcher...",
			"Initializing heartbeat monitoring service...",
			"Initializing command publisher...",
			"Initializing gRPC data plane provider...",
		}
		logger.mu.Lock()
		defer logger.mu.Unlock()
		next := 0
		for _, e := range logger.entries {
			if next < len(order) && e.msg == order[next] {
				next++
			}
		}
		assert.Equal(t, len(order), next, "log lines must appear in the documented order; matched %d of %d", next, len(order))
	})

	t.Run("a control plane provider that cannot initialize fails New and closes every opened store once", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		cfg := servernewhatransportCharTransportConfig(t)
		cfg.Transport.MaxConnections = 0 // the real provider refuses fewer than one connection
		logger := &recordingLogger{}

		srv, err := New(cfg, logger)
		assert.Nil(t, srv)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to initialize gRPC control plane provider: max_connections must be at least 1")
		assert.True(t, logger.containsAny("Initializing gRPC control plane provider..."))
		assert.False(t, logger.containsAny("gRPC control plane provider initialized"))
		assert.False(t, logger.containsAny("Initializing gRPC data plane provider..."))

		assert.Equal(t, 1, counting.auditCloses, "the audit store opened before the failed stage must be closed exactly once")
	})

	t.Run("a successful transport New closes nothing before Stop", func(t *testing.T) {
		counting := servernewCharInstallCountingFlatfile(t)
		srv, err := New(servernewhatransportCharTransportConfig(t), logging.NewNoopLogger())
		require.NoError(t, err)

		assert.Zero(t, counting.auditCloses)
		require.NoError(t, srv.Stop())
	})
}
