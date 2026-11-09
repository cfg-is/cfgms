// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/initialization"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Characterization tests for Server.Start (Issue #5865). They pin the observable
// behavior of Start (the order of its steps, the error text of the steps that
// abort it, the steps that only warn, what the Server holds afterwards, and the
// context handed to the config sync service) so Start can be split into one
// helper per step without changing it. They reuse the recordingLogger and the
// newStartableWiredEntityGraphTestServer fixtures of the sibling tests; every
// new helper and test carries the serverstartChar prefix.

// serverstartCharMessages returns every message the logger captured, in order.
func serverstartCharMessages(rec *recordingLogger) []string {
	rec.mu.Lock()
	defer rec.mu.Unlock()
	msgs := make([]string, 0, len(rec.entries))
	for _, e := range rec.entries {
		msgs = append(msgs, e.msg)
	}
	return msgs
}

// serverstartCharIndexOf returns the position of the first message equal to
// msg, or -1.
func serverstartCharIndexOf(msgs []string, msg string) int {
	for i, m := range msgs {
		if m == msg {
			return i
		}
	}
	return -1
}

// serverstartCharNewServer builds a startable Server with the gRPC-over-QUIC
// transport enabled whose logger records every message. The fixture of the
// entity-graph tests builds no transport, so the transport step of Start would
// never run on it; this one adds the transport section to the same shape of
// config (a fixed API address, a private metrics listener handed over still
// open, and a first-run initialized controller).
func serverstartCharNewServer(t *testing.T) (*Server, *recordingLogger) {
	t.Helper()
	rec := &recordingLogger{}
	srv := serverstartCharBuild(t, rec, true)
	return srv, rec
}

func serverstartCharBuild(t *testing.T, logger logging.Logger, withTransport bool) *Server {
	t.Helper()
	root := controllerDataRootForTest(t)
	certPath := root + "/certs"
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = metricsListener.Close() })
	httpAddr := "127.0.0.1:0"
	cfg := &config.Config{
		ListenAddr:        httpAddr,
		ExternalURL:       "https://" + httpAddr,
		MetricsListenAddr: metricsListener.Addr().String(),
		CertPath:          certPath,
		DataDir:           root + "/data",
		AdminBundlePath:   root + "/admin.bundle.yaml",
		Storage:           createTestStorageConfig(root, "serverstart-char"),
		Certificate: &config.CertificateConfig{
			EnableCertManagement: true,
			CAPath:               certPath + "/ca",
			Server: &config.ServerCertificateConfig{
				CommonName:   "localhost",
				DNSNames:     []string{"localhost", "127.0.0.1"},
				IPAddresses:  []string{"127.0.0.1", "::1"},
				Organization: "Server Start Characterization Test",
			},
		},
	}
	if withTransport {
		cfg.Transport = &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		}
	}
	_, err = initialization.Run(cfg, logger)
	require.NoError(t, err, "initialization.Run")

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv.httpServer, "New must build the API server")
	srv.httpServer.SetMetricsListener(metricsListener)
	t.Cleanup(func() { assert.NoError(t, srv.Stop()) })
	return srv
}

func TestServerstartChar_StepOrder(t *testing.T) {
	srv, rec := serverstartCharNewServer(t)
	require.NoError(t, srv.Start())

	// The steps log once each, in this order: HA, shared transport and its
	// services, expiry jobs, trigger manager, config sync, entity-graph
	// sweeps, health services, HTTP API, and the final started message.
	ordered := []string{
		"Starting HA manager...",
		"HA manager started successfully",
		"Controller build version",
		"Control plane provider started",
		"Shared gRPC-over-QUIC transport started",
		"Subscribed to steward events via gRPC control plane provider",
		"Heartbeat monitoring service started",
		"Command publisher started",
		"Job dispatcher started",
		"IP-trust expiry job started (Issue #1697)",
		"Pending-registration expiry job started (Issue #1697)",
		"Workflow trigger manager started",
		"Config source sync service started (Issue #4408)",
		"Entity graph tenant-sync periodic sweep started (Issue #4413)",
		"Entity graph correlator periodic sweep started (Issue #4413)",
		"Health collector started",
		"System monitor started",
		"Alert manager started",
		"HTTP API server started",
		"Controller server started (gRPC-over-QUIC transport mode)",
	}
	msgs := serverstartCharMessages(rec)
	last := -1
	for _, want := range ordered {
		idx := serverstartCharIndexOf(msgs, want)
		require.GreaterOrEqual(t, idx, 0, "Start must log %q", want)
		assert.Greater(t, idx, last, "%q must come after the previous step", want)
		last = idx
	}
}

func TestServerstartChar_StartedServerState(t *testing.T) {
	srv, _ := serverstartCharNewServer(t)
	require.NoError(t, srv.Start())

	assert.NotNil(t, srv.grpcServer, "Start builds a fresh shared gRPC server")
	assert.NotNil(t, srv.quicListener, "Start opens the shared QUIC listener")
	assert.NotNil(t, srv.logStreamHandler, "Start retains the log-stream handler")
	assert.NotNil(t, srv.terminalSessionMgr, "Start retains the terminal session manager for Stop")
	assert.NotNil(t, srv.egTenantSyncSweeper)
	assert.NotNil(t, srv.egCorrelatorSweeper)
	assert.NotNil(t, srv.configSyncCancel, "Start keeps the sync context's cancel for Stop")
}

func TestServerstartChar_StartupAuditEvent(t *testing.T) {
	srv, _ := serverstartCharNewServer(t)
	require.NoError(t, srv.Start())

	require.Eventually(t, func() bool {
		entries, err := srv.auditManager.QueryEntries(context.Background(), &business.AuditFilter{
			TenantID: audit.SystemTenantID,
			Actions:  []string{"controller_start"},
		})
		return err == nil && len(entries) > 0
	}, 10*time.Second, 50*time.Millisecond, "Start records a controller_start audit event")
}

func TestServerstartChar_HAManager(t *testing.T) {
	t.Run("the HA manager outlives Start", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NoError(t, srv.Start())

		// Start hands the manager a lifetime context, not a startup deadline:
		// the manager is still started once Start has returned, so a second
		// start is refused rather than silently succeeding on a stopped one.
		err := srv.haManager.Start(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HA manager is already started")
		assert.True(t, rec.containsAny("HA manager started successfully"))
	})

	t.Run("an HA manager that cannot start aborts Start with the wrapped error", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NoError(t, srv.haManager.Start(context.Background()))

		err := srv.Start()
		require.Error(t, err)
		assert.Equal(t, "failed to start HA manager: HA manager is already started", err.Error())
		assert.True(t, rec.containsAny("Starting HA manager..."))
		assert.False(t, rec.containsAny("HA manager started successfully"))
		// Nothing after the HA step ran.
		assert.False(t, rec.containsAny("Controller build version"))
		assert.Nil(t, srv.grpcServer)
		assert.Nil(t, srv.quicListener)
		assert.Nil(t, srv.egTenantSyncSweeper)
		assert.Nil(t, srv.configSyncCancel)
	})
}

func TestServerstartChar_FailingStepStopsTheStepsAfterIt(t *testing.T) {
	t.Run("a QUIC listener that cannot bind aborts before the control plane starts", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		srv.cfg.Transport.ListenAddr = "not-a-listen-address"

		err := srv.Start()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to start shared QUIC listener: ")
		assert.NotNil(t, srv.grpcServer, "the gRPC server is built before the listener")
		assert.Nil(t, srv.quicListener)
		assert.True(t, rec.containsAny("HA manager started successfully"), "the steps before it ran")
		assert.False(t, rec.containsAny("Control plane provider started"))
		assert.False(t, rec.containsAny("Heartbeat monitoring service started"))
		assert.False(t, rec.containsAny("HTTP API server started"))
		assert.Nil(t, srv.configSyncCancel)
	})

	t.Run("a missing certificate manager aborts before the gRPC server is built", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		srv.certManager = nil

		assert.Panics(t, func() { _ = srv.Start() },
			"the TLS config build dereferences the certificate manager")
		assert.False(t, rec.containsAny("Control plane provider started"))
		assert.Nil(t, srv.grpcServer)
	})

	t.Run("a missing secrets store aborts the composite handler wiring", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		srv.httpServer = nil

		err := srv.Start()
		require.Error(t, err)
		assert.Equal(t,
			"failed to create terminal session manager: secrets store is required for the recording HMAC key",
			err.Error())
		// The transport was opened and the providers started before the abort
		// and nothing after the composite handler wiring ran.
		assert.True(t, rec.containsAny("Control plane provider started"))
		assert.False(t, rec.containsAny("Shared gRPC-over-QUIC transport started"))
		assert.False(t, rec.containsAny("Subscribed to steward events via gRPC control plane provider"))
		assert.False(t, rec.containsAny("Heartbeat monitoring service started"))
		assert.False(t, rec.containsAny("IP-trust expiry job started (Issue #1697)"))
		assert.Nil(t, srv.egTenantSyncSweeper)
		assert.Nil(t, srv.configSyncCancel)
		assert.Nil(t, srv.terminalSessionMgr)
	})
}

func TestServerstartChar_StepsThatOnlyWarn(t *testing.T) {
	t.Run("a health collector that fails to start warns and Start continues", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NoError(t, srv.healthCollector.Start(context.Background(), time.Minute))
		// The collector samples the transport as soon as it starts. Wait for that
		// first sample so it cannot overlap the provider initialisation in Start.
		require.Eventually(t, func() bool {
			_, err := srv.healthCollector.GetCurrentMetrics()
			return err == nil
		}, 10*time.Second, 10*time.Millisecond, "the collector takes its first sample")

		require.NoError(t, srv.Start())
		assert.True(t, rec.containsAny("Failed to start health collector"))
		assert.False(t, rec.containsAny("Health collector started"))
		assert.True(t, rec.containsAny("System monitor started"))
		assert.True(t, rec.containsAny("HTTP API server started"))
	})
}

func TestServerstartChar_WorkflowTriggerManager(t *testing.T) {
	t.Run("configured: the trigger manager is started", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NotNil(t, srv.triggerManager, "New wires the trigger manager on this fixture")

		require.NoError(t, srv.Start())
		assert.True(t, rec.containsAny("Workflow trigger manager started"))
		// Started: a second start is refused by the manager itself.
		err := srv.triggerManager.Start(context.Background())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trigger manager is already running")
	})

	t.Run("configured but already running: Start only warns and continues", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NoError(t, srv.triggerManager.Start(context.Background()))

		require.NoError(t, srv.Start())
		assert.True(t, rec.containsAny("Failed to start trigger manager"))
		assert.False(t, rec.containsAny("Workflow trigger manager started"))
		assert.True(t, rec.containsAny("Config source sync service started (Issue #4408)"))
	})

	t.Run("not configured: the step is skipped without a log", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		srv.triggerManager = nil
		srv.workflowEngine = nil

		require.NoError(t, srv.Start())
		assert.False(t, rec.containsAny("Workflow trigger manager started"))
		assert.False(t, rec.containsAny("Failed to start trigger manager"))
		assert.True(t, rec.containsAny("Config source sync service started (Issue #4408)"))
	})
}

func TestServerstartChar_ConfigSync(t *testing.T) {
	t.Run("configured: Run is started on a context Stop cancels", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		require.NotNil(t, srv.configSyncService)

		require.NoError(t, srv.Start())
		require.NotNil(t, srv.configSyncCancel)
		assert.True(t, rec.containsAny("Config source sync service started (Issue #4408)"))

		// Run has been called: a tenant can be registered with it. An unknown
		// tenant is refused for its own reason, not because Run never ran.
		err := srv.configSyncService.Register("serverstart-char-unknown-tenant")
		if err != nil {
			assert.NotContains(t, err.Error(), "Register called before Run")
		}

		// Cancelling the context Start passed to Run stops the polling loop:
		// the service drains at once and Stop has nothing left to wait for.
		srv.configSyncCancel()
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		require.NoError(t, srv.configSyncService.Stop(stopCtx))
	})

	t.Run("not configured: the step is skipped and no cancel is kept", func(t *testing.T) {
		srv, rec := serverstartCharNewServer(t)
		srv.configSyncService = nil

		require.NoError(t, srv.Start())
		assert.Nil(t, srv.configSyncCancel)
		assert.False(t, rec.containsAny("Config source sync service started (Issue #4408)"))
	})
}

func TestServerstartChar_OptionalStepsAreSkippedWhenAbsent(t *testing.T) {
	t.Setenv("CFGMS_TERMINAL_ALLOWED_ORIGINS", " https://a.example , ,https://b.example ")
	srv, rec := serverstartCharNewServer(t)
	srv.heartbeatService = nil
	srv.commandPublisher = nil
	srv.jobDispatcher = nil
	srv.ipTrustExpiryJob = nil
	srv.pendingExpiryJob = nil
	srv.egTenantSyncWriter = nil
	srv.egCorrelatorWriter = nil
	srv.signingRetirementSvc = nil
	srv.signingMigrationSvc = nil
	srv.stewardMigrationSvc = nil

	require.NoError(t, srv.Start())
	for _, absent := range []string{
		"Heartbeat monitoring service started",
		"Command publisher started",
		"Job dispatcher started",
		"IP-trust expiry job started (Issue #1697)",
		"Pending-registration expiry job started (Issue #1697)",
		"Entity graph tenant-sync periodic sweep started (Issue #4413)",
		"Entity graph correlator periodic sweep started (Issue #4413)",
	} {
		assert.False(t, rec.containsAny(absent), "%q must be skipped when its service is absent", absent)
	}
	assert.Nil(t, srv.egTenantSyncSweeper)
	assert.Nil(t, srv.egCorrelatorSweeper)
	assert.True(t, rec.containsAny("Shared gRPC-over-QUIC transport started"))
	assert.True(t, rec.containsAny("Controller server started (gRPC-over-QUIC transport mode)"))
}

func TestServerstartChar_WithoutTransport(t *testing.T) {
	rec := &recordingLogger{}
	srv := serverstartCharBuild(t, rec, false)

	require.NoError(t, srv.Start())
	// The build version is logged before the transport gate; the transport,
	// its services and everything gated on it are skipped, the steps after it
	// still run.
	assert.True(t, rec.containsAny("Controller build version"))
	assert.Nil(t, srv.grpcServer)
	assert.Nil(t, srv.quicListener)
	assert.False(t, rec.containsAny("Shared gRPC-over-QUIC transport started"))
	assert.False(t, rec.containsAny("Heartbeat monitoring service started"))
	assert.True(t, rec.containsAny("Config source sync service started (Issue #4408)"))
	assert.True(t, rec.containsAny("HTTP API server started"))
	assert.True(t, rec.containsAny("Controller server started (gRPC-over-QUIC transport mode)"))
}
