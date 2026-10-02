// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/cert"
	grpcCP "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestIngestAdmissionQueues_WireKeyedFloodCannotStarveConnectOrHeartbeat is the
// security regression guard for Issue #3759: the DNA path keys its admission
// bucket on the first chunk's tenant_id, which a compromised steward controls.
// If that queue were the same instance gating connect and heartbeat, a steward
// could name a victim tenant's bucket, hold MaxConcurrentPerTenant DNA streams
// open, and starve the victim tenant's connects while its heartbeats were
// dropped — making the victim's whole fleet look stale.
//
// Uses the real TenantQueue on both sides; the acquires below are exactly what
// DNAHandler.HandleGRPC does with a wire-supplied tenant ID.
func TestIngestAdmissionQueues_WireKeyedFloodCannotStarveConnectOrHeartbeat(t *testing.T) {
	t.Parallel()

	queues := newIngestAdmissionQueues()
	require.NotSame(t, queues.connectHeartbeatQueue(), queues.dnaBulkQueue(),
		"connect/heartbeat and DNA/bulk must not share a TenantQueue instance")

	const victimTenant = "root/msp-a/victim"

	// Saturate the wire-keyed queue under the victim's tenant ID, as a hostile
	// steward would by opening concurrent SyncDNA streams naming that tenant.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queues.dnaBulkQueue().Acquire(victimTenant),
			"DNA queue must admit up to its per-tenant limit")
	}
	require.ErrorIs(t, queues.dnaBulkQueue().Acquire(victimTenant), controllerTransport.ErrTenantQueueFull,
		"the flood must be bounded by the DNA queue's own per-tenant limit")

	// The victim tenant's connect and heartbeat capacity must be untouched.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queues.connectHeartbeatQueue().Acquire(victimTenant),
			"a DNA flood must not consume the victim tenant's connect/heartbeat slots")
	}
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		queues.connectHeartbeatQueue().Release(victimTenant)
		queues.dnaBulkQueue().Release(victimTenant)
	}

	// And the converse: a connect storm must not consume DNA-sync capacity.
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		require.NoError(t, queues.connectHeartbeatQueue().Acquire(victimTenant))
	}
	assert.NoError(t, queues.dnaBulkQueue().Acquire(victimTenant),
		"a connect storm must not consume the tenant's DNA/bulk slots")
	queues.dnaBulkQueue().Release(victimTenant)
	for i := 0; i < controllerTransport.MaxConcurrentPerTenant; i++ {
		queues.connectHeartbeatQueue().Release(victimTenant)
	}
}

// TestIngestAdmissionQueues_NilReceiverYieldsUsableQueues covers a Server
// assembled without New (some wiring tests build the struct directly): the
// accessors must still hand back a working gate rather than a nil queue that
// would panic on the first Acquire.
func TestIngestAdmissionQueues_NilReceiverYieldsUsableQueues(t *testing.T) {
	t.Parallel()

	var queues *ingestAdmissionQueues
	require.NotNil(t, queues.connectHeartbeatQueue())
	require.NotNil(t, queues.dnaBulkQueue())
	assert.NoError(t, queues.connectHeartbeatQueue().Acquire("tenant-a"))
	assert.NoError(t, queues.dnaBulkQueue().Acquire("tenant-a"))
}

// TestServer_New_ConnectAdmissionGateIsNotTheWireKeyedQueue asserts the wiring
// end to end: New() hands the control-plane provider (Register/ControlChannel)
// the server-verified-key queue, which is a different instance from the one
// Start() gives the DNA and bulk handlers.
func TestServer_New_ConnectAdmissionGateIsNotTheWireKeyedQueue(t *testing.T) {
	logger := logging.NewNoopLogger()

	tempDir := t.TempDir()
	caDir := tempDir + "/ca"
	_, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: tempDir,
		CAConfig: &cert.CAConfig{
			Organization: "Ingest Admission Test",
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
				CommonName:   "ingest-admission-controller",
				Organization: "Ingest Admission Test",
			},
		},
		Transport: &config.TransportConfig{
			ListenAddr:     "127.0.0.1:0",
			UseCertManager: true,
			MaxConnections: 10,
		},
		Storage: createTestStorageConfig(tempDir, "ingest-admission"),
	}

	srv, err := New(cfg, logger)
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.admissionQueues, "New() must create the ingest admission gates")
	require.NotSame(t, srv.admissionQueues.connectHeartbeatQueue(), srv.admissionQueues.dnaBulkQueue(),
		"the wire-keyed DNA/bulk gate must be a separate instance from the connect/heartbeat gate")

	cpProvider, ok := srv.controlPlane.(*grpcCP.Provider)
	require.True(t, ok, "control plane must be the gRPC provider")
	require.NotNil(t, cpProvider.TenantAdmission(), "connect/heartbeat must be gated by an admission queue")
	assert.Same(t, srv.admissionQueues.connectHeartbeatQueue(), cpProvider.TenantAdmission(),
		"the CP provider must hold the server-verified-key gate")
	assert.NotSame(t, srv.admissionQueues.dnaBulkQueue(), cpProvider.TenantAdmission(),
		"the CP provider must never hold the queue the wire-keyed DNA path uses")
}
