// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package cluster holds the repeatable benchmarks for Epic #3751 (ADR-031):
// proving the epic's own core claim — adding a controller node adds serving
// capacity — with measured numbers instead of assertion. See
// docs/testing/cluster-benchmark.md for how to run these and read the output.
package cluster

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	deliverypb "github.com/cfgis/cfgms/api/proto/clusterdelivery"
	controllerapi "github.com/cfgis/cfgms/features/controller/api"
	"github.com/cfgis/cfgms/features/controller/commands"
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	certpkg "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/internaldelivery"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// ---------------------------------------------------------------------------
// BenchmarkAPIThroughput_SingleVsMultiNode (S7: any-node service)
// ---------------------------------------------------------------------------

// newBenchStorageManager builds one real OSS storage manager (flatfile +
// file-backed SQLite) shared by every simulated node in a sub-benchmark, the
// same way every real controller node in a cluster shares one durable DB
// (ADR-007).
func newBenchStorageManager(b *testing.B) *interfaces.StorageManager {
	b.Helper()
	flatfileRoot := b.TempDir()
	sqlitePath := "file:" + filepath.Join(b.TempDir(), "cluster-bench.db")
	sm, err := interfaces.CreateOSSStorageManager(flatfileRoot, sqlitePath)
	require.NoError(b, err)
	b.Cleanup(func() { _ = sm.Close() })
	return sm
}

// newBenchControllerNode builds one real *controllerapi.Server against the
// shared storage manager, mirroring the exact component wiring order used by
// TestStewardDecommissionCycle_FullControllerStack
// (test/integration/steward_controller_detailed_test.go) — real RBAC, tenant,
// controller and configuration services, real audit manager — so that each
// simulated "node" is the same production stack, just an independent
// in-memory instance layered on the one shared durable store.
func newBenchControllerNode(b *testing.B, storageManager *interfaces.StorageManager) *controllerapi.Server {
	b.Helper()
	ctx := context.Background()
	logger := logging.NewNoopLogger()

	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	require.NoError(b, rbacManager.Initialize(ctx))
	b.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(b, err)
	b.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	server, err := controllerapi.New(
		cfg, logger, controllerService, configService, nil, rbacService,
		nil, tenantManager, rbacManager,
		nil, nil, nil, "", nil, auditMgr, nil, nil, nil,
	)
	require.NoError(b, err)
	b.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Close(closeCtx)
	})

	server.SetStewardStore(storageManager.GetStewardStore())
	return server
}

// newBenchAdminCert mints a self-signed admin-marker client certificate, the
// same shape as newAdminPeerCert in steward_controller_detailed_test.go. The
// admin marker resolves to an ImplicitAdmin principal (middleware.go), which
// is what lets the same certificate authenticate against every node without
// per-node account provisioning — reused across the whole benchmark run since
// certificate generation itself must not be in the timed loop.
func newBenchAdminCert(b *testing.B) *x509.Certificate {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "cluster-bench-admin"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certpkg.SetAdminMarker(tmpl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(b, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(b, err)
	return parsed
}

// runAPIThroughput drives GET /api/v1/stewards — the [minimum real,
// authenticated, storage-backed, state-serving GET] per handlers_stewards.go
// (an unfiltered list touches both the in-memory controllerService and, once
// SetStewardStore is wired, the real steward store) — through each node's
// production router concurrently, distributing load round-robin across
// however many node stacks are given. Measuring the same request shape at
// node count 1 vs N is what isolates "does adding a node add capacity" from
// "is this endpoint fast."
func runAPIThroughput(b *testing.B, nodes []*controllerapi.Server, adminCert *x509.Certificate) {
	b.Helper()
	var next int64

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		node := nodes[atomic.AddInt64(&next, 1)%int64(len(nodes))]
		for pb.Next() {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
			req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{adminCert}}
			rec := httptest.NewRecorder()
			node.GetRouter().ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				b.Fatalf("unexpected status %d: %s", rec.Code, rec.Body.String())
			}
		}
	})
}

// BenchmarkAPIThroughput_SingleVsMultiNode measures aggregate GET
// /api/v1/stewards throughput at 1 node vs 3 nodes, all real controller
// stacks sharing one real storage manager (ADR-007's shared DB is the actual
// serialization point any-node service relies on — see
// docs/architecture/decisions/031-controller-cluster-service-model.md). The
// epic's claim under test: ops/sec at 3 nodes should scale up relative to 1
// node, not be capped by a single node's capacity.
func BenchmarkAPIThroughput_SingleVsMultiNode(b *testing.B) {
	secretsCleanup, err := testutil.ProvisionSecretsEnv("cluster-bench-secrets")
	require.NoError(b, err)
	b.Cleanup(secretsCleanup)

	ctx := context.Background()

	storageManager := newBenchStorageManager(b)
	stewardStore := storageManager.GetStewardStore()
	for i := 0; i < 10; i++ {
		require.NoError(b, stewardStore.RegisterSteward(ctx, &business.StewardRecord{
			ID:       fmt.Sprintf("cluster-bench-steward-%d", i),
			TenantID: "cluster-bench-tenant",
			Status:   business.StewardStatusActive,
		}))
	}

	adminCert := newBenchAdminCert(b)

	b.Run("1-node", func(b *testing.B) {
		node := newBenchControllerNode(b, storageManager)
		runAPIThroughput(b, []*controllerapi.Server{node}, adminCert)
	})

	b.Run("3-node", func(b *testing.B) {
		nodes := []*controllerapi.Server{
			newBenchControllerNode(b, storageManager),
			newBenchControllerNode(b, storageManager),
			newBenchControllerNode(b, storageManager),
		}
		runAPIThroughput(b, nodes, adminCert)
	})
}

// ---------------------------------------------------------------------------
// BenchmarkCrossNodeDeliveryLatency (S10: cross-node command delivery)
// ---------------------------------------------------------------------------
//
// This mirrors test/integration/transport/cross_node_command_delivery_test.go
// exactly (same real components: routing store, ClusterAwareSender, real mTLS
// gRPC internal delivery service, real memory control-plane provider) but as
// a timed b.N loop instead of a single pass/fail assertion. The helpers below
// are intentionally duplicated rather than imported: they are unexported in
// package transport, and this benchmark's story (#3765) is explicit that it
// must exercise the real #3764 delivery path, not a stand-in — duplicating
// the same real-component wiring keeps that true here too.

// benchStewardSender is a registry.MessageSender role fake — the registry
// only needs somewhere to record that a connection exists; the real delivery
// path never calls SendMsg (it goes through the control-plane provider).
type benchStewardSender struct{}

func (benchStewardSender) SendMsg(_ interface{}) error { return nil }

// benchNodeResolver implements internaldelivery.NodeResolver against a fixed
// map, standing in for pkg/ha's cluster-membership-backed resolver.
type benchNodeResolver struct {
	addrs map[string]string
}

func (r *benchNodeResolver) ResolveDeliveryAddr(nodeID string) (string, bool) {
	addr, ok := r.addrs[nodeID]
	return addr, ok
}

// benchCrossNodeTLS issues real mTLS material for the forwarding hop. Calls
// testutil.GenerateTestCertificates directly against a b.TempDir() (rather
// than testutil.SetupTestCertsWithConfig, which requires *testing.T) since
// *testing.B does not satisfy *testing.T.
func benchCrossNodeTLS(b *testing.B, callerNodeID string) (serverTLS, clientTLS *tls.Config) {
	b.Helper()
	certConfig := testutil.DefaultCertConfig()
	certConfig.ClientName = callerNodeID
	certConfig.CertDir = b.TempDir()
	require.NoError(b, testutil.GenerateTestCertificates(certConfig))

	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(certConfig.CertDir, name)) // #nosec G304 -- benchmark-generated path under b's own temp dir
		require.NoError(b, err)
		return data
	}

	serverTLS, err := certpkg.CreateServerTLSConfig(read("server.crt"), read("server.key"), read("ca.crt"), tls.VersionTLS13)
	require.NoError(b, err)
	clientTLS, err = certpkg.CreateClientTLSConfig(read("client.crt"), read("client.key"), read("ca.crt"), "cfgms-controller", tls.VersionTLS13)
	require.NoError(b, err)
	return serverTLS, clientTLS
}

// benchStartNodeBListener stands up node B: a real registry.Registry with
// stewardID connected, a real memory.Provider control plane with a client
// subscribed for stewardID, and the real internaldelivery.Server exposed over
// a real mTLS gRPC listener.
func benchStartNodeBListener(b *testing.B, stewardID string, serverTLS *tls.Config, authorizedNodeIDs []string) (addr string, received chan *controlplaneTypes.SignedCommand) {
	b.Helper()
	ctx := context.Background()

	bus := memory.NewBus()
	nodeBControlPlane := memory.New(memory.ModeServer)
	require.NoError(b, nodeBControlPlane.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(b, nodeBControlPlane.Start(ctx))
	b.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = nodeBControlPlane.Stop(stopCtx)
	})

	stewardClient := memory.New(memory.ModeClient)
	require.NoError(b, stewardClient.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": stewardID}))
	require.NoError(b, stewardClient.Start(ctx))
	b.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = stewardClient.Stop(stopCtx)
	})

	received = make(chan *controlplaneTypes.SignedCommand, 16)
	require.NoError(b, stewardClient.SubscribeCommands(ctx, stewardID, func(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
		received <- cmd
		return nil
	}))

	nodeBRegistry := registry.NewRegistry()
	require.NoError(b, nodeBRegistry.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      benchStewardSender{},
		ConnectedAt: time.Now(),
	}))

	deliveryServer := internaldelivery.NewServer(nodeBRegistry, nodeBControlPlane, logging.NewNoopLogger())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(b, err)

	// The peer authorizer the API server installs in production: only mTLS
	// leaves whose CommonName is a live cluster node ID are admitted.
	peerAuth := internaldelivery.NewPeerAuthorizer(
		func() []string { return authorizedNodeIDs }, logging.NewNoopLogger())

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.UnaryInterceptor(peerAuth.UnaryInterceptor),
	)
	deliverypb.RegisterDeliveryServiceServer(grpcServer, deliveryServer)
	go func() { _ = grpcServer.Serve(lis) }()
	b.Cleanup(grpcServer.Stop)

	return lis.Addr().String(), received
}

// BenchmarkCrossNodeDeliveryLatency measures real end-to-end delivery time
// from dispatch on node A to receipt confirmation for a steward connected
// only to peer node B (Issue #3764, ADR-031 Decision 3): node A's local
// control plane never has a connection for the steward, so every iteration is
// forced through ClusterAwareSender's routing-table lookup and real mTLS gRPC
// forwarding hop to node B, exactly as
// TestCrossNodeCommandDelivery_ReachesStewardConnectedToPeerNode proves
// correctness for, just timed here instead of asserted once.
func BenchmarkCrossNodeDeliveryLatency(b *testing.B) {
	ctx := context.Background()
	const stewardID = "cluster-bench-steward-cross-node"
	const nodeAID = "cluster-bench-node-a"
	const nodeBID = "cluster-bench-node-b"

	serverTLS, clientTLS := benchCrossNodeTLS(b, nodeAID)
	nodeBAddr, nodeBReceived := benchStartNodeBListener(b, stewardID, serverTLS, []string{nodeAID})

	// Node A's own local control plane: started, but with no client ever
	// connected for stewardID, so every local SendCommand attempt fails with
	// ErrStewardNotConnected — the only way to force every iteration through
	// the cross-node forwarding path.
	nodeABus := memory.NewBus()
	nodeAControlPlane := memory.New(memory.ModeServer)
	require.NoError(b, nodeAControlPlane.Initialize(ctx, map[string]interface{}{"bus": nodeABus}))
	require.NoError(b, nodeAControlPlane.Start(ctx))
	b.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = nodeAControlPlane.Stop(stopCtx)
	})

	// The shared steward-routing table, populated exactly as
	// routingTableConnectHook populates it on node B's real connect path.
	routingStore, err := flatfile.NewFlatFileRoutingStore(b.TempDir())
	require.NoError(b, err)
	require.NoError(b, routingStore.RecordConnection(ctx, stewardID, nodeBID))

	resolver := &benchNodeResolver{addrs: map[string]string{nodeBID: nodeBAddr}}
	clusterSender := internaldelivery.NewClusterAwareSender(nodeAControlPlane, nodeAID, routingStore, resolver, clientTLS, logging.NewNoopLogger())
	b.Cleanup(func() { _ = clusterSender.Close() })

	publisher, err := commands.New(&commands.Config{ControlPlane: clusterSender, Logger: logging.NewNoopLogger()})
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, pubErr := publisher.PublishCommand(ctx, stewardID, controlplaneTypes.CommandSyncConfig, nil); pubErr != nil {
			b.Fatalf("cross-node publish failed on iteration %d: %v", i, pubErr)
		}
		select {
		case <-nodeBReceived:
		case <-time.After(5 * time.Second):
			b.Fatalf("steward connected to peer node B never received the command on iteration %d", i)
		}
	}
	b.StopTimer()
}
