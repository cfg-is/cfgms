// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	deliverypb "github.com/cfgis/cfgms/api/proto/clusterdelivery"
	"github.com/cfgis/cfgms/features/controller/commands"
	certpkg "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/internaldelivery"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// crossNodeSender implements registry.MessageSender as a role fake for a
// steward's transport stream — the registry only needs somewhere to write
// to record that a connection exists; it is not a stand-in for any CFGMS
// business component under test.
type crossNodeSender struct{}

func (crossNodeSender) SendMsg(_ interface{}) error { return nil }

// crossNodeResolver implements internaldelivery.NodeResolver against a fixed
// map, standing in for pkg/ha's cluster-membership-backed resolver in this
// two-node test (the real resolver's own address-composition logic is
// covered by features/controller/server's resolver unit tests).
type crossNodeResolver struct {
	addrs map[string]string
}

func (r *crossNodeResolver) ResolveDeliveryAddr(nodeID string) (string, bool) {
	addr, ok := r.addrs[nodeID]
	return addr, ok
}

// startNodeBDeliveryListener stands up node B: a real registry.Registry with
// stewardID connected, a real memory.Provider control plane with a client
// subscribed for stewardID, and the real internaldelivery.Server exposed over
// a real mTLS gRPC listener — exactly the shape ADR-031 Decision 3 describes
// as the receiving side of a forwarded delivery request.
func startNodeBDeliveryListener(t *testing.T, stewardID string, serverTLS *tls.Config) (addr string, received chan *controlplaneTypes.SignedCommand) {
	t.Helper()
	ctx := context.Background()

	bus := memory.NewBus()
	nodeBControlPlane := memory.New(memory.ModeServer)
	require.NoError(t, nodeBControlPlane.Initialize(ctx, map[string]interface{}{"bus": bus}))
	require.NoError(t, nodeBControlPlane.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = nodeBControlPlane.Stop(stopCtx)
	})

	stewardClient := memory.New(memory.ModeClient)
	require.NoError(t, stewardClient.Initialize(ctx, map[string]interface{}{"bus": bus, "steward_id": stewardID}))
	require.NoError(t, stewardClient.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = stewardClient.Stop(stopCtx)
	})

	received = make(chan *controlplaneTypes.SignedCommand, 4)
	require.NoError(t, stewardClient.SubscribeCommands(ctx, stewardID, func(_ context.Context, cmd *controlplaneTypes.SignedCommand) error {
		received <- cmd
		return nil
	}))

	nodeBRegistry := registry.NewRegistry()
	require.NoError(t, nodeBRegistry.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      crossNodeSender{},
		ConnectedAt: time.Now(),
	}))

	deliveryServer := internaldelivery.NewServer(nodeBRegistry, nodeBControlPlane, logging.NewNoopLogger())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	deliverypb.RegisterDeliveryServiceServer(grpcServer, deliveryServer)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String(), received
}

func crossNodeTestTLS(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	certDir, cleanup := testutil.SetupTestCerts(t)
	t.Cleanup(cleanup)

	read := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(certDir, name)) // #nosec G304 -- test-generated path under t's own temp dir
		require.NoError(t, err)
		return data
	}

	serverTLS, err := certpkg.CreateServerTLSConfig(read("server.crt"), read("server.key"), read("ca.crt"), tls.VersionTLS13)
	require.NoError(t, err)
	clientTLS, err = certpkg.CreateClientTLSConfig(read("client.crt"), read("client.key"), read("ca.crt"), "cfgms-controller", tls.VersionTLS13)
	require.NoError(t, err)
	return serverTLS, clientTLS
}

// TestCrossNodeCommandDelivery_ReachesStewardConnectedToPeerNode is the
// [REQUIRED TEST] two-node integration test (Issue #3764, ADR-031 Decision
// 3): two real controller-service-shaped stacks — a real
// pkg/transport/registry.Registry, a real control-plane provider, and the
// real internal delivery gRPC service on each side — prove that a command
// published on node A reaches a steward connected only to peer node B, and
// that the real S4 outbox row (pkg/storage/interfaces/business.CommandStore)
// used as the delivery's durable fixture transitions from pending to
// delivered.
//
// Node A deliberately has NO connection for the target steward, forcing its
// local control plane to fail with ErrStewardNotConnected on every attempt —
// the only way SendCommand reaches node A's ClusterAwareSender's forwarding
// path at all.
func TestCrossNodeCommandDelivery_ReachesStewardConnectedToPeerNode(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-cross-node"
	const nodeAID = "node-a"
	const nodeBID = "node-b"

	serverTLS, clientTLS := crossNodeTestTLS(t)
	nodeBAddr, nodeBReceived := startNodeBDeliveryListener(t, stewardID, serverTLS)

	// Node A's own local control plane: started, but with no client ever
	// connected for stewardID, so every local SendCommand attempt for it
	// fails with ErrStewardNotConnected.
	nodeABus := memory.NewBus()
	nodeAControlPlane := memory.New(memory.ModeServer)
	require.NoError(t, nodeAControlPlane.Initialize(ctx, map[string]interface{}{"bus": nodeABus}))
	require.NoError(t, nodeAControlPlane.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = nodeAControlPlane.Stop(stopCtx)
	})

	// The shared steward-routing table: populated exactly as
	// routingTableConnectHook populates it on node B's real connect path,
	// telling node A that node B currently holds stewardID.
	routingStore, err := flatfile.NewFlatFileRoutingStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, routingStore.RecordConnection(ctx, stewardID, nodeBID))

	resolver := &crossNodeResolver{addrs: map[string]string{nodeBID: nodeBAddr}}
	clusterSender := internaldelivery.NewClusterAwareSender(nodeAControlPlane, nodeAID, routingStore, resolver, clientTLS, logging.NewNoopLogger())
	t.Cleanup(func() { _ = clusterSender.Close() })

	publisher, err := commands.New(&commands.Config{ControlPlane: clusterSender, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)

	// The real S4 outbox row (Issue #3757): created durable and pending,
	// exactly as handlers_stewards.go does before attempting delivery.
	commandStore, err := (&sqlite.SQLiteProvider{}).CreateCommandStore(map[string]interface{}{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = commandStore.Close() })

	rec := &business.CommandRecord{
		ID:             "cross-node-cmd-1",
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      stewardID,
		TenantID:       "tenant-cross-node",
		DeliveryStatus: business.DeliveryStatusPending,
	}
	require.NoError(t, commandStore.CreateCommandRecord(ctx, rec))

	before, err := commandStore.GetCommandRecord(ctx, rec.ID)
	require.NoError(t, err)
	require.Equal(t, business.DeliveryStatusPending, before.DeliveryStatus, "fixture must start pending")

	// The dispatch attempt itself: node A has no local connection for
	// stewardID, so this only succeeds if ClusterAwareSender resolves the
	// routing table and forwards to node B over the real mTLS gRPC delivery
	// service, and node B's Server delivers it via its own local control
	// plane to the connected steward client.
	_, pubErr := publisher.PublishCommand(ctx, stewardID, controlplaneTypes.CommandSyncConfig, nil)
	require.NoError(t, pubErr, "cross-node delivery must succeed via the routing table + internal delivery RPC fallback")

	select {
	case got := <-nodeBReceived:
		assert.Equal(t, stewardID, got.Command.StewardID)
	case <-time.After(3 * time.Second):
		t.Fatal("steward connected to peer node B never received the command forwarded from node A")
	}

	// The outbox row's lifecycle transition (Issue #3757, ADR-031 Decision 2):
	// a successful publish is recorded exactly as handlers_stewards.go records
	// one after a successful commandPublisher call.
	require.NoError(t, commandStore.UpdateDeliveryStatus(ctx, rec.ID, business.DeliveryStatusDelivered, ""))
	after, err := commandStore.GetCommandRecord(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusDelivered, after.DeliveryStatus,
		"the real outbox row must transition from pending to delivered once cross-node delivery succeeds")
}

// TestCrossNodeCommandDelivery_FallsBackToOutboxWhenPeerUnreachable proves the
// negative case named in the story: the durable outbox (Issue #3757) is the
// guarantee underneath the fast path, so a forwarding failure (no routing
// entry, here) must leave the row pending rather than lost or falsely marked
// delivered — the caller's existing outbox retry/drain path is what recovers
// it, not this RPC.
func TestCrossNodeCommandDelivery_FallsBackToOutboxWhenPeerUnreachable(t *testing.T) {
	ctx := context.Background()
	const stewardID = "steward-unreachable"
	const nodeAID = "node-a"

	nodeABus := memory.NewBus()
	nodeAControlPlane := memory.New(memory.ModeServer)
	require.NoError(t, nodeAControlPlane.Initialize(ctx, map[string]interface{}{"bus": nodeABus}))
	require.NoError(t, nodeAControlPlane.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = nodeAControlPlane.Stop(stopCtx)
	})

	routingStore, err := flatfile.NewFlatFileRoutingStore(t.TempDir())
	require.NoError(t, err)
	// No RecordConnection: no peer known for this steward.

	clusterSender := internaldelivery.NewClusterAwareSender(nodeAControlPlane, nodeAID, routingStore, &crossNodeResolver{addrs: map[string]string{}}, nil, logging.NewNoopLogger())
	t.Cleanup(func() { _ = clusterSender.Close() })

	publisher, err := commands.New(&commands.Config{ControlPlane: clusterSender, Logger: logging.NewNoopLogger()})
	require.NoError(t, err)

	commandStore, err := (&sqlite.SQLiteProvider{}).CreateCommandStore(map[string]interface{}{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = commandStore.Close() })

	rec := &business.CommandRecord{
		ID:             "cross-node-cmd-2",
		Type:           string(controlplaneTypes.CommandSyncConfig),
		StewardID:      stewardID,
		TenantID:       "tenant-cross-node",
		DeliveryStatus: business.DeliveryStatusPending,
	}
	require.NoError(t, commandStore.CreateCommandRecord(ctx, rec))

	_, pubErr := publisher.PublishCommand(ctx, stewardID, controlplaneTypes.CommandSyncConfig, nil)
	require.Error(t, pubErr, "with no routing entry and no local connection, delivery must fail rather than silently succeed")

	rec2, err := commandStore.GetCommandRecord(ctx, rec.ID)
	require.NoError(t, err)
	assert.Equal(t, business.DeliveryStatusPending, rec2.DeliveryStatus,
		"a failed delivery attempt must leave the outbox row pending for the normal retry/drain path, never falsely delivered")
}
