// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package internaldelivery

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
	certpkg "github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testutil"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// fakeNodeResolver is a role fake for internaldelivery.NodeResolver — a small
// seam interface owned by this package specifically to decouple it from
// pkg/ha, not a stand-in for a CFGMS business component.
type fakeNodeResolver struct {
	addrs map[string]string
}

func (r *fakeNodeResolver) ResolveDeliveryAddr(nodeID string) (string, bool) {
	addr, ok := r.addrs[nodeID]
	return addr, ok
}

// startPeerDeliveryServer starts a real mTLS gRPC server hosting a real
// internaldelivery.Server backed by a real memory.Provider + registry, with
// stewardID connected. Returns its listen address and a channel the test can
// read delivered commands from.
func startPeerDeliveryServer(t *testing.T, stewardID string, serverTLS *tls.Config) (addr string, received chan *controlplaneTypes.SignedCommand) {
	t.Helper()

	localCP, received := newConnectedMemoryPair(t, stewardID)
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      fakeSender{},
		ConnectedAt: time.Now(),
	}))

	deliveryServer := NewServer(reg, localCP, logging.NewNoopLogger())

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)))
	deliverypb.RegisterDeliveryServiceServer(grpcServer, deliveryServer)

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String(), received
}

// testTLSPair generates a CA + server + client certificate set via the
// shared test cert helper and returns ready-to-use server/client tls.Config.
func testTLSPair(t *testing.T) (serverTLS, clientTLS *tls.Config) {
	t.Helper()
	certDir, cleanup := testutil.SetupTestCerts(t)
	t.Cleanup(cleanup)

	readFile := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(certDir, name)) // #nosec G304 -- test-generated path under t's own temp dir
		require.NoError(t, err)
		return data
	}

	caCert := readFile("ca.crt")
	serverCert := readFile("server.crt")
	serverKey := readFile("server.key")
	clientCert := readFile("client.crt")
	clientKey := readFile("client.key")

	serverTLS, err := certpkg.CreateServerTLSConfig(serverCert, serverKey, caCert, tls.VersionTLS13)
	require.NoError(t, err)
	clientTLS, err = certpkg.CreateClientTLSConfig(clientCert, clientKey, caCert, "cfgms-controller", tls.VersionTLS13)
	require.NoError(t, err)
	return serverTLS, clientTLS
}

func TestClusterAwareSender_SendCommand_ForwardsToRoutedPeer(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS := testTLSPair(t)

	peerAddr, received := startPeerDeliveryServer(t, "steward-remote", serverTLS)

	// The local node has no connection for steward-remote — every SendCommand
	// through it must fail with ErrStewardNotConnected.
	localCP, _ := newConnectedMemoryPair(t, "some-other-steward")

	routingStore := newFlatFileRoutingStore(t)
	require.NoError(t, routingStore.RecordConnection(ctx, "steward-remote", "node-b"))

	resolver := &fakeNodeResolver{addrs: map[string]string{"node-b": peerAddr}}

	sender := NewClusterAwareSender(localCP, "node-a", routingStore, resolver, clientTLS, logging.NewNoopLogger())
	t.Cleanup(func() { _ = sender.Close() })

	cmd := &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        "cmd-forward-1",
			Type:      controlplaneTypes.CommandSyncConfig,
			StewardID: "steward-remote",
			Timestamp: time.Now(),
		},
	}

	require.NoError(t, sender.SendCommand(ctx, cmd))

	select {
	case got := <-received:
		assert.Equal(t, "cmd-forward-1", got.Command.ID)
	case <-time.After(2 * time.Second):
		t.Fatal("peer node never received the forwarded command")
	}
}

func TestClusterAwareSender_SendCommand_LocalDeliverySucceedsWithoutForwarding(t *testing.T) {
	ctx := context.Background()
	localCP, received := newConnectedMemoryPair(t, "steward-local")

	// No routing store / resolver needed: local delivery must succeed and
	// never consult the cluster fallback at all.
	sender := NewClusterAwareSender(localCP, "node-a", nil, nil, nil, logging.NewNoopLogger())

	cmd := &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        "cmd-local-1",
			Type:      controlplaneTypes.CommandSyncConfig,
			StewardID: "steward-local",
			Timestamp: time.Now(),
		},
	}
	require.NoError(t, sender.SendCommand(ctx, cmd))

	select {
	case got := <-received:
		assert.Equal(t, "cmd-local-1", got.Command.ID)
	case <-time.After(2 * time.Second):
		t.Fatal("locally connected steward never received the command")
	}
}

func TestClusterAwareSender_SendCommand_FallsBackToOriginalErrorWhenNoRoute(t *testing.T) {
	ctx := context.Background()
	localCP, _ := newConnectedMemoryPair(t, "some-other-steward")

	routingStore := newFlatFileRoutingStore(t)
	// No RecordConnection call: no routing entry exists for steward-remote.

	sender := NewClusterAwareSender(localCP, "node-a", routingStore, &fakeNodeResolver{addrs: map[string]string{}}, nil, logging.NewNoopLogger())

	cmd := &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        "cmd-2",
			Type:      controlplaneTypes.CommandSyncConfig,
			StewardID: "steward-remote",
			Timestamp: time.Now(),
		},
	}

	err := sender.SendCommand(ctx, cmd)
	require.Error(t, err)
	assert.ErrorIs(t, err, controlplaneInterfaces.ErrStewardNotConnected,
		"with no routing entry, the caller must see the same error it would see without cluster mode, so its existing outbox fallback still fires")
}

func TestClusterAwareSender_SendCommand_DoesNotForwardWhenRoutingPointsToSelf(t *testing.T) {
	ctx := context.Background()
	localCP, _ := newConnectedMemoryPair(t, "some-other-steward")

	routingStore := newFlatFileRoutingStore(t)
	require.NoError(t, routingStore.RecordConnection(ctx, "steward-remote", "node-a"))

	sender := NewClusterAwareSender(localCP, "node-a", routingStore, &fakeNodeResolver{addrs: map[string]string{}}, nil, logging.NewNoopLogger())

	cmd := &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        "cmd-3",
			Type:      controlplaneTypes.CommandSyncConfig,
			StewardID: "steward-remote",
			Timestamp: time.Now(),
		},
	}

	err := sender.SendCommand(ctx, cmd)
	require.Error(t, err)
	assert.ErrorIs(t, err, controlplaneInterfaces.ErrStewardNotConnected)
}

func TestClusterAwareSender_FanOutCommand_ForwardsOnlyFailedStewards(t *testing.T) {
	ctx := context.Background()
	serverTLS, clientTLS := testTLSPair(t)
	peerAddr, received := startPeerDeliveryServer(t, "steward-remote", serverTLS)

	localCP, localReceived := newConnectedMemoryPair(t, "steward-local")

	routingStore := newFlatFileRoutingStore(t)
	require.NoError(t, routingStore.RecordConnection(ctx, "steward-remote", "node-b"))

	resolver := &fakeNodeResolver{addrs: map[string]string{"node-b": peerAddr}}
	sender := NewClusterAwareSender(localCP, "node-a", routingStore, resolver, clientTLS, logging.NewNoopLogger())
	t.Cleanup(func() { _ = sender.Close() })

	cmd := &controlplaneTypes.SignedCommand{
		Command: controlplaneTypes.Command{
			ID:        "cmd-fanout-1",
			Type:      controlplaneTypes.CommandSyncConfig,
			Timestamp: time.Now(),
		},
	}

	result, err := sender.FanOutCommand(ctx, cmd, []string{"steward-local", "steward-remote"})
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"steward-local", "steward-remote"}, result.Succeeded)
	assert.Empty(t, result.Failed)

	select {
	case <-localReceived:
	case <-time.After(2 * time.Second):
		t.Fatal("local steward never received the fanned-out command")
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("remote steward never received the forwarded command")
	}
}
