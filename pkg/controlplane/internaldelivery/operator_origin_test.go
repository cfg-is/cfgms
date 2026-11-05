// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package internaldelivery

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	deliverypb "github.com/cfgis/cfgms/api/proto/clusterdelivery"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// originSeen is what the receiving node's control plane observed on one SendCommand.
type originSeen struct {
	commandID string
	principal string
	marked    bool
}

// originCapturingCP wraps the receiving node's real local provider and records the
// operator-origin marker on the context of each SendCommand. It optionally refuses,
// as the node's own gate does for a locked-down steward.
type originCapturingCP struct {
	controlplaneInterfaces.ControlPlaneProvider
	mu     sync.Mutex
	seen   []originSeen
	refuse error
}

func (c *originCapturingCP) SendCommand(ctx context.Context, cmd *controlplaneTypes.SignedCommand) error {
	principal, marked := controlplaneInterfaces.OperatorOriginFrom(ctx)
	c.mu.Lock()
	c.seen = append(c.seen, originSeen{commandID: cmd.Command.ID, principal: principal, marked: marked})
	refuse := c.refuse
	c.mu.Unlock()
	if refuse != nil {
		return refuse
	}
	return c.ControlPlaneProvider.SendCommand(ctx, cmd)
}

func (c *originCapturingCP) snapshot() []originSeen {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]originSeen(nil), c.seen...)
}

// startOriginPeer serves the real delivery service behind the real PeerAuthorizer
// and returns its address and the capturing local control plane.
func startOriginPeer(t *testing.T, ca *peerAuthCA, stewardID string) (string, *originCapturingCP) {
	t.Helper()
	localCP, _ := newConnectedMemoryPair(t, stewardID)
	capture := &originCapturingCP{ControlPlaneProvider: localCP}

	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{StewardID: stewardID, Sender: fakeSender{}, ConnectedAt: time.Now()}))

	authorizer := NewPeerAuthorizer(func() []string { return []string{"node-a", "node-b"} }, logging.NewNoopLogger())
	handler := NewServer(reg, capture, logging.NewNoopLogger())
	handler.SetPeerAuthorizer(authorizer)

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(ca.serverTLS(t))),
		grpc.UnaryInterceptor(authorizer.UnaryInterceptor),
	)
	deliverypb.RegisterDeliveryServiceServer(grpcServer, handler)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)
	return lis.Addr().String(), capture
}

func originSender(t *testing.T, peerAddr string, clientTLS *tls.Config) *ClusterAwareSender {
	t.Helper()
	localCP, _ := newConnectedMemoryPair(t, "some-other-steward")
	routing := newFlatFileRoutingStore(t)
	require.NoError(t, routing.RecordConnection(context.Background(), "steward-remote", "node-b"))
	sender := NewClusterAwareSender(localCP, "node-a", routing,
		&fakeNodeResolver{addrs: map[string]string{"node-b": peerAddr}}, clientTLS, logging.NewNoopLogger())
	t.Cleanup(func() { _ = sender.Close() })
	return sender
}

func originCmd(id string) *controlplaneTypes.SignedCommand {
	return &controlplaneTypes.SignedCommand{Command: controlplaneTypes.Command{
		ID: id, Type: controlplaneTypes.CommandExecuteScript, StewardID: "steward-remote", Timestamp: time.Now(),
	}}
}

// The marker and principal survive ClusterAwareSender to the receiving node, and
// an unmarked command does not gain it.
func TestClusterAwareSender_OperatorOriginSurvivesForwarding(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr, capture := startOriginPeer(t, ca, "steward-remote")
	sender := originSender(t, addr, ca.clientTLS(t, "node-a", "CFGMS", nil))

	opCtx := controlplaneInterfaces.WithOperatorOrigin(context.Background(), "alice")
	require.NoError(t, sender.SendCommand(opCtx, originCmd("marked")))
	require.NoError(t, sender.SendCommand(context.Background(), originCmd("unmarked")))

	seen := capture.snapshot()
	require.Len(t, seen, 2)
	assert.Equal(t, originSeen{commandID: "marked", principal: "alice", marked: true}, seen[0])
	assert.Equal(t, originSeen{commandID: "unmarked"}, seen[1])
}

func TestClusterAwareSender_FanOutForwardsOperatorOrigin(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr, capture := startOriginPeer(t, ca, "steward-remote")
	sender := originSender(t, addr, ca.clientTLS(t, "node-a", "CFGMS", nil))

	opCtx := controlplaneInterfaces.WithOperatorOrigin(context.Background(), "alice")
	result, err := sender.FanOutCommand(opCtx, originCmd("fan"), []string{"steward-remote"})
	require.NoError(t, err)
	assert.Equal(t, []string{"steward-remote"}, result.Succeeded)
	require.Len(t, capture.snapshot(), 1)
	assert.Equal(t, "alice", capture.snapshot()[0].principal)
}

// A caller holding a steward or admin certificate cannot supply the marker.
func TestDeliverCommand_StewardOrAdminCertificateCannotSupplyOperatorOrigin(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr, capture := startOriginPeer(t, ca, "steward-remote")

	for name, clientTLS := range map[string]*tls.Config{
		"steward": ca.clientTLS(t, "node-b", StewardCertOrganization, nil),
		"admin":   ca.clientTLS(t, "node-b", "CFGMS", cert.SetAdminMarker),
	} {
		t.Run(name, func(t *testing.T) {
			conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
			require.NoError(t, err)
			defer func() { _ = conn.Close() }()

			req := newTestRequest("steward-remote", "forged-"+name)
			req.OperatorOrigin = true
			req.OperatorPrincipal = "mallory"
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err = deliverypb.NewDeliveryServiceClient(conn).DeliverCommand(ctx, req)
			require.Error(t, err)
			assert.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
	assert.Empty(t, capture.snapshot(), "no forged command may reach the local control plane")
}

// The handler itself restores the marker only after the peer authorization, so it
// does not depend on how the server is mounted.
func TestServer_DeliverCommand_DoesNotRestoreMarkerWithoutPeerAuthorization(t *testing.T) {
	localCP, _ := newConnectedMemoryPair(t, "steward-1")
	capture := &originCapturingCP{ControlPlaneProvider: localCP}
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{StewardID: "steward-1", Sender: fakeSender{}, ConnectedAt: time.Now()}))

	req := newTestRequest("steward-1", "c1")
	req.OperatorOrigin = true
	req.OperatorPrincipal = "mallory"

	noAuthorizer := NewServer(reg, capture, logging.NewNoopLogger())
	_, err := noAuthorizer.DeliverCommand(context.Background(), req)
	require.NoError(t, err)

	// An authorizer is bound but the call carries no verified peer certificate.
	withAuthorizer := NewServer(reg, capture, logging.NewNoopLogger())
	withAuthorizer.SetPeerAuthorizer(NewPeerAuthorizer(func() []string { return []string{"node-a"} }, logging.NewNoopLogger()))
	_, err = withAuthorizer.DeliverCommand(context.Background(), req)
	require.NoError(t, err)

	for _, s := range capture.snapshot() {
		assert.False(t, s.marked, "marker must not be restored for %s", s.commandID)
	}
}

// The receiving node's own gate refusal is reported as a refusal, not "not connected".
func TestServer_DeliverCommand_LockdownRefusalIsNotNotConnected(t *testing.T) {
	localCP, _ := newConnectedMemoryPair(t, "steward-1")
	capture := &originCapturingCP{ControlPlaneProvider: localCP, refuse: controlplaneInterfaces.ErrStewardLockedDown}
	reg := registry.NewRegistry()
	require.NoError(t, reg.Register(&registry.StewardConnection{StewardID: "steward-1", Sender: fakeSender{}, ConnectedAt: time.Now()}))

	resp, err := NewServer(reg, capture, logging.NewNoopLogger()).DeliverCommand(context.Background(), newTestRequest("steward-1", "c1"))
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	assert.Nil(t, resp)
}
