// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

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
	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/internaldelivery"
	grpcconvert "github.com/cfgis/cfgms/pkg/controlplane/providers/grpc"
	"github.com/cfgis/cfgms/pkg/controlplane/providers/memory"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// newDeliveryListenerServer returns an api.Server configured so Start() reaches
// the internal delivery listener branch: cluster mode (which is what produces a
// non-nil internal mTLS config), managed TLS from a real cert.Manager, and
// ephemeral public/metrics/Raft addresses. The caller supplies the delivery
// address and peer-node allowlist via SetDeliveryHandler.
func newDeliveryListenerServer(t *testing.T, certMgr *cert.Manager) *Server {
	t.Helper()
	t.Setenv("CFGMS_HTTP_LISTEN_ADDR", "127.0.0.1:0")

	server := setupTestServer(t)
	server.cfg.MetricsListenAddr = reservePrivateMetricsAddress(t)
	server.cfg.Certificate.EnableCertManagement = true
	server.certManager = certMgr
	// Cluster mode is the gate on internalRaftTLSConfig, whose result is also
	// the delivery listener's TLS material. The inherited controller-CA client
	// pool is the trust anchor here, exactly as it is in production.
	server.cfg.HA = &config.HAConfig{Mode: "cluster"}
	server.cfg.InternalListenAddr = reservePrivateMetricsAddress(t)
	return server
}

// newDeliveryHandler builds a real internaldelivery.Server over a real
// registry and a real (started) control-plane provider. The registry is empty,
// so an authorized peer's delivery attempt reports not-connected — enough to
// prove the RPC was served and authorized end to end.
func newDeliveryHandler(t *testing.T) *internaldelivery.Server {
	t.Helper()
	ctx := context.Background()

	controlPlane := memory.New(memory.ModeServer)
	require.NoError(t, controlPlane.Initialize(ctx, map[string]interface{}{"bus": memory.NewBus()}))
	require.NoError(t, controlPlane.Start(ctx))
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = controlPlane.Stop(stopCtx)
	})

	return internaldelivery.NewServer(registry.NewRegistry(), controlPlane, logging.NewNoopLogger())
}

// deliveryClientTLS mints a client certificate from certMgr's CA and returns a
// client TLS config presenting it. commonName carries the caller identity the
// PeerAuthorizer checks; organization distinguishes a steward leaf
// (internaldelivery.StewardCertOrganization) from a peer-node leaf.
func deliveryClientTLS(t *testing.T, certMgr *cert.Manager, commonName, organization string) *tls.Config {
	t.Helper()

	clientCert, err := certMgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:   commonName,
		Organization: organization,
		ValidityDays: 1,
	})
	require.NoError(t, err)

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)

	clientTLS, err := cert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM, caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	return clientTLS
}

// deliverCommandAs dials addr with clientTLS and issues one DeliverCommand RPC.
func deliverCommandAs(t *testing.T, addr string, clientTLS *tls.Config, stewardID string) (*deliverypb.DeliverCommandResponse, error) {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return deliverypb.NewDeliveryServiceClient(conn).DeliverCommand(ctx, &deliverypb.DeliverCommandRequest{
		StewardId: stewardID,
		Command: grpcconvert.SignedCommandToProto(&controlplaneTypes.SignedCommand{
			Command: controlplaneTypes.Command{
				ID:        "delivery-listener-test-cmd",
				Type:      controlplaneTypes.CommandSyncConfig,
				StewardID: stewardID,
			},
		}),
	})
}

// portIsFree reports whether addr can be bound, i.e. Start's cleanup actually
// released the listeners it had already opened.
func portIsFree(t *testing.T, addr string) bool {
	t.Helper()
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	require.NoError(t, lis.Close())
	return true
}

// TestServerStart_RejectsUnsafeDeliveryListenAddr covers the delivery
// listener's address validation: the internal delivery RPC must never bind a
// public interface, and rejecting it must leave no half-started server behind —
// the public, metrics and Raft listeners bound moments earlier have to be
// closed again, not leaked.
func TestServerStart_RejectsUnsafeDeliveryListenAddr(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	server := newDeliveryListenerServer(t, certMgr)
	metricsAddr := server.cfg.MetricsListenAddr

	server.SetDeliveryHandler(newDeliveryHandler(t), "0.0.0.0:19099", func() []string { return []string{"node-a"} })

	err := server.Start()

	require.ErrorContains(t, err, "invalid internal delivery listener",
		"a delivery listener on a public interface must fail closed")
	assert.Nil(t, server.httpServer, "the public API must not be published when the delivery listener is rejected")
	assert.Nil(t, server.deliveryGRPCServer, "no delivery gRPC server may exist after the address is rejected")
	assert.True(t, portIsFree(t, metricsAddr),
		"the already-bound metrics listener must be closed when the delivery address is rejected")
}

// TestServerStart_FailsWhenDeliveryListenerCannotBind covers the bind-failure
// branch: an address already in use must abort Start with a clear error and
// release every listener bound before it.
func TestServerStart_FailsWhenDeliveryListenerCannotBind(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	server := newDeliveryListenerServer(t, certMgr)
	metricsAddr := server.cfg.MetricsListenAddr

	// Hold the delivery port for the duration of Start so the bind must fail.
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = occupied.Close() }()

	server.SetDeliveryHandler(newDeliveryHandler(t), occupied.Addr().String(), func() []string { return []string{"node-a"} })

	err = server.Start()

	require.ErrorContains(t, err, "bind private delivery listener",
		"a delivery port that is already in use must abort startup")
	assert.Nil(t, server.httpServer, "the public API must not be published when the delivery listener cannot bind")
	assert.Nil(t, server.deliveryGRPCServer, "no delivery gRPC server may exist after a bind failure")
	assert.True(t, portIsFree(t, metricsAddr),
		"the already-bound metrics listener must be closed when the delivery bind fails")
}

// TestServerStartClose_DeliveryListenerServesAuthorizedPeersOnly is the
// end-to-end wiring proof for SetDeliveryHandler + Start + Close: the delivery
// RPC is actually served over private mTLS, a cluster peer node's certificate
// is accepted, a steward certificate signed by the SAME controller CA is
// refused with PermissionDenied (the listener's trust anchor is wider than its
// authorized caller set), and Close releases the port.
func TestServerStartClose_DeliveryListenerServesAuthorizedPeersOnly(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	server := newDeliveryListenerServer(t, certMgr)

	deliveryAddr := reservePrivateMetricsAddress(t)
	server.SetDeliveryHandler(newDeliveryHandler(t), deliveryAddr, func() []string { return []string{"node-peer"} })

	require.NoError(t, server.Start())
	require.NotNil(t, server.deliveryGRPCServer, "Start must publish the delivery gRPC server")

	// An authorized peer node reaches the handler: the steward is unknown to
	// this node's registry, so the service reports not-connected rather than an
	// authorization error.
	resp, err := deliverCommandAs(t, deliveryAddr,
		deliveryClientTLS(t, certMgr, "node-peer", "CFGMS"), "steward-not-here")
	require.NoError(t, err, "a cluster peer node certificate must be authorized")
	assert.True(t, resp.GetNotConnected(), "the steward is not in this node's registry")

	// A steward certificate is signed by the same controller CA and therefore
	// completes the mTLS handshake — the application-layer check is what must
	// stop it before it can probe steward connectivity on this node.
	_, err = deliverCommandAs(t, deliveryAddr,
		deliveryClientTLS(t, certMgr, "steward-attacker", internaldelivery.StewardCertOrganization), "steward-not-here")
	require.Error(t, err, "a steward certificate must not be able to call the inter-node delivery RPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"a steward certificate must be refused with PermissionDenied, not served")

	// An unknown node ID is refused even though its certificate is valid.
	_, err = deliverCommandAs(t, deliveryAddr,
		deliveryClientTLS(t, certMgr, "node-not-in-cluster", "CFGMS"), "steward-not-here")
	require.Error(t, err, "a CN that is not a known cluster node must be refused")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, server.Close(closeCtx), "Close must stop the delivery server cleanly")

	assert.True(t, portIsFree(t, deliveryAddr), "Close must release the delivery listener port")
}

// TestServerClose_DeliveryGracefulStopHonoursContext covers the Close fallback:
// GracefulStop blocks until in-flight RPCs finish, so Close must bound it by the
// caller's context instead of inheriting an unbounded drain.
//
// The RPC is held open inside the real peer-authorization interceptor by a
// cluster-membership lookup that does not return — the production lookup reads
// pkg/ha cluster membership, which is exactly the kind of call that can stall.
// Close returning within the caller's deadline (rather than blocking on the
// held RPC) is the property under test; the deadline itself is asserted, not
// merely relied on, because a regression here manifests as a hang rather than
// a failure.
func TestServerClose_DeliveryGracefulStopHonoursContext(t *testing.T) {
	certMgr := newTLSTestCertManager(t)
	server := newDeliveryListenerServer(t, certMgr)

	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	releaseOnce := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseOnce)

	deliveryAddr := reservePrivateMetricsAddress(t)
	server.SetDeliveryHandler(newDeliveryHandler(t), deliveryAddr, func() []string {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-release
		return []string{"node-peer"}
	})

	require.NoError(t, server.Start())

	rpcDone := make(chan struct{})
	go func() {
		defer close(rpcDone)
		_, _ = deliverCommandAs(t, deliveryAddr, deliveryClientTLS(t, certMgr, "node-peer", "CFGMS"), "steward-not-here")
	}()

	select {
	case <-entered:
	case <-time.After(15 * time.Second):
		t.Fatal("the delivery RPC never reached the peer-authorization interceptor")
	}

	closeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	closeErr := make(chan error, 1)
	go func() { closeErr <- server.Close(closeCtx) }()

	select {
	case err := <-closeErr:
		require.Error(t, err, "Close must report that the delivery server could not drain in time")
		assert.ErrorContains(t, err, "timed out stopping internal delivery server",
			"the delivery drain timeout must be the reported cause")
	case <-time.After(30 * time.Second):
		t.Fatal("Close did not return within its context deadline: the delivery drain is unbounded")
	}

	// GracefulStop closes listeners before it starts draining, so the port is
	// released even though the RPC is still held.
	assert.True(t, portIsFree(t, deliveryAddr),
		"the delivery listener must be closed even when the drain times out")

	releaseOnce()
	select {
	case <-rpcDone:
	case <-time.After(15 * time.Second):
		t.Fatal("the held delivery RPC never completed after being released")
	}
}
