// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package internaldelivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
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
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// peerAuthCA is one real controller-shaped CA: it signs the delivery listener's
// server certificate, the peer nodes' client certificates, and the steward and
// admin client certificates. That single anchor is the point of these tests —
// the controller CA signs every one of those identities in production too, so
// the TLS handshake cannot be what separates a peer node from a steward.
type peerAuthCA struct {
	ca    *cert.CA
	caPEM []byte
}

func newPeerAuthCA(t *testing.T) *peerAuthCA {
	t.Helper()

	ca, err := cert.NewCA(&cert.CAConfig{
		Organization: "CFGMS Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	return &peerAuthCA{ca: ca, caPEM: caPEM}
}

// serverTLS returns the delivery listener's mTLS server config: client
// certificates are required and verified against the same CA.
func (c *peerAuthCA) serverTLS(t *testing.T) *tls.Config {
	t.Helper()

	serverCert, err := c.ca.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	serverTLS, err := cert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM, c.caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	return serverTLS
}

// clientTLS mints a client certificate with the given identity and returns a
// client TLS config presenting it. modifier stamps extra template state (the
// admin marker) when non-nil.
func (c *peerAuthCA) clientTLS(t *testing.T, commonName, organization string, modifier func(*x509.Certificate)) *tls.Config {
	t.Helper()

	clientCert, err := c.ca.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName:       commonName,
		Organization:     organization,
		ValidityDays:     1,
		KeySize:          2048,
		TemplateModifier: modifier,
	})
	require.NoError(t, err)

	clientTLS, err := cert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM, c.caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	return clientTLS
}

// startAuthorizedDeliveryListener serves the real delivery service behind the
// real PeerAuthorizer over real mTLS, and returns its dial address.
func startAuthorizedDeliveryListener(t *testing.T, serverTLS *tls.Config, nodeIDs func() []string) string {
	t.Helper()

	handler := NewServer(registry.NewRegistry(), nil, logging.NewNoopLogger())
	authorizer := NewPeerAuthorizer(nodeIDs, logging.NewNoopLogger())

	grpcServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(serverTLS)),
		grpc.UnaryInterceptor(authorizer.UnaryInterceptor),
	)
	deliverypb.RegisterDeliveryServiceServer(grpcServer, handler)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String()
}

// callDelivery issues one DeliverCommand RPC against addr as clientTLS.
func callDelivery(t *testing.T, addr string, clientTLS *tls.Config) (*deliverypb.DeliverCommandResponse, error) {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return deliverypb.NewDeliveryServiceClient(conn).DeliverCommand(ctx, newTestRequest("steward-target", "cmd-authz"))
}

// TestPeerAuthorizer_AuthorizesClusterPeerNode proves the allow path: a client
// certificate whose CommonName is a known cluster node ID reaches the handler.
func TestPeerAuthorizer_AuthorizesClusterPeerNode(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), func() []string { return []string{"node-a", "node-b"} })

	resp, err := callDelivery(t, addr, ca.clientTLS(t, "node-b", "CFGMS", nil))
	require.NoError(t, err, "a peer node certificate must be authorized")
	assert.True(t, resp.GetNotConnected(),
		"the handler must have run: the target steward is absent from this node's registry")
}

// TestPeerAuthorizer_RejectsStewardCertificate is the primary security
// regression test (security review, Issue #3764): every steward client
// certificate is signed by the controller CA that also anchors this listener,
// so a steward completes the handshake. Delivering to it would hand any
// registered steward in any tenant a connectivity oracle over the whole fleet.
//
// The steward's CommonName here is deliberately a valid cluster node ID: the
// Organization marker must be sufficient on its own, so an ID collision cannot
// buy access.
func TestPeerAuthorizer_RejectsStewardCertificate(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), func() []string { return []string{"node-a"} })

	_, err := callDelivery(t, addr, ca.clientTLS(t, "node-a", StewardCertOrganization, nil))
	require.Error(t, err, "a steward certificate must never reach the inter-node delivery RPC")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestPeerAuthorizer_RejectsAdminCertificate covers the other identity the
// controller CA signs: an mTLS admin certificate carries full API authority but
// is not a cluster node, and the internal delivery RPC is not part of the admin
// API surface.
func TestPeerAuthorizer_RejectsAdminCertificate(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), func() []string { return []string{"admin-user"} })

	_, err := callDelivery(t, addr, ca.clientTLS(t, "admin-user", "CFGMS", cert.SetAdminMarker))
	require.Error(t, err, "an admin certificate must not be usable as a cluster peer identity")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestPeerAuthorizer_RejectsUnknownNodeID covers a well-formed, CA-signed
// certificate that simply is not a member of this cluster.
func TestPeerAuthorizer_RejectsUnknownNodeID(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), func() []string { return []string{"node-a"} })

	_, err := callDelivery(t, addr, ca.clientTLS(t, "node-unknown", "CFGMS", nil))
	require.Error(t, err, "a CN outside the cluster membership must be refused")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestPeerAuthorizer_FailsClosedWithoutMembership proves the fail-closed
// contract: with no membership source, no caller is authorized — a
// misconfiguration must not silently open the endpoint.
func TestPeerAuthorizer_FailsClosedWithoutMembership(t *testing.T) {
	ca := newPeerAuthCA(t)

	t.Run("nil node ID source", func(t *testing.T) {
		addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), nil)
		_, err := callDelivery(t, addr, ca.clientTLS(t, "node-a", "CFGMS", nil))
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})

	t.Run("empty cluster membership", func(t *testing.T) {
		addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), func() []string { return nil })
		_, err := callDelivery(t, addr, ca.clientTLS(t, "node-a", "CFGMS", nil))
		require.Error(t, err)
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	})
}

// TestPeerAuthorizer_RejectsNonMTLSContext covers the guard that runs before any
// certificate inspection: a context with no verified TLS peer (a plaintext
// listener, or a handshake that produced no verified chain) is denied rather
// than treated as anonymous-but-allowed.
func TestPeerAuthorizer_RejectsNonMTLSContext(t *testing.T) {
	authorizer := NewPeerAuthorizer(func() []string { return []string{"node-a"} }, logging.NewNoopLogger())

	err := authorizer.Authorize(context.Background())
	require.Error(t, err, "an RPC with no peer TLS identity must be denied")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestPeerAuthorizer_DenialMessageLeaksNothing guards the error contract: every
// rejection returns the same opaque message, so the endpoint cannot be used to
// enumerate cluster membership or learn why a certificate was refused.
func TestPeerAuthorizer_DenialMessageLeaksNothing(t *testing.T) {
	ca := newPeerAuthCA(t)
	addr := startAuthorizedDeliveryListener(t, ca.serverTLS(t), func() []string { return []string{"node-secret-id"} })

	_, stewardErr := callDelivery(t, addr, ca.clientTLS(t, "steward-1", StewardCertOrganization, nil))
	require.Error(t, stewardErr)
	_, unknownErr := callDelivery(t, addr, ca.clientTLS(t, "node-other", "CFGMS", nil))
	require.Error(t, unknownErr)

	assert.Equal(t, status.Convert(stewardErr).Message(), status.Convert(unknownErr).Message(),
		"every denial must be indistinguishable to the caller")
	assert.NotContains(t, status.Convert(unknownErr).Message(), "node-secret-id",
		"a denial must not disclose cluster membership")
}
