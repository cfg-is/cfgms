// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

// revocationEnv is a real cert.Manager plus a server whose steward is approved.
type revocationEnv struct {
	mgr       *cfgcert.Manager
	serverTLS *tls.Config
	caPEM     []byte
}

func newRevocationEnv(t *testing.T) *revocationEnv {
	t.Helper()
	mgr, err := cfgcert.NewManager(&cfgcert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cfgcert.CAConfig{Organization: "CFGMS Test", Country: "US", ValidityDays: 1},
	})
	require.NoError(t, err)
	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)
	sc, err := mgr.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, ValidityDays: 1,
	})
	require.NoError(t, err)
	serverTLS, err := cfgcert.CreateServerTLSConfig(sc.CertificatePEM, sc.PrivateKeyPEM, caPEM, tls.VersionTLS13)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}
	return &revocationEnv{mgr: mgr, serverTLS: serverTLS, caPEM: caPEM}
}

// clientTLS issues a steward client certificate and returns its TLS config and serial.
func (e *revocationEnv) clientTLS(t *testing.T, stewardID string) (*tls.Config, string) {
	t.Helper()
	cc, err := e.mgr.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: stewardID, ValidityDays: 1})
	require.NoError(t, err)
	block, _ := pem.Decode(cc.CertificatePEM)
	require.NotNil(t, block)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	cfg, err := cfgcert.CreateClientTLSConfig(cc.CertificatePEM, cc.PrivateKeyPEM, e.caPEM, "localhost", tls.VersionTLS13)
	require.NoError(t, err)
	cfg.NextProtos = []string{quictransport.ALPNProtocol}
	return cfg, parsed.SerialNumber.String()
}

func (e *revocationEnv) startServer(t *testing.T, opts ...option) (*Provider, registry.Registry) {
	t.Helper()
	reg := registry.NewRegistry()
	server := New(ModeServer, append([]option{WithApprovalChecker(approveAll{})}, opts...)...)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "127.0.0.1:0", "tls_config": e.serverTLS, "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	return server, reg
}

func startRevocationClient(t *testing.T, addr string, tlsCfg *tls.Config, stewardID string, window time.Duration) (*Provider, error) {
	t.Helper()
	client := New(ModeClient)
	cfg := map[string]interface{}{
		"mode": "client", "addr": addr, "tls_config": tlsCfg, "steward_id": stewardID,
	}
	if window > 0 {
		cfg["admission_window"] = window
	}
	require.NoError(t, client.Initialize(context.Background(), cfg))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	return client, client.Start(context.Background())
}

type errRevocationChecker struct{}

func (errRevocationChecker) IsRevoked(string) (bool, error) {
	return false, errors.New("revocation store unavailable")
}

func TestRevocation_RevokedSerialRefused(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t, WithRevocationChecker(env.mgr))
	tlsCfg, serial := env.clientTLS(t, "steward-revoked")
	require.NoError(t, env.mgr.Revoke(serial))

	_, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-revoked", 5*time.Second)
	require.Error(t, err)
	assert.ErrorIs(t, err, interfaces.ErrIdentityRejected, "revoked serial must be an identity rejection (PermissionDenied)")
	_, ok := reg.Get("steward-revoked")
	assert.False(t, ok)
}

func TestRevocation_NonRevokedSerialAdmitted(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t, WithRevocationChecker(env.mgr))
	tlsCfg, _ := env.clientTLS(t, "steward-ok")

	_, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-ok", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-ok"); return ok },
		5*time.Second, 10*time.Millisecond)
}

func TestRevocation_StoreErrorFailsClosed(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t, WithRevocationChecker(errRevocationChecker{}))
	tlsCfg, _ := env.clientTLS(t, "steward-store-err")

	_, _ = startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-store-err", 0)
	require.Never(t, func() bool { _, ok := reg.Get("steward-store-err"); return ok },
		700*time.Millisecond, 10*time.Millisecond, "revocation lookup error must refuse admission")
}

func TestRevocation_RegisterRefusesRevokedSerial(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	p := New(ModeServer, WithRevocationChecker(env.mgr))
	cc, err := env.mgr.GenerateClientCertificate(&cfgcert.ClientCertConfig{CommonName: "steward-reg", ValidityDays: 1})
	require.NoError(t, err)
	block, _ := pem.Decode(cc.CertificatePEM)
	parsed, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{
			HandshakeComplete: true,
			PeerCertificates:  []*x509.Certificate{parsed},
			VerifiedChains:    [][]*x509.Certificate{{parsed}},
		},
	}})
	ts := &transportServer{provider: p}

	require.NoError(t, env.mgr.Revoke(parsed.SerialNumber.String()))
	_, err = ts.Register(ctx, &controllerpb.RegisterRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	p.revocationChecker = errRevocationChecker{}
	_, err = ts.Register(ctx, &controllerpb.RegisterRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestRevocation_OpenStreamClosedAfterRevoke(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	server, reg := env.startServer(t,
		WithRevocationChecker(env.mgr), WithRevocationRecheckInterval(100*time.Millisecond))
	tlsCfg, serial := env.clientTLS(t, "steward-open")

	_, err := startRevocationClient(t, server.ListenAddr(), tlsCfg, "steward-open", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-open"); return ok },
		5*time.Second, 10*time.Millisecond)

	require.NoError(t, env.mgr.Revoke(serial))

	// Closed within a few re-check intervals; the reconnect is then refused.
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-open"); return !ok },
		5*time.Second, 20*time.Millisecond, "open stream must close after its serial is revoked")
}
