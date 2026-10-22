// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
)

const revocationTestMethod = "/cfgms.test.StreamRevocation/Hold"

// errChecker returns a lookup error for every serial. A real cert.Manager has
// no way to fail a lookup on demand, and this one case only needs the
// interceptor's reaction to an error, so a minimal checker is used here.
type errChecker struct{}

func (errChecker) IsRevoked(string) (bool, error) { return false, errors.New("store unavailable") }

type revocationTestEnv struct {
	mgr       *cert.Manager
	addr      string
	clientTLS func(t *testing.T) *tls.Config
	handlerCh chan error // receives the handler's return once its context ends
}

// startRevocationServer runs a TCP gRPC server with mTLS from a real
// cert.Manager and the interceptor under test. The "Hold" stream handler
// blocks until its (possibly interceptor-wrapped) context is done.
func startRevocationServer(t *testing.T, checker streamRevocationChecker, interval time.Duration) *revocationTestEnv {
	t.Helper()
	mgr, err := cert.NewManager(&cert.ManagerConfig{
		StoragePath: t.TempDir(),
		CAConfig:    &cert.CAConfig{Organization: "Test", Country: "US", ValidityDays: 30},
	})
	require.NoError(t, err)
	if checker == nil {
		checker = mgr
	}

	srvCert, err := mgr.GenerateServerCertificate(&cert.ServerCertConfig{
		CommonName: "localhost", DNSNames: []string{"localhost"}, IPAddresses: []string{"127.0.0.1"},
		Organization: "Test", ValidityDays: 30,
	})
	require.NoError(t, err)
	tlsCert, err := tls.X509KeyPair(srvCert.CertificatePEM, srvCert.PrivateKeyPEM)
	require.NoError(t, err)
	caPEM, err := mgr.GetCACertificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))

	env := &revocationTestEnv{mgr: mgr, handlerCh: make(chan error, 1)}
	logger := logging.NewLogger("debug")
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{tlsCert}, ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13,
		})),
		grpc.ChainStreamInterceptor(newStreamRevocationInterceptor(checker, logger, interval)),
		grpc.UnknownServiceHandler(func(_ interface{}, ss grpc.ServerStream) error {
			<-ss.Context().Done()
			env.handlerCh <- ss.Context().Err()
			return ss.Context().Err()
		}),
	)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	env.addr = lis.Addr().String()
	env.clientTLS = func(t *testing.T) *tls.Config {
		return &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
	}
	return env
}

// openStream issues a fresh client certificate and opens the Hold stream.
// The returned error is the first RecvMsg result, which carries the
// admission refusal when the interceptor rejects the stream.
func (e *revocationTestEnv) openStream(t *testing.T, ctx context.Context, revokeFirst bool) (serial string, recv func() error) {
	t.Helper()
	c, err := e.mgr.GenerateClientCertificate(&cert.ClientCertConfig{
		CommonName: "steward-test", Organization: "Test", ValidityDays: 30,
	})
	require.NoError(t, err)
	if revokeFirst {
		require.NoError(t, e.mgr.Revoke(c.SerialNumber))
	}
	pair, err := tls.X509KeyPair(c.CertificatePEM, c.PrivateKeyPEM)
	require.NoError(t, err)
	cfg := e.clientTLS(t)
	cfg.Certificates = []tls.Certificate{pair}

	conn, err := grpc.NewClient(e.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	cs, err := conn.NewStream(ctx, &grpc.StreamDesc{StreamName: "Hold", ServerStreams: true, ClientStreams: true}, revocationTestMethod)
	require.NoError(t, err)
	return c.SerialNumber, func() error {
		var out emptypb.Empty
		return cs.RecvMsg(&out)
	}
}

func TestStreamRevocation_RevokedCertRefusedAtAdmission(t *testing.T) {
	env := startRevocationServer(t, nil, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, recv := env.openStream(t, ctx, true)
	assert.Equal(t, codes.PermissionDenied, status.Code(recv()))
}

func TestStreamRevocation_ValidCertCancelledAfterRevocation(t *testing.T) {
	env := startRevocationServer(t, nil, 25*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	serial, recv := env.openStream(t, ctx, false)
	got := make(chan error, 1)
	go func() { got <- recv() }()

	select {
	case err := <-got:
		t.Fatalf("stream ended before revocation: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	require.NoError(t, env.mgr.Revoke(serial))
	select {
	case herr := <-env.handlerCh:
		assert.ErrorIs(t, herr, context.Canceled, "handler context must be cancelled by the interceptor")
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not cancelled after revocation")
	}
	select {
	case err := <-got:
		assert.Equal(t, codes.PermissionDenied, status.Code(err))
	case <-time.After(5 * time.Second):
		t.Fatal("client did not observe stream termination")
	}
}

func TestStreamRevocation_LookupErrorRefusedAtAdmission(t *testing.T) {
	env := startRevocationServer(t, errChecker{}, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, recv := env.openStream(t, ctx, false)
	assert.Equal(t, codes.Unavailable, status.Code(recv()))
}

func TestStreamRevocation_NoPeerCertificateUnauthenticated(t *testing.T) {
	interceptor := newStreamRevocationInterceptor(errChecker{}, logging.NewLogger("debug"), time.Hour)
	err := interceptor(nil, &fakeCtxStream{ctx: context.Background()}, &grpc.StreamServerInfo{FullMethod: revocationTestMethod},
		func(interface{}, grpc.ServerStream) error { t.Fatal("handler must not run"); return nil })
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// fakeCtxStream is a bare ServerStream carrying only a context, used for the
// no-peer case that a TLS listener never produces.
type fakeCtxStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeCtxStream) Context() context.Context { return f.ctx }
