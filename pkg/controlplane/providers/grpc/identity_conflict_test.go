// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
)

type recordingConflictObserver struct {
	mu        sync.Mutex
	conflicts []IdentityConflict
}

func (r *recordingConflictObserver) ObserveIdentityConflict(_ context.Context, c IdentityConflict) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conflicts = append(r.conflicts, c)
}

func (r *recordingConflictObserver) snapshot() []IdentityConflict {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]IdentityConflict(nil), r.conflicts...)
}

// startWildcardServer listens on all interfaces so a client can reach it from
// distinct loopback source addresses (127.0.0.1 and 127.0.0.2).
func (e *revocationEnv) startWildcardServer(t *testing.T, opts ...option) (*Provider, registry.Registry, string) {
	t.Helper()
	reg := registry.NewRegistry()
	server := New(ModeServer, append([]option{WithApprovalChecker(approveAll{})}, opts...)...)
	require.NoError(t, server.Initialize(context.Background(), map[string]interface{}{
		"mode": "server", "addr": "0.0.0.0:0", "tls_config": e.serverTLS, "registry": reg,
	}))
	require.NoError(t, server.Start(context.Background()))
	t.Cleanup(server.ForceStop)
	_, port, err := net.SplitHostPort(server.ListenAddr())
	require.NoError(t, err)
	_, err = strconv.Atoi(port)
	require.NoError(t, err)
	return server, reg, port
}

// sharedClientTLS issues one client certificate and returns its config and serial.
func (e *revocationEnv) sharedClientTLS(t *testing.T, stewardID string) (*tls.Config, string) {
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

// quicStreamConn adapts a QUIC stream to net.Conn so grpc can run over a
// connection bound to a chosen source address.
type quicStreamConn struct {
	*quicgo.Stream
	conn *quicgo.Conn
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

// openControlChannelFrom opens a real ControlChannel stream whose UDP source
// address is srcIP, so the server observes a distinct peer host. The kernel
// would otherwise pick 127.0.0.1 for every loopback destination.
func openControlChannelFrom(t *testing.T, srcIP, serverAddr string, tlsCfg *tls.Config) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(srcIP)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = udp.Close() })
	remote, err := net.ResolveUDPAddr("udp", serverAddr)
	require.NoError(t, err)

	dialer := func(ctx context.Context, _ string) (net.Conn, error) {
		qc, err := quicgo.Dial(ctx, udp, remote, tlsCfg, &quicgo.Config{KeepAlivePeriod: time.Second})
		if err != nil {
			return nil, err
		}
		st, err := qc.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return &quicStreamConn{Stream: st, conn: qc}, nil
	}
	cc, err := grpc.NewClient(quictransport.DialTarget(serverAddr),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stream, err := transportpb.NewStewardTransportClient(cc).ControlChannel(ctx)
	require.NoError(t, err)
	// Send a heartbeat so the stream is definitely flushed to the server.
	_ = stream.Send(&transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: &transportpb.Heartbeat{}}})
}

func TestControlChannel_DuplicateIdentityDifferentPeer_ReportsConflict(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	obs := &recordingConflictObserver{}
	_, reg, port := env.startWildcardServer(t, WithRevocationChecker(env.mgr), WithIdentityConflictObserver(obs))
	tlsCfg, serial := env.sharedClientTLS(t, "steward-dup")

	_, err := startRevocationClient(t, "127.0.0.1:"+port, tlsCfg, "steward-dup", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-dup"); return ok },
		5*time.Second, 10*time.Millisecond)
	assert.Empty(t, obs.snapshot(), "first connection is not a conflict")

	openControlChannelFrom(t, "127.0.0.2", "127.0.0.1:"+port, tlsCfg)
	require.Eventually(t, func() bool { return len(obs.snapshot()) >= 1 },
		5*time.Second, 10*time.Millisecond)

	got := obs.snapshot()
	require.Len(t, got, 1)
	c := got[0]
	assert.Equal(t, "steward-dup", c.StewardID)
	assert.Equal(t, "127.0.0.1", addrHost(c.ExistingAddr))
	assert.Equal(t, "127.0.0.2", addrHost(c.NewAddr))
	assert.Equal(t, serial, c.ExistingSerial)
	assert.Equal(t, serial, c.NewSerial)
	assert.False(t, c.DetectedAt.IsZero())
}

func TestControlChannel_SameHostReconnect_NoConflict(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	obs := &recordingConflictObserver{}
	_, reg, port := env.startWildcardServer(t, WithRevocationChecker(env.mgr), WithIdentityConflictObserver(obs))
	tlsCfg, _ := env.sharedClientTLS(t, "steward-restart")

	_, err := startRevocationClient(t, "127.0.0.1:"+port, tlsCfg, "steward-restart", 0)
	require.NoError(t, err)
	var first *registry.StewardConnection
	require.Eventually(t, func() bool { c, ok := reg.Get("steward-restart"); first = c; return ok },
		5*time.Second, 10*time.Millisecond)

	// Second stream from the same host (different source port) while the first is live.
	_, err = startRevocationClient(t, "127.0.0.1:"+port, tlsCfg, "steward-restart", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { c, ok := reg.Get("steward-restart"); return ok && c != first },
		5*time.Second, 10*time.Millisecond, "new stream must still replace the stale one")

	assert.Empty(t, obs.snapshot(), "same-host reconnect is not a conflict")
}

func TestControlChannel_RevokedPeerNeverReportsConflict(t *testing.T) {
	t.Parallel()
	env := newRevocationEnv(t)
	obs := &recordingConflictObserver{}
	_, reg, port := env.startWildcardServer(t, WithRevocationChecker(env.mgr), WithIdentityConflictObserver(obs))
	okCfg, _ := env.sharedClientTLS(t, "steward-rv")
	revCfg, revSerial := env.sharedClientTLS(t, "steward-rv")

	_, err := startRevocationClient(t, "127.0.0.1:"+port, okCfg, "steward-rv", 0)
	require.NoError(t, err)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-rv"); return ok },
		5*time.Second, 10*time.Millisecond)

	require.NoError(t, env.mgr.Revoke(revSerial))
	openControlChannelFrom(t, "127.0.0.2", "127.0.0.1:"+port, revCfg)
	time.Sleep(500 * time.Millisecond)
	assert.Empty(t, obs.snapshot(), "a revoked serial is refused before conflict detection")
}
