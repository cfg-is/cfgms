// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package grpc

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// openStreamFrom opens a real ControlChannel stream whose UDP source address is
// srcIP, optionally carrying host attributes, and returns the client stream so a
// test can observe how the controller ends it.
func openStreamFrom(t *testing.T, srcIP, serverAddr string, tlsCfg *tls.Config, attrs map[string]string) grpc.BidiStreamingClient[transportpb.ControlMessage, transportpb.ControlMessage] {
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
	if enc := encodeHostAttrs(attrs); enc != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, HostAttrsHeader, enc)
	}
	stream, err := transportpb.NewStewardTransportClient(cc).ControlChannel(ctx)
	require.NoError(t, err)
	// The controller refuses without reading, so a refusal can land before this
	// Send: gRPC then reports io.EOF and delivers the real status on Recv.
	if err := stream.Send(&transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: &transportpb.Heartbeat{}}}); err != nil {
		require.ErrorIs(t, err, io.EOF)
	}
	return stream
}

// recvStatus blocks until the stream ends and returns its terminal error.
func recvStatus(t *testing.T, stream grpc.BidiStreamingClient[transportpb.ControlMessage, transportpb.ControlMessage]) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				done <- err
				return
			}
		}
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not end")
		return nil
	}
}

func requireIdentityInUse(t *testing.T, err error) {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status, got %v", err)
	assert.Equal(t, codes.PermissionDenied, st.Code())
	var reason, domain string
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			reason, domain = info.GetReason(), info.GetDomain()
		}
	}
	assert.Equal(t, "IDENTITY_IN_USE", reason)
	assert.Equal(t, "cfgms.io", domain)
}

var (
	matchingAttrs = map[string]string{"machine_id": "m-1", "nic_macs": "aa:bb", "disk_serials": "d-1", "install_date": "2026-01-01"}
	copyAttrs     = map[string]string{"machine_id": "m-1", "nic_macs": "cc:dd", "disk_serials": "d-9", "install_date": "2030-01-01"}
)

func TestControlChannel_CopyRefusedWithIdentityInUseReason(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-ciu", baselineJSON)
	server, _ := env.startServer(t, WithProvenanceChecker(env.spy))
	tlsCfg, _ := env.clientTLS(t, "steward-ciu")

	// Raw wire: PermissionDenied carrying the ErrorInfo detail, no peer address.
	stream := openStreamFrom(t, "127.0.0.1", server.ListenAddr(), tlsCfg, copyAttrs)
	err := recvStatus(t, stream)
	requireIdentityInUse(t, err)
	st, _ := status.FromError(err)
	assert.NotContains(t, st.Message(), "127.0.0.1")
	assert.NotContains(t, st.Message(), "::1")

	// Real provider client: surfaces ErrIdentityInUse, which is also a rejection.
	client := New(ModeClient, WithHostAttributes(func() map[string]string { return copyAttrs }))
	require.NoError(t, client.Initialize(context.Background(), map[string]interface{}{
		"mode": "client", "addr": server.ListenAddr(), "tls_config": tlsCfg, "steward_id": "steward-ciu",
		"admission_window": 5 * time.Second,
	}))
	t.Cleanup(func() { _ = client.Stop(context.Background()) })
	cerr := client.Start(context.Background())
	require.Error(t, cerr)
	assert.ErrorIs(t, cerr, interfaces.ErrIdentityInUse)
	assert.ErrorIs(t, cerr, interfaces.ErrIdentityRejected)
	assert.NotContains(t, cerr.Error(), "127.0.0.1")
}

// TestControlChannel_RefusalSurvivesClientSendAfterTeardown covers a client that
// keeps sending after the controller has refused it: Send reports io.EOF once the
// stream has ended, and the refusal status must still be what Recv returns
// (Issue #5039), never a bare EOF.
func TestControlChannel_RefusalSurvivesClientSendAfterTeardown(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-late", baselineJSON)
	server, _ := env.startServer(t, WithProvenanceChecker(env.spy))
	tlsCfg, _ := env.clientTLS(t, "steward-late")

	stream := openStreamFrom(t, "127.0.0.1", server.ListenAddr(), tlsCfg, copyAttrs)
	hb := &transportpb.ControlMessage{Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: &transportpb.Heartbeat{}}}
	require.Eventually(t, func() bool { return stream.Send(hb) != nil },
		5*time.Second, time.Millisecond, "controller never ended the refused stream")
	requireIdentityInUse(t, recvStatus(t, stream))
}

func TestControlChannel_PlainPermissionDeniedIsNotIdentityInUse(t *testing.T) {
	t.Parallel()
	assert.False(t, isIdentityInUse(status.Error(codes.PermissionDenied, "steward reconnect not approved")))
	assert.True(t, isIdentityInUse(identityInUseError()))
	assert.False(t, isIdentityInUse(nil))
}

func TestControlChannel_ApprovedMachineDisplacesCopyOnOtherHost(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-disp", baselineJSON)
	_, reg, port := env.startWildcardServer(t, WithProvenanceChecker(env.spy))
	tlsCfg, _ := env.sharedClientTLS(t, "steward-disp")

	// Host A connects without attributes (Unknown) and holds the channel.
	existing := openStreamFrom(t, "127.0.0.1", "127.0.0.1:"+port, tlsCfg, nil)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-disp"); return ok }, 5*time.Second, 10*time.Millisecond)
	first, _ := reg.Get("steward-disp")

	// Host B presents the approved machine's provenance: admitted.
	_ = openStreamFrom(t, "::1", "[::1]:"+port, tlsCfg, matchingAttrs)
	require.Eventually(t, func() bool { c, ok := reg.Get("steward-disp"); return ok && c != first },
		5*time.Second, 10*time.Millisecond, "approved machine must take the channel")

	requireIdentityInUse(t, recvStatus(t, existing))

	cur, ok := reg.Get("steward-disp")
	require.True(t, ok)
	assert.Contains(t, cur.RemoteAddr, "::1")
}

func TestControlChannel_UnknownProvenanceKeepsFirstConnection(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-keep", baselineJSON)
	_, reg, port := env.startWildcardServer(t, WithProvenanceChecker(env.spy))
	tlsCfg, _ := env.sharedClientTLS(t, "steward-keep")

	first := openStreamFrom(t, "127.0.0.1", "127.0.0.1:"+port, tlsCfg, nil)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-keep"); return ok }, 5*time.Second, 10*time.Millisecond)
	firstConn, _ := reg.Get("steward-keep")

	second := openStreamFrom(t, "::1", "[::1]:"+port, tlsCfg, nil)
	requireIdentityInUse(t, recvStatus(t, second))

	cur, ok := reg.Get("steward-keep")
	require.True(t, ok)
	assert.Same(t, firstConn, cur, "refused newcomer must not displace the first connection")

	// First connection undisturbed: its stream is still open.
	ended := make(chan error, 1)
	go func() { _, err := first.Recv(); ended <- err }()
	select {
	case err := <-ended:
		t.Fatalf("first connection was disturbed: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
}

func TestControlChannel_SameHostReconnectStillReplaces(t *testing.T) {
	t.Parallel()
	env := newProvEnv(t, "steward-same", baselineJSON)
	_, reg, port := env.startWildcardServer(t, WithProvenanceChecker(env.spy))
	tlsCfg, _ := env.sharedClientTLS(t, "steward-same")

	_ = openStreamFrom(t, "127.0.0.1", "127.0.0.1:"+port, tlsCfg, nil)
	require.Eventually(t, func() bool { _, ok := reg.Get("steward-same"); return ok }, 5*time.Second, 10*time.Millisecond)
	first, _ := reg.Get("steward-same")

	_ = openStreamFrom(t, "127.0.0.1", "127.0.0.1:"+port, tlsCfg, nil)
	require.Eventually(t, func() bool { c, ok := reg.Get("steward-same"); return ok && c != first },
		5*time.Second, 10*time.Millisecond, "same-host reconnect must replace the stale stream")
}
