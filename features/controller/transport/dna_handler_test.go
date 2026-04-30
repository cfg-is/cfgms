// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	cfgcert "github.com/cfgis/cfgms/pkg/cert"
	"github.com/cfgis/cfgms/pkg/logging"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
)

// ---------------------------------------------------------------------------
// Mock stream
// ---------------------------------------------------------------------------

type testDNAStream struct {
	chunks  []*transportpb.DNAChunk
	pos     int
	resp    *transportpb.DNASyncResponse
	ctx     context.Context
	recvErr error
}

func newTestDNAStream(ctx context.Context, chunks ...*transportpb.DNAChunk) *testDNAStream {
	return &testDNAStream{chunks: chunks, ctx: ctx}
}

func (s *testDNAStream) Recv() (*transportpb.DNAChunk, error) {
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	if s.pos >= len(s.chunks) {
		return nil, io.EOF
	}
	chunk := s.chunks[s.pos]
	s.pos++
	return chunk, nil
}

func (s *testDNAStream) SendAndClose(resp *transportpb.DNASyncResponse) error {
	s.resp = resp
	return nil
}

func (s *testDNAStream) SetHeader(metadata.MD) error  { return nil }
func (s *testDNAStream) SendHeader(metadata.MD) error { return nil }
func (s *testDNAStream) SetTrailer(metadata.MD)       {}
func (s *testDNAStream) Context() context.Context     { return s.ctx }
func (s *testDNAStream) SendMsg(interface{}) error    { return nil }
func (s *testDNAStream) RecvMsg(interface{}) error    { return nil }

// Compile-time check: testDNAStream must implement the required interface.
var _ grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse] = (*testDNAStream)(nil)

// ---------------------------------------------------------------------------
// testTransportSrv — minimal StewardTransportServer for round-trip tests
// ---------------------------------------------------------------------------

type testTransportSrv struct {
	transportpb.UnimplementedStewardTransportServer
	dnaHandler  *DNAHandler
	bulkHandler *BulkHandler
}

func (s *testTransportSrv) SyncDNA(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	return s.dnaHandler.HandleGRPC(stream)
}

func (s *testTransportSrv) BulkTransfer(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	return s.bulkHandler.HandleGRPC(stream)
}

// Compile-time check.
var _ transportpb.StewardTransportServer = (*testTransportSrv)(nil)

// ---------------------------------------------------------------------------
// roundTripEnv — gRPC-over-QUIC server+client pair
// ---------------------------------------------------------------------------

type roundTripEnv struct {
	client    transportpb.StewardTransportClient
	stewardID string
	cleanup   func()
}

// newRoundTripEnv starts a gRPC-over-QUIC server and returns a client whose
// mTLS certificate CN matches stewardID.
func newRoundTripEnv(t *testing.T, stewardID string) *roundTripEnv {
	t.Helper()

	ca, err := cfgcert.NewCA(&cfgcert.CAConfig{
		Organization: "CFGMS Transport Test",
		Country:      "US",
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)
	require.NoError(t, ca.Initialize(nil))

	caPEM, err := ca.GetCACertificate()
	require.NoError(t, err)

	serverCert, err := ca.GenerateServerCertificate(&cfgcert.ServerCertConfig{
		CommonName:   "localhost",
		DNSNames:     []string{"localhost"},
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	serverTLS, err := cfgcert.CreateServerTLSConfig(
		serverCert.CertificatePEM, serverCert.PrivateKeyPEM,
		caPEM, tls.VersionTLS13,
	)
	require.NoError(t, err)
	serverTLS.NextProtos = []string{quictransport.ALPNProtocol}

	clientCert, err := ca.GenerateClientCertificate(&cfgcert.ClientCertConfig{
		CommonName:   stewardID,
		ValidityDays: 1,
		KeySize:      2048,
	})
	require.NoError(t, err)

	clientTLS, err := cfgcert.CreateClientTLSConfig(
		clientCert.CertificatePEM, clientCert.PrivateKeyPEM,
		caPEM, "localhost", tls.VersionTLS13,
	)
	require.NoError(t, err)
	clientTLS.NextProtos = []string{quictransport.ALPNProtocol}

	ql, err := quictransport.Listen("127.0.0.1:0", serverTLS, nil)
	require.NoError(t, err)

	grpcSrv := grpc.NewServer(
		grpc.Creds(quictransport.TransportCredentials()),
		grpc.MaxRecvMsgSize(8*1024*1024),
	)
	srv := &testTransportSrv{
		dnaHandler:  NewDNAHandler(logging.NewNoopLogger()),
		bulkHandler: NewBulkHandler(logging.NewNoopLogger()),
	}
	transportpb.RegisterStewardTransportServer(grpcSrv, srv)
	go func() { _ = grpcSrv.Serve(ql) }()

	dialer := quictransport.NewDialer(clientTLS, nil)
	conn, err := grpc.NewClient(
		ql.Addr().String(),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(quictransport.TransportCredentials()),
	)
	require.NoError(t, err)

	return &roundTripEnv{
		client:    transportpb.NewStewardTransportClient(conn),
		stewardID: stewardID,
		cleanup: func() {
			_ = conn.Close()
			grpcSrv.GracefulStop()
			_ = ql.Close()
		},
	}
}

// ---------------------------------------------------------------------------
// Unit tests — mTLS peer validation
// ---------------------------------------------------------------------------

// TestDNAHandler_MissingPeerCert verifies that a request with no mTLS peer
// info in context is rejected with Unauthenticated.
func TestDNAHandler_MissingPeerCert(t *testing.T) {
	h := NewDNAHandler(logging.NewNoopLogger())
	stream := newTestDNAStream(context.Background())

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestDNAHandler_StewardIDMismatch verifies that a chunk whose steward_id
// does not match the mTLS peer CN is rejected with PermissionDenied.
func TestDNAHandler_StewardIDMismatch(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger())

	ctx := peerContextWithCA(t, ca, "steward-alice")
	stream := newTestDNAStream(ctx, &transportpb.DNAChunk{
		StewardId:   "steward-bob",
		TenantId:    "tenant-1",
		Data:        []byte("dna"),
		ChunkIndex:  0,
		TotalChunks: 1,
	})

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))

	msg := status.Convert(err).Message()
	assert.Equal(t, "steward ID mismatch", msg)
	assert.NotContains(t, msg, "steward-alice", "must not disclose peer CN")
	assert.NotContains(t, msg, "steward-bob", "must not disclose chunk steward ID")
}

// TestDNAHandler_MatchingStewardIDAccepted verifies that matching steward ID
// passes validation and the handler sends an accepted response.
func TestDNAHandler_MatchingStewardIDAccepted(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger())

	ctx := peerContextWithCA(t, ca, "steward-match")
	stream := newTestDNAStream(ctx,
		&transportpb.DNAChunk{StewardId: "steward-match", TenantId: "t1", Data: []byte("p1"), ChunkIndex: 0, TotalChunks: 2},
		&transportpb.DNAChunk{StewardId: "steward-match", TenantId: "t1", Data: []byte("p2"), ChunkIndex: 1, TotalChunks: 2},
	)

	err := h.HandleGRPC(stream)

	require.NoError(t, err)
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())
	assert.Equal(t, "accepted", stream.resp.GetMessage())
}

// TestDNAHandler_EmptyStream verifies that an empty stream (no chunks) is
// accepted and returns a valid response.
func TestDNAHandler_EmptyStream(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger())

	ctx := peerContextWithCA(t, ca, "steward-empty")
	stream := newTestDNAStream(ctx) // zero chunks

	err := h.HandleGRPC(stream)

	require.NoError(t, err)
	require.NotNil(t, stream.resp)
	assert.True(t, stream.resp.GetAccepted())
}

// TestDNAHandler_RecvError verifies that a Recv() error (not EOF) causes
// HandleGRPC to return a wrapped error with the expected message.
func TestDNAHandler_RecvError(t *testing.T) {
	ca := newTestCA(t)
	h := NewDNAHandler(logging.NewNoopLogger())

	ctx := peerContextWithCA(t, ca, "steward-recv-err")
	injectedErr := errors.New("simulated network failure")
	stream := &testDNAStream{ctx: ctx, recvErr: injectedErr}

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.True(t, errors.Is(err, injectedErr), "error must wrap the injected recv error")
	assert.Contains(t, err.Error(), "failed to receive DNA chunk")
}

// ---------------------------------------------------------------------------
// Round-trip integration tests
// ---------------------------------------------------------------------------

// TestSyncDNA_RoundTrip verifies that a steward can stream DNA chunks over
// real gRPC-over-QUIC with mTLS and receive an accepted response.
func TestSyncDNA_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC integration test in short mode")
	}

	env := newRoundTripEnv(t, "steward-dna-rt")
	defer env.cleanup()

	stream, err := env.client.SyncDNA(context.Background())
	require.NoError(t, err)

	require.NoError(t, stream.Send(&transportpb.DNAChunk{
		StewardId:   env.stewardID,
		TenantId:    "tenant-rt",
		Data:        []byte(`{"os":"linux","arch":"amd64"}`),
		ChunkIndex:  0,
		TotalChunks: 1,
	}))

	resp, err := stream.CloseAndRecv()
	require.NoError(t, err)
	assert.True(t, resp.GetAccepted())
	assert.Equal(t, "accepted", resp.GetMessage())
}

// TestSyncDNA_RoundTrip_StewardIDMismatch verifies end-to-end rejection when
// the chunk steward_id does not match the client cert CN over real QUIC+mTLS.
func TestSyncDNA_RoundTrip_StewardIDMismatch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC integration test in short mode")
	}

	env := newRoundTripEnv(t, "steward-real")
	defer env.cleanup()

	stream, err := env.client.SyncDNA(context.Background())
	require.NoError(t, err)

	require.NoError(t, stream.Send(&transportpb.DNAChunk{
		StewardId:   "steward-impersonator",
		TenantId:    "tenant-rt",
		Data:        []byte("dna"),
		ChunkIndex:  0,
		TotalChunks: 1,
	}))

	_, err = stream.CloseAndRecv()
	require.Error(t, err)
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestSyncDNA_OversizedMessageRejected verifies that the gRPC server enforces
// MaxRecvMsgSize for DNA chunks over QUIC (DoS protection).
func TestSyncDNA_OversizedMessageRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC integration test in short mode")
	}

	env := newRoundTripEnv(t, "steward-dos")
	defer env.cleanup()

	stream, err := env.client.SyncDNA(context.Background())
	require.NoError(t, err)

	sendErr := stream.Send(&transportpb.DNAChunk{
		StewardId: env.stewardID,
		Data:      make([]byte, 9*1024*1024), // 9 MB > 8 MB limit
	})
	if sendErr == nil {
		_, sendErr = stream.CloseAndRecv()
	}

	require.Error(t, sendErr)
	assert.Equal(t, codes.ResourceExhausted, status.Code(sendErr))
}
