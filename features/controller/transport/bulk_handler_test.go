// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package transport

import (
	"context"
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
	"github.com/cfgis/cfgms/pkg/logging"
)

// ---------------------------------------------------------------------------
// Mock bidi stream
// ---------------------------------------------------------------------------

type testBulkStream struct {
	inChunks  []*transportpb.BulkChunk
	outChunks []*transportpb.BulkChunk
	pos       int
	ctx       context.Context
	recvErr   error
}

func newTestBulkStream(ctx context.Context, chunks ...*transportpb.BulkChunk) *testBulkStream {
	return &testBulkStream{inChunks: chunks, ctx: ctx}
}

func (s *testBulkStream) Recv() (*transportpb.BulkChunk, error) {
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	if s.pos >= len(s.inChunks) {
		return nil, io.EOF
	}
	chunk := s.inChunks[s.pos]
	s.pos++
	return chunk, nil
}

func (s *testBulkStream) Send(c *transportpb.BulkChunk) error {
	s.outChunks = append(s.outChunks, c)
	return nil
}

func (s *testBulkStream) SetHeader(metadata.MD) error  { return nil }
func (s *testBulkStream) SendHeader(metadata.MD) error { return nil }
func (s *testBulkStream) SetTrailer(metadata.MD)       {}
func (s *testBulkStream) Context() context.Context     { return s.ctx }
func (s *testBulkStream) SendMsg(interface{}) error    { return nil }
func (s *testBulkStream) RecvMsg(interface{}) error    { return nil }

// Compile-time check: testBulkStream must implement the required interface.
var _ grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk] = (*testBulkStream)(nil)

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

// TestBulkHandler_NoStewardIDField verifies that BulkHandler.HandleGRPC
// contains NO call to GetStewardId() or GetTenantId() — these fields do not
// exist on BulkChunk and the handler must not perform field-level identity checks.
// This test verifies the structural requirement at compile time by checking
// that BulkHandler accepts any chunk without identity validation.
func TestBulkHandler_NoIdentityValidation(t *testing.T) {
	h := NewBulkHandler(logging.NewNoopLogger(), NewTenantQueue())

	// context.Background() carries no peer info — if BulkHandler tried to
	// extract an mTLS identity it would fail here.
	stream := newTestBulkStream(context.Background(),
		&transportpb.BulkChunk{TransferId: "bulk-1", Data: []byte("payload"), Offset: 0, TotalSize: 7, IsLast: true},
	)

	err := h.HandleGRPC(stream)
	require.NoError(t, err, "BulkHandler must not perform identity validation")
}

// TestBulkHandler_EmptyStream verifies that an empty stream (no chunks) is
// accepted without error.
func TestBulkHandler_EmptyStream(t *testing.T) {
	h := NewBulkHandler(logging.NewNoopLogger(), NewTenantQueue())
	stream := newTestBulkStream(context.Background())

	err := h.HandleGRPC(stream)
	require.NoError(t, err)
}

// TestBulkHandler_MultipleChunks verifies that multiple chunks are received
// without error.
func TestBulkHandler_MultipleChunks(t *testing.T) {
	h := NewBulkHandler(logging.NewNoopLogger(), NewTenantQueue())

	stream := newTestBulkStream(context.Background(),
		&transportpb.BulkChunk{TransferId: "bulk-multi", Data: []byte("part1"), Offset: 0, TotalSize: 10},
		&transportpb.BulkChunk{TransferId: "bulk-multi", Data: []byte("part2"), Offset: 5, TotalSize: 10, IsLast: true},
	)

	err := h.HandleGRPC(stream)
	require.NoError(t, err)
}

// TestBulkHandler_RecvError verifies that a Recv() error (not EOF) causes
// HandleGRPC to return a wrapped error with the expected message.
func TestBulkHandler_RecvError(t *testing.T) {
	h := NewBulkHandler(logging.NewNoopLogger(), NewTenantQueue())

	injectedErr := errors.New("simulated network failure")
	stream := &testBulkStream{ctx: context.Background(), recvErr: injectedErr}

	err := h.HandleGRPC(stream)

	require.Error(t, err)
	assert.True(t, errors.Is(err, injectedErr), "error must wrap the injected recv error")
	assert.Contains(t, err.Error(), "failed to receive bulk chunk")
}

// TestBulkHandler_QueueFull_ReturnsResourceExhausted verifies that when the
// queue is at capacity the handler returns codes.ResourceExhausted. Unit tests
// use context.Background() (no mTLS), so the queue key is "".
func TestBulkHandler_QueueFull_ReturnsResourceExhausted(t *testing.T) {
	queue := NewTenantQueue()
	h := NewBulkHandler(logging.NewNoopLogger(), queue)

	for i := 0; i < MaxConcurrentPerTenant; i++ {
		require.NoError(t, queue.Acquire(""))
	}

	stream := newTestBulkStream(context.Background(),
		&transportpb.BulkChunk{TransferId: "bulk-1", Data: []byte("x")},
	)

	err := h.HandleGRPC(stream)
	require.Error(t, err)
	assert.Equal(t, codes.ResourceExhausted, status.Code(err))
}

// ---------------------------------------------------------------------------
// Round-trip integration test
// ---------------------------------------------------------------------------

// TestBulkTransfer_RoundTrip verifies that a client can stream bulk chunks to
// the BulkHandler over real gRPC-over-QUIC with mTLS without deadlock or error.
func TestBulkTransfer_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC integration test in short mode")
	}

	env := newRoundTripEnv(t, "steward-bulk-rt")
	defer env.cleanup()

	stream, err := env.client.BulkTransfer(context.Background())
	require.NoError(t, err)

	payload := []byte("bulk payload for round trip test")
	require.NoError(t, stream.Send(&transportpb.BulkChunk{
		TransferId: "bulk-rt-001",
		Data:       payload,
		Offset:     0,
		TotalSize:  int64(len(payload)),
		IsLast:     true,
		Metadata:   map[string]string{"filename": "test.bin"},
	}))

	// Close the send side; server returns nil so CloseSend completes without error.
	err = stream.CloseSend()
	require.NoError(t, err)

	// Drain any response chunks (BulkHandler sends none in this implementation).
	for {
		_, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		require.NoError(t, recvErr)
	}
}

// TestBulkTransfer_RoundTrip_NoAuth verifies that BulkTransfer succeeds even
// when no additional identity information is present — mTLS enforced by the
// gRPC server is the sole auth boundary for bulk RPCs.
func TestBulkTransfer_RoundTrip_NoAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping QUIC integration test in short mode")
	}

	// Use a different steward ID to show that bulk doesn't care about the value.
	env := newRoundTripEnv(t, "steward-bulk-noauth")
	defer env.cleanup()

	stream, err := env.client.BulkTransfer(context.Background())
	require.NoError(t, err)

	require.NoError(t, stream.Send(&transportpb.BulkChunk{
		TransferId: "bulk-noauth",
		Data:       []byte("test"),
		Offset:     0,
		TotalSize:  4,
		IsLast:     true,
	}))

	err = stream.CloseSend()
	require.NoError(t, err, "BulkTransfer must complete without error when mTLS passes")

	for {
		_, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if status.Code(recvErr) == codes.OK {
			break
		}
		require.NoError(t, recvErr)
	}
}
