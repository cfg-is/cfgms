// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package grpc

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
)

// floodTransport is a real StewardTransport server that plays a hostile
// controller: it streams chunks produced by next() and never sends EOF. done is
// closed when the handler returns, which only happens once the steward aborts
// the stream.
type floodTransport struct {
	transportpb.UnimplementedStewardTransportServer
	nextConfig func(i int) *transportpb.ConfigChunk
	nextBulk   func(i int) *transportpb.BulkChunk
	done       chan struct{}
}

func (f *floodTransport) SyncConfig(_ *transportpb.ConfigSyncRequest, stream grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	defer close(f.done)
	for i := 0; ; i++ {
		if err := stream.Send(f.nextConfig(i)); err != nil {
			return err
		}
	}
}

func (f *floodTransport) BulkTransfer(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	defer close(f.done)
	for i := 0; ; i++ {
		if err := stream.Send(f.nextBulk(i)); err != nil {
			return err
		}
	}
}

func floodSession(t *testing.T, srv *floodTransport) *Session {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer(ServerOptions()...)
	transportpb.RegisterStewardTransportServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	s := makeTestSession("client")
	s.client = transportpb.NewStewardTransportClient(conn)
	return s
}

func requireAborted(t *testing.T, srv *floodTransport) {
	t.Helper()
	select {
	case <-srv.done:
	case <-time.After(10 * time.Second):
		t.Fatal("steward kept reading an unbounded stream instead of aborting early")
	}
}

func TestClientReceiveConfig_RejectsChunkFlood(t *testing.T) {
	srv := &floodTransport{done: make(chan struct{}), nextConfig: func(i int) *transportpb.ConfigChunk {
		// TotalChunks at the cap boundary, but the stream keeps going past it.
		return &transportpb.ConfigChunk{Data: []byte{'x'}, ChunkIndex: int32(i % maxRecvChunks), TotalChunks: maxRecvChunks, ConfigId: "c"}
	}}
	s := floodSession(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := s.ReceiveConfig(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadTooLarge)
	requireAborted(t, srv)
}

func TestClientReceiveConfig_RejectsByteFlood(t *testing.T) {
	big := make([]byte, 1024*1024)
	srv := &floodTransport{done: make(chan struct{}), nextConfig: func(i int) *transportpb.ConfigChunk {
		return &transportpb.ConfigChunk{Data: big, ChunkIndex: int32(i), TotalChunks: 200, ConfigId: "c"}
	}}
	s := floodSession(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := s.ReceiveConfig(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadTooLarge)
	requireAborted(t, srv)
}

func TestClientReceiveConfig_RejectsInconsistentTotalChunks(t *testing.T) {
	srv := &floodTransport{done: make(chan struct{}), nextConfig: func(i int) *transportpb.ConfigChunk {
		return &transportpb.ConfigChunk{Data: []byte{'x'}, ChunkIndex: int32(i), TotalChunks: int32(10 + i), ConfigId: "c"}
	}}
	s := floodSession(t, srv)

	_, err := s.ReceiveConfig(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkCountMismatch)
	requireAborted(t, srv)
}

func TestClientReceiveConfig_RejectsHugeTotalChunks(t *testing.T) {
	srv := &floodTransport{done: make(chan struct{}), nextConfig: func(i int) *transportpb.ConfigChunk {
		return &transportpb.ConfigChunk{Data: []byte{'x'}, ChunkIndex: int32(i), TotalChunks: 1 << 30, ConfigId: "c"}
	}}
	s := floodSession(t, srv)

	_, err := s.ReceiveConfig(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadTooLarge)
	requireAborted(t, srv)
}

func TestClientReceiveBulk_RejectsChunkFlood(t *testing.T) {
	srv := &floodTransport{done: make(chan struct{}), nextBulk: func(i int) *transportpb.BulkChunk {
		return &transportpb.BulkChunk{TransferId: "t", Data: []byte{'x'}, Offset: int64(i), TotalSize: 1 << 20}
	}}
	s := floodSession(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := s.ReceiveBulk(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadTooLarge)
	requireAborted(t, srv)
}

func TestClientReceiveBulk_RejectsByteFlood(t *testing.T) {
	big := make([]byte, 1024*1024)
	srv := &floodTransport{done: make(chan struct{}), nextBulk: func(i int) *transportpb.BulkChunk {
		return &transportpb.BulkChunk{TransferId: "t", Data: big, Offset: int64(i) * int64(len(big)), TotalSize: 1 << 40}
	}}
	s := floodSession(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_, err := s.ReceiveBulk(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPayloadTooLarge)
	requireAborted(t, srv)
}

func TestClientReceiveBulk_RejectsInconsistentTotalSize(t *testing.T) {
	srv := &floodTransport{done: make(chan struct{}), nextBulk: func(i int) *transportpb.BulkChunk {
		return &transportpb.BulkChunk{TransferId: "t", Data: []byte{'x'}, Offset: int64(i), TotalSize: int64(1000 + i)}
	}}
	s := floodSession(t, srv)

	_, err := s.ReceiveBulk(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTotalSizeMismatch)
	requireAborted(t, srv)
}
