// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"io"
	"testing"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// recordingHandler records which RPC methods were called.
type recordingHandler struct {
	transportpb.UnimplementedStewardTransportServer
	called map[string]bool
}

func newRecordingHandler() *recordingHandler {
	return &recordingHandler{called: make(map[string]bool)}
}

func (h *recordingHandler) Register(_ context.Context, _ *controllerpb.RegisterRequest) (*controllerpb.RegisterResponse, error) {
	h.called["Register"] = true
	return &controllerpb.RegisterResponse{}, nil
}

func (h *recordingHandler) Ping(_ context.Context, _ *transportpb.PingRequest) (*transportpb.PingResponse, error) {
	h.called["Ping"] = true
	return &transportpb.PingResponse{}, nil
}

func (h *recordingHandler) ControlChannel(_ grpc.BidiStreamingServer[transportpb.ControlMessage, transportpb.ControlMessage]) error {
	h.called["ControlChannel"] = true
	return nil
}

// emptyDNAStream implements grpc.ClientStreamingServer[DNAChunk, DNASyncResponse].
// Recv immediately returns EOF so the handler drains cleanly.
type emptyDNAStream struct {
	ctx  context.Context
	done bool
}

func (s *emptyDNAStream) Recv() (*transportpb.DNAChunk, error) {
	if s.done {
		return nil, io.EOF
	}
	s.done = true
	return nil, io.EOF
}
func (s *emptyDNAStream) SendAndClose(*transportpb.DNASyncResponse) error { return nil }
func (s *emptyDNAStream) SetHeader(metadata.MD) error                     { return nil }
func (s *emptyDNAStream) SendHeader(metadata.MD) error                    { return nil }
func (s *emptyDNAStream) SetTrailer(metadata.MD)                          {}
func (s *emptyDNAStream) Context() context.Context {
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
func (s *emptyDNAStream) SendMsg(interface{}) error { return nil }
func (s *emptyDNAStream) RecvMsg(interface{}) error { return nil }

// Compile-time check.
var _ grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse] = (*emptyDNAStream)(nil)

// emptyBulkStream implements grpc.BidiStreamingServer[BulkChunk, BulkChunk].
// Recv immediately returns EOF so the handler drains cleanly.
type emptyBulkStream struct{}

func (s *emptyBulkStream) Recv() (*transportpb.BulkChunk, error) { return nil, io.EOF }
func (s *emptyBulkStream) Send(*transportpb.BulkChunk) error     { return nil }
func (s *emptyBulkStream) SetHeader(metadata.MD) error           { return nil }
func (s *emptyBulkStream) SendHeader(metadata.MD) error          { return nil }
func (s *emptyBulkStream) SetTrailer(metadata.MD)                {}
func (s *emptyBulkStream) Context() context.Context              { return context.Background() }
func (s *emptyBulkStream) SendMsg(interface{}) error             { return nil }
func (s *emptyBulkStream) RecvMsg(interface{}) error             { return nil }

// Compile-time check.
var _ grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk] = (*emptyBulkStream)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestComposite_RegisterDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil, nil, nil, nil)

	_, err := composite.Register(context.Background(), &controllerpb.RegisterRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Register"], "Register should delegate to CP handler")
}

func TestComposite_PingDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil, nil, nil, nil)

	_, err := composite.Ping(context.Background(), &transportpb.PingRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Ping"], "Ping should delegate to CP handler")
}

func TestComposite_ControlChannelDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil, nil, nil, nil)

	err := composite.ControlChannel(nil)
	require.NoError(t, err)
	assert.True(t, cp.called["ControlChannel"], "ControlChannel should delegate to CP handler")
}

func TestComposite_SyncDNA_NilHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil, nil, nil, nil)

	err := composite.SyncDNA(&emptyDNAStream{})
	require.Error(t, err, "SyncDNA with nil dnaHandler should return unimplemented error")
}

func TestComposite_SyncDNA_WithHandler(t *testing.T) {
	cp := newRecordingHandler()
	logger := logging.NewNoopLogger()
	dnaHandler := controllerTransport.NewDNAHandler(logger, controllerTransport.NewTenantQueue())
	composite := newCompositeTransportServer(cp, dnaHandler, nil, nil, nil)

	// Empty stream with background context (no mTLS peer) → Unauthenticated from handler.
	// This proves that dnaHandler.HandleGRPC is called, not the Unimplemented fallback.
	err := composite.SyncDNA(&emptyDNAStream{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "not implemented",
		"SyncDNA must route through dnaHandler, not the Unimplemented fallback")
}

func TestComposite_BulkTransfer_NilHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil, nil, nil, nil)

	err := composite.BulkTransfer(&emptyBulkStream{})
	require.Error(t, err, "BulkTransfer with nil bulkHandler should return unimplemented error")
}

func TestComposite_BulkTransfer_WithHandler(t *testing.T) {
	cp := newRecordingHandler()
	logger := logging.NewNoopLogger()
	bulkHandler := controllerTransport.NewBulkHandler(logger, controllerTransport.NewTenantQueue())
	composite := newCompositeTransportServer(cp, nil, bulkHandler, nil, nil)

	err := composite.BulkTransfer(&emptyBulkStream{})
	require.NoError(t, err, "BulkTransfer with valid handler and empty stream must succeed")
}

func TestComposite_SyncConfigWithoutHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil, nil, nil, nil)

	err := composite.SyncConfig(&transportpb.ConfigSyncRequest{}, nil)
	require.Error(t, err, "SyncConfig without handler should return unimplemented error")
}
