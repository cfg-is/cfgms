// SPDX-License-Identifier: AGPL-3.0-only
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

// emptyLogStream implements grpc.ClientStreamingServer[LogEntry, LogStreamResponse].
// Recv immediately returns EOF so the nil-handler fallback path is tested.
type emptyLogStream struct{}

func (s *emptyLogStream) Recv() (*transportpb.LogEntry, error)              { return nil, io.EOF }
func (s *emptyLogStream) SendAndClose(*transportpb.LogStreamResponse) error { return nil }
func (s *emptyLogStream) SetHeader(metadata.MD) error                       { return nil }
func (s *emptyLogStream) SendHeader(metadata.MD) error                      { return nil }
func (s *emptyLogStream) SetTrailer(metadata.MD)                            {}
func (s *emptyLogStream) Context() context.Context                          { return context.Background() }
func (s *emptyLogStream) SendMsg(interface{}) error                         { return nil }
func (s *emptyLogStream) RecvMsg(interface{}) error                         { return nil }

// Compile-time check.
var _ grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse] = (*emptyLogStream)(nil)

// ---------------------------------------------------------------------------
// Additive-extension helpers (TestComposite_AdditiveExtension)
// ---------------------------------------------------------------------------

// testFooHandler is a throwaway handler representing a hypothetical 7th RPC
// (standing in for Terminal/TelemetryStream from stories #2761/#2765).
type testFooHandler struct{ called bool }

// fooCompositeExt shows that adding a new data-plane RPC handler is purely
// additive: embed compositeTransportServer, add one field, one setter, and one
// delegation method — zero edits to newCompositeTransportServer, struct fields,
// or any existing handler's setter or delegation method.
type fooCompositeExt struct {
	*compositeTransportServer
	fooHandler *testFooHandler
}

func (c *fooCompositeExt) SetFooHandler(h *testFooHandler) { c.fooHandler = h }

func (c *fooCompositeExt) callFoo() bool {
	if c.fooHandler != nil {
		c.fooHandler.called = true
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestComposite_RegisterDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	_, err := composite.Register(context.Background(), &controllerpb.RegisterRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Register"], "Register should delegate to CP handler")
}

func TestComposite_PingDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	_, err := composite.Ping(context.Background(), &transportpb.PingRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Ping"], "Ping should delegate to CP handler")
}

func TestComposite_ControlChannelDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	err := composite.ControlChannel(nil)
	require.NoError(t, err)
	assert.True(t, cp.called["ControlChannel"], "ControlChannel should delegate to CP handler")
}

func TestComposite_SyncDNA_NilHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	err := composite.SyncDNA(&emptyDNAStream{})
	require.Error(t, err, "SyncDNA with nil dnaHandler should return unimplemented error")
}

func TestComposite_SyncDNA_WithHandler(t *testing.T) {
	cp := newRecordingHandler()
	logger := logging.NewNoopLogger()
	dnaHandler := controllerTransport.NewDNAHandler(logger, controllerTransport.NewTenantQueue(), nil)
	composite := newCompositeTransportServer(cp, logger)
	composite.SetDNAHandler(dnaHandler)

	// Empty stream with background context (no mTLS peer) → Unauthenticated from handler.
	// This proves that dnaHandler.HandleGRPC is called, not the Unimplemented fallback.
	err := composite.SyncDNA(&emptyDNAStream{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "Unimplemented",
		"SyncDNA must route through dnaHandler, not the Unimplemented fallback")
}

func TestComposite_BulkTransfer_NilHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	err := composite.BulkTransfer(&emptyBulkStream{})
	require.Error(t, err, "BulkTransfer with nil bulkHandler should return unimplemented error")
}

func TestComposite_BulkTransfer_WithHandler(t *testing.T) {
	cp := newRecordingHandler()
	logger := logging.NewNoopLogger()
	bulkHandler := controllerTransport.NewBulkHandler(logger, controllerTransport.NewTenantQueue())
	composite := newCompositeTransportServer(cp, logger)
	composite.SetBulkHandler(bulkHandler)

	err := composite.BulkTransfer(&emptyBulkStream{})
	require.NoError(t, err, "BulkTransfer with valid handler and empty stream must succeed")
}

func TestComposite_SyncConfigWithoutHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	err := composite.SyncConfig(&transportpb.ConfigSyncRequest{}, nil)
	require.Error(t, err, "SyncConfig without handler should return unimplemented error")
}

func TestComposite_LogStream_NilHandler(t *testing.T) {
	cp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, nil)

	err := composite.LogStream(&emptyLogStream{})
	require.Error(t, err, "LogStream with nil logStreamHandler should return unimplemented error")
	assert.Contains(t, err.Error(), "not implemented",
		"LogStream with nil handler must return Unimplemented")
}

// TestComposite_AdditiveExtension proves that adding a new data-plane handler
// (as stories #2761/#2765 will do for Terminal/TelemetryStream) requires zero
// edits to newCompositeTransportServer or any existing handler field, setter, or
// delegation method. The fooCompositeExt type above demonstrates the additive
// pattern: one new field + one new setter + one new delegation method.
func TestComposite_AdditiveExtension(t *testing.T) {
	cp := newRecordingHandler()

	// 2-arg constructor — unchanged whether 1 or 10 optional handlers exist.
	base := newCompositeTransportServer(cp, nil)

	// All four existing setters work; no constructor signature edit required.
	base.SetConfigHandler(nil)
	base.SetDNAHandler(nil)
	base.SetBulkHandler(nil)
	base.SetLogStreamHandler(nil)

	// Wire in the hypothetical 7th handler. Zero changes to the constructor or
	// any of the four existing handlers' fields, setters, or delegation methods.
	ext := &fooCompositeExt{compositeTransportServer: base}
	fooH := &testFooHandler{}
	ext.SetFooHandler(fooH)

	// Existing CP delegation still works through the embedded composite.
	_, err := ext.Register(context.Background(), &controllerpb.RegisterRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Register"], "existing CP delegation is unaffected by the new handler")

	// New handler routes correctly.
	assert.True(t, ext.callFoo(), "new handler setter and delegation work correctly")
	assert.True(t, fooH.called, "new handler was invoked")

	// Nil-check: the fallthrough pattern holds without calling SetFooHandler.
	ext2 := &fooCompositeExt{compositeTransportServer: newCompositeTransportServer(cp, nil)}
	assert.False(t, ext2.callFoo(), "nil handler falls through correctly")
}
