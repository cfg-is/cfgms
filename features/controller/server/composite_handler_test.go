// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"testing"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

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

func (h *recordingHandler) SyncConfig(_ *transportpb.ConfigSyncRequest, _ grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	h.called["SyncConfig"] = true
	return nil
}

func (h *recordingHandler) SyncDNA(_ grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	h.called["SyncDNA"] = true
	return nil
}

func (h *recordingHandler) BulkTransfer(_ grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	h.called["BulkTransfer"] = true
	return nil
}

func TestComposite_RegisterDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	dp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, dp, nil, nil)

	_, err := composite.Register(context.Background(), &controllerpb.RegisterRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Register"], "Register should delegate to CP handler")
	assert.False(t, dp.called["Register"], "Register should not call DP handler")
}

func TestComposite_PingDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	dp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, dp, nil, nil)

	_, err := composite.Ping(context.Background(), &transportpb.PingRequest{})
	require.NoError(t, err)
	assert.True(t, cp.called["Ping"], "Ping should delegate to CP handler")
}

func TestComposite_ControlChannelDelegatesToCP(t *testing.T) {
	cp := newRecordingHandler()
	dp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, dp, nil, nil)

	// Pass nil stream — recording handler doesn't use it
	err := composite.ControlChannel(nil)
	require.NoError(t, err)
	assert.True(t, cp.called["ControlChannel"], "ControlChannel should delegate to CP handler")
}

func TestComposite_SyncDNADelegatesToDP(t *testing.T) {
	cp := newRecordingHandler()
	dp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, dp, nil, nil)

	err := composite.SyncDNA(nil)
	require.NoError(t, err)
	assert.True(t, dp.called["SyncDNA"], "SyncDNA should delegate to DP handler")
	assert.False(t, cp.called["SyncDNA"], "SyncDNA should not call CP handler")
}

func TestComposite_BulkTransferDelegatesToDP(t *testing.T) {
	cp := newRecordingHandler()
	dp := newRecordingHandler()
	composite := newCompositeTransportServer(cp, dp, nil, nil)

	err := composite.BulkTransfer(nil)
	require.NoError(t, err)
	assert.True(t, dp.called["BulkTransfer"], "BulkTransfer should delegate to DP handler")
}

func TestComposite_SyncConfigWithoutHandler(t *testing.T) {
	cp := newRecordingHandler()
	dp := newRecordingHandler()
	// No config handler — should fall through to unimplemented
	composite := newCompositeTransportServer(cp, dp, nil, nil)

	err := composite.SyncConfig(&transportpb.ConfigSyncRequest{}, nil)
	require.Error(t, err, "SyncConfig without handler should return unimplemented error")
}
