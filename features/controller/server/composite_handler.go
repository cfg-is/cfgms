// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package server

import (
	"context"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"
	"github.com/cfgis/cfgms/pkg/logging"
	"google.golang.org/grpc"
)

// compositeTransportServer delegates StewardTransport RPCs to the appropriate
// provider handler. Control plane RPCs go to the CP handler; data plane RPCs
// go to the DP handler. SyncConfig is handled directly by the config handler
// to avoid the session-channel indirection. Future RPCs (TaskStream, Terminal,
// LogStream) fall through to the Unimplemented base.
type compositeTransportServer struct {
	transportpb.UnimplementedStewardTransportServer

	cpHandler     transportpb.StewardTransportServer // Register, Ping, ControlChannel
	dpHandler     transportpb.StewardTransportServer // SyncDNA, BulkTransfer
	configHandler *controllerTransport.ConfigHandler // SyncConfig (direct handling)
	logger        logging.Logger
}

// newCompositeTransportServer creates a composite handler that delegates RPCs.
func newCompositeTransportServer(
	cpHandler transportpb.StewardTransportServer,
	dpHandler transportpb.StewardTransportServer,
	configHandler *controllerTransport.ConfigHandler,
	logger logging.Logger,
) *compositeTransportServer {
	return &compositeTransportServer{
		cpHandler:     cpHandler,
		dpHandler:     dpHandler,
		configHandler: configHandler,
		logger:        logger,
	}
}

// --- Control Plane RPCs (delegated to CP handler) ---

func (c *compositeTransportServer) Register(ctx context.Context, req *controllerpb.RegisterRequest) (*controllerpb.RegisterResponse, error) {
	return c.cpHandler.Register(ctx, req)
}

func (c *compositeTransportServer) Ping(ctx context.Context, req *transportpb.PingRequest) (*transportpb.PingResponse, error) {
	return c.cpHandler.Ping(ctx, req)
}

func (c *compositeTransportServer) ControlChannel(stream grpc.BidiStreamingServer[transportpb.ControlMessage, transportpb.ControlMessage]) error {
	return c.cpHandler.ControlChannel(stream)
}

// --- Data Plane RPCs ---

// SyncConfig is handled directly by the config handler, bypassing the DP
// provider's session-channel model. The config handler looks up the config
// for the requesting steward, signs it, and streams chunks back.
func (c *compositeTransportServer) SyncConfig(req *transportpb.ConfigSyncRequest, stream grpc.ServerStreamingServer[transportpb.ConfigChunk]) error {
	if c.configHandler != nil {
		return c.configHandler.HandleGRPC(stream.Context(), req, stream)
	}
	if c.logger != nil {
		c.logger.Warn("SyncConfig called but config handler not initialized")
	}
	return c.UnimplementedStewardTransportServer.SyncConfig(req, stream)
}

// SyncDNA delegates to the DP handler's channel-based model.
func (c *compositeTransportServer) SyncDNA(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	return c.dpHandler.SyncDNA(stream)
}

// BulkTransfer delegates to the DP handler's channel-based model.
func (c *compositeTransportServer) BulkTransfer(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	return c.dpHandler.BulkTransfer(stream)
}
