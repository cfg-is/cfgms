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
// handler. Control plane RPCs go to the CP handler; SyncConfig is handled
// directly by the config handler; SyncDNA by the DNA handler; BulkTransfer
// by the bulk handler. Future RPCs (TaskStream, Terminal, LogStream) fall
// through to the Unimplemented base.
type compositeTransportServer struct {
	transportpb.UnimplementedStewardTransportServer

	cpHandler     transportpb.StewardTransportServer // Register, Ping, ControlChannel
	configHandler *controllerTransport.ConfigHandler // SyncConfig (direct handling)
	dnaHandler    *controllerTransport.DNAHandler    // SyncDNA (direct handling)
	bulkHandler   *controllerTransport.BulkHandler   // BulkTransfer (direct handling)
	logger        logging.Logger
}

// newCompositeTransportServer creates a composite handler that delegates RPCs.
func newCompositeTransportServer(
	cpHandler transportpb.StewardTransportServer,
	dnaHandler *controllerTransport.DNAHandler,
	bulkHandler *controllerTransport.BulkHandler,
	configHandler *controllerTransport.ConfigHandler,
	logger logging.Logger,
) *compositeTransportServer {
	return &compositeTransportServer{
		cpHandler:     cpHandler,
		configHandler: configHandler,
		dnaHandler:    dnaHandler,
		bulkHandler:   bulkHandler,
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

// SyncDNA is handled directly by the DNA handler.
func (c *compositeTransportServer) SyncDNA(stream grpc.ClientStreamingServer[transportpb.DNAChunk, transportpb.DNASyncResponse]) error {
	if c.dnaHandler != nil {
		return c.dnaHandler.HandleGRPC(stream)
	}
	return c.UnimplementedStewardTransportServer.SyncDNA(stream)
}

// BulkTransfer is handled directly by the bulk handler.
func (c *compositeTransportServer) BulkTransfer(stream grpc.BidiStreamingServer[transportpb.BulkChunk, transportpb.BulkChunk]) error {
	if c.bulkHandler != nil {
		return c.bulkHandler.HandleGRPC(stream)
	}
	return c.UnimplementedStewardTransportServer.BulkTransfer(stream)
}
