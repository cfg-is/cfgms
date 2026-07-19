// SPDX-License-Identifier: AGPL-3.0-only
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
// by the bulk handler; LogStream by the log stream handler. Future RPCs
// (TaskStream, Terminal) fall through to the Unimplemented base.
type compositeTransportServer struct {
	transportpb.UnimplementedStewardTransportServer

	cpHandler        transportpb.StewardTransportServer    // Register, Ping, ControlChannel
	configHandler    *controllerTransport.ConfigHandler    // SyncConfig (direct handling)
	dnaHandler       *controllerTransport.DNAHandler       // SyncDNA (direct handling)
	bulkHandler      *controllerTransport.BulkHandler      // BulkTransfer (direct handling)
	logStreamHandler *controllerTransport.LogStreamHandler // LogStream (direct handling)
	logger           logging.Logger
}

// newCompositeTransportServer creates a composite handler with the always-required
// CP handler and logger. Wire optional data-plane handlers via SetConfigHandler,
// SetDNAHandler, SetBulkHandler, and SetLogStreamHandler before serving.
func newCompositeTransportServer(
	cpHandler transportpb.StewardTransportServer,
	logger logging.Logger,
) *compositeTransportServer {
	return &compositeTransportServer{
		cpHandler: cpHandler,
		logger:    logger,
	}
}

// SetConfigHandler sets the SyncConfig handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetConfigHandler(h *controllerTransport.ConfigHandler) {
	c.configHandler = h
}

// SetDNAHandler sets the SyncDNA handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetDNAHandler(h *controllerTransport.DNAHandler) {
	c.dnaHandler = h
}

// SetBulkHandler sets the BulkTransfer handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetBulkHandler(h *controllerTransport.BulkHandler) {
	c.bulkHandler = h
}

// SetLogStreamHandler sets the LogStream handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetLogStreamHandler(h *controllerTransport.LogStreamHandler) {
	c.logStreamHandler = h
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

// LogStream is handled directly by the log stream handler. Each ingested
// LogEntry is CN-matched against the authenticated mTLS peer, tenant-derived
// server-side from the fleet registry, rate-limited per steward, and written
// via the dedicated steward-event LoggingManager.
func (c *compositeTransportServer) LogStream(stream grpc.ClientStreamingServer[transportpb.LogEntry, transportpb.LogStreamResponse]) error {
	if c.logStreamHandler != nil {
		return c.logStreamHandler.HandleGRPC(stream)
	}
	return c.UnimplementedStewardTransportServer.LogStream(stream)
}
