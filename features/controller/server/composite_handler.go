// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"

	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	controllerTransport "github.com/cfgis/cfgms/features/controller/transport"

	// stewardosquery is imported here following the same pattern as
	// features/controller/transport importing features/steward/dna: the
	// controller-side stream handler (HandleGRPC) and the steward-side execution
	// path (Execute) share one type. Splitting them is tracked as future work.
	stewardosquery "github.com/cfgis/cfgms/features/steward/osquery"
	"github.com/cfgis/cfgms/pkg/logging"
	"google.golang.org/grpc"
)

// compositeTransportServer delegates StewardTransport RPCs to the appropriate
// handler. Control plane RPCs go to the CP handler; SyncConfig is handled
// directly by the config handler; SyncDNA by the DNA handler; BulkTransfer
// by the bulk handler; LogStream by the log stream handler; TelemetryStream
// by the telemetry handler; Terminal by the terminal handler; OsqueryQuery
// by the osquery handler. Future RPCs fall through to the Unimplemented base.
type compositeTransportServer struct {
	transportpb.UnimplementedStewardTransportServer

	cpHandler        transportpb.StewardTransportServer    // Register, Ping, ControlChannel
	configHandler    *controllerTransport.ConfigHandler    // SyncConfig (direct handling)
	dnaHandler       *controllerTransport.DNAHandler       // SyncDNA (direct handling)
	bulkHandler      *controllerTransport.BulkHandler      // BulkTransfer (direct handling)
	logStreamHandler *controllerTransport.LogStreamHandler // LogStream (direct handling)
	telemetryHandler *controllerTransport.TelemetryHandler // TelemetryStream (direct handling)
	terminalHandler  *controllerTransport.TerminalHandler  // Terminal (direct handling)
	osqueryHandler   *stewardosquery.OsqueryHandler        // OsqueryQuery (direct handling)
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

// SetTelemetryHandler sets the TelemetryStream handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetTelemetryHandler(h *controllerTransport.TelemetryHandler) {
	c.telemetryHandler = h
}

// SetTerminalHandler sets the Terminal bidi RPC handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetTerminalHandler(h *controllerTransport.TerminalHandler) {
	c.terminalHandler = h
}

// SetOsqueryHandler sets the OsqueryQuery bidi RPC handler. Call after newCompositeTransportServer.
func (c *compositeTransportServer) SetOsqueryHandler(h *stewardosquery.OsqueryHandler) {
	c.osqueryHandler = h
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

// TelemetryStream is handled directly by the telemetry handler. Received
// TelemetrySnapshot frames are fanned out to browser WebSocket subscribers;
// TelemetryRequest frames (subscribe/unsubscribe/interval) are sent upstream
// on 0→1 and 1→0 browser subscriber transitions.
func (c *compositeTransportServer) TelemetryStream(stream grpc.BidiStreamingServer[transportpb.TelemetrySnapshot, transportpb.TelemetryRequest]) error {
	if c.telemetryHandler != nil {
		return c.telemetryHandler.HandleGRPC(stream)
	}
	return c.UnimplementedStewardTransportServer.TelemetryStream(stream)
}

// Terminal is handled directly by the terminal handler. The steward opens this
// bidi stream after receiving COMMAND_TYPE_OPEN_TERMINAL; the handler correlates
// the stream to the pending browser WebSocket session by session_id.
func (c *compositeTransportServer) Terminal(stream grpc.BidiStreamingServer[transportpb.TerminalData, transportpb.TerminalData]) error {
	if c.terminalHandler != nil {
		return c.terminalHandler.HandleGRPC(stream)
	}
	return c.UnimplementedStewardTransportServer.Terminal(stream)
}

// OsqueryQuery is handled directly by the osquery handler. The steward opens
// this bidi stream to receive ad-hoc catalog query requests from the controller
// and return result rows. The handler enforces mTLS peer authentication.
func (c *compositeTransportServer) OsqueryQuery(stream grpc.BidiStreamingServer[transportpb.OsqueryQueryResponse, transportpb.OsqueryQueryRequest]) error {
	if c.osqueryHandler != nil {
		return c.osqueryHandler.HandleGRPC(stream)
	}
	return c.UnimplementedStewardTransportServer.OsqueryQuery(stream)
}
