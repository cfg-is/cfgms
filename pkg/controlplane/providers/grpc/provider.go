// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz

// Package grpc provides a gRPC-over-QUIC control plane provider implementation.
//
// This provider implements the ControlPlaneProvider interface using a persistent
// bidirectional gRPC ControlChannel stream per steward, replacing the MQTT broker
// with direct controller-steward communication over QUIC.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	controllerpb "github.com/cfgis/cfgms/api/proto/controller"
	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/controlplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"github.com/cfgis/cfgms/pkg/transport/registry"
	quicgo "github.com/quic-go/quic-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func init() {
	interfaces.RegisterProvider(New(ModeServer))
}

// Mode defines the provider operating mode.
type Mode string

const (
	// ModeServer indicates controller (server) mode.
	ModeServer Mode = "server"

	// ModeClient indicates steward (client) mode.
	ModeClient Mode = "client"
)

// Provider implements the ControlPlaneProvider interface using gRPC-over-QUIC.
type Provider struct {
	mu sync.RWMutex

	name        string
	description string
	mode        Mode

	// Server-side components
	grpcServer    *grpc.Server
	ownGRPCServer bool // true when this provider created the gRPC server
	listener      *quictransport.Listener
	registry      registry.Registry
	serverImpl    *transportServer

	// Client-side components
	grpcConn      *grpc.ClientConn
	grpcClient    transportpb.StewardTransportClient
	controlStream grpc.BidiStreamingClient[transportpb.ControlMessage, transportpb.ControlMessage]
	sendMu        sync.Mutex // serializes writes to controlStream
	connState     atomic.Int32
	onStateChange func(ConnectionState)

	// Shared configuration
	config          map[string]interface{}
	addr            string
	tlsConfig       *tls.Config
	keepalivePeriod time.Duration // 0 = use QUIC default (25s)
	idleTimeout     time.Duration // 0 = use QUIC default (90s)
	stewardID       string
	tenantID        string
	logger          *slog.Logger
	startTime       time.Time

	// Subscription handlers (client mode)
	commandHandler interfaces.CommandHandler

	// Subscription handlers (server mode)
	eventHandlers     []eventSubscription
	heartbeatHandlers []interfaces.HeartbeatHandler

	// Response tracking (server mode: WaitForResponse)
	pendingResponses map[string]chan *types.Response
	responseMu       sync.Mutex

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc

	// Statistics (atomic for lock-free updates)
	commandsSent       atomic.Int64
	commandsReceived   atomic.Int64
	eventsPublished    atomic.Int64
	eventsReceived     atomic.Int64
	heartbeatsSent     atomic.Int64
	heartbeatsReceived atomic.Int64
	responsesSent      atomic.Int64
	responsesReceived  atomic.Int64
	deliveryFailures   atomic.Int64
	reconnectAttempts  atomic.Int64

	// Connection timestamps (protected by mu)
	lastConnectedAt    time.Time
	lastDisconnectedAt time.Time
}

// eventSubscription represents an event subscription with filter.
type eventSubscription struct {
	filter  *types.EventFilter
	handler interfaces.EventHandler
}

// New creates a new gRPC control plane provider.
func New(mode Mode) *Provider {
	return &Provider{
		name:              "grpc",
		description:       "gRPC-over-QUIC control plane provider",
		mode:              mode,
		eventHandlers:     []eventSubscription{},
		heartbeatHandlers: []interfaces.HeartbeatHandler{},
		pendingResponses:  make(map[string]chan *types.Response),
		logger:            slog.Default(),
	}
}

func (p *Provider) Name() string        { return p.name }
func (p *Provider) Description() string { return p.description }

// Initialize configures the provider.
//
// Common config keys:
//   - "mode": string - "server" or "client"
//   - "addr": string - Listen address (server) or controller address (client)
//   - "tls_config": *tls.Config - TLS configuration for mTLS
//   - "logger": *slog.Logger - Logger (optional)
//   - "keepalive_period": time.Duration - QUIC keepalive interval (optional, default 25s)
//   - "idle_timeout": time.Duration - QUIC idle timeout (optional, default 90s)
//   - "on_state_change": func(ConnectionState) - Connection state change callback (optional, client mode only)
//
// Server mode additional keys:
//   - "grpc_server": *grpc.Server - Externally-created gRPC server (optional; when provided,
//     the provider will not create its own QUIC listener or gRPC server)
//   - "registry": registry.Registry - Connection registry (optional, creates one if nil)
//
// Client mode additional keys:
//   - "steward_id": string - This steward's ID
//   - "tenant_id": string - Tenant ID (optional)
func (p *Provider) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config

	if modeStr, ok := config["mode"].(string); ok {
		p.mode = Mode(modeStr)
	}

	if logger, ok := config["logger"].(*slog.Logger); ok {
		p.logger = logger
	}

	if addr, ok := config["addr"].(string); ok {
		p.addr = addr
	}

	if tlsCfg, ok := config["tls_config"].(*tls.Config); ok {
		p.tlsConfig = tlsCfg
	}

	if kp, ok := config["keepalive_period"].(time.Duration); ok {
		p.keepalivePeriod = kp
	}
	if it, ok := config["idle_timeout"].(time.Duration); ok {
		p.idleTimeout = it
	}
	if cb, ok := config["on_state_change"].(func(ConnectionState)); ok {
		p.onStateChange = cb
	}

	switch p.mode {
	case ModeServer:
		return p.initializeServer(config)
	case ModeClient:
		return p.initializeClient(config)
	default:
		return fmt.Errorf("invalid mode: %s (must be 'server' or 'client')", p.mode)
	}
}

func (p *Provider) initializeServer(config map[string]interface{}) error {
	// Accept an externally-created gRPC server (Story #515: shared CP+DP server).
	// When provided, the provider will not create its own QUIC listener or gRPC server.
	if srv, ok := config["grpc_server"].(*grpc.Server); ok && srv != nil {
		p.grpcServer = srv
		p.ownGRPCServer = false
		p.logger.Info("CP provider using external gRPC server (ownGRPCServer=false)")
	} else {
		p.ownGRPCServer = true
		p.logger.Info("CP provider will create own gRPC server (ownGRPCServer=true)")
		if p.addr == "" {
			return fmt.Errorf("server mode requires 'addr' or 'grpc_server' in config")
		}
		if p.tlsConfig == nil {
			return fmt.Errorf("server mode requires 'tls_config' when creating own gRPC server")
		}
	}

	if reg, ok := config["registry"].(registry.Registry); ok {
		p.registry = reg
	} else {
		p.registry = registry.NewRegistry()
	}

	return nil
}

func (p *Provider) initializeClient(config map[string]interface{}) error {
	if p.addr == "" {
		return fmt.Errorf("client mode requires 'addr' in config")
	}
	if p.tlsConfig == nil {
		return fmt.Errorf("client mode requires 'tls_config' in config")
	}

	stewardID, ok := config["steward_id"].(string)
	if !ok || stewardID == "" {
		return fmt.Errorf("client mode requires 'steward_id' in config")
	}
	p.stewardID = stewardID

	if tenantID, ok := config["tenant_id"].(string); ok {
		p.tenantID = tenantID
	}

	return nil
}

// Start begins control plane operation.
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.startTime = time.Now()

	switch p.mode {
	case ModeServer:
		return p.startServer()
	case ModeClient:
		return p.startClient()
	default:
		return fmt.Errorf("provider not initialized")
	}
}

// quicConfig returns a *quicgo.Config with any user overrides, or nil for defaults.
func (p *Provider) quicConfig() *quicgo.Config {
	if p.keepalivePeriod == 0 && p.idleTimeout == 0 {
		return nil // use QUIC transport defaults
	}
	cfg := &quicgo.Config{}
	if p.keepalivePeriod > 0 {
		cfg.KeepAlivePeriod = p.keepalivePeriod
	}
	if p.idleTimeout > 0 {
		cfg.MaxIdleTimeout = p.idleTimeout
	}
	return cfg
}

func (p *Provider) startServer() error {
	p.serverImpl = &transportServer{provider: p}

	if p.ownGRPCServer {
		ql, err := quictransport.Listen(p.addr, p.tlsConfig, p.quicConfig())
		if err != nil {
			return fmt.Errorf("failed to start QUIC listener: %w", err)
		}
		p.listener = ql

		p.grpcServer = grpc.NewServer(
			grpc.Creds(quictransport.TransportCredentials()),
		)
		transportpb.RegisterStewardTransportServer(p.grpcServer, p.serverImpl)

		go func() {
			if err := p.grpcServer.Serve(ql); err != nil {
				p.logger.Error("gRPC server stopped", "error", err)
			}
		}()

		p.logger.Info("gRPC control plane server started", "addr", p.addr)
	} else {
		// External gRPC server (Story #515): the caller is responsible for
		// registering a composite handler and starting the server. We only
		// create serverImpl so ServerHandler() returns a usable handler.
		p.logger.Info("gRPC control plane handler attached to existing gRPC server")
	}

	return nil
}

// startClient must be called with p.mu held.
func (p *Provider) startClient() error {
	p.setState(StateConnecting)

	if err := p.dialAndOpenStream(); err != nil {
		p.setState(StateDisconnected)
		return err
	}

	p.setState(StateConnected)
	p.lastConnectedAt = time.Now() // mu already held by caller

	go p.clientReceiveLoop()

	p.logger.Info("gRPC control plane client connected", "addr", p.addr, "steward_id", p.stewardID)
	return nil
}

// dialAndOpenStream creates a new gRPC client connection over QUIC and opens the
// ControlChannel bidi stream. On failure, any partially created connection is closed.
func (p *Provider) dialAndOpenStream() error {
	// Check context before attempting to dial
	select {
	case <-p.ctx.Done():
		return p.ctx.Err()
	default:
	}

	// Read addr under sendMu (not mu) because this function is called from
	// startClient which already holds mu. sendMu serializes with the test
	// helper restartServerAndRepoint which updates addr under sendMu.
	p.sendMu.Lock()
	addr := p.addr
	p.sendMu.Unlock()

	dialer := quictransport.NewDialer(p.tlsConfig, p.quicConfig())

	conn, err := grpc.NewClient(
		addr,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(quictransport.TransportCredentials()),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC client: %w", err)
	}

	stream, err := transportpb.NewStewardTransportClient(conn).ControlChannel(p.ctx)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("failed to open ControlChannel: %w", err)
	}

	p.sendMu.Lock()
	p.grpcConn = conn
	p.grpcClient = transportpb.NewStewardTransportClient(conn)
	p.controlStream = stream
	p.sendMu.Unlock()

	return nil
}

// clientReceiveLoop reads messages from the ControlChannel and dispatches them.
// When the stream breaks, it triggers the reconnection loop unless the provider
// is shutting down.
func (p *Provider) clientReceiveLoop() {
	// Capture the stream reference at goroutine start to avoid reading the
	// field concurrently with closeClientConn/dialAndOpenStream writes.
	p.sendMu.Lock()
	stream := p.controlStream
	p.sendMu.Unlock()

	if stream == nil {
		p.logger.Error("clientReceiveLoop started with nil stream")
		return
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			select {
			case <-p.ctx.Done():
				p.setState(StateDisconnected)
				return
			default:
			}
			p.logger.Error("ControlChannel receive error", "error", err)
			p.setState(StateDisconnected)
			p.mu.Lock()
			p.lastDisconnectedAt = time.Now()
			p.mu.Unlock()

			p.closeClientConn()
			p.reconnectLoop()
			return
		}

		switch payload := msg.GetPayload().(type) {
		case *transportpb.ControlMessage_Command:
			cmd := commandFromProto(payload.Command)
			p.commandsReceived.Add(1)

			p.mu.RLock()
			handler := p.commandHandler
			p.mu.RUnlock()

			if handler != nil {
				go func() {
					if err := handler(p.ctx, cmd); err != nil {
						p.logger.Error("command handler error", "command_id", cmd.ID, "error", err)
					}
				}()
			}
		}
	}
}

// testBackoffOverride allows tests to use shorter backoff intervals.
// Only set from test code via the unexported field.
var testBackoffOverride *backoff

// reconnectLoop attempts to re-establish the ControlChannel with exponential backoff.
// It runs until either a connection is established or the provider context is cancelled.
func (p *Provider) reconnectLoop() {
	bo := defaultBackoff()
	if testBackoffOverride != nil {
		bo = &backoff{
			initial:    testBackoffOverride.initial,
			max:        testBackoffOverride.max,
			multiplier: testBackoffOverride.multiplier,
			jitter:     testBackoffOverride.jitter,
		}
	}

	for {
		select {
		case <-p.ctx.Done():
			p.setState(StateDisconnected)
			return
		default:
		}

		p.setState(StateReconnecting)
		p.reconnectAttempts.Add(1)

		wait := bo.next()
		p.logger.Info("reconnecting to controller",
			"attempt", bo.attempt,
			"backoff", wait,
			"addr", p.addr,
		)

		// Wait for backoff duration or cancellation
		timer := time.NewTimer(wait)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			p.setState(StateDisconnected)
			return
		case <-timer.C:
		}

		// Attempt to reconnect
		if err := p.dialAndOpenStream(); err != nil {
			p.logger.Warn("reconnection failed", "error", err, "attempt", bo.attempt)
			continue
		}

		// Success — reset backoff and restart receive loop
		bo.reset()
		p.setState(StateConnected)
		p.mu.Lock()
		p.lastConnectedAt = time.Now()
		p.mu.Unlock()

		p.logger.Info("reconnected to controller", "addr", p.addr, "steward_id", p.stewardID)

		// Restart the receive loop (which will call reconnectLoop again if it breaks)
		go p.clientReceiveLoop()
		return
	}
}

// closeClientConn closes the current gRPC connection and clears the stream reference.
func (p *Provider) closeClientConn() {
	p.sendMu.Lock()
	// Nil the stream reference first to prevent new sends. Don't call
	// CloseSend — it races with concurrent Recv in clientReceiveLoop.
	// Closing the gRPC conn below will terminate the stream.
	p.controlStream = nil
	conn := p.grpcConn
	p.grpcConn = nil
	p.sendMu.Unlock()

	if conn != nil {
		_ = conn.Close()
	}
}

// setState updates the connection state and fires the on_state_change callback.
func (p *Provider) setState(state ConnectionState) {
	old := ConnectionState(p.connState.Swap(int32(state)))
	if old == state {
		return
	}
	if p.onStateChange != nil {
		p.onStateChange(state)
	}
}

// getState returns the current connection state.
func (p *Provider) getState() ConnectionState {
	return ConnectionState(p.connState.Load())
}

// sendControlMessage sends a ControlMessage on the client stream under sendMu.
// It handles the TOCTOU race where closeClientConn may nil the stream between
// the checkClientConnected call and the actual send.
func (p *Provider) sendControlMessage(msg *transportpb.ControlMessage) error {
	p.sendMu.Lock()
	stream := p.controlStream
	p.sendMu.Unlock()

	if stream == nil {
		return fmt.Errorf("provider is %s", p.getState())
	}
	return stream.Send(msg)
}

// checkClientConnected returns an error if the client is not in the Connected state.
func (p *Provider) checkClientConnected() error {
	state := p.getState()
	if state != StateConnected {
		return fmt.Errorf("provider is %s", state)
	}
	return nil
}

// Stop gracefully shuts down the control plane.
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancel != nil {
		p.cancel()
	}

	switch p.mode {
	case ModeServer:
		return p.stopServer()
	case ModeClient:
		return p.stopClient()
	default:
		return nil
	}
}

func (p *Provider) stopServer() error {
	if p.ownGRPCServer {
		if p.grpcServer != nil {
			p.grpcServer.GracefulStop()
		}
		if p.listener != nil {
			_ = p.listener.Close()
		}
	}
	// Clear server state so the singleton can be re-initialized cleanly
	// (e.g., when multiple integration tests create separate controllers)
	p.grpcServer = nil
	p.listener = nil
	p.serverImpl = nil
	p.eventHandlers = nil
	p.heartbeatHandlers = nil
	return nil
}

func (p *Provider) stopClient() error {
	// cancel() was already called in Stop(), which will cause reconnectLoop
	// and clientReceiveLoop to exit. Clean up the connection.
	p.closeClientConn()
	p.setState(StateDisconnected)
	return nil
}

// --- Commands (Controller → Steward) ---

func (p *Provider) SendCommand(ctx context.Context, cmd *types.Command) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SendCommand is only available in server mode")
	}
	if cmd == nil {
		return fmt.Errorf("SendCommand: command must not be nil")
	}

	conn, ok := p.registry.Get(cmd.StewardID)
	if !ok {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("steward %s not connected", cmd.StewardID)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Command{Command: commandToProto(cmd)},
	}

	if err := conn.Send(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send command to steward %s: %w", cmd.StewardID, err)
	}

	p.commandsSent.Add(1)
	return nil
}

func (p *Provider) FanOutCommand(ctx context.Context, cmd *types.Command, stewardIDs []string) (*types.FanOutResult, error) {
	if p.mode != ModeServer {
		return nil, fmt.Errorf("FanOutCommand is only available in server mode")
	}
	if len(stewardIDs) == 0 {
		return nil, fmt.Errorf("stewardIDs must not be empty")
	}

	result := &types.FanOutResult{
		Failed: make(map[string]error),
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Command{Command: commandToProto(cmd)},
	}

	conns := p.registry.GetMany(stewardIDs)

	for _, id := range stewardIDs {
		conn, ok := conns[id]
		if !ok {
			result.Failed[id] = fmt.Errorf("steward not connected")
			p.deliveryFailures.Add(1)
			continue
		}

		if err := conn.Send(msg); err != nil {
			result.Failed[id] = err
			p.deliveryFailures.Add(1)
			continue
		}

		result.Succeeded = append(result.Succeeded, id)
		p.commandsSent.Add(1)
	}

	return result, nil
}

func (p *Provider) SubscribeCommands(ctx context.Context, stewardID string, handler interfaces.CommandHandler) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SubscribeCommands is only available in client mode")
	}

	p.mu.Lock()
	p.commandHandler = handler
	p.mu.Unlock()

	return nil
}

// --- Events (Steward → Controller) ---

func (p *Provider) PublishEvent(ctx context.Context, event *types.Event) error {
	if p.mode != ModeClient {
		return fmt.Errorf("PublishEvent is only available in client mode")
	}
	if event == nil {
		return fmt.Errorf("PublishEvent: event must not be nil")
	}
	if err := p.checkClientConnected(); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Event{Event: eventToProto(event)},
	}

	if err := p.sendControlMessage(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to publish event: %w", err)
	}

	p.eventsPublished.Add(1)
	return nil
}

func (p *Provider) SubscribeEvents(ctx context.Context, filter *types.EventFilter, handler interfaces.EventHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeEvents is only available in server mode")
	}

	p.mu.Lock()
	p.eventHandlers = append(p.eventHandlers, eventSubscription{
		filter:  filter,
		handler: handler,
	})
	p.mu.Unlock()

	return nil
}

// --- Heartbeats ---

func (p *Provider) SendHeartbeat(ctx context.Context, heartbeat *types.Heartbeat) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendHeartbeat is only available in client mode")
	}
	if heartbeat == nil {
		return fmt.Errorf("SendHeartbeat: heartbeat must not be nil")
	}
	if err := p.checkClientConnected(); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Heartbeat{Heartbeat: heartbeatToProto(heartbeat)},
	}

	if err := p.sendControlMessage(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send heartbeat: %w", err)
	}

	p.heartbeatsSent.Add(1)
	return nil
}

func (p *Provider) SubscribeHeartbeats(ctx context.Context, handler interfaces.HeartbeatHandler) error {
	if p.mode != ModeServer {
		return fmt.Errorf("SubscribeHeartbeats is only available in server mode")
	}

	p.mu.Lock()
	p.heartbeatHandlers = append(p.heartbeatHandlers, handler)
	p.mu.Unlock()

	return nil
}

// --- Responses ---

func (p *Provider) SendResponse(ctx context.Context, response *types.Response) error {
	if p.mode != ModeClient {
		return fmt.Errorf("SendResponse is only available in client mode")
	}
	if response == nil {
		return fmt.Errorf("SendResponse: response must not be nil")
	}
	if err := p.checkClientConnected(); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send response: %w", err)
	}

	msg := &transportpb.ControlMessage{
		Payload: &transportpb.ControlMessage_Response{Response: responseToProto(response)},
	}

	if err := p.sendControlMessage(msg); err != nil {
		p.deliveryFailures.Add(1)
		return fmt.Errorf("failed to send response: %w", err)
	}

	p.responsesSent.Add(1)
	return nil
}

func (p *Provider) WaitForResponse(ctx context.Context, commandID string, timeout time.Duration) (*types.Response, error) {
	if p.mode != ModeServer {
		return nil, fmt.Errorf("WaitForResponse is only available in server mode")
	}

	ch := make(chan *types.Response, 1)

	p.responseMu.Lock()
	p.pendingResponses[commandID] = ch
	p.responseMu.Unlock()

	defer func() {
		p.responseMu.Lock()
		delete(p.pendingResponses, commandID)
		p.responseMu.Unlock()
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case resp := <-ch:
		p.responsesReceived.Add(1)
		return resp, nil
	case <-timer.C:
		return nil, fmt.Errorf("timeout waiting for response to command %s", commandID)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// dispatchResponse routes an incoming response to a waiting WaitForResponse call.
func (p *Provider) dispatchResponse(resp *types.Response) {
	p.responseMu.Lock()
	ch, ok := p.pendingResponses[resp.CommandID]
	p.responseMu.Unlock()

	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

// dispatchEvent routes an incoming event to matching event handlers.
func (p *Provider) dispatchEvent(event *types.Event) {
	p.eventsReceived.Add(1)

	p.mu.RLock()
	handlers := make([]eventSubscription, len(p.eventHandlers))
	copy(handlers, p.eventHandlers)
	p.mu.RUnlock()

	for _, sub := range handlers {
		if sub.filter != nil && !sub.filter.Match(event) {
			continue
		}
		handler := sub.handler
		go func() {
			if err := handler(p.ctx, event); err != nil {
				p.logger.Error("event handler error", "event_id", event.ID, "error", err)
			}
		}()
	}
}

// dispatchHeartbeat routes an incoming heartbeat to all heartbeat handlers.
func (p *Provider) dispatchHeartbeat(hb *types.Heartbeat) {
	p.heartbeatsReceived.Add(1)

	p.mu.RLock()
	handlers := make([]interfaces.HeartbeatHandler, len(p.heartbeatHandlers))
	copy(handlers, p.heartbeatHandlers)
	p.mu.RUnlock()

	for _, handler := range handlers {
		handler := handler
		go func() {
			if err := handler(p.ctx, hb); err != nil {
				p.logger.Error("heartbeat handler error", "steward_id", hb.StewardID, "error", err)
			}
		}()
	}
}

// --- Status & Monitoring ---

func (p *Provider) GetStats(ctx context.Context) (*types.ControlPlaneStats, error) {
	stats := &types.ControlPlaneStats{
		CommandsSent:       p.commandsSent.Load(),
		CommandsReceived:   p.commandsReceived.Load(),
		EventsPublished:    p.eventsPublished.Load(),
		EventsReceived:     p.eventsReceived.Load(),
		HeartbeatsSent:     p.heartbeatsSent.Load(),
		HeartbeatsReceived: p.heartbeatsReceived.Load(),
		ResponsesSent:      p.responsesSent.Load(),
		ResponsesReceived:  p.responsesReceived.Load(),
		DeliveryFailures:   p.deliveryFailures.Load(),
		ProviderMetrics:    make(map[string]interface{}),
	}

	p.mu.RLock()
	if !p.startTime.IsZero() {
		stats.Uptime = time.Since(p.startTime)
	}
	numEventHandlers := int64(len(p.eventHandlers))
	numHeartbeatHandlers := int64(len(p.heartbeatHandlers))
	lastConnected := p.lastConnectedAt
	lastDisconnected := p.lastDisconnectedAt
	p.mu.RUnlock()

	stats.ActiveSubscriptions = numEventHandlers + numHeartbeatHandlers

	if p.mode == ModeServer && p.registry != nil {
		stats.ConnectedStewards = int64(p.registry.Count())
	}

	// Client-mode reconnection metrics
	if p.mode == ModeClient {
		stats.ProviderMetrics["reconnect_attempts"] = p.reconnectAttempts.Load()
		stats.ProviderMetrics["connection_state"] = p.getState().String()
		if !lastConnected.IsZero() {
			stats.ProviderMetrics["last_connected_at"] = lastConnected
		}
		if !lastDisconnected.IsZero() {
			stats.ProviderMetrics["last_disconnected_at"] = lastDisconnected
		}
	}

	return stats, nil
}

func (p *Provider) Available() (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.mode {
	case ModeServer:
		if p.addr == "" || p.tlsConfig == nil {
			return false, fmt.Errorf("server mode requires addr and tls_config")
		}
		return true, nil
	case ModeClient:
		if p.addr == "" || p.tlsConfig == nil || p.stewardID == "" {
			return false, fmt.Errorf("client mode requires addr, tls_config, and steward_id")
		}
		return true, nil
	default:
		return false, fmt.Errorf("provider not initialized")
	}
}

func (p *Provider) IsConnected() bool {
	switch p.mode {
	case ModeServer:
		p.mu.RLock()
		defer p.mu.RUnlock()
		if p.ownGRPCServer {
			return p.grpcServer != nil && p.listener != nil
		}
		return p.grpcServer != nil && p.serverImpl != nil
	case ModeClient:
		return p.getState() == StateConnected
	default:
		return false
	}
}

// ListenAddr returns the actual listen address after Start() in server mode.
// Returns empty string if not started or in client mode.
func (p *Provider) ListenAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.listener != nil {
		return p.listener.Addr().String()
	}
	return ""
}

// ForceStop immediately closes all connections and stops the server without
// waiting for in-progress RPCs to complete. Use in tests when GracefulStop
// would hang on long-lived ControlChannel streams.
func (p *Provider) ForceStop() {
	if p.ownGRPCServer {
		if p.listener != nil {
			_ = p.listener.Close()
		}
		if p.grpcServer != nil {
			p.grpcServer.Stop()
		}
	}
}

// ServerHandler returns the CP handler that implements StewardTransportServer
// for control plane RPCs (Register, Ping, ControlChannel). Used by the controller
// to build a composite handler that delegates CP and DP RPCs appropriately.
// Returns nil if Start() has not been called.
func (p *Provider) ServerHandler() transportpb.StewardTransportServer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.serverImpl
}

// --- gRPC StewardTransportServer implementation ---

// transportServer implements the gRPC StewardTransportServer interface,
// delegating to the Provider for handler dispatch and registry management.
type transportServer struct {
	transportpb.UnimplementedStewardTransportServer
	provider *Provider
}

func (s *transportServer) Register(ctx context.Context, req *controllerpb.RegisterRequest) (*controllerpb.RegisterResponse, error) {
	// Extract steward identity from the request
	stewardID := req.GetCredentials().GetClientId()
	if stewardID == "" {
		return nil, status.Error(codes.InvalidArgument, "client_id is required in credentials")
	}

	s.provider.logger.Info("steward registered", "steward_id", stewardID, "version", req.GetVersion())

	return &controllerpb.RegisterResponse{
		StewardId: stewardID,
		Status: &commonpb.Status{
			Code:    commonpb.Status_OK,
			Message: "registered",
		},
	}, nil
}

func (s *transportServer) Ping(ctx context.Context, req *transportpb.PingRequest) (*transportpb.PingResponse, error) {
	return &transportpb.PingResponse{
		RequestTimestampNs:  req.GetTimestampNs(),
		ResponseTimestampNs: timestamppb.Now().AsTime().UnixNano(),
	}, nil
}

func (s *transportServer) ControlChannel(stream grpc.BidiStreamingServer[transportpb.ControlMessage, transportpb.ControlMessage]) error {
	// Extract steward identity from mTLS peer certificate
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer info")
	}

	stewardID, err := extractStewardIDFromPeer(stream.Context())
	if err != nil {
		return status.Errorf(codes.Unauthenticated, "failed to extract steward identity: %v", err)
	}

	// Create a stream sender adapter for the registry
	sender := &streamSender{stream: stream}

	conn := &registry.StewardConnection{
		StewardID:   stewardID,
		Sender:      sender,
		ConnectedAt: time.Now(),
		RemoteAddr:  p.Addr.String(),
	}

	if err := s.provider.registry.Register(conn); err != nil {
		return status.Errorf(codes.Internal, "failed to register steward: %v", err)
	}
	defer s.provider.registry.Unregister(stewardID)

	s.provider.logger.Info("steward connected to ControlChannel", "steward_id", stewardID, "remote_addr", p.Addr.String())

	// Receive loop: read messages from steward and dispatch
	for {
		msg, err := stream.Recv()
		if err != nil {
			s.provider.logger.Info("steward ControlChannel closed", "steward_id", stewardID, "error", err)
			return nil
		}

		conn.UpdateActivity()

		switch payload := msg.GetPayload().(type) {
		case *transportpb.ControlMessage_Event:
			event := eventFromProto(payload.Event)
			s.provider.dispatchEvent(event)

		case *transportpb.ControlMessage_Heartbeat:
			hb := heartbeatFromProto(payload.Heartbeat)
			s.provider.dispatchHeartbeat(hb)

		case *transportpb.ControlMessage_Response:
			resp := responseFromProto(payload.Response)
			s.provider.dispatchResponse(resp)
		}
	}
}

// extractStewardIDFromPeer extracts the steward ID from the peer's TLS certificate CN.
//
// The QUIC transport credentials (quictransport.TransportCredentials) bridge the
// QUIC-layer TLS state into gRPC's peer AuthInfo as credentials.TLSInfo. This
// function reads the peer certificates from that TLS state and extracts the CN.
func extractStewardIDFromPeer(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer info in context")
	}

	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("no TLS auth info in peer (got %T)", p.AuthInfo)
	}

	return quictransport.PeerStewardID(tlsInfo.State)
}

// streamSender adapts a gRPC server stream to the registry.MessageSender interface.
type streamSender struct {
	stream grpc.BidiStreamingServer[transportpb.ControlMessage, transportpb.ControlMessage]
}

func (s *streamSender) SendMsg(msg interface{}) error {
	cm, ok := msg.(*transportpb.ControlMessage)
	if !ok {
		return fmt.Errorf("expected *ControlMessage, got %T", msg)
	}
	return s.stream.Send(cm)
}
