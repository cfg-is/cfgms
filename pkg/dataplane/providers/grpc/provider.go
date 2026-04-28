// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	transportpb "github.com/cfgis/cfgms/api/proto/transport"
	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
	quictransport "github.com/cfgis/cfgms/pkg/transport/quic"
	"google.golang.org/grpc"
)

func init() {
	interfaces.RegisterProvider(New())
}

// Stats tracks provider-level statistics using atomic operations for lock-free reads.
type Stats struct {
	sessionsAccepted   atomic.Int64
	connectionAttempts atomic.Int64
	failedConnections  atomic.Int64
	configsSent        atomic.Int64
	configsReceived    atomic.Int64
	dnaSent            atomic.Int64
	dnaReceived        atomic.Int64
	bulkSent           atomic.Int64
	bulkReceived       atomic.Int64
	bytesSent          atomic.Int64
	bytesReceived      atomic.Int64
	transferErrors     atomic.Int64
	timeoutErrors      atomic.Int64
	protocolErrors     atomic.Int64
}

// Provider implements DataPlaneProvider using gRPC streaming RPCs over QUIC.
//
// Server mode registers SyncConfig, SyncDNA, and BulkTransfer handlers with a
// gRPC server. Client mode wraps an existing *grpc.ClientConn (shared with the
// control plane) or dials a new connection.
type Provider struct {
	mu sync.RWMutex

	// Configuration
	mode       string // "server" or "client"
	listenAddr string
	serverAddr string
	stewardID  string
	tlsConfig  *tls.Config

	// Server-side (one or the other, not both)
	grpcServer    *grpc.Server            // may be externally provided or owned
	ownGRPCServer bool                    // true if we started grpcServer
	listener      *quictransport.Listener // QUIC listener, only when ownGRPCServer
	handler       *dataPlaneHandler       // incoming-RPC dispatch handler

	// Client-side (one or the other, not both)
	grpcConn    *grpc.ClientConn // may be externally provided or owned
	ownGRPCConn bool             // true if we dialed grpcConn
	grpcClient  transportpb.StewardTransportClient

	// Session tracking
	sessions       map[string]*Session
	sessionCounter atomic.Uint64

	// Lifecycle
	started   atomic.Bool
	startTime time.Time

	// Stats
	stats Stats

	// Logger
	logger *slog.Logger
}

// New creates a new gRPC data plane provider with defaults.
func New() *Provider {
	return &Provider{
		sessions: make(map[string]*Session),
		logger:   slog.Default(),
	}
}

// Name returns the provider name.
func (p *Provider) Name() string { return "grpc" }

// Description returns a human-readable description.
func (p *Provider) Description() string {
	return "gRPC-based data plane provider over QUIC transport"
}

// Initialize configures the provider.
//
// Config keys:
//   - "mode": string ("server" or "client") — required
//   - "tls_config": *tls.Config — required when creating own server or connection
//   - "logger": *slog.Logger — optional
//
// Server mode additional keys:
//   - "listen_addr": string — required if "grpc_server" not provided
//   - "grpc_server": *grpc.Server — existing server to register handlers with (optional)
//
// Client mode additional keys:
//   - "server_addr": string — required if "grpc_conn" not provided
//   - "grpc_conn": *grpc.ClientConn — existing connection to reuse (optional)
//   - "steward_id": string — required
func (p *Provider) Initialize(_ context.Context, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	mode, ok := config["mode"].(string)
	if !ok || (mode != "server" && mode != "client") {
		return fmt.Errorf("mode must be 'server' or 'client'")
	}
	p.mode = mode

	if logger, ok := config["logger"].(*slog.Logger); ok {
		p.logger = logger
	}

	if tlsCfg, ok := config["tls_config"].(*tls.Config); ok {
		p.tlsConfig = tlsCfg
	}

	if mode == "server" {
		return p.initServer(config)
	}
	return p.initClient(config)
}

func (p *Provider) initServer(config map[string]interface{}) error {
	if srv, ok := config["grpc_server"].(*grpc.Server); ok && srv != nil {
		p.grpcServer = srv
		p.ownGRPCServer = false
	} else {
		addr, ok := config["listen_addr"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("server mode requires 'listen_addr' or 'grpc_server' in config")
		}
		if p.tlsConfig == nil {
			return fmt.Errorf("server mode requires 'tls_config' when creating own gRPC server")
		}
		p.listenAddr = addr
		p.ownGRPCServer = true
	}
	return nil
}

func (p *Provider) initClient(config map[string]interface{}) error {
	stewardID, ok := config["steward_id"].(string)
	if !ok || stewardID == "" {
		return fmt.Errorf("client mode requires 'steward_id' in config")
	}
	p.stewardID = stewardID

	if conn, ok := config["grpc_conn"].(*grpc.ClientConn); ok && conn != nil {
		p.grpcConn = conn
		p.ownGRPCConn = false
	} else {
		addr, ok := config["server_addr"].(string)
		if !ok || addr == "" {
			return fmt.Errorf("client mode requires 'server_addr' or 'grpc_conn' in config")
		}
		if p.tlsConfig == nil {
			return fmt.Errorf("client mode requires 'tls_config' when dialing own connection")
		}
		p.serverAddr = addr
		p.ownGRPCConn = true
	}
	return nil
}

// Start begins provider operation.
func (p *Provider) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.started.Load() {
		return fmt.Errorf("provider already started")
	}
	p.startTime = time.Now()

	if p.mode == "server" {
		return p.startServer()
	}
	return p.startClient()
}

func (p *Provider) startServer() error {
	p.handler = newDataPlaneHandler()

	if p.ownGRPCServer {
		ql, err := quictransport.Listen(p.listenAddr, p.tlsConfig, nil)
		if err != nil {
			return fmt.Errorf("failed to start QUIC listener: %w", err)
		}
		p.listener = ql
		p.listenAddr = ql.Addr().String() // capture actual port if ":0"

		p.grpcServer = grpc.NewServer(
			grpc.Creds(quictransport.TransportCredentials()),
		)
		transportpb.RegisterStewardTransportServer(p.grpcServer, p.handler)

		go func() {
			if err := p.grpcServer.Serve(ql); err != nil {
				p.logger.Error("gRPC data plane server stopped", "error", err)
			}
		}()
		p.logger.Info("gRPC data plane server started", "addr", p.listenAddr)
	} else {
		// Register only the data-transfer methods on the shared server.
		// The shared server already has a StewardTransportServer registered
		// (for the control plane). We cannot double-register, so we attach
		// our handler via the server's internal mechanism. In practice the
		// controller wires the handler at server-build time; for testing we
		// create our own server above. When grpc_server is provided the
		// caller is responsible for registering the handler.
		p.logger.Info("gRPC data plane handler attached to existing gRPC server")
	}

	p.started.Store(true)
	return nil
}

func (p *Provider) startClient() error {
	if p.ownGRPCConn {
		dialer := quictransport.NewDialer(p.tlsConfig, nil)
		conn, err := grpc.NewClient(
			p.serverAddr,
			grpc.WithContextDialer(dialer),
			grpc.WithTransportCredentials(quictransport.TransportCredentials()),
		)
		if err != nil {
			return fmt.Errorf("failed to dial gRPC server: %w", err)
		}
		p.grpcConn = conn
	}
	p.grpcClient = transportpb.NewStewardTransportClient(p.grpcConn)
	p.started.Store(true)
	p.logger.Info("gRPC data plane client ready", "steward_id", p.stewardID)
	return nil
}

// Stop gracefully shuts down the provider.
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started.Load() {
		return nil
	}

	// Mark all sessions closed; the map is replaced below.
	// Session.Close() acquires p.mu, so we cannot call it while holding the lock.
	for _, s := range p.sessions {
		s.closed.Store(true)
	}
	p.sessions = make(map[string]*Session)

	if p.handler != nil {
		p.handler.close()
	}

	if p.ownGRPCServer && p.grpcServer != nil {
		p.grpcServer.GracefulStop()
		p.grpcServer = nil
	}
	if p.listener != nil {
		_ = p.listener.Close()
		p.listener = nil
	}

	if p.ownGRPCConn && p.grpcConn != nil {
		_ = p.grpcConn.Close()
		p.grpcConn = nil
	}

	p.started.Store(false)
	p.logger.Info("gRPC data plane provider stopped")
	return nil
}

// Handler returns the DP handler that implements StewardTransportServer for
// data plane RPCs (SyncConfig, SyncDNA, BulkTransfer). Used by the controller
// to build a composite handler that delegates CP and DP RPCs appropriately.
// Returns nil if Start() has not been called.
func (p *Provider) Handler() transportpb.StewardTransportServer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.handler
}

// AcceptConnection accepts an incoming data-plane connection (server-side).
//
// In the gRPC model, "accepting a connection" means returning a Session that
// is ready to handle incoming SyncConfig, SyncDNA, and BulkTransfer RPCs.
// The session blocks on its handler channels when a transfer method is called.
func (p *Provider) AcceptConnection(_ context.Context) (interfaces.DataPlaneSession, error) {
	p.mu.RLock()
	mode := p.mode
	started := p.started.Load()
	handler := p.handler
	p.mu.RUnlock()

	if mode != "server" {
		return nil, fmt.Errorf("AcceptConnection only available in server mode")
	}
	if !started || handler == nil {
		return nil, fmt.Errorf("server not started")
	}

	sessionID := fmt.Sprintf("grpc-server-session-%d", p.sessionCounter.Add(1))
	s := &Session{
		id:       sessionID,
		peerID:   "", // populated from RPC context when first RPC arrives
		mode:     "server",
		handler:  handler,
		provider: p,
	}

	p.mu.Lock()
	p.sessions[sessionID] = s
	p.mu.Unlock()

	p.stats.sessionsAccepted.Add(1)
	p.logger.Debug("gRPC data plane server session created", "session_id", sessionID)
	return s, nil
}

// Connect establishes a data-plane connection to the controller (client-side).
func (p *Provider) Connect(ctx context.Context, serverAddr string) (interfaces.DataPlaneSession, error) {
	p.mu.RLock()
	mode := p.mode
	started := p.started.Load()
	client := p.grpcClient
	p.mu.RUnlock()

	if mode != "client" {
		return nil, fmt.Errorf("Connect only available in client mode")
	}
	if !started || client == nil {
		return nil, fmt.Errorf("client not started")
	}

	p.stats.connectionAttempts.Add(1)

	sessionID := fmt.Sprintf("grpc-client-session-%d", p.sessionCounter.Add(1))
	s := &Session{
		id:       sessionID,
		peerID:   "controller",
		mode:     "client",
		client:   client,
		provider: p,
	}

	p.mu.Lock()
	p.sessions[sessionID] = s
	p.mu.Unlock()

	p.logger.Debug("gRPC data plane client session created",
		"session_id", sessionID,
		"steward_id", p.stewardID)
	return s, nil
}

// GetStats returns provider statistics.
func (p *Provider) GetStats(_ context.Context) (*types.DataPlaneStats, error) {
	p.mu.RLock()
	activeSessions := len(p.sessions)
	p.mu.RUnlock()

	uptime := time.Duration(0)
	if p.started.Load() {
		uptime = time.Since(p.startTime)
	}

	return &types.DataPlaneStats{
		ProviderName:            "grpc",
		Uptime:                  uptime,
		ActiveSessions:          activeSessions,
		TotalSessionsAccepted:   p.stats.sessionsAccepted.Load(),
		TotalConnectionAttempts: p.stats.connectionAttempts.Load(),
		FailedConnections:       p.stats.failedConnections.Load(),
		ConfigTransfers: types.TransferStats{
			Sent:     p.stats.configsSent.Load(),
			Received: p.stats.configsReceived.Load(),
		},
		DNATransfers: types.TransferStats{
			Sent:     p.stats.dnaSent.Load(),
			Received: p.stats.dnaReceived.Load(),
		},
		BulkTransfers: types.TransferStats{
			Sent:     p.stats.bulkSent.Load(),
			Received: p.stats.bulkReceived.Load(),
		},
		BytesSent:      p.stats.bytesSent.Load(),
		BytesReceived:  p.stats.bytesReceived.Load(),
		TransferErrors: p.stats.transferErrors.Load(),
		TimeoutErrors:  p.stats.timeoutErrors.Load(),
		ProtocolErrors: p.stats.protocolErrors.Load(),
	}, nil
}

// Available reports whether the provider is configured and ready to start.
func (p *Provider) Available() (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.mode {
	case "server":
		if p.grpcServer == nil && p.listenAddr == "" {
			return false, fmt.Errorf("server mode requires listen_addr or grpc_server")
		}
		if p.ownGRPCServer && p.tlsConfig == nil {
			return false, fmt.Errorf("TLS configuration required for standalone server")
		}
		return true, nil
	case "client":
		if p.grpcConn == nil && p.serverAddr == "" {
			return false, fmt.Errorf("client mode requires server_addr or grpc_conn")
		}
		if p.ownGRPCConn && p.tlsConfig == nil {
			return false, fmt.Errorf("TLS configuration required for dialing connection")
		}
		return true, nil
	default:
		return false, fmt.Errorf("provider not initialized: call Initialize first")
	}
}

// IsListening reports whether the server is listening for connections.
func (p *Provider) IsListening() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mode == "server" && p.started.Load()
}

// IsConnected reports whether the client is connected.
func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mode == "client" && p.started.Load() && p.grpcClient != nil
}

// ListenAddr returns the actual listen address (after port assignment).
// Returns empty string if not started or in client mode.
func (p *Provider) ListenAddr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.listenAddr
}
