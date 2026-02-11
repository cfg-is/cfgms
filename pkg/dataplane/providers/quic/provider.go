// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package quic implements the QUIC data plane provider for CFGMS.
//
// This provider wraps the existing pkg/quic implementation and provides
// the pluggable DataPlaneProvider interface for high-throughput transfers.
package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/pkg/dataplane/interfaces"
	"github.com/cfgis/cfgms/pkg/dataplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
	quicClient "github.com/cfgis/cfgms/pkg/quic/client"
	quicServer "github.com/cfgis/cfgms/pkg/quic/server"
	quicSession "github.com/cfgis/cfgms/pkg/quic/session"
)

// Provider implements the DataPlaneProvider interface using QUIC.
type Provider struct {
	mu sync.RWMutex

	// Configuration
	name        string
	description string
	mode        string // "server" or "client"
	listenAddr  string
	serverAddr  string
	stewardID   string
	tlsConfig   *tls.Config

	// Server-side
	server *quicServer.Server

	// Client-side
	client *quicClient.Client

	// Session management
	sessionManager *quicSession.Manager
	sessions       map[string]*Session
	sessionCounter atomic.Uint64

	// State
	started   atomic.Bool
	startTime time.Time

	// Statistics
	stats Stats

	// Logger
	logger logging.Logger
}

// Stats tracks provider statistics using atomic operations.
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

// init registers the QUIC provider.
func init() {
	// Register a prototype provider - actual instances created via Initialize
	interfaces.RegisterProvider(&Provider{
		name:        "quic",
		description: "QUIC-based high-throughput data plane",
	})
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return "quic"
}

// Description returns a human-readable description.
func (p *Provider) Description() string {
	return "QUIC-based high-throughput data plane for configuration and DNA transfers"
}

// Initialize configures the provider.
func (p *Provider) Initialize(ctx context.Context, config map[string]interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Extract configuration
	mode, ok := config["mode"].(string)
	if !ok || (mode != "server" && mode != "client") {
		return fmt.Errorf("mode must be 'server' or 'client'")
	}
	p.mode = mode

	// TLS configuration (required for QUIC)
	tlsConfig, ok := config["tls_config"].(*tls.Config)
	if !ok || tlsConfig == nil {
		return fmt.Errorf("tls_config is required")
	}
	p.tlsConfig = tlsConfig

	// Logger
	if logger, ok := config["logger"].(logging.Logger); ok {
		p.logger = logger
	} else {
		// Use module logger as fallback
		p.logger = logging.GetLogger()
	}

	// Mode-specific configuration
	if mode == "server" {
		// Server-side configuration
		listenAddr, ok := config["listen_addr"].(string)
		if !ok || listenAddr == "" {
			return fmt.Errorf("listen_addr is required for server mode")
		}
		p.listenAddr = listenAddr

		// Session manager (optional)
		if sm, ok := config["session_manager"].(*quicSession.Manager); ok {
			p.sessionManager = sm
		}
	} else {
		// Client-side configuration
		serverAddr, ok := config["server_addr"].(string)
		if !ok || serverAddr == "" {
			return fmt.Errorf("server_addr is required for client mode")
		}
		p.serverAddr = serverAddr

		stewardID, ok := config["steward_id"].(string)
		if !ok || stewardID == "" {
			return fmt.Errorf("steward_id is required for client mode")
		}
		p.stewardID = stewardID
	}

	p.sessions = make(map[string]*Session)
	p.logger.Info("QUIC data plane provider initialized",
		"mode", p.mode,
		"listen_addr", p.listenAddr,
		"server_addr", p.serverAddr)

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
		// Start server
		serverCfg := &quicServer.Config{
			ListenAddr:     p.listenAddr,
			TLSConfig:      p.tlsConfig,
			SessionTimeout: 5 * time.Minute,
			SessionManager: p.sessionManager,
			Logger:         p.logger,
		}

		server, err := quicServer.New(serverCfg)
		if err != nil {
			return fmt.Errorf("failed to create QUIC server: %w", err)
		}

		if err := server.Start(ctx); err != nil {
			return fmt.Errorf("failed to start QUIC server: %w", err)
		}

		p.server = server
		p.logger.Info("QUIC server started", "listen_addr", p.listenAddr)
	} else {
		// Client mode doesn't auto-connect - connection happens via Connect()
		p.logger.Info("QUIC client ready", "server_addr", p.serverAddr)
	}

	p.started.Store(true)
	return nil
}

// Stop gracefully shuts down the provider.
func (p *Provider) Stop(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.started.Load() {
		return nil // Already stopped
	}

	// Close all sessions
	for _, session := range p.sessions {
		_ = session.Close(ctx)
	}
	p.sessions = make(map[string]*Session)

	// Stop server or client
	if p.server != nil {
		if err := p.server.Stop(ctx); err != nil {
			p.logger.Error("Error stopping QUIC server", "error", err)
		}
		p.server = nil
	}

	if p.client != nil {
		if err := p.client.Disconnect(); err != nil {
			p.logger.Error("Error disconnecting QUIC client", "error", err)
		}
		p.client = nil
	}

	p.started.Store(false)
	p.logger.Info("QUIC data plane provider stopped")
	return nil
}

// AcceptConnection accepts an incoming connection (server-side).
func (p *Provider) AcceptConnection(ctx context.Context) (interfaces.DataPlaneSession, error) {
	p.mu.RLock()
	mode := p.mode
	server := p.server
	p.mu.RUnlock()

	if mode != "server" {
		return nil, fmt.Errorf("AcceptConnection only available in server mode")
	}

	if server == nil {
		return nil, fmt.Errorf("server not started")
	}

	// Use server's AcceptConnection
	// Note: We'll need to add this method to pkg/quic/server in the next step
	// For now, return a placeholder error
	return nil, fmt.Errorf("AcceptConnection not yet implemented - requires pkg/quic/server enhancement")
}

// Connect establishes a connection (client-side).
func (p *Provider) Connect(ctx context.Context, serverAddr string) (interfaces.DataPlaneSession, error) {
	p.mu.RLock()
	mode := p.mode
	p.mu.RUnlock()

	if mode != "client" {
		return nil, fmt.Errorf("Connect only available in client mode")
	}

	// Use provided address or configured address
	addr := serverAddr
	if addr == "" {
		addr = p.serverAddr
	}

	p.stats.connectionAttempts.Add(1)

	// Create QUIC client
	sessionID := fmt.Sprintf("session-%d", p.sessionCounter.Add(1))
	clientCfg := &quicClient.Config{
		ServerAddr: addr,
		TLSConfig:  p.tlsConfig,
		SessionID:  sessionID,
		StewardID:  p.stewardID,
		Logger:     p.logger,
	}

	client, err := quicClient.New(clientCfg)
	if err != nil {
		p.stats.failedConnections.Add(1)
		return nil, fmt.Errorf("failed to create QUIC client: %w", err)
	}

	if err := client.Connect(ctx); err != nil {
		p.stats.failedConnections.Add(1)
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Wrap client in a session
	session := &Session{
		id:        sessionID,
		peerID:    "controller", // Controller doesn't have a specific ID in current impl
		client:    client,
		provider:  p,
		createdAt: time.Now(),
		logger:    p.logger,
	}

	p.mu.Lock()
	p.sessions[sessionID] = session
	p.mu.Unlock()

	p.logger.Info("QUIC connection established", "session_id", sessionID, "server_addr", addr)
	return session, nil
}

// GetStats returns provider statistics.
func (p *Provider) GetStats(ctx context.Context) (*types.DataPlaneStats, error) {
	p.mu.RLock()
	activeSessions := len(p.sessions)
	p.mu.RUnlock()

	uptime := time.Duration(0)
	if p.started.Load() {
		uptime = time.Since(p.startTime)
	}

	stats := &types.DataPlaneStats{
		ProviderName:            p.name,
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
	}

	return stats, nil
}

// Available checks if the provider can be started.
func (p *Provider) Available() (bool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.tlsConfig == nil {
		return false, fmt.Errorf("TLS configuration not provided")
	}

	if p.mode == "server" && p.listenAddr == "" {
		return false, fmt.Errorf("listen address not configured")
	}

	if p.mode == "client" && p.serverAddr == "" {
		return false, fmt.Errorf("server address not configured")
	}

	return true, nil
}

// IsListening reports server listening status.
func (p *Provider) IsListening() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.mode == "server" && p.started.Load() && p.server != nil
}

// IsConnected reports connection status.
func (p *Provider) IsConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.mode != "client" {
		return false
	}

	// Check if we have any active sessions
	return len(p.sessions) > 0
}

// RegisterStreamHandler registers a handler for a specific stream ID with the underlying QUIC server.
// This is a bridge method to support the transition period while session acceptance is being implemented.
// The handler receives the raw QUIC server session and stream, which can be wrapped for provider interface compatibility.
//
// Note: This method is only valid for server-mode providers and will return an error in client mode.
// Note: stream parameter uses *quicgo.Stream which is type-aliased from github.com/quic-go/quic-go
func (p *Provider) RegisterStreamHandler(streamID int64, handler quicServer.StreamHandler) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.mode != "server" {
		return fmt.Errorf("RegisterStreamHandler only available in server mode")
	}

	if p.server == nil {
		return fmt.Errorf("server not initialized")
	}

	// Register with underlying QUIC server
	p.server.RegisterStreamHandler(streamID, handler)
	return nil
}
