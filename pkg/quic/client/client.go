// Package client provides QUIC client functionality for CFGMS steward.
//
// This package implements the QUIC client that connects to the controller
// for high-throughput data transfers (Story #198).
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Client represents a QUIC client for data transfers to controller.
type Client struct {
	mu sync.RWMutex

	// QUIC connection
	conn *quic.Conn

	// Configuration
	serverAddr string
	tlsConfig  *tls.Config
	sessionID  string
	stewardID  string

	// Streams
	streams map[int64]*quic.Stream

	// Control
	ctx    context.Context
	cancel context.CancelFunc

	// Logger
	logger logging.Logger
}

// Config holds QUIC client configuration.
type Config struct {
	// ServerAddr is the controller QUIC address (e.g., "controller:4433")
	ServerAddr string

	// TLSConfig for mTLS authentication
	TLSConfig *tls.Config

	// SessionID from MQTT connect_quic command
	SessionID string

	// StewardID identifies this steward
	StewardID string

	// Logger for client logging
	Logger logging.Logger
}

// New creates a new QUIC client.
func New(cfg *Config) (*Client, error) {
	if cfg.ServerAddr == "" {
		return nil, fmt.Errorf("server address is required")
	}
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("TLS config is required")
	}
	if cfg.SessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}
	if cfg.StewardID == "" {
		return nil, fmt.Errorf("steward ID is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		serverAddr: cfg.ServerAddr,
		tlsConfig:  cfg.TLSConfig,
		sessionID:  cfg.SessionID,
		stewardID:  cfg.StewardID,
		streams:    make(map[int64]*quic.Stream),
		ctx:        ctx,
		cancel:     cancel,
		logger:     cfg.Logger,
	}, nil
}

// Connect establishes a QUIC connection to the controller.
func (c *Client) Connect(ctx context.Context) error {
	c.logger.Info("Connecting to controller via QUIC",
		"server_addr", c.serverAddr,
		"session_id", c.sessionID)

	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:  5 * time.Minute,
		KeepAlivePeriod: 30 * time.Second,
	}

	// Dial QUIC connection
	conn, err := quic.DialAddr(ctx, c.serverAddr, c.tlsConfig, quicConfig)
	if err != nil {
		return fmt.Errorf("failed to dial QUIC: %w", err)
	}

	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()

	// Perform handshake on control stream
	if err := c.performHandshake(ctx); err != nil {
		_ = conn.CloseWithError(1, "handshake failed")
		return fmt.Errorf("handshake failed: %w", err)
	}

	c.logger.Info("QUIC connection established successfully")
	return nil
}

// performHandshake performs the QUIC handshake on the control stream.
func (c *Client) performHandshake(ctx context.Context) error {
	// Open control stream (stream 0)
	stream, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("failed to open control stream: %w", err)
	}

	// Send handshake message
	// Format: "session_id:steward_id\n"
	handshake := fmt.Sprintf("%s:%s\n", c.sessionID, c.stewardID)
	if _, err := stream.Write([]byte(handshake)); err != nil {
		return fmt.Errorf("failed to write handshake: %w", err)
	}

	// Read handshake response
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to read handshake response: %w", err)
	}

	response := string(buf[:n])
	c.logger.Debug("Received handshake response", "response", response)

	// TODO: Parse proper protobuf handshake response
	if response != "OK\n" {
		return fmt.Errorf("handshake rejected: %s", response)
	}

	// Store control stream
	c.mu.Lock()
	c.streams[0] = stream
	c.mu.Unlock()

	return nil
}

// OpenStream opens a new stream for data transfer.
func (c *Client) OpenStream(ctx context.Context, streamID int64) (*quic.Stream, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to open stream: %w", err)
	}

	c.mu.Lock()
	c.streams[streamID] = stream
	c.mu.Unlock()

	c.logger.Debug("Opened QUIC stream", "stream_id", streamID)

	return stream, nil
}

// CloseStream closes a specific stream.
func (c *Client) CloseStream(streamID int64) error {
	c.mu.Lock()
	stream, exists := c.streams[streamID]
	if exists {
		delete(c.streams, streamID)
	}
	c.mu.Unlock()

	if !exists {
		return fmt.Errorf("stream not found: %d", streamID)
	}

	if err := stream.Close(); err != nil {
		return fmt.Errorf("failed to close stream: %w", err)
	}

	c.logger.Debug("Closed QUIC stream", "stream_id", streamID)
	return nil
}

// Disconnect closes the QUIC connection.
func (c *Client) Disconnect() error {
	c.logger.Info("Disconnecting QUIC connection")

	c.cancel()

	c.mu.Lock()
	conn := c.conn
	c.conn = nil

	// Close all streams
	for streamID, stream := range c.streams {
		c.logger.Debug("Closing stream", "stream_id", streamID)
		_ = stream.Close()
	}
	c.streams = make(map[int64]*quic.Stream)
	c.mu.Unlock()

	if conn != nil {
		if err := conn.CloseWithError(0, "client disconnect"); err != nil {
			return fmt.Errorf("failed to close connection: %w", err)
		}
	}

	c.logger.Info("QUIC connection closed")
	return nil
}

// IsConnected returns whether the client is connected.
func (c *Client) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}

// GetStream returns a stream by ID.
func (c *Client) GetStream(streamID int64) (*quic.Stream, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	stream, exists := c.streams[streamID]
	return stream, exists
}
