// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package server provides QUIC server functionality for CFGMS controller.
//
// Deprecated: Server-side QUIC functionality should be accessed through
// pkg/dataplane/interfaces.DataPlaneProvider (Story #267.5). This package
// is retained as internal infrastructure for the QUIC data plane provider
// at pkg/dataplane/providers/quic. Feature code should not import directly.
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/cfgis/cfgms/pkg/logging"
	quicSession "github.com/cfgis/cfgms/pkg/quic/session" //nolint:staticcheck // SA1019: Internal infrastructure
)

// Server represents a QUIC server for steward data transfers.
type Server struct {
	mu sync.RWMutex

	// QUIC listener
	listener *quic.Listener

	// Configuration
	listenAddr string
	tlsConfig  *tls.Config

	// Session management
	sessions       map[string]*Session
	sessionTimeout time.Duration

	// Stream handlers
	streamHandlers map[int64]StreamHandler

	// Session validator
	sessionManager *quicSession.Manager

	// Control
	ctx    context.Context
	cancel context.CancelFunc

	// Logger
	logger logging.Logger
}

// Session represents an active QUIC connection from a steward.
type Session struct {
	ID         string
	StewardID  string
	Connection *quic.Conn
	CreatedAt  time.Time
	LastActive time.Time
	Streams    map[int64]*quic.Stream
}

// StreamHandler processes data on a specific stream.
type StreamHandler func(ctx context.Context, session *Session, stream *quic.Stream) error

// Config holds QUIC server configuration.
type Config struct {
	// ListenAddr is the address to listen on (e.g., ":4433")
	ListenAddr string

	// TLSConfig for mTLS authentication
	TLSConfig *tls.Config

	// SessionTimeout for inactive sessions
	SessionTimeout time.Duration

	// SessionManager for validating QUIC sessions
	SessionManager *quicSession.Manager

	// Logger for server logging
	Logger logging.Logger
}

// New creates a new QUIC server.
func New(cfg *Config) (*Server, error) {
	if cfg.ListenAddr == "" {
		return nil, fmt.Errorf("listen address is required")
	}
	if cfg.TLSConfig == nil {
		return nil, fmt.Errorf("TLS config is required")
	}
	if cfg.Logger == nil {
		return nil, fmt.Errorf("logger is required")
	}

	sessionTimeout := cfg.SessionTimeout
	if sessionTimeout == 0 {
		sessionTimeout = 5 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		listenAddr:     cfg.ListenAddr,
		tlsConfig:      cfg.TLSConfig,
		sessions:       make(map[string]*Session),
		sessionTimeout: sessionTimeout,
		streamHandlers: make(map[int64]StreamHandler),
		sessionManager: cfg.SessionManager,
		ctx:            ctx,
		cancel:         cancel,
		logger:         cfg.Logger,
	}, nil
}

// RegisterStreamHandler registers a handler for a specific stream ID.
func (s *Server) RegisterStreamHandler(streamID int64, handler StreamHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streamHandlers[streamID] = handler
	s.logger.Info("Registered QUIC stream handler", "stream_id", streamID)
}

// Start starts the QUIC server.
func (s *Server) Start(ctx context.Context) error {
	fmt.Printf("[DEBUG] QUIC Server Start() called, listen_addr=%s\n", s.listenAddr)
	s.logger.Info("Starting QUIC server", "listen_addr", s.listenAddr)

	// Configure QUIC
	quicConfig := &quic.Config{
		MaxIdleTimeout:  s.sessionTimeout,
		KeepAlivePeriod: 30 * time.Second,
	}

	fmt.Printf("[DEBUG] QUIC attempting to listen on %s\n", s.listenAddr)
	// Create QUIC listener
	listener, err := quic.ListenAddr(s.listenAddr, s.tlsConfig, quicConfig)
	if err != nil {
		fmt.Printf("[DEBUG] QUIC failed to create listener: %v\n", err)
		return fmt.Errorf("failed to start QUIC listener: %w", err)
	}

	fmt.Printf("[DEBUG] QUIC listener created successfully\n")

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	fmt.Printf("[DEBUG] QUIC starting acceptConnections goroutine\n")
	// Start accepting connections
	go s.acceptConnections()

	fmt.Printf("[DEBUG] QUIC starting cleanupSessions goroutine\n")
	// Start session cleanup
	go s.cleanupSessions()

	s.logger.Info("QUIC server started successfully")
	return nil
}

// Stop stops the QUIC server.
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping QUIC server")

	s.cancel()

	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()

	if listener != nil {
		if err := listener.Close(); err != nil {
			s.logger.Warn("Error closing QUIC listener", "error", err)
		}
	}

	// Close all sessions
	s.mu.Lock()
	for sessionID, session := range s.sessions {
		s.logger.Info("Closing QUIC session", "session_id", sessionID, "steward_id", session.StewardID)
		if err := session.Connection.CloseWithError(0, "server shutdown"); err != nil {
			s.logger.Warn("Error closing session", "session_id", sessionID, "error", err)
		}
	}
	s.sessions = make(map[string]*Session)
	s.mu.Unlock()

	s.logger.Info("QUIC server stopped")
	return nil
}

// acceptConnections accepts incoming QUIC connections.
func (s *Server) acceptConnections() {
	fmt.Printf("[DEBUG] QUIC acceptConnections loop started\n")
	for {
		select {
		case <-s.ctx.Done():
			fmt.Printf("[DEBUG] QUIC acceptConnections context done\n")
			return
		default:
			// Get listener with proper locking to avoid race condition
			s.mu.Lock()
			listener := s.listener
			s.mu.Unlock()

			if listener == nil {
				fmt.Printf("[DEBUG] QUIC listener is nil, exiting acceptConnections\n")
				return
			}

			conn, err := listener.Accept(s.ctx)
			if err != nil {
				if s.ctx.Err() != nil {
					// Server is shutting down
					fmt.Printf("[DEBUG] QUIC server shutting down\n")
					return
				}
				s.logger.Error("Failed to accept QUIC connection", "error", err)
				fmt.Printf("[DEBUG] Failed to accept QUIC connection: %v\n", err)
				continue
			}

			// Handle connection in background
			fmt.Printf("[DEBUG] Accepted QUIC connection from: %v\n", conn.RemoteAddr())
			go s.handleConnection(conn)
		}
	}
}

// handleConnection handles a QUIC connection.
func (s *Server) handleConnection(conn *quic.Conn) {
	s.logger.Info("Accepted QUIC connection", "remote_addr", conn.RemoteAddr())
	fmt.Printf("[DEBUG] handleConnection started for: %v\n", conn.RemoteAddr())

	// Accept control stream (stream 0) for handshake
	stream, err := conn.AcceptStream(s.ctx)
	if err != nil {
		s.logger.Error("Failed to accept control stream", "error", err)
		fmt.Printf("[DEBUG] Failed to accept control stream: %v\n", err)
		_ = conn.CloseWithError(1, "handshake failed")
		return
	}

	fmt.Printf("[DEBUG] Accepted control stream, calling performHandshake\n")

	// Perform handshake to get session ID and steward ID
	sessionID, stewardID, err := s.performHandshake(stream)
	if err != nil {
		s.logger.Error("Handshake failed", "error", err.Error())
		fmt.Printf("[DEBUG] performHandshake returned error: %v\n", err)
		_ = conn.CloseWithError(1, "handshake failed")
		return
	}

	fmt.Printf("[DEBUG] Handshake succeeded: sessionID=%s stewardID=%s\n", sessionID, stewardID)

	s.logger.Info("QUIC handshake successful",
		"session_id", sessionID,
		"steward_id", stewardID,
		"remote_addr", conn.RemoteAddr())

	// Create session
	session := &Session{
		ID:         sessionID,
		StewardID:  stewardID,
		Connection: conn,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		Streams:    make(map[int64]*quic.Stream),
	}

	// Store session
	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	// Clean up session when connection closes
	defer func() {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		s.logger.Info("QUIC session closed", "session_id", sessionID, "steward_id", stewardID)
	}()

	// Accept and handle streams
	for {
		stream, err := conn.AcceptStream(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				// Server shutting down
				return
			}
			s.logger.Error("Failed to accept stream", "error", err, "session_id", sessionID)
			return
		}

		// Update last active time
		s.mu.Lock()
		session.LastActive = time.Now()
		s.mu.Unlock()

		// Handle stream in background
		go s.handleStream(session, stream)
	}
}

// performHandshake performs the QUIC handshake on the control stream.
func (s *Server) performHandshake(stream *quic.Stream) (string, string, error) {
	// Read handshake message
	// Format: "session_id:steward_id\n"
	buf := make([]byte, 256)
	n, err := stream.Read(buf)
	if err != nil {
		s.logger.Error("Failed to read handshake from stream", "error", err)
		return "", "", fmt.Errorf("failed to read handshake: %w", err)
	}

	handshake := string(buf[:n])
	s.logger.Info("Received QUIC handshake",
		"handshake", handshake,
		"bytes_read", n,
		"raw_bytes", fmt.Sprintf("%q", buf[:n]))

	fmt.Printf("[DEBUG] Handshake raw bytes: %q\n", buf[:n])
	fmt.Printf("[DEBUG] Handshake string: %q\n", handshake)
	fmt.Printf("[DEBUG] Handshake length: %d\n", len(handshake))

	// Parse handshake: "session_id:steward_id"
	// Trim whitespace and split on colon
	parts := strings.Split(strings.TrimSpace(handshake), ":")
	fmt.Printf("[DEBUG] Split result: parts=%v len=%d\n", parts, len(parts))

	if len(parts) != 2 {
		s.logger.Error("Failed to parse handshake format",
			"error", "expected format 'session_id:steward_id'",
			"handshake", handshake,
			"parts", parts)
		return "", "", fmt.Errorf("invalid handshake format: expected 'session_id:steward_id', got %d parts", len(parts))
	}

	sessionID := strings.TrimSpace(parts[0])
	stewardID := strings.TrimSpace(parts[1])
	fmt.Printf("[DEBUG] Parsed: sessionID=%q stewardID=%q\n", sessionID, stewardID)

	s.logger.Info("Parsed handshake successfully",
		"session_id", sessionID,
		"steward_id", stewardID)

	// Validate session if session manager is available
	if s.sessionManager == nil {
		s.logger.Warn("Session manager is nil, skipping validation")
	} else {
		s.logger.Info("Attempting session validation",
			"session_id", sessionID,
			"steward_id", stewardID)

		_, err := s.sessionManager.ValidateSession(sessionID, stewardID)
		if err != nil {
			// If session doesn't exist, auto-create an ephemeral session
			// This supports the on-demand nature of QUIC connections
			s.logger.Info("Session not found, auto-creating ephemeral session",
				"session_id", sessionID,
				"steward_id", stewardID)

			if err := s.sessionManager.CreateEphemeralSession(sessionID, stewardID, 5*time.Minute); err != nil {
				s.logger.Error("Failed to auto-create session",
					"session_id", sessionID,
					"steward_id", stewardID,
					"error", err)

				// Send error response
				response := fmt.Sprintf("ERROR: failed to create session: %s\n", err.Error())
				_, _ = stream.Write([]byte(response))
				return "", "", fmt.Errorf("session creation failed: %w", err)
			}

			s.logger.Info("Ephemeral session auto-created successfully",
				"session_id", sessionID,
				"steward_id", stewardID)
		} else {
			s.logger.Info("Session validated successfully",
				"session_id", sessionID,
				"steward_id", stewardID)
		}
	}

	// Send success response
	response := "OK\n"
	if _, err := stream.Write([]byte(response)); err != nil {
		return "", "", fmt.Errorf("failed to write handshake response: %w", err)
	}

	return sessionID, stewardID, nil
}

// handleStream handles a QUIC stream.
func (s *Server) handleStream(session *Session, stream *quic.Stream) {
	streamID := int64(stream.StreamID())

	fmt.Printf("[DEBUG] handleStream called: stream_id=%d session_id=%s steward_id=%s\n",
		streamID, session.ID, session.StewardID)
	s.logger.Debug("Handling stream",
		"stream_id", streamID,
		"session_id", session.ID,
		"steward_id", session.StewardID)

	// Store stream in session
	s.mu.Lock()
	session.Streams[streamID] = stream
	s.mu.Unlock()

	// Clean up stream when done
	defer func() {
		s.mu.Lock()
		delete(session.Streams, streamID)
		s.mu.Unlock()
		_ = stream.Close()
	}()

	// Get handler for this stream
	s.mu.RLock()
	handler, exists := s.streamHandlers[streamID]
	handlersCount := len(s.streamHandlers)
	s.mu.RUnlock()

	fmt.Printf("[DEBUG] Looking up handler: stream_id=%d exists=%v total_handlers=%d\n",
		streamID, exists, handlersCount)

	if !exists {
		fmt.Printf("[DEBUG] No handler found for stream_id=%d, discarding data\n", streamID)
		s.logger.Warn("No handler for stream", "stream_id", streamID)
		// Read and discard data
		_, _ = io.Copy(io.Discard, stream)
		return
	}

	fmt.Printf("[DEBUG] Calling handler for stream_id=%d\n", streamID)

	// Execute handler
	if err := handler(s.ctx, session, stream); err != nil {
		s.logger.Error("Stream handler failed",
			"stream_id", streamID,
			"session_id", session.ID,
			"error", err)
	}
}

// cleanupSessions periodically removes expired sessions.
func (s *Server) cleanupSessions() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for sessionID, session := range s.sessions {
				if now.Sub(session.LastActive) > s.sessionTimeout {
					s.logger.Info("Cleaning up expired session",
						"session_id", sessionID,
						"steward_id", session.StewardID,
						"last_active", session.LastActive)
					_ = session.Connection.CloseWithError(0, "session timeout")
					delete(s.sessions, sessionID)
				}
			}
			s.mu.Unlock()
		}
	}
}

// GetSession returns a session by ID.
func (s *Server) GetSession(sessionID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, exists := s.sessions[sessionID]
	return session, exists
}

// GetSessionBySteward returns a session by steward ID.
func (s *Server) GetSessionBySteward(stewardID string) (*Session, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if session.StewardID == stewardID {
			return session, true
		}
	}
	return nil, false
}

// GetActiveSessions returns all active sessions.
func (s *Server) GetActiveSessions() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()

	sessions := make([]*Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		sessions = append(sessions, session)
	}

	return sessions
}
