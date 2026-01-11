// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package session provides QUIC session management for controller-steward connections.
//
// Session IDs are short-lived tokens that authenticate QUIC connections after initial
// MQTT registration. This prevents unauthorized QUIC connections while allowing the
// controller to trigger on-demand QUIC sessions for large data transfers.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Session represents a QUIC connection session.
type Session struct {
	// SessionID is the unique identifier for this session
	SessionID string

	// StewardID is the steward this session is for
	StewardID string

	// CreatedAt is when the session was created
	CreatedAt time.Time

	// ExpiresAt is when the session expires
	ExpiresAt time.Time

	// Used tracks if the session has been consumed
	Used bool

	// UsedAt is when the session was first used
	UsedAt *time.Time
}

// IsValid returns true if the session is valid for use.
func (s *Session) IsValid() bool {
	now := time.Now()

	// Check expiration
	if now.After(s.ExpiresAt) {
		return false
	}

	// Check if already used (single-use sessions)
	if s.Used {
		return false
	}

	return true
}

// Manager manages QUIC session IDs.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session // sessionID -> Session

	// Default session TTL
	sessionTTL time.Duration

	// Cleanup interval
	cleanupInterval time.Duration

	// Shutdown
	ctx    context.Context
	cancel context.CancelFunc
}

// Config holds session manager configuration.
type Config struct {
	// SessionTTL is how long sessions are valid (default: 30s)
	SessionTTL time.Duration

	// CleanupInterval is how often to clean expired sessions (default: 1m)
	CleanupInterval time.Duration
}

// NewManager creates a new session manager.
func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 30 * time.Second
	}

	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 1 * time.Minute
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		sessions:        make(map[string]*Session),
		sessionTTL:      cfg.SessionTTL,
		cleanupInterval: cfg.CleanupInterval,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start cleanup goroutine
	go m.cleanupLoop()

	return m
}

// GenerateSession creates a new session for a steward.
func (m *Manager) GenerateSession(stewardID string) (*Session, error) {
	if stewardID == "" {
		return nil, fmt.Errorf("steward ID is required")
	}

	// Generate session ID
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate session ID: %w", err)
	}

	now := time.Now()
	session := &Session{
		SessionID: sessionID,
		StewardID: stewardID,
		CreatedAt: now,
		ExpiresAt: now.Add(m.sessionTTL),
		Used:      false,
	}

	m.mu.Lock()
	m.sessions[sessionID] = session
	m.mu.Unlock()

	return session, nil
}

// ValidateSession validates a session ID and marks it as used.
func (m *Manager) ValidateSession(sessionID, stewardID string) (*Session, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("session ID is required")
	}

	if stewardID == "" {
		return nil, fmt.Errorf("steward ID is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check steward ID matches
	if session.StewardID != stewardID {
		return nil, fmt.Errorf("steward ID mismatch")
	}

	// Check validity
	if !session.IsValid() {
		return nil, fmt.Errorf("session expired or already used")
	}

	// Mark as used
	now := time.Now()
	session.Used = true
	session.UsedAt = &now

	return session, nil
}

// RevokeSession revokes a session.
func (m *Manager) RevokeSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, sessionID)
	return nil
}

// GetActiveSessionCount returns the number of active sessions.
func (m *Manager) GetActiveSessionCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	now := time.Now()

	for _, session := range m.sessions {
		if now.Before(session.ExpiresAt) && !session.Used {
			count++
		}
	}

	return count
}

// Stop stops the session manager.
func (m *Manager) Stop() {
	m.cancel()
}

// cleanupLoop periodically removes expired sessions.
func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanup()
		}
	}
}

// cleanup removes expired and used sessions.
func (m *Manager) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for sessionID, session := range m.sessions {
		// Remove if expired or used more than 1 minute ago
		if now.After(session.ExpiresAt) ||
			(session.Used && session.UsedAt != nil && now.Sub(*session.UsedAt) > time.Minute) {
			delete(m.sessions, sessionID)
		}
	}
}

// generateSessionID generates a cryptographically secure session ID.
func generateSessionID() (string, error) {
	const sessionIDLength = 16 // 16 bytes = 128 bits

	randomBytes := make([]byte, sessionIDLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", err
	}

	// Use base32 for URL-safe encoding
	encoded := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes))

	return "sess_" + encoded, nil
}
