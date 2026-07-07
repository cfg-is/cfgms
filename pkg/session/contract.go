// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package session defines the foundational contracts for cfg admin sessions
// (zero-standing-privilege model, ADR-014).
//
// This package is a Direct Provider (no interfaces/ subdirectory). Manager and Store
// are defined here; their implementations land in Story #4 of epic #2213.
package session

import (
	"context"
	"errors"
	"time"
)

// ErrNotAdmin is returned when the caller presents credentials that are not admin-level mTLS.
var ErrNotAdmin = errors.New("session: caller is not an admin principal")

// ErrSessionExpired is returned when the session has exceeded its idle or absolute timeout.
var ErrSessionExpired = errors.New("session: session has expired")

// ErrSessionRevoked is returned when the session has been explicitly revoked.
var ErrSessionRevoked = errors.New("session: session has been revoked")

// ErrSessionNotFound is returned when the requested session does not exist in the store.
var ErrSessionNotFound = errors.New("session: session not found")

// Session is the runtime record for a cfg admin session (ADR-014 §2).
// ID holds the opaque session identifier (not the bearer token; that is never stored).
// AbsoluteExpiresAt is measured from the original connect, capping even continuously-active sessions.
type Session struct {
	ID                string
	ConnectionName    string
	PrincipalID       string
	TenantID          string
	IssuedAt          time.Time
	LastActivity      time.Time
	AbsoluteExpiresAt time.Time
}

// Config holds the lifecycle tunables for cfg admin sessions (ADR-014 §3).
// Use DefaultConfig() to obtain the ratified defaults.
type Config struct {
	// IdleTimeout is the maximum idle gap before the session lapses.
	IdleTimeout time.Duration
	// AbsoluteTimeout is the hard cap measured from the original connect.
	AbsoluteTimeout time.Duration
	// GraceWindow is the time-only window during which the prior token remains valid
	// after a renewal (tolerates racing requests from a stateless CLI; see ADR-014 §3).
	GraceWindow time.Duration
}

// DefaultConfig returns the ratified ADR-014 tunables: idle 15m, absolute 8h, grace 30s.
// Tests lock these values so implementation stories cannot silently drift them.
func DefaultConfig() Config {
	return Config{
		IdleTimeout:     15 * time.Minute,
		AbsoluteTimeout: 8 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
}

// Manager is the runtime interface for cfg admin session lifecycle (ADR-014 §2).
// The implementation lives in Story #4 of epic #2213; this definition is the contract
// that all callers in this epic build against.
//
// Issue mints a new session for the given principal + connection (admin mTLS gated by
// the controller). It returns the Session record and an opaque bearer token (32 bytes from
// crypto/rand, base64url). The caller writes the token to the OS-native secret store via
// pkg/secrets/providers/oskeychain; the controller stores only SHA-256(token).
//
// Validate authenticates an incoming request token and returns the live Session, updating
// LastActivity. It returns ErrSessionExpired or ErrSessionRevoked on failure.
//
// Renew re-issues a fresh TTL'd token for an active session (rolling token model). The
// prior token remains valid for the GraceWindow after renewal.
//
// Revoke invalidates a session by ID. Accepts a valid session token or an admin mTLS cert
// so a client holding an expired token can still clean up server-side.
//
// List returns copies of all currently-live sessions across all tenants. A session is live
// if it is not revoked, not absolute-expired, and not idle-expired — the same three checks
// Validate applies. Tenant scoping is the caller's responsibility.
type Manager interface {
	Issue(ctx context.Context, principalID, connectionName, tenantID string) (*Session, string, error)
	Validate(ctx context.Context, token string) (*Session, error)
	Renew(ctx context.Context, token string) (*Session, string, error)
	Revoke(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Session, error)
}

// Store is the in-memory backing store for the session Manager (ADR-014 §2, v1).
// The key for Set/Get is SHA-256(token) encoded as hex — the controller never persists
// the raw token. Delete removes by session ID. A controller restart drops all sessions
// (re-auth required); durable/shared store is deferred to the SaaS cluster story (#2051).
//
// The implementation lives in Story #4 of epic #2213.
type Store interface {
	Set(ctx context.Context, tokenHash string, session *Session) error
	Get(ctx context.Context, tokenHash string) (*Session, error)
	Delete(ctx context.Context, id string) error
	ListAll(ctx context.Context) ([]*Session, error)
}
