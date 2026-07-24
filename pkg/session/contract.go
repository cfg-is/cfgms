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
//
// Device-continuity fields (ADR-021 Decision 3, Issue #2788) are additive: they are
// zero-valued for sessions that predate this story and for sessions that have never
// undergone a strong-factor proof. Middleware reads Assurance from this struct rather
// than hardcoding AssuranceBasic so that upgrades (WebAuthn assertion — later story)
// and downgrades (IP change, proof expiry) are reflected on every request.
type Session struct {
	ID                string
	ConnectionName    string
	PrincipalID       string
	TenantID          string
	IssuedAt          time.Time
	LastActivity      time.Time
	AbsoluteExpiresAt time.Time

	// Assurance is the current identity assurance level. Set to AssuranceBasic for
	// newly issued sessions; upgraded to AssuranceStrong by a successful WebAuthn
	// assertion (later story); downgraded back to AssuranceBasic on IP change or
	// when the silent-proof interval has elapsed without a fresh proof.
	Assurance AssuranceLevel
	// CredentialID is the WebAuthn credential ID that established AssuranceStrong.
	// Nil/empty when no device-bound proof has been recorded for this session.
	CredentialID []byte
	// BoundIP is the source IP at the last successful strong-factor proof.
	// Empty until the first proof. IP-change detection compares the current request
	// IP against this value — not the IP at original session issuance.
	BoundIP string
	// LastProvenAt is the wall-clock time of the last successful strong-factor proof.
	// Zero until the first proof. Used to enforce the SilentReproofInterval cadence.
	LastProvenAt time.Time
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
	// SilentReproofInterval is the maximum duration AssuranceStrong can be held without
	// a fresh device proof. After this interval, the session is downgraded to
	// AssuranceBasic unless a valid WebAuthn assertion is provided (ADR-021 Decision 3,
	// "Remaining tunables"). Zero disables the interval check.
	SilentReproofInterval time.Duration
}

// DefaultConfig returns the ratified ADR-014 tunables: idle 15m, absolute 8h, grace 30s.
// SilentReproofInterval defaults to 5 minutes per ADR-021 "Remaining tunables" (PO-set).
// Tests lock these values so implementation stories cannot silently drift them.
func DefaultConfig() Config {
	return Config{
		IdleTimeout:           15 * time.Minute,
		AbsoluteTimeout:       8 * time.Hour,
		GraceWindow:           30 * time.Second,
		SilentReproofInterval: 5 * time.Minute,
	}
}

// sourceIPKeyType is unexported so no external package can construct a value of this type,
// preventing context-key aliasing across package boundaries (the standard Go opaque-key idiom).
type sourceIPKeyType struct{}

var sourceIPKey = sourceIPKeyType{}

// WithSourceIP returns a context carrying the client's source IP address.
// Called by the authentication middleware before Manager.Validate to enable
// IP-change detection (ADR-021 Decision 5, Issue #2788).
// Pass only the host portion — not "host:port".
func WithSourceIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, sourceIPKey, ip)
}

// SourceIPFromContext returns the source IP stored by WithSourceIP.
// Returns "" when no IP has been set (Validate skips IP-change detection in that case).
func SourceIPFromContext(ctx context.Context) string {
	if ip, ok := ctx.Value(sourceIPKey).(string); ok {
		return ip
	}
	return ""
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
//
// Elevate atomically upgrades an existing session to AssuranceStrong (ADR-021 Amendment 2,
// Issue #2965). It sets Assurance=Strong, BoundIP=sourceIP, CredentialID=credentialID,
// LastProvenAt=now, and rotates the session token — preserving the session ID and CSRF
// binding while invalidating a pre-elevation stolen cookie. The prior token stays valid for
// GraceWindow to let concurrent requests complete cleanly.
type Manager interface {
	Issue(ctx context.Context, principalID, connectionName, tenantID string) (*Session, string, error)
	Validate(ctx context.Context, token string) (*Session, error)
	Renew(ctx context.Context, token string) (*Session, string, error)
	Revoke(ctx context.Context, id string) error
	List(ctx context.Context) ([]*Session, error)
	Elevate(ctx context.Context, sessionID string, credentialID []byte, sourceIP string) (*Session, string, error)
}

// Store is the backing store for the session Manager (ADR-014 §2).
// The key for Set/Get is SHA-256(token) encoded as hex — the controller never persists
// the raw token. Delete removes by session ID.
//
// Implementations:
//   - pkg/session.MemStore — in-memory; sessions lost on restart (dev/test default).
//   - pkg/storage/providers/sqlite.SQLiteSessionTokenStore — SQLite; survives restarts
//     for single-node deployments (epic #2735, story #2736).
//   - pkg/storage/providers/database.DatabaseSessionTokenStore — Postgres; shared across
//     all controller nodes in cluster mode so a token issued on node A validates on node B
//     (epic #2735, story #2775). Selected automatically when cfg.HA.IsClusterMode() is true.
//
// Bootstrap wiring (store selection based on deployment mode) lives in
// features/controller/server.initializeSessionStore (stories #2774 and #2775).
type Store interface {
	Set(ctx context.Context, tokenHash string, session *Session) error
	Get(ctx context.Context, tokenHash string) (*Session, error)
	Delete(ctx context.Context, id string) error
	ListAll(ctx context.Context) ([]*Session, error)
}
