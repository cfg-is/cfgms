// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// managedSession tracks the rolling-token state for a single live session.
// mu serialises Renew calls so two concurrent prior-token requests cannot
// each trigger a rotation (compare-and-swap semantics without atomic ops).
type managedSession struct {
	mu          sync.Mutex
	session     *Session
	currentHash string
	prevHash    string    // non-empty during the GraceWindow following a Renew
	prevExpiry  time.Time // absolute time after which prevHash is rejected; zero when prevHash is ""
	revoked     bool
}

// manager implements Manager using a pluggable Store and an injectable clock.
type manager struct {
	cfg     Config
	store   Store
	clockFn func() time.Time

	mu       sync.RWMutex
	sessions map[string]*managedSession // key = session ID
	byHash   map[string]*managedSession // key = token hash (current or prev)
}

// NewManager creates a Manager that delegates persistence to store.
// Pass time.Now as clockFn in production; inject a fixed or advancing clock in tests.
func NewManager(cfg Config, store Store, clockFn func() time.Time) Manager {
	if clockFn == nil {
		clockFn = time.Now
	}
	return &manager{
		cfg:      cfg,
		store:    store,
		clockFn:  clockFn,
		sessions: make(map[string]*managedSession),
		byHash:   make(map[string]*managedSession),
	}
}

// Issue mints a new session for the given principal. It returns the live Session
// record and an opaque 43-char base64url bearer token. The controller stores only
// SHA-256(token); the raw token is returned once and never persisted.
func (m *manager) Issue(ctx context.Context, principalID, connectionName, tenantID string) (*Session, string, error) {
	token, err := GenerateToken()
	if err != nil {
		return nil, "", err
	}
	hash := HashToken(token)
	now := m.clockFn()
	sess := &Session{
		ID:                uuid.New().String(),
		PrincipalID:       principalID,
		ConnectionName:    connectionName,
		TenantID:          tenantID,
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(m.cfg.AbsoluteTimeout),
	}
	ms := &managedSession{
		session:     sess,
		currentHash: hash,
	}
	m.mu.Lock()
	m.sessions[sess.ID] = ms
	m.byHash[hash] = ms
	m.mu.Unlock()
	if err := m.store.Set(ctx, hash, sess); err != nil {
		m.mu.Lock()
		delete(m.sessions, sess.ID)
		delete(m.byHash, hash)
		m.mu.Unlock()
		return nil, "", err
	}
	out := *sess
	return &out, token, nil
}

// Validate authenticates the bearer token and returns the live session, updating
// LastActivity. It returns ErrSessionExpired or ErrSessionRevoked on failure.
// Prior-token grace entries (within GraceWindow after a Renew) are also accepted
// but do NOT update LastActivity (the renewed token owns the idle TTL).
func (m *manager) Validate(ctx context.Context, token string) (*Session, error) {
	hash := HashToken(token)
	m.mu.RLock()
	ms := m.byHash[hash]
	m.mu.RUnlock()
	if ms == nil {
		return nil, ErrSessionNotFound
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.revoked {
		return nil, ErrSessionRevoked
	}
	now := m.clockFn()
	if now.After(ms.session.AbsoluteExpiresAt) {
		return nil, ErrSessionExpired
	}
	if hash == ms.prevHash {
		// Prior-token path: only grace-window check; idle TTL is on the new token.
		if !ms.prevExpiry.IsZero() && now.After(ms.prevExpiry) {
			return nil, ErrSessionExpired
		}
	} else {
		// Current-token path: enforce idle TTL and bump LastActivity.
		if now.After(ms.session.LastActivity.Add(m.cfg.IdleTimeout)) {
			return nil, ErrSessionExpired
		}
		ms.session.LastActivity = now
		_ = m.store.Set(ctx, hash, ms.session) // best-effort sync; in-memory is authoritative
	}
	out := *ms.session
	return &out, nil
}

// Renew re-issues a fresh TTL'd token for an active session (rolling token model).
// If token is the current token a new token is generated, the current token moves
// to the grace slot, and the new token is returned. If token is already in the
// grace slot (concurrent prior-token request), no rotation occurs and the returned
// new-token string is empty — the caller should not overwrite any X-Session-Token
// header the client may have already received.
func (m *manager) Renew(ctx context.Context, token string) (*Session, string, error) {
	hash := HashToken(token)
	m.mu.RLock()
	ms := m.byHash[hash]
	m.mu.RUnlock()
	if ms == nil {
		return nil, "", ErrSessionNotFound
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.revoked {
		return nil, "", ErrSessionRevoked
	}
	now := m.clockFn()
	if now.After(ms.session.AbsoluteExpiresAt) {
		return nil, "", ErrSessionExpired
	}
	// Prior-token path: idempotent — don't double-rotate.
	if hash == ms.prevHash {
		if !ms.prevExpiry.IsZero() && now.After(ms.prevExpiry) {
			return nil, "", ErrSessionExpired
		}
		out := *ms.session
		return &out, "", nil
	}
	// Current-token path: check idle TTL.
	if now.After(ms.session.LastActivity.Add(m.cfg.IdleTimeout)) {
		return nil, "", ErrSessionExpired
	}
	// Rotate: generate a new token.
	newToken, err := GenerateToken()
	if err != nil {
		return nil, "", err
	}
	newHash := HashToken(newToken)
	ms.session.LastActivity = now
	// Evict the old grace entry (if any) from byHash before overwriting prevHash.
	if ms.prevHash != "" {
		m.mu.Lock()
		delete(m.byHash, ms.prevHash)
		m.mu.Unlock()
	}
	ms.prevHash = ms.currentHash
	ms.prevExpiry = now.Add(m.cfg.GraceWindow)
	ms.currentHash = newHash
	m.mu.Lock()
	m.byHash[newHash] = ms
	m.mu.Unlock()
	// Persist the new hash mapping.
	_ = m.store.Set(ctx, newHash, ms.session)
	out := *ms.session
	return &out, newToken, nil
}

// Revoke immediately invalidates the session identified by id. Subsequent Validate
// or Renew calls for any token belonging to this session return ErrSessionRevoked.
func (m *manager) Revoke(ctx context.Context, id string) error {
	m.mu.RLock()
	ms := m.sessions[id]
	m.mu.RUnlock()
	if ms == nil {
		return ErrSessionNotFound
	}
	ms.mu.Lock()
	ms.revoked = true
	ms.mu.Unlock()
	return m.store.Delete(ctx, id)
}
