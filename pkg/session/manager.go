// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session

import (
	"context"
	"errors"
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

// graceStamper is optionally implemented by stores that can record a per-hash expiry
// so that prior-token grace slots are bounded on cluster nodes and after restarts.
// MemStore omits this since it manages grace in-memory; SQLiteSessionTokenStore implements it.
type graceStamper interface {
	StampGraceExpiry(ctx context.Context, tokenHash string, expiresAt time.Time) error
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
		// All Manager-issued sessions are human sessions. Assurance starts at Basic;
		// it is upgraded to Strong by a successful WebAuthn assertion (later story).
		Assurance: AssuranceBasic,
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

// loadFromStore attempts to load a session from the durable store on in-memory cache miss.
// This supports sessions that survived a controller restart or were issued by another node.
// After loading, the session is registered in the in-memory index so subsequent calls are fast.
// Returns nil when the session is not found in or was deleted from the store.
func (m *manager) loadFromStore(ctx context.Context, hash string) *managedSession {
	sess, err := m.store.Get(ctx, hash)
	if err != nil {
		return nil // not found, revoked, or store error — treat as absent
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// Double-check: another goroutine may have registered this hash while we were in the store.
	if existing, ok := m.byHash[hash]; ok {
		return existing
	}
	// If a managedSession for this session ID already exists (e.g., loaded via another hash
	// such as the grace-window token), reuse it to keep revocation state consistent.
	if existing, ok := m.sessions[sess.ID]; ok {
		m.byHash[hash] = existing
		return existing
	}
	// First time loading this session: create a new managedSession from store data.
	// After a restart, any prior-token grace window has long expired (restart > 30s grace),
	// so we treat the loaded hash as the current token.
	ms := &managedSession{
		session:     sess,
		currentHash: hash,
	}
	m.byHash[hash] = ms
	m.sessions[sess.ID] = ms
	return ms
}

// Validate authenticates the bearer token and returns the live session, updating
// LastActivity. It returns ErrSessionExpired or ErrSessionRevoked on failure.
// Prior-token grace entries (within GraceWindow after a Renew) are also accepted
// but do NOT update LastActivity (the renewed token owns the idle TTL).
//
// Validate falls back to the durable store on cache miss (supporting restart survival
// and cross-node validation) and verifies the store record on every call so that a
// revocation issued on another node propagates immediately.
func (m *manager) Validate(ctx context.Context, token string) (*Session, error) {
	hash := HashToken(token)
	m.mu.RLock()
	ms := m.byHash[hash]
	m.mu.RUnlock()
	if ms == nil {
		ms = m.loadFromStore(ctx, hash)
	}
	if ms == nil {
		return nil, ErrSessionNotFound
	}
	ms.mu.Lock()
	defer ms.mu.Unlock()
	if ms.revoked {
		return nil, ErrSessionRevoked
	}
	// Cross-node revocation: verify the store still holds this token hash.
	// Another node's Revoke deletes all hashes for the session from the store;
	// a Get miss here means the session was revoked remotely.
	if _, storeErr := m.store.Get(ctx, hash); storeErr != nil {
		if errors.Is(storeErr, ErrSessionNotFound) || errors.Is(storeErr, ErrSessionRevoked) {
			ms.revoked = true
			return nil, ErrSessionRevoked
		}
		// Non-fatal store errors: proceed with in-memory state (best-effort).
	}
	now := m.clockFn()
	if now.After(ms.session.AbsoluteExpiresAt) {
		return nil, ErrSessionExpired
	}
	needsSync := false
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
		needsSync = true
	}

	// Device-continuity check (ADR-021 Decision 3/5, Issue #2788).
	// Only AssuranceStrong sessions have continuity state to lose; AssuranceBasic
	// sessions are never downgraded further by this logic.
	if ms.session.Assurance == AssuranceStrong {
		currentIP := SourceIPFromContext(ctx)
		downgrade := false

		// Decision 5: a source-IP change is an immediate downgrade — never hard-lock.
		// Compare against BoundIP (last proof), not session issuance IP.
		if currentIP != "" && ms.session.BoundIP != "" && currentIP != ms.session.BoundIP {
			downgrade = true
		}

		// Re-proof cadence: if LastProvenAt is set and the silent-proof interval has
		// elapsed, attempt silent re-proof. Since no WebAuthn assertion is present in
		// this Validate call (the assertion path is a later story), the "attempt"
		// always falls back to AssuranceBasic. When CredentialID is nil, proof is
		// structurally impossible regardless of the timer.
		if !downgrade && m.cfg.SilentReproofInterval > 0 && !ms.session.LastProvenAt.IsZero() {
			if now.Sub(ms.session.LastProvenAt) > m.cfg.SilentReproofInterval {
				downgrade = true
			}
		}

		if downgrade {
			ms.session.Assurance = AssuranceBasic
			ms.session.LastProvenAt = time.Time{}
			needsSync = true
		}
	}

	if needsSync {
		// best-effort sync to durable store (persists LastActivity and/or downgrade)
		_ = m.store.Set(ctx, hash, ms.session)
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
//
// Renew falls back to the durable store on cache miss (supporting restart survival
// and cross-node renewal).
func (m *manager) Renew(ctx context.Context, token string) (*Session, string, error) {
	hash := HashToken(token)
	m.mu.RLock()
	ms := m.byHash[hash]
	m.mu.RUnlock()
	if ms == nil {
		ms = m.loadFromStore(ctx, hash)
	}
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
	// best-effort sync of the new token to the durable store
	_ = m.store.Set(ctx, newHash, ms.session)
	// Bound the prior token's validity in the durable store so that cross-node and
	// post-restart lookups of the rotated-away hash are rejected once the grace window elapses.
	if gs, ok := m.store.(graceStamper); ok {
		_ = gs.StampGraceExpiry(ctx, ms.prevHash, ms.prevExpiry)
	}
	out := *ms.session
	return &out, newToken, nil
}

// List returns copies of all currently-live sessions. A session is live if it is not
// revoked, not absolute-expired, and not idle-expired — the same three checks Validate
// applies. Tenant scoping is the caller's responsibility. Results are copies so callers
// cannot mutate manager-internal state through the returned pointers.
//
// When the in-memory session map is empty (e.g., immediately after a controller restart),
// List falls back to the durable store so the admin session listing survives restarts.
func (m *manager) List(ctx context.Context) ([]*Session, error) {
	now := m.clockFn()
	// Snapshot the managedSession pointers under m.mu, then release m.mu BEFORE
	// acquiring any per-session ms.mu. Holding m.mu while taking ms.mu would invert
	// the lock order used by Renew (ms.mu then m.mu), producing an ABBA deadlock
	// under concurrent List/Renew on the same session.
	m.mu.RLock()
	snapshot := make([]*managedSession, 0, len(m.sessions))
	for _, ms := range m.sessions {
		snapshot = append(snapshot, ms)
	}
	hasInMemory := len(m.sessions) > 0
	m.mu.RUnlock()

	seen := make(map[string]struct{}, len(snapshot))
	out := make([]*Session, 0, len(snapshot))
	for _, ms := range snapshot {
		ms.mu.Lock()
		live := !ms.revoked &&
			now.Before(ms.session.AbsoluteExpiresAt) &&
			now.Before(ms.session.LastActivity.Add(m.cfg.IdleTimeout))
		var copy *Session
		if live {
			c := *ms.session
			copy = &c
		}
		ms.mu.Unlock()
		if copy != nil {
			seen[copy.ID] = struct{}{}
			out = append(out, copy)
		}
	}

	// After a restart the in-memory map is empty; fall back to the durable store
	// so that existing sessions are visible before their owners re-validate.
	if !hasInMemory {
		stored, err := m.store.ListAll(ctx)
		if err == nil {
			for _, sess := range stored {
				if _, dup := seen[sess.ID]; dup {
					continue
				}
				live := now.Before(sess.AbsoluteExpiresAt) &&
					now.Before(sess.LastActivity.Add(m.cfg.IdleTimeout))
				if live {
					seen[sess.ID] = struct{}{}
					c := *sess
					out = append(out, &c)
				}
			}
		}
	}

	return out, nil
}

// Revoke immediately invalidates the session identified by id. Subsequent Validate
// or Renew calls for any token belonging to this session return ErrSessionRevoked.
// Revoke deletes all token-hash records from the durable store so revocation is
// visible to other nodes that share the store: the Validate store-check detects
// the missing record and returns ErrSessionRevoked on any node's next request.
//
// After a controller restart the in-memory index is empty; Revoke falls back to the
// durable store so administrative revocation works before any Validate re-populates
// the cache. Returns ErrSessionNotFound when the session is in neither the cache nor
// the store.
func (m *manager) Revoke(ctx context.Context, id string) error {
	m.mu.RLock()
	ms := m.sessions[id]
	m.mu.RUnlock()
	if ms == nil {
		// Cache miss — attempt the durable store delete (post-restart support).
		// store.Delete returns ErrSessionNotFound when the session has no records.
		return m.store.Delete(ctx, id)
	}
	ms.mu.Lock()
	ms.revoked = true
	ms.mu.Unlock()
	// Ignore ErrSessionNotFound: another node may have already deleted the records.
	if err := m.store.Delete(ctx, id); err != nil && !errors.Is(err, ErrSessionNotFound) {
		return err
	}
	return nil
}
