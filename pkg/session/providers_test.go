// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package session_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newSQLiteSessionStore creates a file-backed SQLite session token store for testing.
// Each call gets an isolated database in t.TempDir().
func newSQLiteSessionStore(t *testing.T) session.Store {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateSessionTokenStore(map[string]interface{}{"path": filepath.Join(dir, "sessions.db")})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestStoreContract_SQLite runs the shared contract suite against the SQLite-backed store.
func TestStoreContract_SQLite(t *testing.T) {
	RunStoreContractSuite(t, newSQLiteSessionStore(t))
}

// TestManagerSurvivesRestartViaDurableStore verifies that sessions issued by one manager
// instance remain valid for a fresh manager instance that shares the same durable store.
// This simulates a controller restart: the first manager is discarded but the store persists.
func TestManagerSurvivesRestartViaDurableStore(t *testing.T) {
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	dbPath := filepath.Join(dir, "sessions.db")
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	ctx := context.Background()

	// --- "Before restart": first manager issues a session ---
	store1, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store1): %v", err)
	}
	mgr1 := session.NewManager(cfg, store1, time.Now)
	_, token, err := mgr1.Issue(ctx, "alice", "ctrl", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := mgr1.Validate(ctx, token); err != nil {
		t.Fatalf("Validate on mgr1: %v", err)
	}
	_ = store1.Close()

	// --- "After restart": second manager with the SAME store file ---
	store2, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store2): %v", err)
	}
	defer func() { _ = store2.Close() }()
	mgr2 := session.NewManager(cfg, store2, time.Now)

	// The token issued by mgr1 must still be valid on mgr2.
	got, err := mgr2.Validate(ctx, token)
	if err != nil {
		t.Fatalf("Validate on mgr2 after restart: %v (session not found in durable store)", err)
	}
	if got.PrincipalID != "alice" {
		t.Errorf("PrincipalID: got %q, want %q", got.PrincipalID, "alice")
	}
}

// TestRevocationPropagatesAcrossManagers verifies that revoking a session on one manager
// makes the session invalid on a second manager sharing the same durable store.
// This simulates cross-node revocation: node A revokes, node B detects it on next Validate.
func TestRevocationPropagatesAcrossManagers(t *testing.T) {
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	dbPath := filepath.Join(dir, "sessions.db")
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	ctx := context.Background()

	// Both "nodes" share the same SQLite file.
	storeA, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore A: %v", err)
	}
	defer func() { _ = storeA.Close() }()

	storeB, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore B: %v", err)
	}
	defer func() { _ = storeB.Close() }()

	mgrA := session.NewManager(cfg, storeA, time.Now)
	mgrB := session.NewManager(cfg, storeB, time.Now)

	// Node A issues a session.
	sess, token, err := mgrA.Issue(ctx, "bob", "ctrl", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Node B can validate it (cache miss → durable store lookup).
	if _, err := mgrB.Validate(ctx, token); err != nil {
		t.Fatalf("Validate on mgrB before revocation: %v", err)
	}

	// Node A revokes the session — this deletes all token hashes from the shared store.
	if err := mgrA.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Revoke on mgrA: %v", err)
	}

	// Node B must now reject the token (the store record was deleted by mgrA's Revoke).
	_, err = mgrB.Validate(ctx, token)
	if err == nil {
		t.Fatal("Validate on mgrB after cross-node revocation: expected error, got nil")
	}
	if !errors.Is(err, session.ErrSessionRevoked) && !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("Validate on mgrB after revocation: got %v, want ErrSessionRevoked or ErrSessionNotFound", err)
	}
}

// TestManagerSurvivesRestartAfterRenew verifies that the NEW token produced by Renew
// is persisted in the durable store and survives a controller restart.
func TestManagerSurvivesRestartAfterRenew(t *testing.T) {
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	dbPath := filepath.Join(dir, "sessions.db")
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	ctx := context.Background()

	// Issue and immediately renew on the first manager.
	store1, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store1): %v", err)
	}
	mgr1 := session.NewManager(cfg, store1, time.Now)
	_, oldToken, err := mgr1.Issue(ctx, "alice", "ctrl", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, newToken, err := mgr1.Renew(ctx, oldToken)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	_ = store1.Close()

	// After restart: second manager with the same db file must accept the new token.
	store2, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store2): %v", err)
	}
	defer func() { _ = store2.Close() }()
	mgr2 := session.NewManager(cfg, store2, time.Now)

	got, err := mgr2.Validate(ctx, newToken)
	if err != nil {
		t.Fatalf("Validate new token on mgr2 after restart: %v", err)
	}
	if got.PrincipalID != "alice" {
		t.Errorf("PrincipalID: got %q, want %q", got.PrincipalID, "alice")
	}
}

// TestGraceExpiryHonouredAcrossNodes verifies that a rotated-away token hash is rejected
// on a sibling node once its grace window elapses. This is the cross-node analogue of the
// in-memory ms.prevExpiry check — enforced via the hash_expires_at column in the store.
func TestGraceExpiryHonouredAcrossNodes(t *testing.T) {
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	dbPath := filepath.Join(dir, "sessions.db")
	// Use a very short GraceWindow so we can expire it with a short sleep.
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     10 * time.Millisecond,
	}
	ctx := context.Background()

	storeA, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore A: %v", err)
	}
	defer func() { _ = storeA.Close() }()

	storeB, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore B: %v", err)
	}
	defer func() { _ = storeB.Close() }()

	mgrA := session.NewManager(cfg, storeA, time.Now)
	mgrB := session.NewManager(cfg, storeB, time.Now)

	// Node A: issue → renew; oldToken is rotated away into grace.
	_, oldToken, err := mgrA.Issue(ctx, "dave", "ctrl", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_, newToken, err := mgrA.Renew(ctx, oldToken)
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}

	// Wait for the grace window to expire.
	time.Sleep(30 * time.Millisecond)

	// Node B: new token is always valid.
	if _, err := mgrB.Validate(ctx, newToken); err != nil {
		t.Errorf("Validate new token on mgrB: %v", err)
	}
	// Node B: old token's hash_expires_at has passed → must be rejected.
	_, err = mgrB.Validate(ctx, oldToken)
	if err == nil {
		t.Error("Validate old (grace-expired) token on mgrB: expected error, got nil")
	}
}

// TestRevokeAfterRestartViaDurableStore verifies that Revoke works post-restart even when
// the session is not in the revoking node's in-memory index (store-fallback path).
func TestRevokeAfterRestartViaDurableStore(t *testing.T) {
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	dbPath := filepath.Join(dir, "sessions.db")
	cfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
	}
	ctx := context.Background()

	// Issue on the first manager.
	store1, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store1): %v", err)
	}
	mgr1 := session.NewManager(cfg, store1, time.Now)
	sess, token, err := mgr1.Issue(ctx, "eve", "ctrl", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_ = store1.Close()

	// After restart: mgr2 has an empty in-memory index.
	store2, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store2): %v", err)
	}
	defer func() { _ = store2.Close() }()
	mgr2 := session.NewManager(cfg, store2, time.Now)

	// Revoke on mgr2 must succeed via the store fallback path.
	if err := mgr2.Revoke(ctx, sess.ID); err != nil {
		t.Fatalf("Revoke on mgr2 after restart: %v", err)
	}

	// Token is now gone from the store — Validate on a third fresh manager must reject it.
	store3, err := p.CreateSessionTokenStore(map[string]interface{}{"path": dbPath})
	if err != nil {
		t.Fatalf("CreateSessionTokenStore (store3): %v", err)
	}
	defer func() { _ = store3.Close() }()
	mgr3 := session.NewManager(cfg, store3, time.Now)

	_, err = mgr3.Validate(ctx, token)
	if err == nil {
		t.Error("Validate after post-restart Revoke: expected error, got nil")
	}
}

// TestNoRawTokenInDurableStore verifies that the SQLite-backed store never persists
// the raw bearer token — only SHA-256(token) hex.
func TestNoRawTokenInDurableStore(t *testing.T) {
	store := newSQLiteSessionStore(t)
	cfg := session.DefaultConfig()
	ctx := context.Background()

	mgr := session.NewManager(cfg, store, time.Now)
	_, token, err := mgr.Issue(ctx, "carol", "ctrl", "tenant-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Raw token lookup must miss — the store key is SHA-256(token), not the token itself.
	_, err = store.Get(ctx, token)
	if !errors.Is(err, session.ErrSessionNotFound) {
		t.Errorf("raw-token lookup in durable store: got %v, want ErrSessionNotFound", err)
	}

	// Hash lookup must hit.
	hash := session.HashToken(token)
	if _, err := store.Get(ctx, hash); err != nil {
		t.Errorf("hash lookup in durable store: got %v, want nil", err)
	}
}
