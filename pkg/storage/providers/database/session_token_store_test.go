// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// newTestSessionTokenStore creates a DatabaseSessionTokenStore against the test Postgres
// instance, skipping if it is not available.
func newTestSessionTokenStore(t *testing.T) *DatabaseSessionTokenStore {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}
	db := getTestDB(t) // skips if postgres not reachable
	// Drop and recreate the table so each test starts clean.
	ctx := context.Background()
	_, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS session_token_store")
	_ = db.Close()

	store, err := NewDatabaseSessionTokenStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestDatabaseSessionTokenStore_Set verifies basic Set/Get round-trip.
func TestDatabaseSessionTokenStore_Set(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, err := session.GenerateToken()
	require.NoError(t, err)
	hash := session.HashToken(tok)
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &session.Session{
		ID:                "set-test-id",
		PrincipalID:       "alice",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}

	require.NoError(t, store.Set(ctx, hash, sess))
	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, sess.PrincipalID, got.PrincipalID)
	assert.Equal(t, sess.TenantID, got.TenantID)
}

// TestDatabaseSessionTokenStore_GetMissReturnsNotFound confirms ErrSessionNotFound.
func TestDatabaseSessionTokenStore_GetMissReturnsNotFound(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "0000000000000000000000000000000000000000000000000000000000000000")
	assert.True(t, errors.Is(err, session.ErrSessionNotFound))
}

// TestDatabaseSessionTokenStore_DeleteRemovesAllHashes verifies all hashes for a
// session_id are deleted and ErrSessionNotFound is returned afterwards.
func TestDatabaseSessionTokenStore_DeleteRemovesAllHashes(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	t1, _ := session.GenerateToken()
	t2, _ := session.GenerateToken()
	h1, h2 := session.HashToken(t1), session.HashToken(t2)
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "del-test-id",
		PrincipalID:       "bob",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}

	require.NoError(t, store.Set(ctx, h1, sess))
	require.NoError(t, store.Set(ctx, h2, sess))
	require.NoError(t, store.Delete(ctx, sess.ID))

	_, err := store.Get(ctx, h1)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound), "h1 should be gone after Delete")
	_, err = store.Get(ctx, h2)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound), "h2 should be gone after Delete")
}

// TestDatabaseSessionTokenStore_DeleteIdempotent verifies double-Delete returns ErrSessionNotFound.
func TestDatabaseSessionTokenStore_DeleteIdempotent(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, _ := session.GenerateToken()
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "del-idem-id",
		PrincipalID:       "carol",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, session.HashToken(tok), sess))
	require.NoError(t, store.Delete(ctx, sess.ID))

	err := store.Delete(ctx, sess.ID)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound))
}

// TestDatabaseSessionTokenStore_StampGraceExpiry verifies that a grace-stamped hash
// is rejected after the expiry time passes.
func TestDatabaseSessionTokenStore_StampGraceExpiry(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, _ := session.GenerateToken()
	hash := session.HashToken(tok)
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "grace-test-id",
		PrincipalID:       "dave",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, hash, sess))

	// Stamp with a past expiry — the hash should be immediately unreachable.
	pastExpiry := now.Add(-time.Second)
	require.NoError(t, store.StampGraceExpiry(ctx, hash, pastExpiry))

	_, err := store.Get(ctx, hash)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound), "grace-expired hash must not be returned")
}

// TestDatabaseSessionTokenStore_ListAllDeduplicates verifies one result per session_id.
func TestDatabaseSessionTokenStore_ListAllDeduplicates(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	mkSess := func(id string) *session.Session {
		return &session.Session{
			ID:                id,
			PrincipalID:       "listuser",
			ConnectionName:    "ctrl",
			TenantID:          "tenant-1",
			IssuedAt:          now,
			LastActivity:      now,
			AbsoluteExpiresAt: now.Add(time.Hour),
		}
	}

	// s1: one hash.
	t1, _ := session.GenerateToken()
	s1 := mkSess("list-s1")
	require.NoError(t, store.Set(ctx, session.HashToken(t1), s1))

	// s2: two hashes (simulates current + grace slot from Renew).
	t2a, _ := session.GenerateToken()
	t2b, _ := session.GenerateToken()
	s2 := mkSess("list-s2")
	require.NoError(t, store.Set(ctx, session.HashToken(t2a), s2))
	require.NoError(t, store.Set(ctx, session.HashToken(t2b), s2))

	all, err := store.ListAll(ctx)
	require.NoError(t, err)
	counts := make(map[string]int)
	for _, s := range all {
		counts[s.ID]++
	}
	assert.Equal(t, 1, counts["list-s1"], "s1 should appear once")
	assert.Equal(t, 1, counts["list-s2"], "s2 should appear once (dedup)")
}

// TestDatabaseSessionTokenStore_NoRawToken verifies the raw token is never a valid key.
func TestDatabaseSessionTokenStore_NoRawToken(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, _ := session.GenerateToken()
	hash := session.HashToken(tok)
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "no-raw-id",
		PrincipalID:       "eve",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, hash, sess))

	// Raw token lookup must miss.
	_, err := store.Get(ctx, tok)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound), "raw token must not be a valid key")

	// Hash lookup must hit.
	_, err = store.Get(ctx, hash)
	assert.NoError(t, err)
}

// TestDatabaseSessionTokenStore_SetUpdatesExistingEntry verifies upsert semantics.
func TestDatabaseSessionTokenStore_SetUpdatesExistingEntry(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, _ := session.GenerateToken()
	hash := session.HashToken(tok)
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "update-test-id",
		PrincipalID:       "frank",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, hash, sess))

	updated := *sess
	updated.LastActivity = now.Add(5 * time.Minute)
	require.NoError(t, store.Set(ctx, hash, &updated))

	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.True(t, got.LastActivity.Equal(updated.LastActivity),
		"LastActivity should be updated; got %v want %v", got.LastActivity, updated.LastActivity)
}

// TestDatabaseSessionTokenStore_NoRawTokenInStoredRows performs a raw-SQL scan of
// every row to confirm neither the token value nor its base64 representation appears.
// This is the Postgres-backed analog of TestNoRawTokenInDurableStore from providers_test.go.
func TestDatabaseSessionTokenStore_NoRawTokenInStoredRows(t *testing.T) {
	store := newTestSessionTokenStore(t)
	cfg := session.DefaultConfig()
	ctx := context.Background()

	mgr := session.NewManager(cfg, store, time.Now)
	_, tok, err := mgr.Issue(ctx, "forensic-user", "ctrl", "tenant-1")
	require.NoError(t, err)

	// Query every column of every row for the raw token value.
	rows, err := store.db.QueryContext(ctx, `
		SELECT token_hash, session_id, principal_id, connection_name, tenant_id
		FROM session_token_store`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var tokenHash, sessionID, principalID, connectionName, tenantID string
		require.NoError(t, rows.Scan(&tokenHash, &sessionID, &principalID, &connectionName, &tenantID))

		assert.False(t, strings.Contains(tokenHash, tok), "raw token found in token_hash column")
		assert.False(t, strings.Contains(sessionID, tok), "raw token found in session_id column")
		assert.False(t, strings.Contains(principalID, tok), "raw token found in principal_id column")
		assert.False(t, strings.Contains(connectionName, tok), "raw token found in connection_name column")
		assert.False(t, strings.Contains(tenantID, tok), "raw token found in tenant_id column")

		// The stored token_hash must equal the expected SHA-256 hash.
		expected := session.HashToken(tok)
		assert.Equal(t, expected, tokenHash, "stored hash must be SHA-256(token)")
	}
	require.NoError(t, rows.Err())
}

// TestDatabaseProvider_CreateSessionTokenStore verifies the plugin factory constructs
// a working store from test config.
func TestDatabaseProvider_CreateSessionTokenStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}
	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	p := &DatabaseProvider{}
	store, err := p.CreateSessionTokenStore(getTestConfig())
	require.NoError(t, err)
	require.NotNil(t, store)
	defer func() { _ = store.Close() }()

	// Basic smoke test: round-trip a session.
	ctx := context.Background()
	tok, _ := session.GenerateToken()
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "factory-test",
		PrincipalID:       "smoke",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, store.Set(ctx, session.HashToken(tok), sess))
	got, err := store.Get(ctx, session.HashToken(tok))
	require.NoError(t, err)
	assert.Equal(t, "factory-test", got.ID)
}
