// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
)

// mustGenerateToken generates a session token, failing the test if crypto/rand is unavailable.
func mustGenerateToken(t *testing.T) string {
	t.Helper()
	tok, err := session.GenerateToken()
	require.NoError(t, err)
	return tok
}

// newTestSessionTokenStore creates a DatabaseSessionTokenStore against the test Postgres
// instance, skipping if it is not available.
func newTestSessionTokenStore(t *testing.T) *DatabaseSessionTokenStore {
	t.Helper()
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}
	db := getTestDB(t) // skips if postgres not reachable
	t.Cleanup(func() { _ = db.Close() })
	// Drop and recreate the table so each test starts clean.
	ctx := context.Background()
	_, dropErr := db.ExecContext(ctx, "DROP TABLE IF EXISTS session_token_store")
	require.NoError(t, dropErr)

	store, err := NewDatabaseSessionTokenStore(db, getTestConfig())
	require.NoError(t, err)
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

	t1 := mustGenerateToken(t)
	t2 := mustGenerateToken(t)
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

	tok := mustGenerateToken(t)
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

	tok := mustGenerateToken(t)
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
	t1 := mustGenerateToken(t)
	s1 := mkSess("list-s1")
	require.NoError(t, store.Set(ctx, session.HashToken(t1), s1))

	// s2: two hashes (simulates current + grace slot from Renew).
	t2a := mustGenerateToken(t)
	t2b := mustGenerateToken(t)
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

	tok := mustGenerateToken(t)
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

	tok := mustGenerateToken(t)
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
	// Postgres TIMESTAMP WITH TIME ZONE columns store microsecond precision, so the
	// value Get() returns is rounded to microseconds; round the expectation the same
	// way rather than comparing against a nanosecond-precision time.Now() value that
	// the column can never represent exactly.
	updated.LastActivity = now.Add(5 * time.Minute).Round(time.Microsecond)
	require.NoError(t, store.Set(ctx, hash, &updated))

	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.True(t, got.LastActivity.Equal(updated.LastActivity),
		"LastActivity should be updated; got %v want %v", got.LastActivity, updated.LastActivity)
}

// TestRoundToStorablePrecision verifies the microsecond-quantization helper against the
// exact values from the Issue #3864 CI failure: Postgres returned 2026-09-03
// 01:42:51.117902 +0000 UTC for a value written as .117901613 (nanosecond precision) —
// i.e. Postgres rounds to the nearest microsecond rather than truncating.
func TestRoundToStorablePrecision(t *testing.T) {
	in := time.Date(2026, 9, 3, 1, 42, 51, 117901613, time.UTC)
	want := time.Date(2026, 9, 3, 1, 42, 51, 117902000, time.UTC)

	got := roundToStorablePrecision(in)
	assert.True(t, got.Equal(want), "got %v want %v", got, want)

	assert.True(t, roundToStorablePrecision(time.Time{}).IsZero(), "zero time must remain zero")

	// A value already at microsecond precision must round-trip unchanged.
	exact := time.Date(2026, 9, 3, 1, 42, 51, 117902000, time.UTC)
	assert.True(t, roundToStorablePrecision(exact).Equal(exact))
}

// TestComputeStorableSessionTimestamps verifies computeStorableSessionTimestamps
// rounds every write-path timestamp field to microsecond precision, purely in memory
// — no Postgres required. This is the revert-proof counterpart to the round-3
// acceptance-review finding on PR #3869: a round-trip through Postgres cannot
// distinguish "the write path rounds" from "it doesn't", because Postgres rounds
// TIMESTAMPTZ values to microsecond precision on write regardless of what the client
// sends (verified against a real Postgres instance: neutralizing
// roundToStorablePrecision to an identity function left every round-trip test still
// passing). Testing the pure computation directly, instead of through a round-trip,
// is the only way to detect a regression here.
func TestComputeStorableSessionTimestamps(t *testing.T) {
	issuedAt := time.Date(2026, 9, 3, 1, 42, 51, 117901613, time.UTC)
	lastActivity := time.Date(2026, 9, 3, 2, 0, 0, 500000500, time.UTC)
	absoluteExpiresAt := time.Date(2026, 9, 3, 9, 42, 51, 999999999, time.UTC)
	lastProvenAt := time.Date(2026, 9, 3, 1, 50, 0, 250000250, time.UTC)

	sess := &session.Session{
		IssuedAt:          issuedAt,
		LastActivity:      lastActivity,
		AbsoluteExpiresAt: absoluteExpiresAt,
		LastProvenAt:      lastProvenAt,
	}

	ts := computeStorableSessionTimestamps(sess)

	assert.True(t, ts.issuedAt.Equal(issuedAt.Round(time.Microsecond)),
		"issuedAt not rounded: got %v", ts.issuedAt)
	assert.True(t, ts.lastActivity.Equal(lastActivity.Round(time.Microsecond)),
		"lastActivity not rounded: got %v", ts.lastActivity)
	assert.True(t, ts.absoluteExpiresAt.Equal(absoluteExpiresAt.Round(time.Microsecond)),
		"absoluteExpiresAt not rounded: got %v", ts.absoluteExpiresAt)
	require.IsType(t, time.Time{}, ts.lastProvenAt)
	assert.True(t, ts.lastProvenAt.(time.Time).Equal(lastProvenAt.Round(time.Microsecond)),
		"lastProvenAt not rounded: got %v", ts.lastProvenAt)

	// None of the inputs happened to already sit on a microsecond boundary, so a
	// reverted (identity) implementation would leave these fields unequal to the
	// rounded expectation above — that is what makes this assertion revert-proof.
	assert.NotEqual(t, issuedAt, ts.issuedAt, "fixture must carry a sub-microsecond remainder")

	// sess itself must be untouched: computeStorableSessionTimestamps must not mutate
	// the caller's Session, since it may already be registered in session.Manager's
	// in-memory index — reachable by a concurrent reader/writer holding a different
	// lock — before Set's caller (manager.issue) gets a chance to guard it.
	assert.Equal(t, issuedAt, sess.IssuedAt, "sess.IssuedAt must not be mutated")
	assert.Equal(t, lastActivity, sess.LastActivity, "sess.LastActivity must not be mutated")
	assert.Equal(t, absoluteExpiresAt, sess.AbsoluteExpiresAt, "sess.AbsoluteExpiresAt must not be mutated")
	assert.Equal(t, lastProvenAt, sess.LastProvenAt, "sess.LastProvenAt must not be mutated")

	// A zero LastProvenAt (no strong-factor proof yet) must produce a nil param, not
	// the zero time rounded to some non-zero value.
	zeroSess := &session.Session{
		IssuedAt:          issuedAt,
		LastActivity:      lastActivity,
		AbsoluteExpiresAt: absoluteExpiresAt,
	}
	zeroTS := computeStorableSessionTimestamps(zeroSess)
	assert.Nil(t, zeroTS.lastProvenAt, "zero LastProvenAt must produce a nil SQL param")
}

// TestDatabaseSessionTokenStore_SetSurvivesNanosecondPrecisionInput exercises Set()
// with a raw, unrounded time.Now() (nanosecond precision) end to end against real
// Postgres, and confirms both that the write succeeds and that the caller's Session
// is left untouched by Set (see TestComputeStorableSessionTimestamps for the
// revert-proof assertion on the rounding logic itself, which a DB round-trip cannot
// provide since Postgres rounds on write regardless of client-side rounding).
func TestDatabaseSessionTokenStore_SetSurvivesNanosecondPrecisionInput(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok := mustGenerateToken(t)
	hash := session.HashToken(tok)
	// A raw time.Now() carries nanosecond precision that essentially never lands
	// exactly on a microsecond boundary — do not round it before calling Set.
	now := time.Now().UTC()
	issuedAt := now
	absoluteExpiresAt := now.Add(time.Hour)

	sess := &session.Session{
		ID:                "nanosecond-input-id",
		PrincipalID:       "grace",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          issuedAt,
		LastActivity:      issuedAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
	}

	require.NoError(t, store.Set(ctx, hash, sess))

	// Set must not mutate the caller's Session.
	assert.Equal(t, issuedAt, sess.IssuedAt, "sess.IssuedAt must not be mutated by Set")
	assert.Equal(t, issuedAt, sess.LastActivity, "sess.LastActivity must not be mutated by Set")
	assert.Equal(t, absoluteExpiresAt, sess.AbsoluteExpiresAt, "sess.AbsoluteExpiresAt must not be mutated by Set")

	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.True(t, got.IssuedAt.Equal(issuedAt.Round(time.Microsecond)),
		"got.IssuedAt: got %v want %v", got.IssuedAt, issuedAt.Round(time.Microsecond))
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

// legacySessionTokenStoreSchema is the session_token_store DDL from Issue #2775, before the
// four device-continuity columns (Issue #2788) were added. Used to simulate a pre-#2788
// deployment whose live table must be upgraded in place by BackfillSessionTokenStoreContinuity.
const legacySessionTokenStoreSchema = `
	CREATE TABLE session_token_store (
		token_hash          TEXT NOT NULL PRIMARY KEY,
		session_id          TEXT NOT NULL,
		principal_id        TEXT NOT NULL,
		connection_name     TEXT NOT NULL,
		tenant_id           TEXT NOT NULL,
		issued_at           TIMESTAMP WITH TIME ZONE NOT NULL,
		last_activity       TIMESTAMP WITH TIME ZONE NOT NULL,
		absolute_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		hash_expires_at     TIMESTAMP WITH TIME ZONE
	);`

// pgColumnExists reports whether the named column is present on session_token_store.
func pgColumnExists(ctx context.Context, t *testing.T, db *sql.DB, column string) bool {
	t.Helper()
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = 'session_token_store' AND column_name = $1
		)`, column).Scan(&exists)
	require.NoError(t, err)
	return exists
}

// TestBackfillSessionTokenStoreContinuity_UpgradePath exercises the true pre-#2788 upgrade
// scenario: a live session_token_store table created without the four continuity columns,
// carrying an existing human-session row. BackfillSessionTokenStoreContinuity must add all
// four columns, default the existing row to assurance=1 / empty bound_ip, leave the nullable
// columns NULL, and be safe to run a second time.
func TestBackfillSessionTokenStoreContinuity_UpgradePath(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}
	db := getTestDB(t) // skips if postgres not reachable
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	// Start from a clean slate, then create the legacy-shaped table.
	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS session_token_store")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS session_token_store") })

	_, err = db.ExecContext(ctx, legacySessionTokenStoreSchema)
	require.NoError(t, err, "create legacy session_token_store table")

	// Seed a pre-#2788 human-session row.
	_, err = db.ExecContext(ctx, `
		INSERT INTO session_token_store
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at)
		VALUES ('legacy-hash', 'legacy-sess', 'admin', 'ctrl', 'tenant-1',
			now(), now(), now() + interval '8 hours')`)
	require.NoError(t, err, "seed legacy row")

	continuityCols := []string{"assurance", "bound_ip", "last_proven_at", "credential_id"}
	for _, col := range continuityCols {
		assert.False(t, pgColumnExists(ctx, t, db, col), "pre-condition: %s absent before back-fill", col)
	}

	schemas := NewDatabaseSchemas()

	// First back-fill — must add all four columns.
	require.NoError(t, schemas.BackfillSessionTokenStoreContinuity(ctx, db), "first back-fill")
	for _, col := range continuityCols {
		assert.True(t, pgColumnExists(ctx, t, db, col), "%s present after back-fill", col)
	}

	// The pre-existing human-session row must default to assurance=1 / empty bound_ip,
	// with the nullable columns left NULL.
	var assurance int
	var boundIP string
	var lastProven, credentialID sql.NullString
	require.NoError(t, db.QueryRowContext(ctx, `
		SELECT assurance, bound_ip, last_proven_at, credential_id::text
		FROM session_token_store WHERE token_hash='legacy-hash'`).
		Scan(&assurance, &boundIP, &lastProven, &credentialID))
	assert.Equal(t, 1, assurance, "legacy row must default to assurance=1 (AssuranceBasic)")
	assert.Equal(t, "", boundIP, "legacy row must default to empty bound_ip")
	assert.False(t, lastProven.Valid, "legacy row last_proven_at must be NULL")
	assert.False(t, credentialID.Valid, "legacy row credential_id must be NULL")

	// Second back-fill must be a no-op and must not error (idempotency).
	require.NoError(t, schemas.BackfillSessionTokenStoreContinuity(ctx, db), "second back-fill (idempotency)")
	for _, col := range continuityCols {
		assert.True(t, pgColumnExists(ctx, t, db, col), "%s still present after second back-fill", col)
	}
	var count int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM session_token_store WHERE token_hash='legacy-hash'`).Scan(&count))
	assert.Equal(t, 1, count, "legacy row must survive the idempotent second back-fill")
}

// preChannelSessionTokenSchema is the DDL for session_token_store immediately before
// Issue #3310 added the channel column. Used to test the backfill upgrade path.
const preChannelSessionTokenSchema = `
	CREATE TABLE session_token_store (
		token_hash          TEXT NOT NULL PRIMARY KEY,
		session_id          TEXT NOT NULL,
		principal_id        TEXT NOT NULL,
		connection_name     TEXT NOT NULL,
		tenant_id           TEXT NOT NULL,
		issued_at           TIMESTAMP WITH TIME ZONE NOT NULL,
		last_activity       TIMESTAMP WITH TIME ZONE NOT NULL,
		absolute_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
		hash_expires_at     TIMESTAMP WITH TIME ZONE,
		assurance           INTEGER NOT NULL DEFAULT 1,
		bound_ip            TEXT    NOT NULL DEFAULT '',
		last_proven_at      TIMESTAMP WITH TIME ZONE,
		credential_id       BYTEA,
		root_scoped         BOOLEAN NOT NULL DEFAULT FALSE
	);`

// TestDatabaseSessionTokenStore_ChannelRoundTrip verifies that the channel field
// survives a Set → Get round-trip through Postgres (Issue #3310).
func TestDatabaseSessionTokenStore_ChannelRoundTrip(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok := mustGenerateToken(t)
	hash := session.HashToken(tok)
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &session.Session{
		ID:                "ch-rt-id",
		PrincipalID:       "alice",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		Assurance:         session.AssuranceBasic,
		Channel:           "cli",
	}

	require.NoError(t, store.Set(ctx, hash, sess))
	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, "cli", got.Channel, "channel must survive Set → Get")
}

// TestDatabaseSessionTokenStore_EmptyChannelRoundTrip verifies that an empty channel
// (simulating a back-filled legacy record) is stored and retrieved as an empty string,
// not coerced to any other value.
func TestDatabaseSessionTokenStore_EmptyChannelRoundTrip(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok := mustGenerateToken(t)
	hash := session.HashToken(tok)
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &session.Session{
		ID:                "empty-ch-id",
		PrincipalID:       "bob",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
		Assurance:         session.AssuranceBasic,
		Channel:           "",
	}

	require.NoError(t, store.Set(ctx, hash, sess))
	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, "", got.Channel, "empty channel must round-trip as empty string")
}

// TestDatabaseSessionTokenStore_GetByID verifies that GetByID returns a session record
// by session ID rather than token hash (Issue #3310).
func TestDatabaseSessionTokenStore_GetByID(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok := mustGenerateToken(t)
	hash := session.HashToken(tok)
	now := time.Now().UTC().Truncate(time.Millisecond)
	sess := &session.Session{
		ID:                "get-by-id-pg",
		PrincipalID:       "carol",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
		Assurance:         session.AssuranceBasic,
		Channel:           "web",
	}
	require.NoError(t, store.Set(ctx, hash, sess))

	got, err := store.GetByID(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, "web", got.Channel)
}

// TestDatabaseSessionTokenStore_GetByIDMissingReturnsNotFound verifies GetByID returns
// ErrSessionNotFound for an unknown session ID.
func TestDatabaseSessionTokenStore_GetByIDMissingReturnsNotFound(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	_, err := store.GetByID(ctx, "no-such-session-pg")
	assert.True(t, errors.Is(err, session.ErrSessionNotFound))
}

// TestDatabaseSessionTokenStore_GetByIDAfterDeleteReturnsNotFound verifies GetByID
// returns ErrSessionNotFound after the session has been deleted.
func TestDatabaseSessionTokenStore_GetByIDAfterDeleteReturnsNotFound(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok := mustGenerateToken(t)
	now := time.Now().UTC()
	sess := &session.Session{
		ID:                "del-get-by-id-pg",
		PrincipalID:       "dave",
		ConnectionName:    "ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(time.Hour),
		Channel:           "cli",
	}
	require.NoError(t, store.Set(ctx, session.HashToken(tok), sess))
	require.NoError(t, store.Delete(ctx, sess.ID))

	_, err := store.GetByID(ctx, sess.ID)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound))
}

// TestDatabaseSessionTokenStore_ChannelInListAll verifies that the channel field is
// returned correctly by ListAll, allowing manager.List to filter by channel after restart.
func TestDatabaseSessionTokenStore_ChannelInListAll(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	mkSess := func(id, channel string) *session.Session {
		return &session.Session{
			ID:                id,
			PrincipalID:       "listuser",
			ConnectionName:    "ctrl",
			TenantID:          "tenant-1",
			IssuedAt:          now,
			LastActivity:      now,
			AbsoluteExpiresAt: now.Add(time.Hour),
			Assurance:         session.AssuranceBasic,
			Channel:           channel,
		}
	}

	cliTok := mustGenerateToken(t)
	webTok := mustGenerateToken(t)
	require.NoError(t, store.Set(ctx, session.HashToken(cliTok), mkSess("ch-list-cli", "cli")))
	require.NoError(t, store.Set(ctx, session.HashToken(webTok), mkSess("ch-list-web", "web")))

	all, err := store.ListAll(ctx)
	require.NoError(t, err)

	channels := make(map[string]string)
	for _, s := range all {
		channels[s.ID] = s.Channel
	}
	assert.Equal(t, "cli", channels["ch-list-cli"], "CLI session must have channel=cli in ListAll")
	assert.Equal(t, "web", channels["ch-list-web"], "web session must have channel=web in ListAll")
}

// TestBackfillAddsChannelColumn verifies the channel column upgrade path: a live
// session_token_store table without the channel column is upgraded in place by
// BackfillSessionTokenStoreContinuity, and the idempotent re-run is safe (Issue #3310).
func TestBackfillAddsChannelColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database tests in short mode")
	}
	db := getTestDB(t)
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	_, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS session_token_store")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = db.ExecContext(ctx, "DROP TABLE IF EXISTS session_token_store") })

	// Create the pre-#3310 schema (no channel column).
	_, err = db.ExecContext(ctx, preChannelSessionTokenSchema)
	require.NoError(t, err, "create pre-channel session_token_store")

	// Seed a row with the pre-channel schema to verify the existing row survives.
	_, err = db.ExecContext(ctx, `
		INSERT INTO session_token_store
			(token_hash, session_id, principal_id, connection_name, tenant_id,
			 issued_at, last_activity, absolute_expires_at, assurance, bound_ip)
		VALUES ('pre-ch-hash', 'pre-ch-sess', 'admin', 'ctrl', 'tenant-1',
			now(), now(), now() + interval '8 hours', 1, '')`)
	require.NoError(t, err, "seed pre-channel row")

	assert.False(t, pgColumnExists(ctx, t, db, "channel"),
		"pre-condition: channel absent before back-fill")

	schemas := NewDatabaseSchemas()

	// First back-fill must add the channel column.
	require.NoError(t, schemas.BackfillSessionTokenStoreContinuity(ctx, db), "first back-fill")
	assert.True(t, pgColumnExists(ctx, t, db, "channel"),
		"channel column must be present after back-fill")

	// Existing row must default to empty string for channel.
	var channel string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT channel FROM session_token_store WHERE token_hash='pre-ch-hash'`).Scan(&channel))
	assert.Equal(t, "", channel, "legacy row must default to empty channel after back-fill")

	// Second back-fill must be idempotent and error-free.
	require.NoError(t, schemas.BackfillSessionTokenStoreContinuity(ctx, db), "second back-fill (idempotency)")
	assert.True(t, pgColumnExists(ctx, t, db, "channel"),
		"channel still present after second back-fill")
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
	tok := mustGenerateToken(t)
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
