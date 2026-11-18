// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/session"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTestSessionTokenStore opens a fresh SQLite-backed session token store in a temp dir.
func newTestSessionTokenStore(t *testing.T) *sqlite.SQLiteSessionTokenStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateSessionTokenStore(map[string]interface{}{
		"path": filepath.Join(dir, "session_tokens.db"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// makeTokenSession returns a session with the given channel, ready for store insertion.
func makeTokenSession(id, channel string) *session.Session {
	now := time.Now().UTC().Truncate(time.Second)
	return &session.Session{
		ID:                id,
		PrincipalID:       "test-principal",
		ConnectionName:    "test-ctrl",
		TenantID:          "tenant-1",
		IssuedAt:          now,
		LastActivity:      now,
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
		Assurance:         session.AssuranceBasic,
		Channel:           channel,
	}
}

// TestSQLiteSessionTokenStore_ChannelRoundTrip verifies that the channel field
// survives a Set → Get round-trip through SQLite (Issue #3310).
func TestSQLiteSessionTokenStore_ChannelRoundTrip(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, err := session.GenerateToken()
	require.NoError(t, err)
	hash := session.HashToken(tok)

	sess := makeTokenSession("ch-roundtrip-id", "cli")
	require.NoError(t, store.Set(ctx, hash, sess))

	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, "cli", got.Channel, "channel must survive Set → Get")
}

// TestSQLiteSessionTokenStore_EmptyChannelRoundTrip verifies that an empty channel
// (simulating a back-filled record) is stored and retrieved as an empty string,
// not coerced to any other value.
func TestSQLiteSessionTokenStore_EmptyChannelRoundTrip(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, err := session.GenerateToken()
	require.NoError(t, err)
	hash := session.HashToken(tok)

	sess := makeTokenSession("empty-ch-id", "")
	require.NoError(t, store.Set(ctx, hash, sess))

	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.Equal(t, "", got.Channel, "empty channel must round-trip as empty, not be grandfathered")
}

// TestSQLiteSessionTokenStore_GetByID verifies that GetByID returns a session record by
// session ID rather than token hash (Issue #3310).
func TestSQLiteSessionTokenStore_GetByID(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, err := session.GenerateToken()
	require.NoError(t, err)
	hash := session.HashToken(tok)

	sess := makeTokenSession("get-by-id-sess", "cli")
	require.NoError(t, store.Set(ctx, hash, sess))

	got, err := store.GetByID(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, sess.ID, got.ID)
	assert.Equal(t, "cli", got.Channel)
}

// TestSQLiteSessionTokenStore_GetByIDMissingReturnsNotFound verifies GetByID returns
// ErrSessionNotFound for an unknown session ID.
func TestSQLiteSessionTokenStore_GetByIDMissingReturnsNotFound(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	_, err := store.GetByID(ctx, "no-such-session-id")
	assert.True(t, errors.Is(err, session.ErrSessionNotFound))
}

// TestSQLiteSessionTokenStore_GetByIDAfterDeleteReturnsNotFound verifies GetByID
// returns ErrSessionNotFound after the session has been deleted.
func TestSQLiteSessionTokenStore_GetByIDAfterDeleteReturnsNotFound(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	tok, err := session.GenerateToken()
	require.NoError(t, err)
	sess := makeTokenSession("del-get-by-id", "web")
	require.NoError(t, store.Set(ctx, session.HashToken(tok), sess))
	require.NoError(t, store.Delete(ctx, sess.ID))

	_, err = store.GetByID(ctx, sess.ID)
	assert.True(t, errors.Is(err, session.ErrSessionNotFound))
}

// TestSQLiteSessionTokenStore_ChannelInListAll verifies that the channel field is
// returned correctly by ListAll, so manager.List can filter by channel after a restart.
func TestSQLiteSessionTokenStore_ChannelInListAll(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	// Insert one CLI and one web session.
	cliTok, err := session.GenerateToken()
	require.NoError(t, err)
	webTok, err := session.GenerateToken()
	require.NoError(t, err)
	cliSess := makeTokenSession("list-cli-id", "cli")
	webSess := makeTokenSession("list-web-id", "web")
	require.NoError(t, store.Set(ctx, session.HashToken(cliTok), cliSess))
	require.NoError(t, store.Set(ctx, session.HashToken(webTok), webSess))

	all, err := store.ListAll(ctx)
	require.NoError(t, err)

	channels := make(map[string]string) // session ID → channel
	for _, s := range all {
		channels[s.ID] = s.Channel
	}

	assert.Equal(t, "cli", channels["list-cli-id"], "CLI session must have channel=cli in ListAll")
	assert.Equal(t, "web", channels["list-web-id"], "Web session must have channel=web in ListAll")
}

// TestSQLiteSessionTokenStore_ManagerCrossChannelRejectAfterRestart verifies the full
// cross-channel rejection path using a real SQLite store — session issued with channel A,
// rehydrated from the durable store, and validated against a manager with channel B.
func TestSQLiteSessionTokenStore_ManagerCrossChannelRejectAfterRestart(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	cliCfg := session.Config{
		IdleTimeout:     5 * time.Minute,
		AbsoluteTimeout: 1 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "cli",
	}
	webCfg := session.Config{
		IdleTimeout:     60 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
		GraceWindow:     30 * time.Second,
		Channel:         "web",
	}

	// Issue a CLI session and persist it to the SQLite store.
	cliMgr := session.NewManager(cliCfg, store, time.Now)
	_, cliToken, err := cliMgr.Issue(ctx, "alice", "ctrl", "")
	require.NoError(t, err)

	// Simulate restart: fresh managers over the same store (empty in-memory maps).
	freshCliMgr := session.NewManager(cliCfg, store, time.Now)
	freshWebMgr := session.NewManager(webCfg, store, time.Now)

	// CLI manager must accept the CLI token (store-rehydration path).
	_, err = freshCliMgr.Validate(ctx, cliToken)
	assert.NoError(t, err, "CLI manager must accept CLI token after restart")

	// Web manager must reject the CLI token (store-rehydration path, channel mismatch).
	_, err = freshWebMgr.Validate(ctx, cliToken)
	assert.Error(t, err, "web manager must reject CLI token after restart")
}

// TestSQLiteSessionTokenStore_GetAndGetByIDAgree characterizes that Get (by token hash)
// and GetByID (by session ID) decode the same row identically, and apply the same
// found / expired / not-found outcomes (Issue #5795).
func TestSQLiteSessionTokenStore_GetAndGetByIDAgree(t *testing.T) {
	ctx := context.Background()

	t.Run("found decodes identically", func(t *testing.T) {
		store := newTestSessionTokenStore(t)
		tok, err := session.GenerateToken()
		require.NoError(t, err)
		hash := session.HashToken(tok)

		sess := makeTokenSession("agree-found", "web")
		sess.BoundIP = "10.0.0.7"
		sess.RootScoped = true
		sess.LastProvenAt = sess.IssuedAt.Add(time.Minute)
		sess.CredentialID = []byte{1, 2, 3}
		sess.LoginCredentialID = []byte{4, 5}
		require.NoError(t, store.Set(ctx, hash, sess))

		byHash, err := store.Get(ctx, hash)
		require.NoError(t, err)
		byID, err := store.GetByID(ctx, sess.ID)
		require.NoError(t, err)
		assert.Equal(t, byHash, byID)
		assert.Equal(t, sess.ID, byHash.ID)
		assert.Equal(t, "10.0.0.7", byHash.BoundIP)
		assert.True(t, byHash.RootScoped)
		assert.True(t, sess.LastProvenAt.Equal(byHash.LastProvenAt))
		assert.Equal(t, []byte{1, 2, 3}, byHash.CredentialID)
		assert.Equal(t, []byte{4, 5}, byHash.LoginCredentialID)
	})

	t.Run("expired hash is not found by either", func(t *testing.T) {
		store := newTestSessionTokenStore(t)
		tok, err := session.GenerateToken()
		require.NoError(t, err)
		hash := session.HashToken(tok)

		sess := makeTokenSession("agree-expired", "web")
		require.NoError(t, store.Set(ctx, hash, sess))
		require.NoError(t, store.StampGraceExpiry(ctx, hash, time.Now().Add(-time.Minute)))

		_, err = store.Get(ctx, hash)
		assert.True(t, errors.Is(err, session.ErrSessionNotFound))
		_, err = store.GetByID(ctx, sess.ID)
		assert.True(t, errors.Is(err, session.ErrSessionNotFound))
	})

	t.Run("missing is not found by either", func(t *testing.T) {
		store := newTestSessionTokenStore(t)
		_, err := store.Get(ctx, "no-such-hash")
		assert.True(t, errors.Is(err, session.ErrSessionNotFound))
		_, err = store.GetByID(ctx, "no-such-id")
		assert.True(t, errors.Is(err, session.ErrSessionNotFound))
	})
}

// TestSQLiteSessionTokenStore_CSRFTokenHashRoundTrip verifies the CSRF token hash
// (Issue #6321) round-trips through Set, Get, GetByID, ListAll and Update, is carried
// to the new row by Rotate so GetByID, Get(previousHash) and Get(newHash) all agree, and
// disappears with Delete.
func TestSQLiteSessionTokenStore_CSRFTokenHashRoundTrip(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	hashA := session.HashToken(mustToken(t))
	hashB := session.HashToken(mustToken(t))
	sess := makeTokenSession("csrf-roundtrip-id", "web")
	sess.CSRFTokenHash = "aa11"
	require.NoError(t, store.Set(ctx, hashA, sess))

	got, err := store.Get(ctx, hashA)
	require.NoError(t, err)
	assert.Equal(t, "aa11", got.CSRFTokenHash, "Get")
	got, err = store.GetByID(ctx, sess.ID)
	require.NoError(t, err)
	assert.Equal(t, "aa11", got.CSRFTokenHash, "GetByID")
	all, err := store.ListAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, "aa11", all[0].CSRFTokenHash, "ListAll")

	// A later Update keeps the column: the upsert's DO UPDATE list names it.
	sess.CSRFTokenHash = "bb22"
	require.NoError(t, store.Update(ctx, hashA, sess))
	got, err = store.Get(ctx, hashA)
	require.NoError(t, err)
	assert.Equal(t, "bb22", got.CSRFTokenHash, "Update")

	// Rotate (Renew/Elevate): every live row carries the hash.
	require.NoError(t, store.Rotate(ctx, hashA, hashB, sess, time.Now().Add(30*time.Second)))
	for name, lookup := range map[string]func() (*session.Session, error){
		"GetByID":       func() (*session.Session, error) { return store.GetByID(ctx, sess.ID) },
		"Get(previous)": func() (*session.Session, error) { return store.Get(ctx, hashA) },
		"Get(new)":      func() (*session.Session, error) { return store.Get(ctx, hashB) },
	} {
		got, err := lookup()
		require.NoError(t, err, name)
		assert.Equal(t, "bb22", got.CSRFTokenHash, name)
	}

	require.NoError(t, store.Delete(ctx, sess.ID))
	_, err = store.GetByID(ctx, sess.ID)
	assert.ErrorIs(t, err, session.ErrSessionNotFound)
	_, err = store.Get(ctx, hashB)
	assert.ErrorIs(t, err, session.ErrSessionNotFound)
}

// TestSQLiteSessionTokenStore_NoCSRFTokenHashByDefault verifies a session stored without
// a hash reads back with none (the column default is the empty string).
func TestSQLiteSessionTokenStore_NoCSRFTokenHashByDefault(t *testing.T) {
	store := newTestSessionTokenStore(t)
	ctx := context.Background()

	hash := session.HashToken(mustToken(t))
	require.NoError(t, store.Set(ctx, hash, makeTokenSession("no-csrf-id", "web")))
	got, err := store.Get(ctx, hash)
	require.NoError(t, err)
	assert.Empty(t, got.CSRFTokenHash)
}

func mustToken(t *testing.T) string {
	t.Helper()
	tok, err := session.GenerateToken()
	require.NoError(t, err)
	return tok
}

// TestSQLiteSessionTokenStore_BackfillAddsCSRFTokenHash opens a database whose
// session_token_records table predates the csrf_token_hash column and verifies the
// provider adds it on open, existing rows read back with no hash, and a new hash can be
// stored (Issue #6321).
func TestSQLiteSessionTokenStore_BackfillAddsCSRFTokenHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "legacy_session_tokens.db")
	ctx := context.Background()

	legacy, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = legacy.ExecContext(ctx, `CREATE TABLE session_token_records (
		token_hash TEXT PRIMARY KEY, session_id TEXT NOT NULL, principal_id TEXT NOT NULL,
		connection_name TEXT NOT NULL, tenant_id TEXT NOT NULL, issued_at TEXT NOT NULL,
		last_activity TEXT NOT NULL, absolute_expires_at TEXT NOT NULL, hash_expires_at TEXT,
		assurance INTEGER NOT NULL DEFAULT 1, bound_ip TEXT NOT NULL DEFAULT '',
		last_proven_at TEXT, credential_id BLOB, login_credential_id BLOB,
		root_scoped INTEGER NOT NULL DEFAULT 0, channel TEXT NOT NULL DEFAULT '')`)
	require.NoError(t, err)
	_, err = legacy.ExecContext(ctx, `INSERT INTO session_token_records
		(token_hash, session_id, principal_id, connection_name, tenant_id, issued_at, last_activity, absolute_expires_at, channel)
		VALUES ('legacy-hash', 'legacy-sess', 'admin', 'ctrl', 'tenant-1',
		        '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z', 'web')`)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())

	store, err := sqlite.NewSQLiteProvider(dir).CreateSessionTokenStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	got, err := store.Get(ctx, "legacy-hash")
	require.NoError(t, err)
	assert.Empty(t, got.CSRFTokenHash, "a legacy row carries no CSRF hash")

	got.CSRFTokenHash = "cc33"
	require.NoError(t, store.Update(ctx, "legacy-hash", got))
	got, err = store.GetByID(ctx, "legacy-sess")
	require.NoError(t, err)
	assert.Equal(t, "cc33", got.CSRFTokenHash)
}
