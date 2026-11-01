// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
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
