// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite provides unit tests for SQLiteNonceStore (Issue #3755).
package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestNonceStore builds the store through SQLiteProvider.CreateNonceStore
// rather than assembling &SQLiteNonceStore{db: ...} by hand, so every behaviour
// test below also covers the factory's config parsing and path resolution — the
// same convention trigger_store_test.go uses for CreateTriggerStore.
func newTestNonceStore(t *testing.T) *SQLiteNonceStore {
	t.Helper()
	return newTestNonceStoreAt(t, ":memory:")
}

// newTestNonceStoreAt builds a nonce store for an explicit SQLite path through
// the provider factory.
func newTestNonceStoreAt(t *testing.T, path string) *SQLiteNonceStore {
	t.Helper()
	p := NewSQLiteProvider(path)
	store, err := p.CreateNonceStore(map[string]interface{}{"path": path})
	require.NoError(t, err)
	require.NotNil(t, store)
	sqliteStore, ok := store.(*SQLiteNonceStore)
	require.True(t, ok, "CreateNonceStore must return a *SQLiteNonceStore")
	t.Cleanup(func() { _ = sqliteStore.Close() })
	return sqliteStore
}

func TestSQLiteNonceStore_PutAndConsume(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-1", []byte("payload-1"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("payload-1"), entry)
}

func TestSQLiteNonceStore_ConsumeIsSingleUse(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-2", []byte("payload-2"), time.Minute))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	require.True(t, found)

	_, found, err = store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	assert.False(t, found, "nonce must not be consumable twice")
}

func TestSQLiteNonceStore_ConsumeNotFound(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:never-issued")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestSQLiteNonceStore_ExpiredNonceNotConsumable(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-3", []byte("payload-3"), -time.Second))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-3")
	require.NoError(t, err)
	assert.False(t, found, "expired nonce must not be consumable")
}

func TestSQLiteNonceStore_PutOverwritesPriorEntry(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("first"), time.Minute))
	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("second"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-4")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("second"), entry, "second Put must overwrite the first")
}

func TestSQLiteNonceStore_PutEmptyKeyRejected(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	err := store.PutNonce(ctx, "", []byte("payload"), time.Minute)
	assert.Error(t, err)
}

// TestSQLiteNonceStore_CrossInstanceHandoff proves a nonce PUT via one
// *SQLiteNonceStore instance is consumable via a second, independent instance
// backed by the same on-disk database file — simulating two controller nodes
// sharing one SQLite-backed OSS deployment.
func TestSQLiteNonceStore_CrossInstanceHandoff(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nonce-cross-node.db")

	// Both instances come from the provider factory, so the handoff also proves
	// CreateNonceStore resolves config["path"] to the same on-disk database
	// instead of silently falling back to a private in-memory one.
	nodeA := newTestNonceStoreAt(t, dbPath)
	nodeB := newTestNonceStoreAt(t, dbPath)

	ctx := context.Background()
	require.NoError(t, nodeA.PutNonce(ctx, "refresh-nonce:cross-node", []byte("issued-by-a"), time.Minute))

	entry, found, err := nodeB.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	require.True(t, found, "nonce issued via node A must be consumable via node B")
	assert.Equal(t, []byte("issued-by-a"), entry)

	_, found, err = nodeA.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	assert.False(t, found, "nonce already consumed via node B must not be consumable via node A")
}

// ---- provider factory tests -------------------------------------------------

// TestSQLiteProvider_CreateNonceStore covers the factory method itself — its
// config parsing (getPath), its path resolution, and its error propagation —
// rather than only the SQLiteNonceStore type it returns. CreateNonceStore is the
// entry point every wiring path uses: CreateAllStoresFromConfig in
// single-provider mode and interfaces.CreateNonceStoreFromConfig by provider
// name, neither of which ever constructs SQLiteNonceStore directly.
func TestSQLiteProvider_CreateNonceStore(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves the database path from config", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "nonce-factory.db")
		p := NewSQLiteProvider(dbPath)

		store, err := p.CreateNonceStore(map[string]interface{}{"path": dbPath})
		require.NoError(t, err)
		require.NotNil(t, store)
		t.Cleanup(func() { _ = store.(*SQLiteNonceStore).Close() })

		// The file must exist: an ignored config["path"] would silently give an
		// in-memory database that loses every nonce on restart.
		_, statErr := os.Stat(dbPath)
		require.NoError(t, statErr, "CreateNonceStore must open the database at config[\"path\"]")

		require.NoError(t, store.PutNonce(ctx, "refresh-nonce:factory", []byte("payload"), time.Minute))
		entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:factory")
		require.NoError(t, err)
		require.True(t, found)
		assert.Equal(t, []byte("payload"), entry)
	})

	t.Run("falls back to in-memory when config omits path", func(t *testing.T) {
		p := NewSQLiteProvider(":memory:")

		store, err := p.CreateNonceStore(map[string]interface{}{})
		require.NoError(t, err)
		require.NotNil(t, store)
		t.Cleanup(func() { _ = store.(*SQLiteNonceStore).Close() })

		// The schema must be present on the fallback database too, otherwise the
		// first PutNonce would fail with "no such table: refresh_nonces".
		require.NoError(t, store.PutNonce(ctx, "refresh-nonce:default-path", []byte("payload"), time.Minute))
		_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:default-path")
		require.NoError(t, err)
		assert.True(t, found)
	})

	t.Run("propagates the open error for an unusable path", func(t *testing.T) {
		// Parent directory does not exist, so SQLite cannot create the file.
		dbPath := filepath.Join(t.TempDir(), "missing-dir", "nonce.db")
		p := NewSQLiteProvider(dbPath)

		store, err := p.CreateNonceStore(map[string]interface{}{"path": dbPath})
		require.Error(t, err, "an unopenable path must surface as an error, not a store that fails on first use")
		assert.Nil(t, store)
	})

	t.Run("reachable through the provider registry", func(t *testing.T) {
		// interfaces.CreateNonceStoreFromConfig resolves the provider by name and
		// type-asserts NonceStoreCreator; this fails if SQLiteProvider ever loses
		// CreateNonceStore or its init registration.
		dbPath := filepath.Join(t.TempDir(), "nonce-registry.db")

		store, err := interfaces.CreateNonceStoreFromConfig("sqlite", map[string]interface{}{"path": dbPath})
		require.NoError(t, err)
		require.NotNil(t, store)
		assert.NotErrorIs(t, err, business.ErrNotSupported)
		t.Cleanup(func() { _ = store.(*SQLiteNonceStore).Close() })

		require.NoError(t, store.PutNonce(ctx, "refresh-nonce:registry", []byte("payload"), time.Minute))
		_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:registry")
		require.NoError(t, err)
		assert.True(t, found)
	})
}
