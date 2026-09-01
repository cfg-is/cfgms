// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL NonceStore (Issue #3755).
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestNonceStore creates a NonceStore backed by the test Postgres database.
// The schema is initialised fresh; the test is skipped when Postgres is unavailable.
func newTestNonceStore(t *testing.T) *DatabaseNonceStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateRefreshNoncesTable(ctx, db))

	store, err := NewDatabaseNonceStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestDatabaseNonceStore_PutAndConsume(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-1", []byte("payload-1"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-1")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("payload-1"), entry)
}

func TestDatabaseNonceStore_ConsumeIsSingleUse(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-2", []byte("payload-2"), time.Minute))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	require.True(t, found)

	// Second consume on the same key must find nothing — proves single-use.
	_, found, err = store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-2")
	require.NoError(t, err)
	assert.False(t, found, "nonce must not be consumable twice")
}

func TestDatabaseNonceStore_ConsumeNotFound(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:never-issued")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestDatabaseNonceStore_ExpiredNonceNotConsumable(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	// A negative TTL produces an expires_at already in the past.
	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-3", []byte("payload-3"), -time.Second))

	_, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-3")
	require.NoError(t, err)
	assert.False(t, found, "expired nonce must not be consumable")
}

func TestDatabaseNonceStore_PutOverwritesPriorEntry(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("first"), time.Minute))
	require.NoError(t, store.PutNonce(ctx, "refresh-nonce:dev-4", []byte("second"), time.Minute))

	entry, found, err := store.GetAndConsumeNonce(ctx, "refresh-nonce:dev-4")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []byte("second"), entry, "second Put must overwrite the first")
}

func TestDatabaseNonceStore_PutEmptyKeyRejected(t *testing.T) {
	store := newTestNonceStore(t)
	ctx := context.Background()

	err := store.PutNonce(ctx, "", []byte("payload"), time.Minute)
	assert.Error(t, err)
}

// TestDatabaseNonceStore_CrossInstanceHandoff proves the core cross-node
// requirement at the store layer: a nonce PUT via one *DatabaseNonceStore
// instance is consumable via a second, independent instance backed by the
// same Postgres database — simulating two controller nodes.
func TestDatabaseNonceStore_CrossInstanceHandoff(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateRefreshNoncesTable(context.Background(), db))

	nodeA, err := NewDatabaseNonceStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	nodeB, err := NewDatabaseNonceStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	ctx := context.Background()
	require.NoError(t, nodeA.PutNonce(ctx, "refresh-nonce:cross-node", []byte("issued-by-a"), time.Minute))

	entry, found, err := nodeB.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	require.True(t, found, "nonce issued on node A must be consumable on node B")
	assert.Equal(t, []byte("issued-by-a"), entry)

	// Double-consumption must fail on both nodes.
	_, found, err = nodeA.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	assert.False(t, found, "nonce already consumed via node B must not be consumable via node A")

	_, found, err = nodeB.GetAndConsumeNonce(ctx, "refresh-nonce:cross-node")
	require.NoError(t, err)
	assert.False(t, found, "nonce already consumed must not be consumable twice on the same node either")
}
