// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL CertRevocationStore (Issue #3852).
package database

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	certinterfaces "github.com/cfgis/cfgms/pkg/cert/interfaces"
)

// newTestCertRevocationStore creates a CertRevocationStore backed by the test
// Postgres database. Skipped when Postgres is unavailable.
func newTestCertRevocationStore(t *testing.T) *DatabaseCertRevocationStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseCertRevocationStore(db, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestDatabaseCertRevocationStore_RevokeAndIsRevoked(t *testing.T) {
	store := newTestCertRevocationStore(t)
	ctx := context.Background()

	revoked, err := store.IsRevoked(ctx, "serial-1")
	require.NoError(t, err)
	assert.False(t, revoked, "an unrevoked serial must report false")

	require.NoError(t, store.Revoke(ctx, certinterfaces.RevocationEntry{
		Serial: "serial-1", RevokedAt: time.Now().UTC(), Reason: "compromised",
	}))

	revoked, err = store.IsRevoked(ctx, "serial-1")
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestDatabaseCertRevocationStore_RevokeIsIdempotent(t *testing.T) {
	store := newTestCertRevocationStore(t)
	ctx := context.Background()

	first := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.Revoke(ctx, certinterfaces.RevocationEntry{Serial: "serial-2", RevokedAt: first}))
	require.NoError(t, store.Revoke(ctx, certinterfaces.RevocationEntry{
		Serial: "serial-2", RevokedAt: first.Add(time.Hour), Reason: "attacker-supplied",
	}))

	entries, err := store.ListRevoked(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1, "revocation list must not grow on double-revoke")
	assert.True(t, first.Equal(entries[0].RevokedAt), "original RevokedAt must be preserved on double-revoke")
	assert.Empty(t, entries[0].Reason, "the second revoke's fields must not overwrite the first")
}

func TestDatabaseCertRevocationStore_RevokeEmptySerialRejected(t *testing.T) {
	store := newTestCertRevocationStore(t)
	ctx := context.Background()

	err := store.Revoke(ctx, certinterfaces.RevocationEntry{Serial: "", RevokedAt: time.Now().UTC()})
	assert.Error(t, err)
}

func TestDatabaseCertRevocationStore_ListRevoked(t *testing.T) {
	store := newTestCertRevocationStore(t)
	ctx := context.Background()

	require.NoError(t, store.Revoke(ctx, certinterfaces.RevocationEntry{Serial: "s1", RevokedAt: time.Now().UTC()}))
	require.NoError(t, store.Revoke(ctx, certinterfaces.RevocationEntry{Serial: "s2", RevokedAt: time.Now().UTC()}))

	entries, err := store.ListRevoked(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

// TestDatabaseCertRevocationStore_CrossInstanceHandoff proves the AC4 core
// requirement at the store layer: a revoke via one *DatabaseCertRevocationStore
// instance is observed via a second, independent instance backed by the same
// Postgres database — simulating two controller nodes. This test must fail if
// the implementation is reverted to a node-local file store, because a
// second process's file store would never see node A's write.
func TestDatabaseCertRevocationStore_CrossInstanceHandoff(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	require.NoError(t, NewDatabaseSchemas().CreateCertRevocationsTable(context.Background(), db))

	dbA := getTestDB(t)
	t.Cleanup(func() { _ = dbA.Close() })
	nodeA, err := NewDatabaseCertRevocationStore(dbA, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeA.Close() })

	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	nodeB, err := NewDatabaseCertRevocationStore(dbB, getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeB.Close() })

	ctx := context.Background()
	require.NoError(t, nodeA.Revoke(ctx, certinterfaces.RevocationEntry{
		Serial: "cross-node-serial", RevokedAt: time.Now().UTC(), Reason: "compromised",
	}))

	revoked, err := nodeB.IsRevoked(ctx, "cross-node-serial")
	require.NoError(t, err)
	assert.True(t, revoked, "a serial revoked on node A must be observed as revoked on node B without a restart")

	entries, err := nodeB.ListRevoked(ctx)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "cross-node-serial", entries[0].Serial)
}

// TestDatabaseCertRevocationStore_ConcurrentReadWrite verifies concurrent
// IsRevoked reads and a Revoke write do not race (run with -race).
func TestDatabaseCertRevocationStore_ConcurrentReadWrite(t *testing.T) {
	store := newTestCertRevocationStore(t)
	ctx := context.Background()

	const readers = 20
	var wg sync.WaitGroup
	wg.Add(readers + 1)
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.IsRevoked(ctx, "race-serial")
		}()
	}
	go func() {
		defer wg.Done()
		_ = store.Revoke(ctx, certinterfaces.RevocationEntry{Serial: "race-serial", RevokedAt: time.Now().UTC()})
	}()
	wg.Wait()

	revoked, err := store.IsRevoked(ctx, "race-serial")
	require.NoError(t, err)
	assert.True(t, revoked)
}
