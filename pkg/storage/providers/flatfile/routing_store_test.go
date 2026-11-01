// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestFlatFileRoutingStore(t *testing.T) *FlatFileRoutingStore {
	t.Helper()
	store, err := NewFlatFileRoutingStore(t.TempDir())
	require.NoError(t, err)
	return store
}

func TestFlatFileRoutingStore_LookupNode_NotFound(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	_, ok, err := store.LookupNode(context.Background(), "steward-1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestFlatFileRoutingStore_RecordAndLookup(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	nodeID, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "node-a", nodeID)
}

func TestFlatFileRoutingStore_RecordConnection_ReassignsToNewNode(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))
	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-b"))

	nodeID, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "node-b", nodeID)
}

func TestFlatFileRoutingStore_LookupNode_StaleRecordNotTrusted(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	store.mu.Lock()
	entries, err := store.load()
	require.NoError(t, err)
	entry := entries["steward-1"]
	entry.UpdatedAt = time.Now().Add(-business.RoutingStaleAfter - time.Minute)
	entries["steward-1"] = entry
	require.NoError(t, store.save(entries))
	store.mu.Unlock()

	_, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	assert.False(t, ok, "a stale routing record must not be trusted")
}

func TestFlatFileRoutingStore_RemoveConnection_OnlyRemovesOwnedRecord(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))
	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-b"))
	require.NoError(t, store.RemoveConnection(ctx, "steward-1", "node-a"))

	nodeID, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	require.True(t, ok, "record owned by node-b must survive node-a's stale disconnect")
	assert.Equal(t, "node-b", nodeID)

	require.NoError(t, store.RemoveConnection(ctx, "steward-1", "node-b"))
	_, ok, err = store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestFlatFileRoutingStore_RemoveConnection_AbsentRecordIsNoop(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	require.NoError(t, store.RemoveConnection(context.Background(), "never-recorded", "node-a"))
}

func TestFlatFileRoutingStore_RecordConnection_RejectsEmptyIDs(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.Error(t, store.RecordConnection(ctx, "", "node-a"))
	require.Error(t, store.RecordConnection(ctx, "steward-1", ""))
}

func TestFlatFileRoutingStore_CountByNode(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	count, err := store.CountByNode(ctx, "node-a")
	require.NoError(t, err)
	assert.Equal(t, 0, count, "an unknown node must count zero")

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))
	require.NoError(t, store.RecordConnection(ctx, "steward-2", "node-a"))
	require.NoError(t, store.RecordConnection(ctx, "steward-3", "node-b"))

	count, err = store.CountByNode(ctx, "node-a")
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	count, err = store.CountByNode(ctx, "node-b")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestFlatFileRoutingStore_CountByNode_ExcludesStaleRecords(t *testing.T) {
	store := newTestFlatFileRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	store.mu.Lock()
	entries, err := store.load()
	require.NoError(t, err)
	entry := entries["steward-1"]
	entry.UpdatedAt = time.Now().Add(-business.RoutingStaleAfter - time.Minute)
	entries["steward-1"] = entry
	require.NoError(t, store.save(entries))
	store.mu.Unlock()

	count, err := store.CountByNode(ctx, "node-a")
	require.NoError(t, err)
	assert.Equal(t, 0, count, "a stale routing record must not be counted as a live session")
}
