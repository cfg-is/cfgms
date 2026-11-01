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

func newTestFlatFileNodeRegistryStore(t *testing.T) *FlatFileNodeRegistryStore {
	t.Helper()
	store, err := NewFlatFileNodeRegistryStore(t.TempDir())
	require.NoError(t, err)
	return store
}

func TestFlatFileNodeRegistryStore_ListNodes_EmptyWhenNoneRegistered(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	nodes, err := store.ListNodes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, nodes)
}

func TestFlatFileNodeRegistryStore_RegisterAndList(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "node-a", nodes[0].ID)
	assert.Equal(t, "10.0.0.1:9080", nodes[0].Address)
}

func TestFlatFileNodeRegistryStore_RegisterNode_RefreshesExistingRecord(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.2:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1, "re-registering the same node id must update, not duplicate")
	assert.Equal(t, "10.0.0.2:9080", nodes[0].Address)
}

func TestFlatFileNodeRegistryStore_ListNodes_OmitsStaleRecord(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))

	store.mu.Lock()
	entries, err := store.load()
	require.NoError(t, err)
	entry := entries["node-a"]
	entry.UpdatedAt = time.Now().Add(-business.NodeRegistryStaleAfter - time.Minute)
	entries["node-a"] = entry
	require.NoError(t, store.save(entries))
	store.mu.Unlock()

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	assert.Empty(t, nodes, "a stale node record must not be reported as a live cluster member")
}

func TestFlatFileNodeRegistryStore_ListNodes_ReportsMultipleNodes(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-b", Address: "10.0.0.2:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
}

func TestFlatFileNodeRegistryStore_RegisterNode_RejectsEmptyID(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	require.Error(t, store.RegisterNode(context.Background(), business.NodeRecord{Address: "10.0.0.1:9080"}))
}

// TestNodeRegistryStore_VersionStartedAtLastSeen_RoundTrip registers a record
// with Version and StartedAt and asserts ListNodes returns them plus a LastSeen
// stamped by the store's own clock, ignoring any caller-supplied LastSeen.
func TestFlatFileNodeRegistryStore_VersionStartedAtLastSeen_RoundTrip(t *testing.T) {
	store := newTestFlatFileNodeRegistryStore(t)
	ctx := context.Background()

	startedAt := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	bogusLastSeen := time.Now().Add(-48 * time.Hour)
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{
		ID: "node-a", Address: "10.0.0.1:9080", Version: "v1.2.3", StartedAt: startedAt, LastSeen: bogusLastSeen,
	}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "v1.2.3", nodes[0].Version)
	assert.True(t, startedAt.Equal(nodes[0].StartedAt), "StartedAt round-trip: want %s got %s", startedAt, nodes[0].StartedAt)
	assert.False(t, nodes[0].LastSeen.IsZero())
	assert.WithinDuration(t, time.Now(), nodes[0].LastSeen, time.Minute, "LastSeen must come from the store clock, not the caller")
}
