// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestNodeRegistryStore(t *testing.T) *SQLiteNodeRegistryStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteNodeRegistryStore{db: db}
}

func TestSQLiteNodeRegistryStore_ListNodes_EmptyWhenNoneRegistered(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	nodes, err := store.ListNodes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, nodes)
}

func TestSQLiteNodeRegistryStore_RegisterAndList(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "node-a", nodes[0].ID)
	assert.Equal(t, "10.0.0.1:9080", nodes[0].Address)
}

func TestSQLiteNodeRegistryStore_RegisterNode_RefreshesExistingRecord(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.2:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1, "re-registering the same node id must update, not duplicate")
	assert.Equal(t, "10.0.0.2:9080", nodes[0].Address)
}

func TestSQLiteNodeRegistryStore_ListNodes_OmitsStaleRecord(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))

	stale := nowUTC().Add(-business.NodeRegistryStaleAfter - time.Minute)
	_, err := store.db.ExecContext(ctx, `UPDATE cfgms_node_registry SET updated_at = ? WHERE node_id = ?`, formatTime(stale), "node-a")
	require.NoError(t, err)

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	assert.Empty(t, nodes, "a stale node record must not be reported as a live cluster member")
}

func TestSQLiteNodeRegistryStore_ListNodes_ReportsMultipleNodes(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-b", Address: "10.0.0.2:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
}

func TestSQLiteNodeRegistryStore_RegisterNode_RejectsEmptyID(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	require.Error(t, store.RegisterNode(context.Background(), business.NodeRecord{Address: "10.0.0.1:9080"}))
}
