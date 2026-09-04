// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newTestNodeRegistryStore(t *testing.T) *DatabaseNodeRegistryStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateNodeRegistryTable(ctx, db))
	return &DatabaseNodeRegistryStore{db: db, schemas: schemas}
}

func TestDatabaseNodeRegistryStore_ListNodes_EmptyWhenNoneRegistered(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	nodes, err := store.ListNodes(context.Background())
	require.NoError(t, err)
	assert.Empty(t, nodes)
}

func TestDatabaseNodeRegistryStore_RegisterAndList(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	assert.Equal(t, "node-a", nodes[0].ID)
	assert.Equal(t, "10.0.0.1:9080", nodes[0].Address)
}

func TestDatabaseNodeRegistryStore_RegisterNode_RefreshesExistingRecord(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.2:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	require.Len(t, nodes, 1, "re-registering the same node id must update, not duplicate")
	assert.Equal(t, "10.0.0.2:9080", nodes[0].Address)
}

func TestDatabaseNodeRegistryStore_ListNodes_OmitsStaleRecord(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))

	// Directly backdate updated_at past business.NodeRegistryStaleAfter to
	// simulate a node that crashed without ever refreshing its record.
	stale := time.Now().Add(-business.NodeRegistryStaleAfter - time.Minute)
	_, err := store.db.ExecContext(ctx, `UPDATE cfgms_node_registry SET updated_at = $1 WHERE node_id = $2`, stale, "node-a")
	require.NoError(t, err)

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	assert.Empty(t, nodes, "a stale node record must not be reported as a live cluster member")
}

func TestDatabaseNodeRegistryStore_ListNodes_ReportsMultipleNodes(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-a", Address: "10.0.0.1:9080"}))
	require.NoError(t, store.RegisterNode(ctx, business.NodeRecord{ID: "node-b", Address: "10.0.0.2:9080"}))

	nodes, err := store.ListNodes(ctx)
	require.NoError(t, err)
	assert.Len(t, nodes, 2)
}

func TestDatabaseNodeRegistryStore_RegisterNode_RejectsEmptyID(t *testing.T) {
	store := newTestNodeRegistryStore(t)
	require.Error(t, store.RegisterNode(context.Background(), business.NodeRecord{Address: "10.0.0.1:9080"}))
}
