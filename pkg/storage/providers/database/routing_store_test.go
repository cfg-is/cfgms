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

func newTestRoutingStore(t *testing.T) *DatabaseRoutingStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateRoutingTable(ctx, db))
	return &DatabaseRoutingStore{db: db, schemas: schemas}
}

func TestDatabaseRoutingStore_LookupNode_NotFound(t *testing.T) {
	store := newTestRoutingStore(t)
	_, ok, err := store.LookupNode(context.Background(), "steward-1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestDatabaseRoutingStore_RecordAndLookup(t *testing.T) {
	store := newTestRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	nodeID, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "node-a", nodeID)
}

func TestDatabaseRoutingStore_RecordConnection_ReassignsToNewNode(t *testing.T) {
	store := newTestRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))
	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-b"))

	nodeID, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "node-b", nodeID, "a reconnect on a different node must overwrite the routing record")
}

func TestDatabaseRoutingStore_LookupNode_StaleRecordNotTrusted(t *testing.T) {
	store := newTestRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	// Directly backdate updated_at past business.RoutingStaleAfter to simulate
	// a node that crashed without ever reaching RemoveConnection.
	stale := time.Now().Add(-business.RoutingStaleAfter - time.Minute)
	_, err := store.db.ExecContext(ctx, `UPDATE cfgms_routing SET updated_at = $1 WHERE steward_id = $2`, stale, "steward-1")
	require.NoError(t, err)

	_, ok, err := store.LookupNode(ctx, "steward-1")
	require.NoError(t, err)
	assert.False(t, ok, "a stale routing record must not be trusted")
}

func TestDatabaseRoutingStore_RemoveConnection_OnlyRemovesOwnedRecord(t *testing.T) {
	store := newTestRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	// A late-arriving disconnect from node-a must not remove a record the
	// steward has since reconnected under on node-b.
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

func TestDatabaseRoutingStore_RemoveConnection_AbsentRecordIsNoop(t *testing.T) {
	store := newTestRoutingStore(t)
	require.NoError(t, store.RemoveConnection(context.Background(), "never-recorded", "node-a"))
}

func TestDatabaseRoutingStore_RecordConnection_RejectsEmptyIDs(t *testing.T) {
	store := newTestRoutingStore(t)
	ctx := context.Background()

	require.Error(t, store.RecordConnection(ctx, "", "node-a"))
	require.Error(t, store.RecordConnection(ctx, "steward-1", ""))
}

func TestDatabaseRoutingStore_CountByNode(t *testing.T) {
	store := newTestRoutingStore(t)
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

func TestDatabaseRoutingStore_CountByNode_ExcludesStaleRecords(t *testing.T) {
	store := newTestRoutingStore(t)
	ctx := context.Background()

	require.NoError(t, store.RecordConnection(ctx, "steward-1", "node-a"))

	stale := time.Now().Add(-business.RoutingStaleAfter - time.Minute)
	_, err := store.db.ExecContext(ctx, `UPDATE cfgms_routing SET updated_at = $1 WHERE steward_id = $2`, stale, "steward-1")
	require.NoError(t, err)

	count, err := store.CountByNode(ctx, "node-a")
	require.NoError(t, err)
	assert.Equal(t, 0, count, "a stale routing record must not be counted as a live session")
}
