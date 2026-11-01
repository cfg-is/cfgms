// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatabaseSigningTrustAckStore_CrossNodeVisibility(t *testing.T) {
	// Two stores on two separate connections stand in for two controller nodes.
	dbA := setupTestDatabase(t)
	t.Cleanup(func() { _ = dbA.Close() })
	storeA, err := NewDatabaseSigningTrustAckStore(dbA, getTestConfig())
	require.NoError(t, err)

	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })
	storeB, err := NewDatabaseSigningTrustAckStore(dbB, getTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, storeA.RecordAck(ctx, "steward-1", "serial-a"))

	got, err := storeB.GetAck(ctx, "steward-1", "serial-a")
	require.NoError(t, err)
	require.NotNil(t, got, "an ack recorded through one node must be visible through another")
	assert.Equal(t, "steward-1", got.StewardID)

	listed, err := storeB.ListAcked(ctx, "serial-a")
	require.NoError(t, err)
	require.Len(t, listed, 1)
}

func TestDatabaseSigningTrustAckStore_RejectsEmptyIDs(t *testing.T) {
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewDatabaseSigningTrustAckStore(db, getTestConfig())
	require.NoError(t, err)

	ctx := context.Background()
	assert.Error(t, store.RecordAck(ctx, "", "serial-a"))
	assert.Error(t, store.RecordAck(ctx, "steward-1", ""))
	_, err = store.GetAck(ctx, "", "serial-a")
	assert.Error(t, err)
	_, err = store.ListAcked(ctx, "")
	assert.Error(t, err)
}
