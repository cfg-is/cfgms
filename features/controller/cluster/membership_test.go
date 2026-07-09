// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cluster

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInMemoryMembershipStore_RegisterAndGet(t *testing.T) {
	store := NewInMemoryMembershipStore()
	node := NodeRecord{
		ID:           "node-1",
		State:        StateActive,
		Address:      "10.0.0.1:9090",
		RegisteredAt: time.Now(),
	}

	require.NoError(t, store.Register(node))

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, node.ID, got.ID)
	assert.Equal(t, node.State, got.State)
	assert.Equal(t, node.Address, got.Address)
}

func TestInMemoryMembershipStore_GetNode_NotFound(t *testing.T) {
	store := NewInMemoryMembershipStore()
	_, err := store.GetNode("missing")
	assert.ErrorIs(t, err, ErrNodeNotFound)
}

func TestInMemoryMembershipStore_SetState(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateActive}))

	require.NoError(t, store.SetState("node-1", StateDraining))

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, StateDraining, got.State)
}

func TestInMemoryMembershipStore_SetState_NotFound(t *testing.T) {
	store := NewInMemoryMembershipStore()
	err := store.SetState("ghost", StateDraining)
	assert.ErrorIs(t, err, ErrNodeNotFound)
}

func TestInMemoryMembershipStore_ListActiveNodes(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateActive}))
	require.NoError(t, store.Register(NodeRecord{ID: "node-2", State: StateDraining}))
	require.NoError(t, store.Register(NodeRecord{ID: "node-3", State: StateActive}))

	active := store.ListActiveNodes()
	assert.Len(t, active, 2)
	ids := make(map[string]struct{}, 2)
	for _, n := range active {
		ids[n.ID] = struct{}{}
	}
	assert.Contains(t, ids, "node-1")
	assert.Contains(t, ids, "node-3")
	assert.NotContains(t, ids, "node-2")
}

func TestInMemoryMembershipStore_ListActiveNodes_Empty(t *testing.T) {
	store := NewInMemoryMembershipStore()
	assert.Empty(t, store.ListActiveNodes())
}

func TestInMemoryMembershipStore_RegisterOverwritesExisting(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateActive, Address: "old"}))
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDraining, Address: "new"}))

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, StateDraining, got.State)
	assert.Equal(t, "new", got.Address)
}
