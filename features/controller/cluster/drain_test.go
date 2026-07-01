// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cluster

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRegistrar records the most-recent SetDraining call for assertions.
// This minimal implementation is explicitly required by the story #2283 AC
// ("a stub DrainHealthRegistrar recorded SetDraining(true)") and is
// necessary because the real DrainHealthRegistrar implementation (*api.Server)
// cannot be imported from the cluster package without a circular import.
// The integration path — Drain() wired to a real *api.Server — is tested in
// features/controller/api/handlers_cluster_test.go
// (TestHandleClusterNodeDrain_AdminValidNode_Returns202).
type stubRegistrar struct {
	called   bool
	draining bool
}

func (s *stubRegistrar) SetDraining(v bool) {
	s.called = true
	s.draining = v
}

// TestDrain_SetsDrainingStateAndTriggersHealthGate is the required AC test:
// after Drain() returns nil, the node state is StateDraining and the registrar
// recorded SetDraining(true).
func TestDrain_SetsDrainingStateAndTriggersHealthGate(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateActive}))

	reg := &stubRegistrar{}
	err := Drain(context.Background(), "node-1", store, reg)
	require.NoError(t, err)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, StateDraining, got.State)
	assert.True(t, reg.called, "SetDraining must be called")
	assert.True(t, reg.draining, "SetDraining must be called with true")
}

func TestDrain_NodeNotFound_ReturnsError(t *testing.T) {
	store := NewInMemoryMembershipStore()
	reg := &stubRegistrar{}

	err := Drain(context.Background(), "ghost", store, reg)
	assert.True(t, errors.Is(err, ErrNodeNotFound))
	assert.False(t, reg.called, "SetDraining must not be called when node is not found")
}

func TestDrain_AlreadyDraining_ReturnsError(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDraining}))

	reg := &stubRegistrar{}
	err := Drain(context.Background(), "node-1", store, reg)
	assert.True(t, errors.Is(err, ErrNodeNotActive))
	assert.False(t, reg.called, "SetDraining must not be called for an already-draining node")
}

func TestDrain_Decommissioned_ReturnsError(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDecommissioned}))

	reg := &stubRegistrar{}
	err := Drain(context.Background(), "node-1", store, reg)
	assert.True(t, errors.Is(err, ErrNodeNotActive))
	assert.False(t, reg.called)
}
