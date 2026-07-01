// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cluster

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// stubCounter is a minimal SessionCounter for testing. It returns a fixed
// count, simulating a node with no sessions (count=0) or sessions that never
// drain (count>0). The real SessionCounter is registry.Registry; using a stub
// here avoids a circular import while the integration path is covered by
// features/controller/api/handlers_cluster_test.go.
type stubCounter struct{ count int }

func (s *stubCounter) Count() int { return s.count }

// TestDecommission_MarksDecommissionedAfterSessionsDrain is a required AC test:
// when reg.Count()==0 from the start, Decommission returns nil, the node state
// is StateDecommissioned, and ListActiveNodes() excludes the node.
func TestDecommission_MarksDecommissionedAfterSessionsDrain(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDraining}))

	counter := &stubCounter{count: 0}
	logger := logging.NewNoopLogger()

	err := Decommission(context.Background(), "node-1", store, counter, logger, 5*time.Minute)
	require.NoError(t, err)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, StateDecommissioned, got.State)

	for _, n := range store.ListActiveNodes() {
		assert.NotEqual(t, "node-1", n.ID, "decommissioned node must not appear in ListActiveNodes")
	}
}

// TestDecommission_TimeoutForcesDecommission is a required AC test: when
// reg.Count()>0 throughout and timeout elapses, Decommission still marks the
// node StateDecommissioned (forced decommission on timeout is by design).
func TestDecommission_TimeoutForcesDecommission(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDraining}))

	counter := &stubCounter{count: 1} // sessions never drain
	logger := logging.NewNoopLogger()

	err := Decommission(context.Background(), "node-1", store, counter, logger, 50*time.Millisecond)
	require.NoError(t, err, "forced decommission on timeout must succeed")

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, StateDecommissioned, got.State)

	for _, n := range store.ListActiveNodes() {
		assert.NotEqual(t, "node-1", n.ID, "decommissioned node must not appear in ListActiveNodes")
	}
}

func TestDecommission_NodeNotFound_ReturnsError(t *testing.T) {
	store := NewInMemoryMembershipStore()
	counter := &stubCounter{count: 0}
	logger := logging.NewNoopLogger()

	err := Decommission(context.Background(), "ghost", store, counter, logger, 5*time.Minute)
	assert.True(t, errors.Is(err, ErrNodeNotFound))
}

func TestDecommission_NodeNotDraining_ReturnsError(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateActive}))

	counter := &stubCounter{count: 0}
	logger := logging.NewNoopLogger()

	err := Decommission(context.Background(), "node-1", store, counter, logger, 5*time.Minute)
	assert.True(t, errors.Is(err, ErrNodeNotDraining), "active node should return ErrNodeNotDraining")
}

func TestDecommission_AlreadyDecommissioned_ReturnsError(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDecommissioned}))

	counter := &stubCounter{count: 0}
	logger := logging.NewNoopLogger()

	err := Decommission(context.Background(), "node-1", store, counter, logger, 5*time.Minute)
	assert.True(t, errors.Is(err, ErrNodeNotDraining), "already-decommissioned node should return ErrNodeNotDraining")
}

func TestDecommission_CancelledContext_ForcesDecommission(t *testing.T) {
	store := NewInMemoryMembershipStore()
	require.NoError(t, store.Register(NodeRecord{ID: "node-1", State: StateDraining}))

	counter := &stubCounter{count: 1} // sessions never drain
	logger := logging.NewNoopLogger()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately — poll context derives from this and is done at once

	// Forced decommission proceeds even when the context is cancelled, consistent
	// with the timeout path: both exit waitForSessionDrain and call SetState.
	err := Decommission(ctx, "node-1", store, counter, logger, 5*time.Minute)
	require.NoError(t, err)

	got, err := store.GetNode("node-1")
	require.NoError(t, err)
	assert.Equal(t, StateDecommissioned, got.State)
}
