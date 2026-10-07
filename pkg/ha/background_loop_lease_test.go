// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/testing/storage"
)

// SingleServerMode has one node and nothing to exclude (ADR-029 Decision 4), so
// NewBackgroundLoopLease must hand out a SingletonJob that always runs — a
// background loop gated by it behaves identically to today's ungated loop on a
// single-node deployment.
func TestManager_NewBackgroundLoopLease_SingleServerMode_AlwaysRuns(t *testing.T) {
	storageManager, err := storage.CreateTestStorageManager()
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, storageManager.Close()) })

	cfg := DefaultConfig()
	cfg.Mode = SingleServerMode

	manager, err := NewManager(cfg, logging.GetLogger(), storageManager)
	require.NoError(t, err)

	job, err := manager.NewBackgroundLoopLease("test-loop", nil)
	require.NoError(t, err)
	assert.Nil(t, job.Manager, "SingleServerMode must produce a SingletonJob with no lease substrate")

	var called bool
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) { called = true })
	assert.True(t, ran)
	assert.True(t, called)
}

// A nil *Manager (the "OSS single-node, no HA wired at all" convention used
// throughout the codebase) must produce an always-runs SingletonJob rather
// than panicking, so every background loop's call site can call this method
// unconditionally.
func TestManager_NewBackgroundLoopLease_NilManager_AlwaysRuns(t *testing.T) {
	var manager *Manager

	job, err := manager.NewBackgroundLoopLease("test-loop", nil)
	require.NoError(t, err)
	assert.Nil(t, job.Manager)

	var called bool
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) { called = true })
	assert.True(t, ran)
	assert.True(t, called)
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of a lease-claimed background loop: two ClusterMode Managers
// share one real (not mocked) lease store, each constructs a
// NewBackgroundLoopLease for the same loop name, and only one may run a given
// cycle at a time.
func TestManager_NewBackgroundLoopLease_ClusterMode_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	store := newTestLeaseStore(t)

	managerA := newLeaseBackedClusterManager(t, "bg-lease-node-a", store)
	managerB := newLeaseBackedClusterManager(t, "bg-lease-node-b", store)

	jobA, err := managerA.NewBackgroundLoopLease("test-sweep", nil)
	require.NoError(t, err)
	require.NotNil(t, jobA.Manager, "ClusterMode with a wired lease store must produce a real lease-backed job")

	jobB, err := managerB.NewBackgroundLoopLease("test-sweep", nil)
	require.NoError(t, err)

	nodeAStarted := make(chan struct{})
	releaseNodeA := make(chan struct{})
	var nodeARan, nodeBRan int32

	doneA := make(chan bool, 1)
	go func() {
		ran := jobA.RunIfLeader(context.Background(), func(ctx context.Context) {
			atomic.AddInt32(&nodeARan, 1)
			close(nodeAStarted)
			<-releaseNodeA
		})
		doneA <- ran
	}()

	select {
	case <-nodeAStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a never started its cycle")
	}

	ranB := jobB.RunIfLeader(context.Background(), func(ctx context.Context) {
		atomic.AddInt32(&nodeBRan, 1)
	})
	assert.False(t, ranB, "node-b must not run the same lease-claimed cycle while node-a holds the lease")

	close(releaseNodeA)
	var ranA bool
	select {
	case ranA = <-doneA:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}

	assert.True(t, ranA)
	assert.Equal(t, int32(1), atomic.LoadInt32(&nodeARan))
	assert.Equal(t, int32(0), atomic.LoadInt32(&nodeBRan))
}

// Two calls to NewBackgroundLoopLease with different names on the same Manager
// must not contend with each other — each background loop gets its own,
// independently-claimable lease.
func TestManager_NewBackgroundLoopLease_DistinctNamesDoNotContend(t *testing.T) {
	store := newTestLeaseStore(t)
	manager := newLeaseBackedClusterManager(t, "bg-lease-distinct", store)

	jobX, err := manager.NewBackgroundLoopLease("loop-x", nil)
	require.NoError(t, err)
	jobY, err := manager.NewBackgroundLoopLease("loop-y", nil)
	require.NoError(t, err)

	ranX := jobX.RunIfLeader(context.Background(), func(ctx context.Context) {})
	ranY := jobY.RunIfLeader(context.Background(), func(ctx context.Context) {})
	assert.True(t, ranX)
	assert.True(t, ranY, "a different loop name must acquire its own lease independently")
}
