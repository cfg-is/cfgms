// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// blockingManualReviewStore wraps a real business.PendingRegistrationStore and
// blocks the first ExpireStale call until released before delegating it, so a
// test can observe a sweep cycle "still in flight" and assert a second node
// cannot start an overlapping one. Every other method — and ExpireStale itself
// once released — is served by the real store underneath: no mock framework,
// only the timing of one call changes.
type blockingManualReviewStore struct {
	business.PendingRegistrationStore
	started chan struct{}
	release chan struct{}
	once    int32
}

func (s *blockingManualReviewStore) ExpireStale(ctx context.Context, before time.Time) (int, error) {
	if atomic.CompareAndSwapInt32(&s.once, 0, 1) {
		close(s.started)
		<-s.release
	}
	return s.PendingRegistrationStore.ExpireStale(ctx, before)
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of ManualReviewApprovalHook's expiry sweep: runExpiry delegates
// to leaseJob.RunIfLeader (ADR-031 Decision 4), so a second hook contending
// for the same lease must not start its own sweep while the first's is still
// in flight.
func TestManualReviewApprovalHook_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	leaseJobA, err := lease.NewSingletonJob(m1, "manual-review-pending-expiry-test", "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(m2, "manual-review-pending-expiry-test", "node-b", ttl, renew, nil)
	require.NoError(t, err)

	// One real SQLite-backed pending-registration store shared by both nodes,
	// as a real cluster shares one durable store (newTestManualReviewHook uses
	// the same construction path).
	sm := pkgtesting.SetupTestStorage(t)
	pendingStore := sm.GetPendingRegistrationStore()
	require.NotNil(t, pendingStore, "OSS storage manager must provide a PendingRegistrationStore")

	blocking := &blockingManualReviewStore{
		PendingRegistrationStore: pendingStore,
		started:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}

	hookA := NewManualReviewApprovalHook(blocking, 24*time.Hour, logging.NewNoopLogger(), leaseJobA)
	defer hookA.Stop()
	hookB := NewManualReviewApprovalHook(pendingStore, 24*time.Hour, logging.NewNoopLogger(), leaseJobB)
	defer hookB.Stop()

	doneA := make(chan bool, 1)
	go func() {
		doneA <- hookA.leaseJob.RunIfLeader(context.Background(), hookA.expireTimedOut)
	}()

	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := hookB.leaseJob.RunIfLeader(context.Background(), hookB.expireTimedOut)
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(blocking.release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}
}
