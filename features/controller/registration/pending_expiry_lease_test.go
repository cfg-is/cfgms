// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package registration

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

// blockingPendingStore wraps a real business.PendingRegistrationStore and
// blocks the first ExpireStale call until released before delegating it, so a
// test can observe a sweep cycle "still in flight" and assert a second node
// cannot start an overlapping one. Every other method — and ExpireStale itself
// once released — is served by the real store underneath: no mock framework,
// only the timing of one call changes.
type blockingPendingStore struct {
	business.PendingRegistrationStore
	started chan struct{}
	release chan struct{}
	once    int32
}

func (s *blockingPendingStore) ExpireStale(ctx context.Context, before time.Time) (int, error) {
	if atomic.CompareAndSwapInt32(&s.once, 0, 1) {
		close(s.started)
		<-s.release
	}
	return s.PendingRegistrationStore.ExpireStale(ctx, before)
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of PendingExpiryJob: run() delegates to LeaseJob.RunIfLeader
// (ADR-031 Decision 4), so a second job contending for the same lease must not
// start its own sweep while the first job's is still in flight.
func TestPendingExpiryJob_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	leaseJobA, err := lease.NewSingletonJob(m1, "pending-registration-expiry-test", "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(m2, "pending-registration-expiry-test", "node-b", ttl, renew, nil)
	require.NoError(t, err)

	// One real SQLite-backed pending-registration store shared by both nodes,
	// as a real cluster shares one durable store. Node-a's view of it blocks on
	// the first ExpireStale so its cycle can be held in flight; node-b's is the
	// real store untouched, so a failure to exclude it would run for real.
	pendingStore := pkgtesting.SetupTestStorage(t).GetPendingRegistrationStore()
	require.NotNil(t, pendingStore, "OSS storage manager must provide a PendingRegistrationStore")
	store := &blockingPendingStore{
		PendingRegistrationStore: pendingStore,
		started:                  make(chan struct{}),
		release:                  make(chan struct{}),
	}

	jobA := NewPendingExpiryJob(PendingExpiryConfig{
		Store: store, Logger: logging.NewNoopLogger(), LeaseJob: leaseJobA,
	})
	jobB := NewPendingExpiryJob(PendingExpiryConfig{
		Store: pendingStore, Logger: logging.NewNoopLogger(), LeaseJob: leaseJobB,
	})

	doneA := make(chan bool, 1)
	go func() {
		doneA <- jobA.leaseJob.RunIfLeader(context.Background(), jobA.expireStale)
	}()

	select {
	case <-store.started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := jobB.leaseJob.RunIfLeader(context.Background(), jobB.expireStale)
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(store.release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}
}
