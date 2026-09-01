// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// blockingFlushBackend wraps a real Backend (the package's SQLite backend, as
// built by NewManager) and blocks the first Flush call until released before
// delegating it. Every other method — and Flush itself once released — runs
// against the real backend underneath: no re-implementation, no mock
// framework, only the timing of one call changes.
type blockingFlushBackend struct {
	Backend
	started chan struct{}
	release chan struct{}
	once    int32
}

func (b *blockingFlushBackend) Flush() error {
	if atomic.CompareAndSwapInt32(&b.once, 0, 1) {
		close(b.started)
		<-b.release
	}
	return b.Backend.Flush()
}

// slowFlushBackend wraps a real Backend and delays every Flush by a fixed
// duration before delegating, so a maintenance cycle's wall-clock time can be
// driven past the lease TTL — the condition RunIfLeader's background renewal
// exists to survive.
type slowFlushBackend struct {
	Backend
	delay time.Duration
}

func (b *slowFlushBackend) Flush() error {
	time.Sleep(b.delay)
	return b.Backend.Flush()
}

// newMaintenanceLeaseManager builds a Manager backed by the real SQLite
// backend rooted in t.TempDir() — the construction path every other test in
// this package uses — and then, if wrap is non-nil, replaces its backend with
// a wrapper around that same real backend. Manager.Close closes the wrapper,
// which delegates to the real backend, so cleanup is unchanged.
func newMaintenanceLeaseManager(t *testing.T, wrap func(Backend) Backend) *Manager {
	t.Helper()

	config := createTestConfig(t, BackendSQLite)
	mgr, err := NewManager(config, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := mgr.Close(); err != nil {
			t.Errorf("close storage manager: %v", err)
		}
	})

	if wrap != nil {
		// Safe before any maintenance tick: startMaintenanceTasks first reads
		// storage one FlushInterval (5 minutes by default) after construction.
		mgr.storage = wrap(mgr.storage)
	}
	return mgr
}

// twoMaintenanceLeaseJobs builds two lease.SingletonJob values (simulating two
// cluster nodes) contending for one lease name against a single real lease
// store.
func twoMaintenanceLeaseJobs(t *testing.T, name string, ttl, renew time.Duration) (lease.SingletonJob, lease.SingletonJob) {
	t.Helper()

	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	jobA, err := lease.NewSingletonJob(m1, name, "node-a", ttl, renew, nil)
	require.NoError(t, err)
	jobB, err := lease.NewSingletonJob(m2, name, "node-b", ttl, renew, nil)
	require.NoError(t, err)
	return jobA, jobB
}

// [REQUIRED TEST] A slow maintenance cycle that runs well past the lease TTL
// renews successfully (via RunIfLeader's background renewal goroutine) and
// does not trigger a duplicate run on a second node contending for the same
// lease throughout — the DNA storage maintenance sweep is the longest-running
// of the converted background loops (Flush + Optimize + retention enforcement
// over the full dataset).
func TestManager_MaintenanceLease_SlowCycleRenewsAcrossTTL_NoDuplicateRun(t *testing.T) {
	// Generous margin (ttl-renew=1.8s of scheduling slack per renewal) so this
	// test does not race itself when the full suite runs packages in parallel
	// under load — a tight margin here would make an occasional missed renewal
	// window (goroutine scheduling delay, not a logic bug) look like a broken
	// renewal loop.
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	leaseJobA, leaseJobB := twoMaintenanceLeaseJobs(t, "dna-storage-maintenance-slow-test", ttl, renew)

	// The cycle runs 1.5x the lease TTL — impossible to complete without the
	// background renewal loop extending the lease past its original expiry.
	mgrA := newMaintenanceLeaseManager(t, func(real Backend) Backend {
		return &slowFlushBackend{Backend: real, delay: ttl + ttl/2}
	})
	mgrA.SetMaintenanceLease(leaseJobA)

	mgrB := newMaintenanceLeaseManager(t, nil)
	mgrB.SetMaintenanceLease(leaseJobB)

	var nodeBAttempts int32
	stopProbing := make(chan struct{})
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stopProbing:
				return
			case <-ticker.C:
				mgrB.getMaintenanceLease().RunIfLeader(context.Background(), func(context.Context) {
					atomic.AddInt32(&nodeBAttempts, 1)
					mgrB.runMaintenance()
				})
			}
		}
	}()

	ranA := mgrA.getMaintenanceLease().RunIfLeader(context.Background(), func(context.Context) {
		mgrA.runMaintenance()
	})
	close(stopProbing)
	<-probeDone

	assert.True(t, ranA)
	assert.Equal(t, int32(0), atomic.LoadInt32(&nodeBAttempts),
		"node-b must never run while node-a's slow cycle is still renewing the lease")
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of the DNA storage maintenance sweep: startMaintenanceTasks'
// ticker loop delegates to the lease set by SetMaintenanceLease (ADR-031
// Decision 4), so a second manager contending for the same lease must not run
// its own maintenance cycle while the first's is still in flight.
func TestManager_MaintenanceLease_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	leaseJobA, leaseJobB := twoMaintenanceLeaseJobs(t, "dna-storage-maintenance-test", ttl, renew)

	blocking := &blockingFlushBackend{started: make(chan struct{}), release: make(chan struct{})}
	mgrA := newMaintenanceLeaseManager(t, func(real Backend) Backend {
		blocking.Backend = real
		return blocking
	})
	mgrA.SetMaintenanceLease(leaseJobA)

	mgrB := newMaintenanceLeaseManager(t, nil)
	mgrB.SetMaintenanceLease(leaseJobB)

	cycle := func(m *Manager) func(ctx context.Context) {
		return func(context.Context) { m.runMaintenance() }
	}

	doneA := make(chan bool, 1)
	go func() {
		doneA <- mgrA.getMaintenanceLease().RunIfLeader(context.Background(), cycle(mgrA))
	}()

	select {
	case <-blocking.started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never started")
	}

	ranB := mgrB.getMaintenanceLease().RunIfLeader(context.Background(), cycle(mgrB))
	assert.False(t, ranB, "node-b must not run its own cycle while node-a's is still in flight")

	close(blocking.release)
	select {
	case ranA := <-doneA:
		assert.True(t, ranA)
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
	}
}
