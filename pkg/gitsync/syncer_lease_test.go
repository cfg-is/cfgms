// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/gitsync"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// manualTicker returns a WithTickerFunc-compatible factory whose channel this
// test controls directly, plus a func to send a synthetic tick.
func manualTicker() (func(d time.Duration) (<-chan time.Time, func()), chan time.Time) {
	tickCh := make(chan time.Time, 1)
	factory := func(time.Duration) (<-chan time.Time, func()) {
		return tickCh, func() {}
	}
	return factory, tickCh
}

// newLeaseGatedSyncer builds a Syncer whose per-scope polling cycle claims a
// lease under name via leaseManager, contending as holderID. A manually
// controlled ticker and a sync-notify channel let the test drive and observe
// individual polling cycles without a real ticker interval.
//
// The returned func reports the lease name the syncer's per-scope job was
// built with, so the test can read the lease row back from the store.
func newLeaseGatedSyncer(t *testing.T, leaseManager *lease.Manager, holderID string) (*gitsync.Syncer, chan time.Time, chan struct{}, func() string) {
	t.Helper()
	root := t.TempDir()

	store := pkgtesting.SetupTestStorage(t).GetConfigStore()
	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	tickerFactory, tickCh := manualTicker()
	notify := make(chan struct{}, 4)

	var nameMu sync.Mutex
	var leaseName string

	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logging.NewNoopLogger(),
		gitsync.WithTickerFunc(tickerFactory),
		gitsync.WithSyncNotify(notify),
		gitsync.WithLeaseJobFactory(func(name string) (lease.SingletonJob, error) {
			nameMu.Lock()
			leaseName = name
			nameMu.Unlock()
			return lease.NewSingletonJob(leaseManager, name, holderID, leaseManager.LeaseTTL(), 200*time.Millisecond, nil)
		}),
	)
	require.NoError(t, err)
	t.Cleanup(syncer.Stop)
	return syncer, tickCh, notify, func() string {
		nameMu.Lock()
		defer nameMu.Unlock()
		return leaseName
	}
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of a gitsync scope's polling loop: startScope wraps TriggerSync
// with the per-scope lease built by leaseJobFactory (ADR-031 Decision 4), so a
// second syncer contending for the same scope's lease must not run its own
// poll while the first still holds the unexpired lease.
func TestSyncer_PerScopeLease_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	leaseStore := pkgtesting.SetupTestLeaseStore(t)
	ttl := 3 * time.Second
	renew := 200 * time.Millisecond
	m1, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)
	m2, err := lease.NewManager(leaseStore, ttl, renew, renew)
	require.NoError(t, err)

	syncerA, tickA, notifyA, _ := newLeaseGatedSyncer(t, m1, "node-a")
	syncerB, tickB, notifyB, leaseNameB := newLeaseGatedSyncer(t, m2, "node-b")

	binding := gitsync.ScopeBinding{
		TenantPath: "root/tenant-x",
		Namespace:  "gitsync-lease-test",
		// A guaranteed-nonexistent local filesystem path, not a network URL
		// (Issue #4252): go-git's clone against it fails via a local fs.Stat,
		// so TriggerSync's error path (which still fires syncNotify) completes
		// in sub-millisecond time on every OS. The previous network origin
		// ("http://127.0.0.1:1/nonexistent.git") let this test's timing depend
		// on the runner's OS TCP stack instead — on windows-latest the failed
		// connect took >2s (measured: `FAIL github.com/cfgis/cfgms/pkg/gitsync`
		// with this subtest reporting "(2.29s)", merge-queue run 35927962385
		// job 107407473957, 2026-09-23 22:37Z), past the fixed 2s budget this
		// test used to wait on. No product timing was involved: that run's log
		// shows the lease was acquired immediately (TryAcquire is a single
		// synchronous store round trip, pkg/lease/singleton.go's RunIfLeader);
		// the delay was entirely inside syncScope's HTTP dial attempt, which
		// this change removes rather than papering over with a longer wait.
		OriginURL:       filepath.Join(t.TempDir(), "nonexistent-origin"),
		PollingInterval: time.Hour, // never fires on its own; test drives ticks manually
	}

	require.NoError(t, syncerA.AddBinding(binding))
	require.NoError(t, syncerB.AddBinding(binding))

	// nodeCycleHangBudget bounds how long this test waits for a sync cycle's
	// completion signal. With the local-filesystem origin above it is a pure
	// hang detector, not a correctness-relevant value — real elapsed time is
	// sub-millisecond since no network I/O is involved.
	const nodeCycleHangBudget = 10 * time.Second

	// node-a's tick fires first and must acquire+run.
	cycleStart := time.Now()
	tickA <- time.Now()
	select {
	case <-notifyA:
		t.Logf("node-a's cycle completed in %s", time.Since(cycleStart))
	case <-time.After(nodeCycleHangBudget):
		t.Fatalf("node-a's cycle never completed within %s", nodeCycleHangBudget)
	}

	// node-b's tick fires immediately after, while node-a's lease is still
	// unexpired (ttl=3s) — node-b must not run.
	tickB <- time.Now()
	select {
	case <-notifyB:
		t.Fatal("node-b must not run its own cycle while node-a's lease is still held")
	case <-time.After(300 * time.Millisecond):
	}

	// Once the lease expires, node-b's next tick must succeed — the exclusion
	// is bounded by TTL, not permanent.
	//
	// The lease's actual expiry is not "node-a's notify + ttl": node-a's
	// renewal goroutine (RenewInterval=200ms) keeps extending ExpiresAt for as
	// long as its cycle runs, and a renewal write already in flight when the
	// cycle ends still lands afterwards, stamped with the store's clock at
	// write time. Under a loaded runner a single flatfile write can take well
	// over a second (node-a's acquire+cycle measured 1.59s in the run that
	// exposed this), so a lone tick fired at a fixed "notify + ttl" instant
	// could still find node-a's lease valid and be refused — and with no
	// further tick, node-b would never run. Instead, keep offering node-b
	// ticks (one per contention attempt, exactly as its polling loop would see
	// them) until it acquires, and assert the TTL bound directly: node-a
	// acquired no earlier than nodeACycleStart, so the earliest instant its
	// lease can have expired is nodeACycleStart+ttl.
	nodeACycleStart := cycleStart
	retryTicker := time.NewTicker(100 * time.Millisecond)
	defer retryTicker.Stop()
	deadline := time.After(ttl + nodeCycleHangBudget)
	offerTickB := func() {
		select {
		case tickB <- time.Now():
		default: // a tick is already pending for node-b's loop
		}
	}
	offerTickB()
	var nodeBRanAt time.Time
waitNodeB:
	for {
		select {
		case <-notifyB:
			nodeBRanAt = time.Now()
			break waitNodeB
		case <-retryTicker.C:
			offerTickB()
		case <-deadline:
			t.Fatalf("node-b never ran within %s of node-a's cycle (ttl=%s)", ttl+nodeCycleHangBudget, ttl)
		}
	}
	t.Logf("node-b ran %s after node-a's cycle started", nodeBRanAt.Sub(nodeACycleStart))
	assert.False(t, nodeBRanAt.Before(nodeACycleStart.Add(ttl)),
		"node-b ran %s after node-a's cycle started, before node-a's lease (ttl=%s) could have expired",
		nodeBRanAt.Sub(nodeACycleStart), ttl)

	require.NotEmpty(t, leaseNameB(), "node-b's per-scope lease job must have been built")
	holder, _, _, ok, err := m2.CurrentHolder(context.Background(), leaseNameB())
	require.NoError(t, err)
	require.True(t, ok, "lease row must exist after node-b's cycle")
	assert.Equal(t, "node-b", holder, "node-b must have run by acquiring the scope lease, not ungated")

	assert.NotNil(t, syncerA)
	assert.NotNil(t, syncerB)
}
