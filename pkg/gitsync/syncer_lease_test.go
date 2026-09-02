// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package gitsync_test

import (
	"path/filepath"
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
func newLeaseGatedSyncer(t *testing.T, leaseManager *lease.Manager, holderID string) (*gitsync.Syncer, chan time.Time, chan struct{}) {
	t.Helper()
	root := t.TempDir()

	store := pkgtesting.SetupTestStorage(t).GetConfigStore()
	bindings, err := gitsync.NewBindingStore(root)
	require.NoError(t, err)

	tickerFactory, tickCh := manualTicker()
	notify := make(chan struct{}, 4)

	syncer, err := gitsync.NewSyncer(store, bindings, filepath.Join(root, "repos"), logging.NewNoopLogger(),
		gitsync.WithTickerFunc(tickerFactory),
		gitsync.WithSyncNotify(notify),
		gitsync.WithLeaseJobFactory(func(name string) (lease.SingletonJob, error) {
			return lease.NewSingletonJob(leaseManager, name, holderID, leaseManager.LeaseTTL(), 200*time.Millisecond, nil)
		}),
	)
	require.NoError(t, err)
	return syncer, tickCh, notify
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

	syncerA, tickA, notifyA := newLeaseGatedSyncer(t, m1, "node-a")
	syncerB, tickB, notifyB := newLeaseGatedSyncer(t, m2, "node-b")

	binding := gitsync.ScopeBinding{
		TenantPath:      "root/tenant-x",
		Namespace:       "gitsync-lease-test",
		OriginURL:       "http://127.0.0.1:1/nonexistent.git", // fails fast; TriggerSync's error path still fires syncNotify
		PollingInterval: time.Hour,                            // never fires on its own; test drives ticks manually
	}

	require.NoError(t, syncerA.AddBinding(binding))
	require.NoError(t, syncerB.AddBinding(binding))

	// node-a's tick fires first and must acquire+run.
	tickA <- time.Now()
	select {
	case <-notifyA:
	case <-time.After(2 * time.Second):
		t.Fatal("node-a's cycle never completed")
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
	time.Sleep(ttl)
	tickB <- time.Now()
	select {
	case <-notifyB:
	case <-time.After(2 * time.Second):
		t.Fatal("node-b never ran after node-a's lease expired")
	}

	assert.NotNil(t, syncerA)
	assert.NotNil(t, syncerB)
}
