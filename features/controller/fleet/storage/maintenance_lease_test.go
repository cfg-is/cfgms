// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"fmt"
	"sync"
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

// manualClock is a lease.Clock whose time moves only when the test advances
// it. It lets a test drive node-a's renewal ticker and retry backoff by
// explicit events, so the renewal-outage property does not depend on how fast
// the runner schedules goroutines. Every After/NewTicker registration is
// announced on registered so the test advances only once the code under test
// is actually waiting.
type manualClock struct {
	mu         sync.Mutex
	now        time.Time
	waiters    []*manualWaiter
	registered chan struct{}
}

type manualWaiter struct {
	at      time.Time
	period  time.Duration // zero for a one-shot After
	ch      chan time.Time
	stopped bool
}

func newManualClock() *manualClock {
	return &manualClock{
		now:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		registered: make(chan struct{}, 256),
	}
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Until(t time.Time) time.Duration { return t.Sub(c.Now()) }

func (c *manualClock) add(d, period time.Duration) *manualWaiter {
	c.mu.Lock()
	w := &manualWaiter{at: c.now.Add(d), period: period, ch: make(chan time.Time, 1)}
	c.waiters = append(c.waiters, w)
	c.mu.Unlock()
	c.registered <- struct{}{}
	return w
}

func (c *manualClock) After(d time.Duration) <-chan time.Time { return c.add(d, 0).ch }

func (c *manualClock) NewTicker(d time.Duration) lease.Ticker {
	return &manualTicker{clock: c, w: c.add(d, d)}
}

// advanceToNextAfter moves time forward to the earliest pending one-shot
// After deadline and fires every waiter due by then. Ticker ticks that fall
// due on the way are delivered like *time.Ticker's: at most one buffered,
// the rest dropped.
func (c *manualClock) advanceToNextAfter() {
	c.mu.Lock()
	defer c.mu.Unlock()
	var next *manualWaiter
	for _, w := range c.waiters {
		if w.period == 0 && !w.stopped && (next == nil || w.at.Before(next.at)) {
			next = w
		}
	}
	if next != nil {
		c.advanceLocked(next.at.Sub(c.now))
	}
}

// advance moves time forward by d and fires every waiter due by then.
func (c *manualClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.advanceLocked(d)
}

func (c *manualClock) advanceLocked(d time.Duration) {
	c.now = c.now.Add(d)
	pending := c.waiters[:0]
	for _, w := range c.waiters {
		if w.stopped {
			continue
		}
		if w.at.After(c.now) {
			pending = append(pending, w)
			continue
		}
		select {
		case w.ch <- c.now:
		default:
		}
		if w.period == 0 {
			continue
		}
		for !w.at.After(c.now) {
			w.at = w.at.Add(w.period)
		}
		pending = append(pending, w)
	}
	c.waiters = pending
}

type manualTicker struct {
	clock *manualClock
	w     *manualWaiter
}

func (t *manualTicker) C() <-chan time.Time { return t.w.ch }

func (t *manualTicker) Stop() {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	t.w.stopped = true
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
//
// Time is controlled, not slept (Issue #5178): the earlier version let the
// cycle run 1.5x the TTL on the wall clock while node-b probed every 100ms,
// which made the verdict depend on the runner scheduling node-a's renewal
// goroutine inside a 1.6s window. On a loaded native Windows runner (unretried
// flatfile rename path, coarse timers) one stalled renewal lapsed node-a's
// authority and node-b legitimately took over. Here node-a's lease Clock is a
// manualClock: each renewal tick is released by the test only after the
// previous renewal was observed to complete, node-b probes after every
// observed renewal, and the cycle is held open until logical time has passed
// 1.5x the TTL.
func TestManager_MaintenanceLease_SlowCycleRenewsAcrossTTL_NoDuplicateRun(t *testing.T) {
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond
	cycle := ttl + ttl/2

	type renewalEvent struct {
		n      int32
		failed bool
	}
	events := make(chan renewalEvent, 64)

	realStore := pkgtesting.SetupTestLeaseStore(t)
	observedStore := &transientErrorLeaseStore{
		LeaseStore: realStore, holderID: "node-a", // callNumber 0: never injects a failure
		afterCall: func(n int32, failed bool) { events <- renewalEvent{n: n, failed: failed} },
	}

	clockA := newManualClock()
	mgrAManager, err := lease.NewManagerWithClock(observedStore, ttl, renew, renew, clockA)
	require.NoError(t, err)
	mgrBManager, err := lease.NewManager(realStore, ttl, renew, renew)
	require.NoError(t, err)

	const name = "dna-storage-maintenance-slow-test"
	leaseJobA, err := lease.NewSingletonJob(mgrAManager, name, "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(mgrBManager, name, "node-b", ttl, renew, nil)
	require.NoError(t, err)

	blocking := &blockingFlushBackend{started: make(chan struct{}), release: make(chan struct{})}
	mgrA := newMaintenanceLeaseManager(t, func(real Backend) Backend {
		blocking.Backend = real
		return blocking
	})
	mgrA.SetMaintenanceLease(leaseJobA)

	mgrB := newMaintenanceLeaseManager(t, nil)
	mgrB.SetMaintenanceLease(leaseJobB)

	var nodeBAttempts int32
	probeB := func() {
		mgrB.getMaintenanceLease().RunIfLeader(context.Background(), func(context.Context) {
			atomic.AddInt32(&nodeBAttempts, 1)
			mgrB.runMaintenance()
		})
	}

	runCtxCh := make(chan context.Context, 1)
	var ctxErrAfterCycle error
	doneA := make(chan bool, 1)
	go func() {
		doneA <- mgrA.getMaintenanceLease().RunIfLeader(context.Background(), func(runCtx context.Context) {
			runCtxCh <- runCtx
			mgrA.runMaintenance()
			ctxErrAfterCycle = runCtx.Err()
		})
	}()

	runCtx := <-runCtxCh
	<-blocking.started
	<-events // the initial TryAcquire

	// Each iteration: release exactly one renewal tick, wait for that renewal to finish, probe node-b.
	start := clockA.Now()
	renewals := 0
	select {
	case <-clockA.registered: // the renewal ticker exists; it is the only registration here
	case <-runCtx.Done():
		require.FailNow(t, "node-a's run context was cancelled before its first renewal tick")
	}
	for clockA.Now().Sub(start) < cycle {
		if runCtx.Err() != nil {
			require.FailNow(t, "node-a's run context was cancelled mid-cycle",
				"after %d renewals (logical elapsed %s)", renewals, clockA.Now().Sub(start))
		}
		clockA.advance(renew)
		ev := <-events
		require.False(t, ev.failed, "no failure is injected in this test")
		renewals++
		probeB()
	}
	close(blocking.release)
	ranA := <-doneA

	assert.True(t, ranA)
	assert.NoError(t, ctxErrAfterCycle, "node-a's context must survive a cycle longer than the TTL")
	assert.GreaterOrEqual(t, renewals, int(cycle/renew),
		"the cycle must have outlived the TTL through successful renewals")
	assert.Equal(t, int32(0), atomic.LoadInt32(&nodeBAttempts),
		"node-b must never run while node-a's slow cycle is still renewing the lease")
}

// transientErrorLeaseStore wraps a real business.LeaseStore (the package's
// flatfile store, built by pkgtesting.SetupTestLeaseStore) and fails the
// callNumber'th AcquireOrRenew call made on behalf of holderID with a
// transient-looking error, delegating to the real store on every other call
// — reproducing one unretried store hiccup (e.g. the flatfile provider's
// atomic-rename write path on Windows, which deliberately does not retry:
// pkg/storage/providers/flatfile/rename_windows.go) hitting a single
// renewal mid-cycle, without reimplementing or mocking the store itself.
type transientErrorLeaseStore struct {
	business.LeaseStore
	holderID   string
	callNumber int32
	// lastCallNumber, when greater than callNumber, extends the failure to
	// every call from callNumber through lastCallNumber inclusive.
	lastCallNumber int32
	calls          int32
	// afterCall, when non-nil, is invoked after every holderID call with the
	// call's ordinal and whether it was an injected failure, so a test can
	// drive other actors off observed renewals instead of wall-clock time.
	afterCall func(n int32, failed bool)
}

func (s *transientErrorLeaseStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if holderID == s.holderID {
		last := s.lastCallNumber
		if last < s.callNumber {
			last = s.callNumber
		}
		n := atomic.AddInt32(&s.calls, 1)
		if n >= s.callNumber && n <= last {
			if s.afterCall != nil {
				s.afterCall(n, true)
			}
			return nil, fmt.Errorf("simulated transient lease store error (e.g. Windows ERROR_SHARING_VIOLATION on an unretried rename)")
		}
		state, err := s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
		if s.afterCall != nil {
			s.afterCall(n, false)
		}
		return state, err
	}
	return s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

// [REQUIRED TEST] (Issue #4487) A single transient error from the lease
// store on node-a's first mid-cycle renewal call must not cost node-a the
// lease outright: renewWithRetry (pkg/lease/singleton.go) must retry within
// Manager's MaxAllowedRenewalLatency budget before giving up. Before that
// retry existed, renewWhileRunning gave up on the very first error, cancelled
// node-a's context and stopped renewing, and node-b ran once the lease lapsed.
//
// Time is controlled, not slept (Issue #5228): node-a's lease manager runs on a
// manualClock and its cycle is held in Flush by a channel, so the renewal tick
// and the retry backoff fire only when the test advances time, and the cycle
// ends only when the test releases it. Node-b probes after every renewal call
// node-a makes. No wall-clock duration decides the verdict, so a slow runner
// cannot change it.
func TestManager_MaintenanceLease_TransientRenewalError_DoesNotLoseLease(t *testing.T) {
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond

	type renewalEvent struct {
		n      int32
		failed bool
	}
	events := make(chan renewalEvent, 64)

	realStore := pkgtesting.SetupTestLeaseStore(t)
	// Fail node-a's second AcquireOrRenew call: call #1 is RunIfLeader's
	// initial TryAcquire, call #2 is the first mid-cycle renewal tick, call #3
	// is its retry and succeeds.
	flakyStore := &transientErrorLeaseStore{
		LeaseStore: realStore, holderID: "node-a", callNumber: 2,
		afterCall: func(n int32, failed bool) { events <- renewalEvent{n: n, failed: failed} },
	}

	clockA := newManualClock()
	mgrAManager, err := lease.NewManagerWithClock(flakyStore, ttl, renew, renew, clockA)
	require.NoError(t, err)
	mgrBManager, err := lease.NewManager(realStore, ttl, renew, renew)
	require.NoError(t, err)

	const name = "dna-storage-maintenance-flaky-test"
	leaseJobA, err := lease.NewSingletonJob(mgrAManager, name, "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(mgrBManager, name, "node-b", ttl, renew, nil)
	require.NoError(t, err)

	blocking := &blockingFlushBackend{started: make(chan struct{}), release: make(chan struct{})}
	mgrA := newMaintenanceLeaseManager(t, func(real Backend) Backend {
		blocking.Backend = real
		return blocking
	})
	mgrA.SetMaintenanceLease(leaseJobA)

	mgrB := newMaintenanceLeaseManager(t, nil)
	mgrB.SetMaintenanceLease(leaseJobB)

	var nodeBAttempts int32
	probeB := func() {
		mgrB.getMaintenanceLease().RunIfLeader(context.Background(), func(context.Context) {
			atomic.AddInt32(&nodeBAttempts, 1)
			mgrB.runMaintenance()
		})
	}

	runCtxCh := make(chan context.Context, 1)
	var ctxErrAfterCycle error
	doneA := make(chan bool, 1)
	go func() {
		doneA <- mgrA.getMaintenanceLease().RunIfLeader(context.Background(), func(runCtx context.Context) {
			runCtxCh <- runCtx
			mgrA.runMaintenance()
			ctxErrAfterCycle = runCtx.Err()
		})
	}()

	runCtx := <-runCtxCh
	<-blocking.started
	<-events // the initial TryAcquire

	// waitRegistered blocks until node-a's renewal goroutine is waiting on the
	// clock (its ticker, or a retry backoff), or reports false if node-a gave
	// up and cancelled its run context instead.
	waitRegistered := func() bool {
		select {
		case <-clockA.registered:
			return true
		case <-runCtx.Done():
			return false
		}
	}

	// First renewal tick (fails), then the retry backoff (succeeds), then one
	// further regular tick to show renewal carries on after the error.
	stillRenewing := waitRegistered()
	if stillRenewing {
		clockA.advance(renew)
		ev := <-events
		probeB()
		assert.True(t, ev.failed, "the first mid-cycle renewal is the injected failure")
		if stillRenewing = waitRegistered(); stillRenewing {
			clockA.advanceToNextAfter()
			ev = <-events
			probeB()
			assert.False(t, ev.failed, "the retry after the transient error succeeds")
			clockA.advance(renew)
			ev = <-events
			probeB()
			assert.False(t, ev.failed, "renewal continues after the transient error")
		}
	}
	close(blocking.release)
	ranA := <-doneA

	assert.True(t, stillRenewing, "node-a must retry rather than give up on a single transient error")
	assert.True(t, ranA)
	assert.NoError(t, ctxErrAfterCycle,
		"node-a's context must not be cancelled by a single transient renewal error")
	assert.Equal(t, int32(0), atomic.LoadInt32(&nodeBAttempts),
		"a single transient renewal-store error must not cost node-a the lease")
}

// [REQUIRED TEST] (Issue #4541) A renewal-store outage that outlasts
// Manager's MaxAllowedRenewalLatency (200ms here) but ends well inside the
// lease's safety margin must not cost node-a the lease. Before #4541,
// renewWithRetry gave up at the 200ms latency budget, cancelled node-a's
// context and stopped renewing while the lease still had ~1.8s left; node-a's
// cycle (which, like the real sweep, does not observe cancellation
// mid-Flush) kept running, the lease lapsed, and node-b ran.
//
// The test is event-driven, not wall-clock-driven. node-a's lease manager runs
// on a manualClock, so its renewal tick and every retry backoff happen only
// when the test advances time; node-a's cycle is held in Flush by a channel and
// released once the store has observed the first successful renewal after the
// injected outage (calls #2-#9 fail, call #10 succeeds). In node-a's clock the
// outage spans 200ms (first tick) + 10+20+40+80+160+200+200+200ms of backoff,
// i.e. 1.11s — far past the 200ms latency budget, inside the 1.6s safety
// margin. Node-b probes once after every renewal call node-a makes, and the
// property asserted is that node-a's context was never cancelled by a
// premature give-up and node-b never ran.
func TestManager_MaintenanceLease_RenewalOutageBeyondLatencyBudget_DoesNotLoseLease(t *testing.T) {
	ttl := 2 * time.Second
	renew := 200 * time.Millisecond

	// Call #1 is the initial TryAcquire; calls #2-#9 are the first renewal
	// tick and its retries; call #10 is the first renewal that succeeds.
	const firstSuccessfulRenewal = 10
	type renewalEvent struct {
		n      int32
		failed bool
	}
	events := make(chan renewalEvent, 64)

	realStore := pkgtesting.SetupTestLeaseStore(t)
	flakyStore := &transientErrorLeaseStore{
		LeaseStore: realStore, holderID: "node-a", callNumber: 2, lastCallNumber: 9,
		afterCall: func(n int32, failed bool) { events <- renewalEvent{n: n, failed: failed} },
	}

	clockA := newManualClock()
	mgrAManager, err := lease.NewManagerWithClock(flakyStore, ttl, renew, renew, clockA)
	require.NoError(t, err)
	mgrBManager, err := lease.NewManager(realStore, ttl, renew, renew)
	require.NoError(t, err)

	const name = "dna-storage-maintenance-outage-test"
	leaseJobA, err := lease.NewSingletonJob(mgrAManager, name, "node-a", ttl, renew, nil)
	require.NoError(t, err)
	leaseJobB, err := lease.NewSingletonJob(mgrBManager, name, "node-b", ttl, renew, nil)
	require.NoError(t, err)

	blocking := &blockingFlushBackend{started: make(chan struct{}), release: make(chan struct{})}
	mgrA := newMaintenanceLeaseManager(t, func(real Backend) Backend {
		blocking.Backend = real
		return blocking
	})
	mgrA.SetMaintenanceLease(leaseJobA)

	mgrB := newMaintenanceLeaseManager(t, nil)
	mgrB.SetMaintenanceLease(leaseJobB)

	var nodeBAttempts int32
	probeB := func() {
		mgrB.getMaintenanceLease().RunIfLeader(context.Background(), func(context.Context) {
			atomic.AddInt32(&nodeBAttempts, 1)
			mgrB.runMaintenance()
		})
	}

	runCtxCh := make(chan context.Context, 1)
	var ctxErrAfterCycle error
	doneA := make(chan bool, 1)
	go func() {
		doneA <- mgrA.getMaintenanceLease().RunIfLeader(context.Background(), func(runCtx context.Context) {
			runCtxCh <- runCtx
			mgrA.runMaintenance()
			ctxErrAfterCycle = runCtx.Err()
		})
	}()

	runCtx := <-runCtxCh
	<-blocking.started

	// waitRegistered blocks until node-a's renewal goroutine is waiting on the
	// clock (its ticker, or a retry backoff), or reports false if node-a gave
	// up and cancelled its run context instead.
	waitRegistered := func() bool {
		select {
		case <-clockA.registered:
			return true
		case <-runCtx.Done():
			return false
		}
	}

	// First renewal tick: once the renewal ticker exists, advance one interval.
	stillRenewing := waitRegistered()
	if stillRenewing {
		clockA.advance(renew)
	}
	for stillRenewing {
		ev := <-events
		probeB()
		if ev.n == 1 {
			// The initial TryAcquire, observed before the first tick.
			continue
		}
		if !ev.failed {
			if ev.n >= firstSuccessfulRenewal {
				break
			}
			continue
		}
		// A failed renewal: node-a must schedule a retry backoff rather than
		// give up; fire it.
		if stillRenewing = waitRegistered(); stillRenewing {
			clockA.advanceToNextAfter()
		}
	}
	close(blocking.release)
	ranA := <-doneA

	assert.True(t, ranA)
	assert.NoError(t, ctxErrAfterCycle,
		"node-a's context must not be cancelled by a renewal outage inside the safety margin")
	assert.GreaterOrEqual(t, atomic.LoadInt32(&flakyStore.calls), int32(firstSuccessfulRenewal),
		"node-a must keep renewing through the outage until a renewal succeeds")
	assert.Equal(t, int32(0), atomic.LoadInt32(&nodeBAttempts),
		"a renewal outage inside the safety margin must not let node-b acquire the lease")
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

	// The wait budget is expressed off ttl/renew, not a bare constant: the
	// real Flush that runs after release can absorb Windows SQLITE_BUSY
	// retries (#4189), and a completion budget the same size as the lease TTL
	// (the original fixed 2s) leaves no room for that on a resource-constrained
	// merge-queue runner. 10x ttl gives that headroom; polling on renew keeps
	// the check as responsive as the lease's own renewal cadence.
	var ranA bool
	require.Eventually(t, func() bool {
		select {
		case ranA = <-doneA:
			return true
		default:
			return false
		}
	}, ttl*10, renew, "node-a's cycle never completed")
	assert.True(t, ranA)
}
