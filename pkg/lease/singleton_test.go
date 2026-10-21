// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package lease

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// renewFailingStore delegates every call to a real store, but fails every
// AcquireOrRenew call after the first failAfter successful ones. Used to
// simulate a store outage discovered mid-renewal, not to fake decisions the
// real store would make (CLAUDE.md's no-mocks rule) — every call that does
// succeed is answered by the real underlying store.
type renewFailingStore struct {
	business.LeaseStore
	failAfter int32
	calls     int32
}

func (s *renewFailingStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	n := atomic.AddInt32(&s.calls, 1)
	if n > s.failAfter {
		return nil, errors.New("simulated lease store outage")
	}
	return s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

// fakeClock is a Clock the test advances explicitly. Its Now is anchored at
// the real instant of construction and then moves only when advanced, so a
// deadline derived from the Manager's real monotonic reading (always at or
// after the anchor) can only look further away, never nearer, if the host
// stalls.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	ticker *fakeTicker
	timers []*fakeTimer
	// timerArmed receives one value per NewTimer call, so a test can wait for
	// the watchdog to be parked on the clock before advancing it. Without
	// that, Advance can land between the watchdog reading the remaining time
	// and arming its timer, and the timer is then set relative to the
	// already-advanced clock and never fires.
	timerArmed chan struct{}
}

// fakeTimer fires once the clock has been advanced to or past at.
type fakeTimer struct {
	clock   *fakeClock
	at      time.Time
	c       chan time.Time
	stopped bool
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }
func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	t.stopped = true
	return true
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Now(), ticker: &fakeTicker{c: make(chan time.Time, 1)}, timerArmed: make(chan struct{}, 16)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	pending := c.timers[:0]
	for _, t := range c.timers {
		switch {
		case t.stopped:
		case !t.at.After(c.now):
			t.c <- c.now
		default:
			pending = append(pending, t)
		}
	}
	c.timers = pending
}

// NewTimer fires when the test advances the clock to or past now+d, so the
// authority-deadline watchdog is driven by explicit events, not timer
// scheduling.
func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{clock: c, at: c.now.Add(d), c: make(chan time.Time, 1)}
	c.timers = append(c.timers, t)
	select {
	case c.timerArmed <- struct{}{}:
	default:
	}
	return t
}

func (c *fakeClock) Until(t time.Time) time.Duration { return t.Sub(c.Now()) }

func (c *fakeClock) NewTicker(time.Duration) Ticker { return c.ticker }

// After elapses immediately, advancing the clock by d: a backoff wait costs
// the simulated time it asks for and no real time.
func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.Advance(d)
	ch := make(chan time.Time, 1)
	ch <- c.Now()
	return ch
}

// Tick delivers one renewal tick to the job's ticker.
func (c *fakeClock) Tick() { c.ticker.c <- c.Now() }

type fakeTicker struct{ c chan time.Time }

func (t *fakeTicker) C() <-chan time.Time { return t.c }
func (t *fakeTicker) Stop()               {}

// fakeClockLeaseStore is a business.LeaseStore with the real stores' contract
// (fresh token on acquisition, unchanged token on renewal, refusal while
// another holder's row is unexpired) whose expiry is evaluated against a
// fakeClock instead of the wall clock.
type fakeClockLeaseStore struct {
	clock *fakeClock
	mu    sync.Mutex
	rows  map[string]*business.LeaseState
	high  map[string]uint64
}

func newFakeClockLeaseStore(clock *fakeClock) *fakeClockLeaseStore {
	return &fakeClockLeaseStore{
		clock: clock,
		rows:  make(map[string]*business.LeaseState),
		high:  make(map[string]uint64),
	}
}

func (s *fakeClockLeaseStore) AcquireOrRenew(_ context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	row, ok := s.rows[name]
	switch {
	case ok && now.Before(row.ExpiresAt) && row.HolderID != holderID:
		return &business.LeaseState{Name: name, HolderID: row.HolderID, Token: row.Token, ExpiresAt: row.ExpiresAt, Valid: true}, nil
	case ok && now.Before(row.ExpiresAt):
		row.ExpiresAt = now.Add(ttl)
	default:
		s.high[name]++
		row = &business.LeaseState{Name: name, HolderID: holderID, Token: s.high[name], ExpiresAt: now.Add(ttl)}
		s.rows[name] = row
	}
	return &business.LeaseState{Name: name, HolderID: holderID, Token: row.Token, ExpiresAt: row.ExpiresAt, Valid: true, Acquired: true}, nil
}

func (s *fakeClockLeaseStore) Release(_ context.Context, name, holderID string, token uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if row, ok := s.rows[name]; ok && row.HolderID == holderID && row.Token == token {
		row.ExpiresAt = s.clock.Now()
	}
	return nil
}

func (s *fakeClockLeaseStore) GetLease(_ context.Context, name string) (*business.LeaseState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	row, ok := s.rows[name]
	if !ok {
		return nil, business.ErrLeaseNotFound
	}
	out := *row
	out.Valid = s.clock.Now().Before(row.ExpiresAt)
	return &out, nil
}

func (s *fakeClockLeaseStore) Close() error { return nil }

// signalingStore closes done after the first successful AcquireOrRenew call
// numbered afterCall or later (1-indexed), letting a test wait on the store
// event it needs instead of sleeping.
type signalingStore struct {
	business.LeaseStore
	afterCall int32
	calls     int32
	done      chan struct{}
	once      sync.Once
}

func newSignalingStore(inner business.LeaseStore, afterCall int32) *signalingStore {
	return &signalingStore{LeaseStore: inner, afterCall: afterCall, done: make(chan struct{})}
}

func (s *signalingStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	n := atomic.AddInt32(&s.calls, 1)
	state, err := s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
	if err == nil && n >= s.afterCall {
		s.once.Do(func() { close(s.done) })
	}
	return state, err
}

func TestNewSingletonJob_NilManagerSkipsTTLValidation(t *testing.T) {
	job, err := NewSingletonJob(nil, "x", "node-1", 0, 0, nil)
	require.NoError(t, err)
	assert.Nil(t, job.Manager)
}

func TestNewSingletonJob_RejectsEmptyNameOrHolder(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, time.Second, 200*time.Millisecond, 200*time.Millisecond)
	require.NoError(t, err)

	_, err = NewSingletonJob(m, "", "node-1", time.Second, 200*time.Millisecond, nil)
	require.Error(t, err)

	_, err = NewSingletonJob(m, "x", "", time.Second, 200*time.Millisecond, nil)
	require.Error(t, err)
}

func TestNewSingletonJob_RejectsNonPositiveTTLOrRenewInterval(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, time.Second, 200*time.Millisecond, 200*time.Millisecond)
	require.NoError(t, err)

	_, err = NewSingletonJob(m, "x", "node-1", 0, 200*time.Millisecond, nil)
	require.Error(t, err)

	_, err = NewSingletonJob(m, "x", "node-1", time.Second, 0, nil)
	require.Error(t, err)
}

// A nil Manager means no shared substrate is wired (e.g. SingleServerMode —
// ADR-029 Decision 4: one node, nothing to exclude). RunIfLeader must always
// execute fn in that case.
func TestSingletonJob_NilManager_AlwaysRuns(t *testing.T) {
	job, err := NewSingletonJob(nil, "x", "node-1", 0, 0, nil)
	require.NoError(t, err)

	var called bool
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) { called = true })
	assert.True(t, ran)
	assert.True(t, called)
}

func TestSingletonJob_SkipsWhenLeaseHeldByAnother(t *testing.T) {
	store := newTestStore(t)
	ttl := 5 * time.Second
	m1, err := NewManager(store, ttl, time.Second, time.Second)
	require.NoError(t, err)
	m2, err := NewManager(store, ttl, time.Second, time.Second)
	require.NoError(t, err)

	job1, err := NewSingletonJob(m1, "x", "node-1", ttl, time.Second, nil)
	require.NoError(t, err)
	job2, err := NewSingletonJob(m2, "x", "node-2", ttl, time.Second, nil)
	require.NoError(t, err)

	ran1 := job1.RunIfLeader(context.Background(), func(ctx context.Context) {})
	require.True(t, ran1)

	var called bool
	ran2 := job2.RunIfLeader(context.Background(), func(ctx context.Context) { called = true })
	assert.False(t, ran2, "a second node must not run while the first holds the unexpired lease")
	assert.False(t, called)
}

// [REQUIRED TEST] A two-node simulation proves exactly one node executes a
// given cycle of a lease-claimed loop: node-2 attempts to run while node-1's
// cycle is still in flight (holding the lease) and must be refused. Time is
// simulated: the lease outlives its original TTL only because node-1's
// renewal ran, and nothing here depends on how fast the host schedules
// goroutines.
func TestSingletonJob_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	clock := newFakeClock()
	store := newSignalingStore(newFakeClockLeaseStore(clock), 2) // call #1 acquire, #2 renewal
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	m1, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	m2, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)

	job1, err := NewSingletonJob(m1, "sweep-x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job1.Clock = clock
	job2, err := NewSingletonJob(m2, "sweep-x", "node-2", ttl, renewInterval, nil)
	require.NoError(t, err)
	job2.Clock = clock

	node1Started := make(chan struct{})
	releaseNode1 := make(chan struct{})
	var node1Ran, node2Ran int32

	done1 := make(chan bool, 1)
	go func() {
		ran := job1.RunIfLeader(context.Background(), func(ctx context.Context) {
			atomic.AddInt32(&node1Ran, 1)
			close(node1Started)
			<-releaseNode1
		})
		done1 <- ran
	}()

	<-node1Started

	// Renew inside node-1's local authority window (advancing straight past
	// it would let the authority-deadline watchdog cancel fn before the
	// renewal reaches the store), then move past the original expiry so only
	// the renewal keeps node-1 the holder.
	clock.Advance(renewInterval)
	clock.Tick()
	select {
	case <-store.done:
	case <-time.After(30 * time.Second): // failure bound only; the passing path waits on the event
		t.Fatal("node-1's renewal never reached the store")
	}
	clock.Advance(ttl - renewInterval/2)

	ran2 := job2.RunIfLeader(context.Background(), func(ctx context.Context) {
		atomic.AddInt32(&node2Ran, 1)
	})
	assert.False(t, ran2, "node-2 must not run while node-1 holds the lease")

	close(releaseNode1)
	assert.True(t, <-done1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&node1Ran))
	assert.Equal(t, int32(0), atomic.LoadInt32(&node2Ran))
}

// [REQUIRED TEST] A slow cycle that approaches (and, here, far exceeds) the
// lease TTL renews successfully via RunIfLeader's background renewal
// goroutine and does not trigger a duplicate run on another node contending
// for the same lease throughout.
func TestSingletonJob_SlowCycleRenewsAcrossTTL_NoDuplicateRun(t *testing.T) {
	// Generous margin (ttl-renewInterval=1.8s of scheduling slack per renewal)
	// so this test does not race itself when the full suite runs packages in
	// parallel under load — a tight margin here would make an occasional missed
	// renewal window (goroutine scheduling delay, not a logic bug) look like a
	// broken renewal loop. See TestManager_HasLocalAuthority_ExpiresAtSafetyMarginNotTTL's
	// comment on the same class of flakiness.
	//
	// Issue #4160 investigated widening this margin after a single observed
	// failure on a GitHub-hosted windows-latest merge-queue runner, but measured
	// evidence did not support it: instrumenting the renewal loop's actual
	// inter-renewal gaps (watching the store's ExpiresAt from outside, without
	// touching production code) under this development host's OWN full
	// `go test ./pkg/... ./features/...` suite running concurrently under -race
	// — genuine multi-package compile-and-run contention, not a synthetic
	// busy-loop — measured a worst-case gap of ~290ms against the 200ms
	// renewInterval, an order of magnitude below the 1.8s margin already in
	// place. That does not rule out the one-time GitHub-hosted-runner failure
	// (a shared, resource-constrained host under real merge-queue load is a
	// different environment this one cannot faithfully reproduce), but it does
	// mean there is no measured basis for concluding the existing 1.8s margin
	// is the wrong number, which is what AC2 requires before a margin change
	// counts as a fix rather than a bare timeout inflation. Left unchanged;
	// see the story's PR description for the full investigation.
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	runSlowCycleNoDuplicate(t, newTestStore(t), ttl, renewInterval, false)
}

// delayedAcquireStore delegates every call to a real store after sleeping for
// delay, modelling a slow store write (e.g. the flatfile atomic-rename path on
// Windows or an antivirus-scanned temp file on a CI runner). The delay is a
// real sleep in front of the real store's own grant logic; no decision is
// faked.
type delayedAcquireStore struct {
	business.LeaseStore
	delay time.Duration
}

func (s *delayedAcquireStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	time.Sleep(s.delay)
	return s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

// Issue #5028 / #5106: a holder whose every store write (the first acquire and
// each renewal) takes half the Manager's MaxAllowedRenewalLatency — slow, but
// inside the configured bound — must keep exclusion across a cycle longer than
// the TTL. The delay is derived from the Manager's own bound, so the test
// stays within the margin the Manager was built with; delays beyond it are
// covered by TestSingletonJob_RenewalStallBeyondLatencyBound_CancelsBeforeAnotherHolderAcquires.
func TestSingletonJob_SlowStoreWrites_WithinMargin_NoDuplicateRun(t *testing.T) {
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	runSlowCycleNoDuplicate(t, newTestStore(t), ttl, renewInterval, true)
}

// runSlowCycleNoDuplicate runs node-1 through a cycle of 1.25*ttl while node-2
// probes the same lease every renewInterval/2. Node-2's probe is started from
// inside node-1's fn, i.e. only once node-1 actually holds the lease: starting
// it earlier races node-1's first acquire (the probe's first tick is 100ms
// out, and a runner that delays node-1's acquire by more than that lets node-2
// take the lease first — a test-setup race, not a lease defect, Issue #5028).
// When slowWrites is set, node-1's store writes are delayed by half the
// Manager's MaxAllowedRenewalLatency.
func runSlowCycleNoDuplicate(t *testing.T, base business.LeaseStore, ttl, renewInterval time.Duration, slowWrites bool) {
	t.Helper()
	store1 := &delayedAcquireStore{LeaseStore: base}
	m1, err := NewManager(store1, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	if slowWrites {
		// Derived from the Manager's own bound; set before any store call.
		store1.delay = m1.MaxAllowedRenewalLatency() / 2
	}
	m2, err := NewManager(base, ttl, renewInterval, renewInterval)
	require.NoError(t, err)

	job1, err := NewSingletonJob(m1, "slow-sweep", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job2, err := NewSingletonJob(m2, "slow-sweep", "node-2", ttl, renewInterval, nil)
	require.NoError(t, err)

	var node2Attempts int32
	stopProbing := make(chan struct{})
	var probeWG sync.WaitGroup
	startProbe := func() {
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			ticker := time.NewTicker(renewInterval / 2)
			defer ticker.Stop()
			for {
				select {
				case <-stopProbing:
					return
				case <-ticker.C:
					job2.RunIfLeader(context.Background(), func(ctx context.Context) {
						atomic.AddInt32(&node2Attempts, 1)
					})
				}
			}
		}()
	}

	// node-1's cycle runs longer than ttl, proving the background renewal
	// keeps the lease alive rather than losing it partway through.
	cycleDuration := ttl + ttl/4
	ran1 := job1.RunIfLeader(context.Background(), func(ctx context.Context) {
		startProbe()
		time.Sleep(cycleDuration)
	})
	close(stopProbing)
	probeWG.Wait()

	assert.True(t, ran1)
	assert.Equal(t, int32(0), atomic.LoadInt32(&node2Attempts),
		"node-2 must never run while node-1's slow cycle is still renewing the lease")
}

// A renewal failure mid-cycle (simulated store outage) must cancel fn's
// context so the loop's own business logic can observe the lost lease and
// stop, rather than silently continuing to mutate state after authority is
// gone.
func TestSingletonJob_RenewFailureCancelsFnContext(t *testing.T) {
	base := newTestStore(t)
	store := &renewFailingStore{LeaseStore: base, failAfter: 1} // only the initial acquire succeeds
	ttl := 200 * time.Millisecond
	renewInterval := 30 * time.Millisecond
	m, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	job, err := NewSingletonJob(m, "x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)

	ctxCancelled := make(chan struct{})
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) {
		select {
		case <-ctx.Done():
			close(ctxCancelled)
		case <-time.After(2 * time.Second):
		}
	})
	assert.True(t, ran)

	select {
	case <-ctxCancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for fn's context to be cancelled after a renewal failure")
	}
}

// renewOnceFailingStore delegates every call to a real store, but fails
// exactly the callNumber'th AcquireOrRenew call (1-indexed, across all
// holders) with a transient-looking error, then resumes delegating normally.
// Models one unretried store hiccup — e.g. the flatfile provider's
// atomic-rename write path on Windows, which deliberately does not retry
// (pkg/storage/providers/flatfile/rename_windows.go) — landing on a single
// renewal tick, as opposed to renewFailingStore's permanent outage.
type renewOnceFailingStore struct {
	business.LeaseStore
	callNumber int32
	calls      int32
}

func (s *renewOnceFailingStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if n := atomic.AddInt32(&s.calls, 1); n == s.callNumber {
		return nil, errors.New("simulated transient lease store error")
	}
	return s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

// [REQUIRED TEST] (Issue #4487) renewWithRetry (pkg/lease/singleton.go) must
// absorb a single transient renewal error within Manager's
// MaxAllowedRenewalLatency budget rather than treating it as a lost lease.
// Before that retry existed, renewWhileRunning gave up on the very first
// error and cancelled fn's context on its first mid-cycle renewal tick.
func TestSingletonJob_RenewWithRetry_SingleTransientErrorDoesNotLoseLease(t *testing.T) {
	clock := newFakeClock()
	// Call #1 is RunIfLeader's initial TryAcquire; call #2 is the first
	// mid-cycle renewal tick (fails); call #3 is its retry.
	failing := &renewOnceFailingStore{LeaseStore: newFakeClockLeaseStore(clock), callNumber: 2}
	store := newSignalingStore(failing, 3)
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	m, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	job, err := NewSingletonJob(m, "x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job.Clock = clock

	var ctxCancelled bool
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) {
		clock.Tick()
		select {
		case <-store.done: // the retry after the injected failure succeeded
		case <-ctx.Done():
		}
		select {
		case <-ctx.Done():
			ctxCancelled = true
		default:
		}
	})
	assert.True(t, ran)
	assert.False(t, ctxCancelled, "a single transient renewal error must not cancel fn's context / lose the lease")
}

// renewRunFailingStore delegates every call to a real store, but fails the
// AcquireOrRenew calls numbered firstFail..lastFail (1-indexed) with a
// transient-looking error, then resumes delegating. Models a store hiccup that
// lasts several consecutive attempts rather than one.
type renewRunFailingStore struct {
	business.LeaseStore
	firstFail, lastFail int32
	calls               int32
}

func (s *renewRunFailingStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if n := atomic.AddInt32(&s.calls, 1); n >= s.firstFail && n <= s.lastFail {
		return nil, errors.New("simulated transient lease store error")
	}
	return s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

// [REQUIRED TEST] (Issue #4541) A renewal that keeps failing for longer than
// Manager's MaxAllowedRenewalLatency, but recovers while the holder's lease is
// still inside its safety margin, must not cost the holder the lease. The
// retry budget is the remaining local-authority window, not the (much
// shorter) per-call latency budget: giving up at the latter cancels fn and
// stops renewing while the lease is still valid, so it lapses mid-cycle and a
// second node acquires it.
func TestSingletonJob_RenewWithRetry_OutageLongerThanLatencyBudget_KeepsLease(t *testing.T) {
	clock := newFakeClock()
	// Call #1 is the initial TryAcquire; calls #2-#9 are the first renewal
	// tick and its retries; call #10 succeeds. The retry backoffs total 910ms
	// of simulated time: past the per-call latency budget (200ms), inside the
	// 1.6s safety margin.
	failing := &renewRunFailingStore{LeaseStore: newFakeClockLeaseStore(clock), firstFail: 2, lastFail: 9}
	store := newSignalingStore(failing, 10)
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	m, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	job, err := NewSingletonJob(m, "x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job.Clock = clock

	var ctxCancelled bool
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) {
		clock.Tick()
		select {
		case <-store.done: // the renewal finally went through
		case <-ctx.Done():
		}
		select {
		case <-ctx.Done():
			ctxCancelled = true
		default:
		}
	})
	assert.True(t, ran)
	assert.False(t, ctxCancelled, "an outage shorter than the lease's safety margin must not cancel fn's context")

	// The lease never lapsed, so a second holder is still fenced out. Move
	// past the original expiry: only the post-outage renewal keeps it held.
	clock.Advance(ttl - renewInterval)
	_, acquired, err := m.TryAcquire(context.Background(), "x", "node-2", ttl)
	require.NoError(t, err)
	assert.False(t, acquired, "the lease must still be held after the outage")
}

// A renewal outage that outlasts the whole safety margin must still give up
// (cancel fn) before the lease can expire in the store.
func TestSingletonJob_RenewWithRetry_OutageBeyondSafetyMargin_CancelsBeforeExpiry(t *testing.T) {
	base := newTestStore(t)
	store := &renewFailingStore{LeaseStore: base, failAfter: 1}
	ttl := 1 * time.Second
	renewInterval := 100 * time.Millisecond
	m, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	job, err := NewSingletonJob(m, "x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)

	start := time.Now()
	var cancelledAfter time.Duration
	job.RunIfLeader(context.Background(), func(ctx context.Context) {
		select {
		case <-ctx.Done():
			cancelledAfter = time.Since(start)
		case <-time.After(3 * time.Second):
		}
	})
	require.NotZero(t, cancelledAfter, "fn's context was never cancelled")
	assert.Less(t, cancelledAfter, ttl, "fn must be cancelled before the lease can expire in the store")
}

func TestSingletonJob_AcquireErrorSkipsCycle(t *testing.T) {
	base := newTestStore(t)
	store := &renewFailingStore{LeaseStore: base, failAfter: 0} // every call fails, including the initial acquire
	ttl := time.Second
	renewInterval := 200 * time.Millisecond
	m, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	job, err := NewSingletonJob(m, "x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)

	var called bool
	ran := job.RunIfLeader(context.Background(), func(ctx context.Context) { called = true })
	assert.False(t, ran)
	assert.False(t, called)
}

// warnCapturingLogger delegates every method to a real logger and additionally
// records the key/value pairs passed to Warn, so a test can inspect what
// reached the log sink.
type warnCapturingLogger struct {
	logging.Logger
	mu     sync.Mutex
	warnKV [][]interface{}
}

func (l *warnCapturingLogger) Warn(msg string, keysAndValues ...interface{}) {
	l.mu.Lock()
	l.warnKV = append(l.warnKV, keysAndValues)
	l.mu.Unlock()
	l.Logger.Warn(msg, keysAndValues...)
}

func (l *warnCapturingLogger) warnValue(key string) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, kv := range l.warnKV {
		for i := 0; i+1 < len(kv); i += 2 {
			if k, ok := kv[i].(string); ok && k == key {
				v, _ := kv[i+1].(string)
				return v, true
			}
		}
	}
	return "", false
}

// A lease name is caller-supplied and can be tenant-derived (pkg/gitsync builds
// one from TenantPath + Namespace), so control characters in it must never
// reach the log sink intact and forge a record.
func TestSingletonJob_LogsSanitizedLeaseName(t *testing.T) {
	base := newTestStore(t)
	store := &renewFailingStore{LeaseStore: base, failAfter: 0} // every call fails, so the acquire warning fires
	ttl := time.Second
	renewInterval := 200 * time.Millisecond
	m, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)

	capturing := &warnCapturingLogger{Logger: logging.NewNoopLogger()}
	tainted := "gitsync:root/msp-a\r\nWARN forged record\x00"
	job, err := NewSingletonJob(m, tainted, "node-1", ttl, renewInterval, capturing)
	require.NoError(t, err)

	ran := job.RunIfLeader(context.Background(), func(context.Context) {})
	require.False(t, ran)

	logged, found := capturing.warnValue("lease_name")
	require.True(t, found, "acquire failure must log the lease name")
	assert.Equal(t, logging.SanitizeLogValue(tainted), logged)
	assert.NotContains(t, logged, "\n")
	assert.NotContains(t, logged, "\r")
}

// blockedRenewStore lets the first AcquireOrRenew through, then parks every
// later call — ignoring ctx — until release is closed: a store write that is
// slow rather than failed, so the renewal call never returns an error.
// entered is closed when the first parked call arrives.
type blockedRenewStore struct {
	business.LeaseStore
	entered chan struct{}
	release chan struct{}
	calls   int32
	once    sync.Once
}

func (s *blockedRenewStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	if atomic.AddInt32(&s.calls, 1) > 1 {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return s.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

// [REQUIRED TEST] (Issue #5106, #5275) A renewal call that is still in flight
// when the local-authority deadline passes must not let fn outlive its lease:
// fn's context is cancelled by the deadline, and at that instant another
// holder still cannot acquire the lease (the store row has not expired).
//
// Time is simulated and the stall is an event, so the verdict depends on no
// sleep or timer scheduling. The clock is advanced to exactly the deadline —
// the latest instant at which cancellation is still guaranteed — and the
// competing acquire runs at that simulated instant. Without the watchdog fn's
// context is never cancelled and the test fails on its bound.
func TestSingletonJob_RenewalStallBeyondLatencyBound_CancelsBeforeAnotherHolderAcquires(t *testing.T) {
	clock := newFakeClock()
	base := newFakeClockLeaseStore(clock)
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	store := &blockedRenewStore{LeaseStore: base, entered: make(chan struct{}), release: make(chan struct{})}
	m1, err := NewManagerWithClock(store, ttl, renewInterval, renewInterval, clock)
	require.NoError(t, err)
	m2, err := NewManagerWithClock(base, ttl, renewInterval, renewInterval, clock)
	require.NoError(t, err)
	job1, err := NewSingletonJob(m1, "stall", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job1.Clock = clock

	var acquiredAtCancel bool
	var acquireErr error
	var cancelled bool
	var gapToExpiry time.Duration
	ran := make(chan bool, 1)
	go func() {
		ran <- job1.RunIfLeader(context.Background(), func(ctx context.Context) {
			deadline, ok := m1.LocalAuthorityDeadline("stall", "node-1")
			assert.True(t, ok)
			row, gerr := base.GetLease(context.Background(), "stall")
			assert.NoError(t, gerr)
			gapToExpiry = row.ExpiresAt.Sub(deadline)

			// Free the parked renewal only after the verdict is taken:
			// RunIfLeader waits for it before returning, and freeing it
			// earlier would let it complete and extend the deadline.
			defer close(store.release)

			clock.Tick() // renewal starts and parks in the store
			select {
			case <-store.entered:
			case <-time.After(30 * time.Second): // failure bound only
				return
			}
			select {
			case <-clock.timerArmed: // watchdog is parked on the clock
			case <-time.After(30 * time.Second): // failure bound only
				return
			}
			clock.Advance(clock.Until(deadline)) // reach the authority deadline
			select {
			case <-ctx.Done():
				cancelled = true
				_, acquiredAtCancel, acquireErr = m2.TryAcquire(context.Background(), "stall", "node-2", ttl)
			case <-time.After(30 * time.Second): // failure bound only
			}
		})
	}()

	select {
	case didRun := <-ran:
		assert.True(t, didRun)
	case <-time.After(60 * time.Second): // failure bound only
		t.Fatal("RunIfLeader never returned")
	}
	require.True(t, cancelled, "fn's context was never cancelled while a renewal was stalled")
	require.NoError(t, acquireErr, "the competing acquire must reach the store for its result to prove exclusion")
	assert.False(t, acquiredAtCancel, "another holder must not be able to acquire when fn is cancelled")
	assert.GreaterOrEqual(t, gapToExpiry, renewInterval+renewInterval,
		"the deadline must precede the store row's expiry by at least renewalInterval + maxAllowedRenewalLatency")
}
