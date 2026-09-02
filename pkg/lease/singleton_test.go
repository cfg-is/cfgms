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
// cycle is still in flight (holding the lease) and must be refused.
func TestSingletonJob_TwoNodes_OnlyOneRunsPerCycle(t *testing.T) {
	store := newTestStore(t)
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	m1, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	m2, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)

	job1, err := NewSingletonJob(m1, "sweep-x", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job2, err := NewSingletonJob(m2, "sweep-x", "node-2", ttl, renewInterval, nil)
	require.NoError(t, err)

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

	select {
	case <-node1Started:
	case <-time.After(2 * time.Second):
		t.Fatal("node-1 never started its cycle")
	}

	ran2 := job2.RunIfLeader(context.Background(), func(ctx context.Context) {
		atomic.AddInt32(&node2Ran, 1)
	})
	assert.False(t, ran2, "node-2 must not run while node-1 holds the lease")

	close(releaseNode1)
	var ran1 bool
	select {
	case ran1 = <-done1:
	case <-time.After(2 * time.Second):
		t.Fatal("node-1's cycle never completed")
	}

	assert.True(t, ran1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&node1Ran))
	assert.Equal(t, int32(0), atomic.LoadInt32(&node2Ran))
}

// [REQUIRED TEST] A slow cycle that approaches (and, here, far exceeds) the
// lease TTL renews successfully via RunIfLeader's background renewal
// goroutine and does not trigger a duplicate run on another node contending
// for the same lease throughout.
func TestSingletonJob_SlowCycleRenewsAcrossTTL_NoDuplicateRun(t *testing.T) {
	store := newTestStore(t)
	// Generous margin (ttl-renewInterval=1.8s of scheduling slack per renewal)
	// so this test does not race itself when the full suite runs packages in
	// parallel under load — a tight margin here would make an occasional missed
	// renewal window (goroutine scheduling delay, not a logic bug) look like a
	// broken renewal loop. See TestManager_HasLocalAuthority_ExpiresAtSafetyMarginNotTTL's
	// comment on the same class of flakiness.
	ttl := 2 * time.Second
	renewInterval := 200 * time.Millisecond
	m1, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)
	m2, err := NewManager(store, ttl, renewInterval, renewInterval)
	require.NoError(t, err)

	job1, err := NewSingletonJob(m1, "slow-sweep", "node-1", ttl, renewInterval, nil)
	require.NoError(t, err)
	job2, err := NewSingletonJob(m2, "slow-sweep", "node-2", ttl, renewInterval, nil)
	require.NoError(t, err)

	var node2Attempts int32
	stopProbing := make(chan struct{})
	var probeWG sync.WaitGroup
	probeWG.Add(1)
	go func() {
		defer probeWG.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
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

	// node-1's cycle runs longer than ttl, proving the background renewal
	// keeps the lease alive rather than losing it partway through.
	cycleDuration := ttl + ttl/2
	ran1 := job1.RunIfLeader(context.Background(), func(ctx context.Context) {
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
