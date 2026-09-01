// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package lease

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// delayedStore delegates every call to the real lease store returned by
// newTestStore (see providers_test.go) after a fixed delay, reproducing a
// store round-trip slower than the Manager's maxAllowedRenewalLatency budget.
// It decides nothing itself — the lease state, token and contention outcome
// all still come from the real store.
type delayedStore struct {
	business.LeaseStore
	delay time.Duration
}

func (d delayedStore) AcquireOrRenew(ctx context.Context, name, holderID string, ttl time.Duration) (*business.LeaseState, error) {
	time.Sleep(d.delay)
	return d.LeaseStore.AcquireOrRenew(ctx, name, holderID, ttl)
}

func TestSafetyMargin(t *testing.T) {
	t.Run("strictly positive margin", func(t *testing.T) {
		margin, err := SafetyMargin(10*time.Second, 3*time.Second, 2*time.Second)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, margin)
	})

	t.Run("zero margin rejected", func(t *testing.T) {
		_, err := SafetyMargin(5*time.Second, 3*time.Second, 2*time.Second)
		require.Error(t, err)
	})

	t.Run("negative margin rejected", func(t *testing.T) {
		_, err := SafetyMargin(5*time.Second, 4*time.Second, 4*time.Second)
		require.Error(t, err)
	})
}

func TestNewManager_ValidatesPositiveSafetyMargin(t *testing.T) {
	store := newTestStore(t)

	t.Run("valid configuration succeeds", func(t *testing.T) {
		m, err := NewManager(store, 10*time.Second, 3*time.Second, 2*time.Second)
		require.NoError(t, err)
		assert.Equal(t, 5*time.Second, m.SafetyMargin())
	})

	t.Run("non-positive margin refuses to construct", func(t *testing.T) {
		_, err := NewManager(store, 5*time.Second, 3*time.Second, 3*time.Second)
		require.Error(t, err)
	})

	t.Run("nil store rejected", func(t *testing.T) {
		_, err := NewManager(nil, 10*time.Second, 3*time.Second, 2*time.Second)
		require.Error(t, err)
	})
}

func TestManager_TryAcquire_FirstHolderGetsToken(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, 200*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	token, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", 200*time.Millisecond)
	require.NoError(t, err)
	require.True(t, acquired)
	assert.Equal(t, uint64(1), token)
}

func TestManager_TryAcquire_RejectsMismatchedTTL(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, 200*time.Millisecond, 50*time.Millisecond, 50*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	_, _, err = m.TryAcquire(ctx, "singleton-x", "holder-1", 999*time.Millisecond)
	require.Error(t, err)
}

func TestManager_TryAcquire_ContentionWhileUnexpired(t *testing.T) {
	store := newTestStore(t)
	ttl := 5 * time.Second // long enough that it will not expire during the test
	m, err := NewManager(store, ttl, time.Second, time.Second)
	require.NoError(t, err)
	ctx := context.Background()

	token1, acquired1, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired1)

	token2, acquired2, err := m.TryAcquire(ctx, "singleton-x", "holder-2", ttl)
	require.NoError(t, err)
	require.False(t, acquired2, "a second holder must not acquire an unexpired lease held by someone else")
	assert.Equal(t, token1, token2, "the contended read reports the current holder's token unchanged")
}

// [REQUIRED TEST] Renew by the current holder never changes the fencing token.
func TestManager_Renew_TokenUnchanged(t *testing.T) {
	store := newTestStore(t)
	ttl := 5 * time.Second
	m, err := NewManager(store, ttl, time.Second, time.Second)
	require.NoError(t, err)
	ctx := context.Background()

	token, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	for i := 0; i < 3; i++ {
		newToken, err := m.Renew(ctx, "singleton-x", "holder-1", token)
		require.NoError(t, err)
		assert.Equal(t, token, newToken, "renew must never change the fencing token")
	}

	// The durable row must also report the unchanged token.
	_, currentToken, _, ok, err := m.CurrentHolder(ctx, "singleton-x")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, token, currentToken)
}

func TestManager_Renew_FencedOutWhenHeldByAnotherHolder(t *testing.T) {
	store := newTestStore(t)
	ttl := 50 * time.Millisecond
	m, err := NewManager(store, ttl, 10*time.Millisecond, 10*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	token, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	// Let holder-1's lease expire, then let holder-2 take it over.
	time.Sleep(ttl + 20*time.Millisecond)
	_, acquired2, err := m.TryAcquire(ctx, "singleton-x", "holder-2", ttl)
	require.NoError(t, err)
	require.True(t, acquired2)

	// holder-1 attempting to renew its now-superseded token must fail, not
	// silently succeed or resurrect holder-1's authority.
	_, err = m.Renew(ctx, "singleton-x", "holder-1", token)
	require.Error(t, err)

	_, hasAuthority := m.HasLocalAuthority("singleton-x", "holder-1")
	assert.False(t, hasAuthority, "a fenced-out renew must invalidate the stale holder's local cache")
}

// [REQUIRED TEST] A lease acquired, allowed to expire, and re-acquired by a
// different holder yields a strictly greater token than the first holder ever
// held.
func TestManager_FencingTokenMonotonicity_AcrossExpiry(t *testing.T) {
	store := newTestStore(t)
	ttl := 50 * time.Millisecond
	m, err := NewManager(store, ttl, 10*time.Millisecond, 10*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	firstToken, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	time.Sleep(ttl + 20*time.Millisecond) // allow holder-1's lease to expire

	secondToken, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-2", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	assert.Greater(t, secondToken, firstToken, "re-acquisition after expiry must yield a strictly greater token")
}

func TestManager_FencingTokenMonotonicity_SameHolderReacquiringAfterExpiry(t *testing.T) {
	store := newTestStore(t)
	ttl := 50 * time.Millisecond
	m, err := NewManager(store, ttl, 10*time.Millisecond, 10*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	firstToken, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	time.Sleep(ttl + 20*time.Millisecond) // holder-1's own lease lapses without renewal

	secondToken, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	assert.Greater(t, secondToken, firstToken,
		"even the same holder re-acquiring after its own lease expired must receive a strictly greater token")
}

func TestManager_Release_PreservesTokenAsHighWaterMark(t *testing.T) {
	store := newTestStore(t)
	ttl := 5 * time.Second
	m, err := NewManager(store, ttl, time.Second, time.Second)
	require.NoError(t, err)
	ctx := context.Background()

	token, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	require.NoError(t, m.Release(ctx, "singleton-x", "holder-1", token))

	// A released lease is immediately acquirable by another holder, with a
	// strictly greater token — release must not reset the counter.
	newToken, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-2", ttl)
	require.NoError(t, err)
	require.True(t, acquired)
	assert.Greater(t, newToken, token)
}

func TestManager_Release_StaleTokenIsNoOp(t *testing.T) {
	store := newTestStore(t)
	ttl := 5 * time.Second
	m, err := NewManager(store, ttl, time.Second, time.Second)
	require.NoError(t, err)
	ctx := context.Background()

	token, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	// A stale caller releasing a token that no longer matches the current
	// holder must not disturb the real state.
	require.NoError(t, m.Release(ctx, "singleton-x", "holder-1", token+999))

	holderID, currentToken, _, ok, err := m.CurrentHolder(ctx, "singleton-x")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "holder-1", holderID)
	assert.Equal(t, token, currentToken)
}

func TestManager_CurrentHolder_NotFound(t *testing.T) {
	store := newTestStore(t)
	m, err := NewManager(store, time.Second, 200*time.Millisecond, 200*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	holderID, token, expiresAt, ok, err := m.CurrentHolder(ctx, "never-acquired")
	require.NoError(t, err)
	assert.False(t, ok)
	assert.Empty(t, holderID)
	assert.Zero(t, token)
	assert.True(t, expiresAt.IsZero())
}

func TestManager_CurrentHolder_ReportsExpiredAsNotOK(t *testing.T) {
	store := newTestStore(t)
	ttl := 30 * time.Millisecond
	m, err := NewManager(store, ttl, 5*time.Millisecond, 5*time.Millisecond)
	require.NoError(t, err)
	ctx := context.Background()

	_, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	time.Sleep(ttl + 20*time.Millisecond)

	holderID, _, _, ok, err := m.CurrentHolder(ctx, "singleton-x")
	require.NoError(t, err)
	assert.False(t, ok, "an expired row must not be reported as a valid current holder")
	assert.Equal(t, "holder-1", holderID, "the last holder is still visible even though the lease is expired")
}

// [REQUIRED TEST] Structural guard: CurrentHolder must take the store's own
// validity verdict rather than comparing the stored expiry to this host's wall
// clock. The behavioral tests above cannot distinguish the two on a
// single-process flatfile store, where both clocks are the same clock — but
// against the database provider the difference is a fail-open split brain: a
// host whose clock trails the database server would read an unexpired lease as
// expired (and vice versa), which is precisely the cross-host offset ADR-029
// Decision 2 / Issue #2037 keeps out of authority decisions. Monotonic
// elapsed-time use elsewhere in the file (recordLocalAuthority's time.Now
// baseline, HasLocalAuthority's time.Since) is deliberately untouched by this
// guard.
func TestManager_CurrentHolder_UsesStoreValidityNotLocalWallClock(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "lease.go", nil, 0)
	require.NoError(t, err)

	var checked bool
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "CurrentHolder" {
			return true
		}
		checked = true
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			sel, ok := inner.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			assert.False(t, pkg.Name == "time" && sel.Sel.Name == "Now",
				"CurrentHolder must not read this host's wall clock; validity is the store's verdict (LeaseState.Valid)")
			return true
		})
		return false
	})
	require.True(t, checked, "CurrentHolder not found in lease.go")
}

// [REQUIRED TEST] The local-authority cache lapses at the derived
// safetyMargin, strictly before the underlying lease's full TTL — this is
// the distinguishing behavior from a naive "trust the TTL" cache and the
// property the dual-authority-window bound test below depends on.
func TestManager_HasLocalAuthority_ExpiresAtSafetyMarginNotTTL(t *testing.T) {
	store := newTestStore(t)
	ttl := 1 * time.Second
	renewalInterval := 100 * time.Millisecond
	maxRenewalLatency := 100 * time.Millisecond
	m, err := NewManager(store, ttl, renewalInterval, maxRenewalLatency)
	require.NoError(t, err)
	margin := m.SafetyMargin()
	require.Less(t, margin, ttl, "safety margin must be strictly less than the lease TTL for this test to be meaningful")

	ctx := context.Background()
	_, acquired, err := m.TryAcquire(ctx, "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	_, has := m.HasLocalAuthority("singleton-x", "holder-1")
	require.True(t, has, "immediately after acquiring, local authority must be valid")

	// Sleep past the safety margin but still within the lease's real TTL.
	// The 100ms buffer on each side absorbs scheduling jitter under -race.
	sleepFor := margin + 100*time.Millisecond
	require.Less(t, sleepFor, ttl, "test sleep must still land before the real TTL expires")
	time.Sleep(sleepFor)

	_, has = m.HasLocalAuthority("singleton-x", "holder-1")
	assert.False(t, has, "local authority must lapse at the safety margin, not the full lease TTL")

	// The database-backed lease, by contrast, is still valid at this point.
	holderID, _, _, ok, err := m.CurrentHolder(ctx, "singleton-x")
	require.NoError(t, err)
	require.True(t, ok, "the underlying lease row must still be unexpired at this point in the test")
	assert.Equal(t, "holder-1", holderID)
}

// [REQUIRED TEST] A slow store round-trip must not extend the local-authority
// window. The store stamps the row's expiry when it applies the write, so the
// window has to be anchored at the instant the call was issued; anchoring it
// at the instant the call returned adds the round-trip latency to the window
// and lets this holder keep claiming authority past the point another holder
// can legitimately take the lease.
//
// The store's delay (150ms) deliberately exceeds ttl − safetyMargin (100ms),
// the latency budget the margin is derived from, so the two anchorings give
// different answers at the sampled instant rather than merely different
// timings.
func TestManager_HasLocalAuthority_WindowAnchoredAtCallStartNotCallReturn(t *testing.T) {
	const (
		ttl             = 300 * time.Millisecond
		renewalInterval = 50 * time.Millisecond
		maxLatency      = 50 * time.Millisecond // safetyMargin = 200ms
		storeDelay      = 150 * time.Millisecond
	)

	m, err := NewManager(delayedStore{LeaseStore: newTestStore(t), delay: storeDelay}, ttl, renewalInterval, maxLatency)
	require.NoError(t, err)
	margin := m.SafetyMargin()
	require.Greater(t, storeDelay, ttl-margin, "the store must be slower than the latency budget for this test to discriminate")

	callStart := time.Now()
	_, acquired, err := m.TryAcquire(context.Background(), "singleton-x", "holder-1", ttl)
	require.NoError(t, err)
	require.True(t, acquired)

	// Sample just past callStart+safetyMargin: correct anchoring has lapsed,
	// return-anchoring would still be valid for another storeDelay.
	time.Sleep(time.Until(callStart.Add(margin + 20*time.Millisecond)))

	_, has := m.HasLocalAuthority("singleton-x", "holder-1")
	assert.False(t, has,
		"local authority must lapse one safety margin after the acquire call was issued, not after it returned")
}

// [REQUIRED TEST] Two pkg/lease client instances contending for the same
// lease name, with the primitive's own cached-authority logic exercised (not
// bypassed), never both report holding a valid, unexpired local authority —
// this is the lease-substrate equivalent of
// TestRealClusterPartition_NoDualLeader (ADR-029 / pkg/ha).
//
// holder-1 acquires and then stops renewing (simulating a dead process).
// holder-2 repeatedly attempts TryAcquire. Because safetyMargin is strictly
// less than ttl by construction, holder-1's local authority must lapse
// before the database row physically expires, and holder-2 cannot acquire
// until it does — so at every sampled instant, at most one holder reports
// valid local authority.
func TestManager_DualAuthorityWindowBound_NoOverlapBeyondSafetyMargin(t *testing.T) {
	store := newTestStore(t)
	ttl := 300 * time.Millisecond
	renewalInterval := 50 * time.Millisecond
	maxRenewalLatency := 50 * time.Millisecond // safetyMargin = 200ms

	mHolder1, err := NewManager(store, ttl, renewalInterval, maxRenewalLatency)
	require.NoError(t, err)
	mHolder2, err := NewManager(store, ttl, renewalInterval, maxRenewalLatency)
	require.NoError(t, err)

	ctx := context.Background()
	const name = "contended-singleton"
	const holder1 = "holder-1"
	const holder2 = "holder-2"

	_, acquired, err := mHolder1.TryAcquire(ctx, name, holder1, ttl)
	require.NoError(t, err)
	require.True(t, acquired)
	acquireTime := time.Now()

	var holder2EverAcquired bool
	deadline := acquireTime.Add(ttl + 200*time.Millisecond)
	for time.Now().Before(deadline) {
		_, holder1HasAuthority := mHolder1.HasLocalAuthority(name, holder1)

		_, holder2Acquired, err := mHolder2.TryAcquire(ctx, name, holder2, ttl)
		require.NoError(t, err)
		_, holder2HasAuthority := mHolder2.HasLocalAuthority(name, holder2)
		if holder2Acquired {
			holder2EverAcquired = true
		}

		require.False(t, holder1HasAuthority && holder2HasAuthority,
			"both holders reported valid local authority for the same lease simultaneously")

		time.Sleep(10 * time.Millisecond)
	}

	assert.True(t, holder2EverAcquired, "holder-2 must eventually acquire the lease once holder-1's stopped renewing")
}
