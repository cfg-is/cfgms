// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// trackedKeys is a test-only inspection helper (white-box, same package).
func (l *sourceRateLimiter) trackedKeys() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

func TestSourceRateLimiter_AllowsUpToLimitThenDenies(t *testing.T) {
	rl := newSourceRateLimiter(3, time.Minute)
	for i := 0; i < 3; i++ {
		ok, retryAfter := rl.allow("k1")
		if !ok {
			t.Fatalf("request %d: expected allow, got denied (retryAfter=%v)", i, retryAfter)
		}
	}
	ok, retryAfter := rl.allow("k1")
	if ok {
		t.Fatal("expected 4th request to be denied")
	}
	if retryAfter <= 0 {
		t.Fatalf("expected positive retry-after on denial, got %v", retryAfter)
	}
}

func TestSourceRateLimiter_WindowResets(t *testing.T) {
	fakeNow := time.Now()
	rl := newSourceRateLimiter(1, time.Minute)
	rl.now = func() time.Time { return fakeNow }

	if ok, _ := rl.allow("k1"); !ok {
		t.Fatal("expected first request allowed")
	}
	if ok, _ := rl.allow("k1"); ok {
		t.Fatal("expected second request denied within the same window")
	}

	fakeNow = fakeNow.Add(time.Minute + time.Second)
	if ok, _ := rl.allow("k1"); !ok {
		t.Fatal("expected request allowed after the window elapsed")
	}
}

func TestSourceRateLimiter_KeysAreIndependent(t *testing.T) {
	rl := newSourceRateLimiter(1, time.Minute)
	if ok, _ := rl.allow("a"); !ok {
		t.Fatal("expected key 'a' allowed on first call")
	}
	if ok, _ := rl.allow("b"); !ok {
		t.Fatal("expected key 'b' allowed on first call — independent bucket from 'a'")
	}
	if ok, _ := rl.allow("a"); ok {
		t.Fatal("expected key 'a' denied on second call")
	}
}

func TestSourceRateLimiter_DirectCallForm(t *testing.T) {
	rl := newSourceRateLimiter(1, time.Minute)
	ok, retryAfter := rl.allow("k")
	if !ok || retryAfter != 0 {
		t.Fatalf("expected first call allowed with zero retryAfter, got ok=%v retryAfter=%v", ok, retryAfter)
	}
	ok, retryAfter = rl.allow("k")
	if ok {
		t.Fatal("expected second call denied")
	}
	if retryAfter <= 0 {
		t.Fatal("expected positive retry-after on denial")
	}
}

// REQUIRED TEST: the limiter keys on the trusted-proxy-aware source address and is
// not defeated by a spoofed forwarded-for header from an untrusted peer.
func TestSourceRateLimiterMiddleware_UntrustedPeerXFFSpoofIgnored(t *testing.T) {
	rl := newSourceRateLimiter(2, time.Minute)
	calls := 0
	handler := rl.middleware(nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	// No trusted proxies configured, so X-Forwarded-For must never be honored — the
	// real TCP peer address is used regardless of what the header claims.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:12345"
		req.Header.Set("X-Forwarded-For", "10.0.0."+strconv.Itoa(i+1)) // different spoofed value each call
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i, w.Code)
		}
	}

	// A third request, still from the same peer but with yet another spoofed XFF
	// value, must be denied — if the spoofed header were honored as the key, this
	// would look like a brand-new, unthrottled source.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.99")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after the shared peer bucket was exhausted despite spoofed XFF, got %d", w.Code)
	}
	if got := w.Header().Get("Retry-After"); got == "" {
		t.Fatal("expected a Retry-After header on the 429 response")
	}
	if got := w.Body.String(); got != http.StatusText(http.StatusTooManyRequests)+"\n" {
		t.Fatalf("expected a generic body disclosing nothing about the resource, got %q", got)
	}
	if calls != 2 {
		t.Fatalf("expected the wrapped handler invoked exactly twice, got %d", calls)
	}
}

// Contrast case: when the peer IS a trusted proxy, distinct X-Forwarded-For hops
// legitimately key to separate buckets.
func TestSourceRateLimiterMiddleware_TrustedProxyHonorsDistinctXFF(t *testing.T) {
	_, trustedNet, err := net.ParseCIDR("203.0.113.9/32")
	if err != nil {
		t.Fatalf("ParseCIDR: %v", err)
	}
	trusted := []net.IPNet{*trustedNet}

	rl := newSourceRateLimiter(1, time.Minute)
	handler := rl.middleware(trusted, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "203.0.113.9:12345"
	req1.Header.Set("X-Forwarded-For", "198.51.100.1")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("client A: expected 200, got %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "203.0.113.9:12345"
	req2.Header.Set("X-Forwarded-For", "198.51.100.2")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("client B: expected 200 (independent bucket from client A), got %d", w2.Code)
	}
}

// REQUIRED TEST: stale keys are evicted, so a flood of distinct source addresses
// cannot grow the limiter's memory without bound.
func TestSourceRateLimiter_EvictsStaleKeys(t *testing.T) {
	fakeNow := time.Now()
	rl := newSourceRateLimiter(5, 10*time.Millisecond)
	rl.now = func() time.Time { return fakeNow }

	for i := 0; i < 50; i++ {
		rl.allow("key-" + strconv.Itoa(i))
	}
	if got := rl.trackedKeys(); got != 50 {
		t.Fatalf("expected 50 tracked keys before eviction, got %d", got)
	}

	fakeNow = fakeNow.Add(time.Second) // well past the 10ms window
	rl.allow("trigger-eviction")

	if got := rl.trackedKeys(); got != 1 {
		t.Fatalf("expected only the fresh key tracked after stale eviction, got %d", got)
	}
}

func TestSourceRateLimiter_BoundsMemoryUnderDistinctKeyFlood(t *testing.T) {
	fakeNow := time.Now()
	rl := newSourceRateLimiter(5, time.Minute)
	rl.now = func() time.Time { return fakeNow }
	rl.maxTrackedKeys = 100

	for i := 0; i < 1000; i++ {
		rl.allow("flood-" + strconv.Itoa(i))
	}
	if got := rl.trackedKeys(); got > rl.maxTrackedKeys {
		t.Fatalf("tracked keys %d exceeded the configured cap %d — flood of distinct sources grew memory unbounded", got, rl.maxTrackedKeys)
	}
}

// REQUIRED TEST: concurrent calls from many goroutines are counted correctly and
// the limiter is race-free under the race detector (run with -race).
func TestSourceRateLimiter_ConcurrentCallsAreCountedCorrectly(t *testing.T) {
	const limit = 100
	const goroutines = 50
	const perGoroutine = 10 // 500 total attempts against a 100-call budget

	rl := newSourceRateLimiter(limit, time.Minute)

	var wg sync.WaitGroup
	var mu sync.Mutex
	allowedCount := 0
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				if ok, _ := rl.allow("shared-key"); ok {
					mu.Lock()
					allowedCount++
					mu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	if allowedCount != limit {
		t.Fatalf("expected exactly %d allowed calls out of %d attempts, got %d", limit, goroutines*perGoroutine, allowedCount)
	}
	if got := rl.trackedKeys(); got != 1 {
		t.Fatalf("expected a single tracked key for the shared key, got %d", got)
	}
}

// Concurrent calls across many distinct keys must also stay race-free and each
// key's budget must be independently enforced.
func TestSourceRateLimiter_ConcurrentDistinctKeysCountedIndependently(t *testing.T) {
	const limit = 5
	const keys = 20
	const attemptsPerKey = 20

	rl := newSourceRateLimiter(limit, time.Minute)

	var wg sync.WaitGroup
	results := make([]int, keys)
	for k := 0; k < keys; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()
			key := "key-" + strconv.Itoa(k)
			allowed := 0
			for i := 0; i < attemptsPerKey; i++ {
				if ok, _ := rl.allow(key); ok {
					allowed++
				}
			}
			results[k] = allowed
		}(k)
	}
	wg.Wait()

	for k, allowed := range results {
		if allowed != limit {
			t.Fatalf("key %d: expected exactly %d allowed calls, got %d", k, limit, allowed)
		}
	}
}

// fakeRateCounterStore is a minimal in-memory business.RateCounterStore for tests
// that need to observe or control shared-counter behavior without a real database.
type fakeRateCounterStore struct {
	mu      sync.Mutex
	counts  map[string]int
	err     error
	calls   int
	lastKey string
}

func (f *fakeRateCounterStore) Increment(_ context.Context, key string, window time.Duration) (int, time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastKey = key
	if f.err != nil {
		return 0, 0, f.err
	}
	if f.counts == nil {
		f.counts = make(map[string]int)
	}
	f.counts[key]++
	return f.counts[key], window, nil
}

func (f *fakeRateCounterStore) Peek(_ context.Context, key string, window time.Duration) (int, time.Duration, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, 0, false, f.err
	}
	count, ok := f.counts[key]
	if !ok {
		return 0, 0, false, nil
	}
	return count, window, true, nil
}

func (f *fakeRateCounterStore) Close() error { return nil }

// TestSourceRateLimiter_UseSharedCounterNamespacesKeys proves that once
// useSharedCounter has been called, allow consults the shared backend — namespaced
// under routeName — instead of the in-memory map, and the configured limit is
// enforced directly against the shared count (no divisor, Issue #3896).
func TestSourceRateLimiter_UseSharedCounterNamespacesKeys(t *testing.T) {
	rl := newSourceRateLimiter(2, time.Minute)
	backend := &fakeRateCounterStore{}
	rl.useSharedCounter("test-route", backend)

	for i := 0; i < 2; i++ {
		ok, _ := rl.allow("k1")
		if !ok {
			t.Fatalf("request %d: expected allow within the shared budget", i)
		}
	}
	ok, retryAfter := rl.allow("k1")
	if ok {
		t.Fatal("expected the 3rd request to be denied once the shared budget is exhausted")
	}
	if retryAfter <= 0 {
		t.Fatal("expected a positive retry-after on denial")
	}
	if backend.calls != 3 {
		t.Fatalf("expected exactly 3 calls into the shared backend, got %d", backend.calls)
	}
	if backend.lastKey != "test-route:k1" {
		t.Fatalf("expected the shared backend key to be namespaced by routeName, got %q", backend.lastKey)
	}
	if got := rl.trackedKeys(); got != 0 {
		t.Fatalf("expected the in-memory map to stay empty while a shared backend is active, got %d tracked keys", got)
	}
}

// TestSourceRateLimiter_SharedCounterFailsOpenOnStoreError proves a counter-store
// error does not turn the shared-counter path into an outright lockout: the shared
// counter is defense-in-depth, not the primary auth gate, so an outage in it must
// not block every legitimate caller of a clustered route.
func TestSourceRateLimiter_SharedCounterFailsOpenOnStoreError(t *testing.T) {
	rl := newSourceRateLimiter(1, time.Minute)
	backend := &fakeRateCounterStore{err: errors.New("database unavailable")}
	rl.useSharedCounter("test-route", backend)

	for i := 0; i < 5; i++ {
		ok, _ := rl.allow("k1")
		if !ok {
			t.Fatalf("request %d: expected allow (fail-open) while the shared counter store errors", i)
		}
	}
}

// TestSourceRateLimiter_SharedCounterFailsClosedAtStoreCapacity proves the shared
// path keeps the in-memory path's maxTrackedKeys guarantee: when the store declines
// to begin tracking a key because it is at its tracked-key cap, the request is denied
// rather than allowed. Failing open there would give every fresh source address an
// untracked, unlimited budget — the flood the cap exists to bound.
func TestSourceRateLimiter_SharedCounterFailsClosedAtStoreCapacity(t *testing.T) {
	rl := newSourceRateLimiter(5, time.Minute)
	backend := &fakeRateCounterStore{
		err: fmt.Errorf("rate counter table is at its cap: %w", business.ErrRateCounterCapacityExhausted),
	}
	rl.useSharedCounter("test-route", backend)

	ok, retryAfter := rl.allow("flood-key")
	if ok {
		t.Fatal("expected a denial once the shared counter store reports its tracked-key capacity exhausted")
	}
	if retryAfter < time.Second {
		t.Fatalf("expected a retry-after of at least a second on a capacity denial, got %s", retryAfter)
	}
}

// TestSourceRateLimiter_ClusterModeUsesSharedCounter is the [REQUIRED TEST] for
// Issue #3896: Server.SetRateCounterStore must wire every per-source limiter onto
// the shared counter backend when haManager reports ha.ClusterMode, replacing
// clusterBudgetDivisor's even-distribution approximation with a real shared count.
func TestSourceRateLimiter_ClusterModeUsesSharedCounter(t *testing.T) {
	s := &Server{
		haManager:                     newNonAuthoritativeHAManager(t),
		enrolmentTokenMintLimiter:     newSourceRateLimiter(10, time.Minute),
		credentialRequestLodgeLimiter: newSourceRateLimiter(20, time.Minute),
	}
	store := &fakeRateCounterStore{}
	s.SetRateCounterStore(store)

	if s.enrolmentTokenMintLimiter.sharedCounter == nil {
		t.Fatal("expected enrolmentTokenMintLimiter to be wired to the shared counter store in ClusterMode")
	}
	if s.credentialRequestLodgeLimiter.sharedCounter == nil {
		t.Fatal("expected credentialRequestLodgeLimiter to be wired to the shared counter store in ClusterMode")
	}
	if s.enrolmentTokenMintLimiter.routeName == "" {
		t.Fatal("expected the shared-counter route name to be set, so distinct limiters never collide in the shared table")
	}
	if s.enrolmentTokenMintLimiter.routeName == s.credentialRequestLodgeLimiter.routeName {
		t.Fatal("expected distinct limiters to receive distinct route names")
	}
}

// TestSourceRateLimiter_SingleNodeUsesInMemoryDefault is the [REQUIRED TEST] for
// Issue #3896: SetRateCounterStore must be a no-op — leaving every limiter on its
// in-memory default — for every deployment shape where at most one process serves
// mutating traffic (nil haManager, SingleServerMode, BlueGreenMode), unchanged from
// pre-story behavior (mirrors the deployment-shape coverage
// TestClusterBudgetDivisor_ReflectsDeploymentShape gave clusterBudgetDivisor before
// this story deleted it).
func TestSourceRateLimiter_SingleNodeUsesInMemoryDefault(t *testing.T) {
	newTestServer := func(haManager *ha.Manager) *Server {
		return &Server{
			haManager:                 haManager,
			enrolmentTokenMintLimiter: newSourceRateLimiter(10, time.Minute),
		}
	}

	t.Run("nil haManager", func(t *testing.T) {
		s := newTestServer(nil)
		s.SetRateCounterStore(&fakeRateCounterStore{})
		if s.enrolmentTokenMintLimiter.sharedCounter != nil {
			t.Fatal("expected the limiter to stay on its in-memory default with no haManager configured")
		}
	})

	t.Run("SingleServerMode", func(t *testing.T) {
		s := newTestServer(newAuthoritativeHAManager(t))
		s.SetRateCounterStore(&fakeRateCounterStore{})
		if s.enrolmentTokenMintLimiter.sharedCounter != nil {
			t.Fatal("expected the limiter to stay on its in-memory default in SingleServerMode")
		}
	})

	t.Run("BlueGreenMode", func(t *testing.T) {
		cfg := ha.DefaultConfig()
		cfg.Mode = ha.BlueGreenMode
		cfg.Node.ID = "test-bluegreen-node"
		manager, err := ha.NewManager(cfg, logging.NewNoopLogger(), nil)
		if err != nil {
			t.Fatalf("ha.NewManager: %v", err)
		}
		t.Cleanup(func() {
			if stopErr := manager.Stop(context.Background()); stopErr != nil {
				t.Errorf("manager.Stop: %v", stopErr)
			}
		})

		s := newTestServer(manager)
		s.SetRateCounterStore(&fakeRateCounterStore{})
		if s.enrolmentTokenMintLimiter.sharedCounter != nil {
			t.Fatal("expected the limiter to stay on its in-memory default in BlueGreenMode — the standby instance is a cutover target, not a concurrently-serving peer")
		}
	})

	t.Run("nil store", func(t *testing.T) {
		s := newTestServer(newNonAuthoritativeHAManager(t))
		s.SetRateCounterStore(nil)
		if s.enrolmentTokenMintLimiter.sharedCounter != nil {
			t.Fatal("expected the limiter to stay on its in-memory default when store is nil, even in ClusterMode")
		}
	})
}
