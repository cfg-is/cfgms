// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
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

// TestSourceRateLimiter_UseSharedCounterNamespacesKeys proves that once
// useSharedCounter has been called, allow consults the shared backend — namespaced
// under routeName — instead of the in-memory map, and the configured limit is
// enforced directly against the shared count (no divisor, Issue #3896).
func TestSourceRateLimiter_UseSharedCounterNamespacesKeys(t *testing.T) {
	rl := newSourceRateLimiter(2, time.Minute)
	backend := pkgtesting.SetupTestRateCounterStore()
	rl.useSharedCounter("test-route", backend, logging.NewNoopLogger())

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

	// Every attempt — including the denied one — must be recorded under the
	// route-namespaced key in the shared store, and nowhere else in it.
	ctx := context.Background()
	count, _, found, err := backend.Peek(ctx, "test-route:k1", time.Minute)
	if err != nil {
		t.Fatalf("Peek on the namespaced key: %v", err)
	}
	if !found {
		t.Fatal("expected the shared store to hold a count under the route-namespaced key")
	}
	if count != 3 {
		t.Fatalf("expected all 3 attempts recorded against the shared count, got %d", count)
	}
	if _, _, foundBare, peekErr := backend.Peek(ctx, "k1", time.Minute); peekErr != nil || foundBare {
		t.Fatalf("expected no un-namespaced key in the shared store (found=%v, err=%v) — two limiters sharing one store would collide", foundBare, peekErr)
	}
	if got := rl.trackedKeys(); got != 0 {
		t.Fatalf("expected the in-memory map to stay empty while a healthy shared backend is active, got %d tracked keys", got)
	}
}

// TestSourceRateLimiter_SharedCounterOutageEnforcesInMemoryBudget is the security
// regression test for the fail-open hole (security review, Issue #3896): when the
// shared counter store errors, the limiter must degrade to its node-local
// fixed-window budget, not stop limiting. These limiters are the only abuse
// control on unauthenticated routes (enrolment-token mint, credential-request and
// cli-login lodge/collect), and flooding those routes is itself what exhausts a
// shared database pool — so "allow on error" is attacker-reachable and
// self-reinforcing. The store here is genuinely unusable (a real store, closed),
// not an error-injecting double.
func TestSourceRateLimiter_SharedCounterOutageEnforcesInMemoryBudget(t *testing.T) {
	const limit = 3
	rl := newSourceRateLimiter(limit, time.Minute)
	backend := pkgtesting.SetupTestRateCounterStore()
	logger := logging.NewCapturingLogger()
	rl.useSharedCounter("test-route", backend, logger)
	if err := backend.Close(); err != nil {
		t.Fatalf("closing the shared counter store: %v", err)
	}

	for i := 0; i < limit; i++ {
		ok, _ := rl.allow("k1")
		if !ok {
			t.Fatalf("request %d: a store outage must not lock out callers within the configured budget", i)
		}
	}

	ok, retryAfter := rl.allow("k1")
	if ok {
		t.Fatal("expected the node-local budget to be enforced during a shared-counter outage — an unmetered unauthenticated route is the fail-open this test exists to catch")
	}
	if retryAfter < time.Second {
		t.Fatalf("expected a usable retry-after on the fallback denial, got %s", retryAfter)
	}
	if got := rl.trackedKeys(); got != 1 {
		t.Fatalf("expected the in-memory map to be tracking the key during the outage, got %d tracked keys", got)
	}

	// A silent reversion from a fleet-wide budget to a per-node one is an
	// operational event, so it must be logged — once per window, not once per
	// request, or a flood against a route whose store is down becomes a log flood.
	if got := logger.WarnCount(); got != 1 {
		t.Fatalf("expected exactly one outage warning per window across %d fallback calls, got %d", limit+1, got)
	}
	fields, found := logger.FindWarn("Cluster-visible rate counter unavailable; enforcing this node's in-memory budget instead")
	if !found {
		t.Fatalf("expected the fallback warning to name the unavailable subsystem, got messages %v", logger.WarnMessages)
	}
	if fields["route"] != "test-route" {
		t.Fatalf("expected the warning to identify the affected route, got %v", fields["route"])
	}
	if fields["error"] == nil {
		t.Fatal("expected the warning to carry the (sanitized) store error")
	}
}

// TestSourceRateLimiter_SharedCounterOutageKeepsDistinctKeysIndependent guards the
// fallback's key handling: the shared path namespaces keys under routeName, and the
// in-memory fallback must still bucket by the caller's own key, so an outage cannot
// collapse every source address into one shared bucket (a self-inflicted denial of
// service) or into one unlimited bucket.
func TestSourceRateLimiter_SharedCounterOutageKeepsDistinctKeysIndependent(t *testing.T) {
	rl := newSourceRateLimiter(1, time.Minute)
	backend := pkgtesting.SetupTestRateCounterStore()
	rl.useSharedCounter("test-route", backend, logging.NewNoopLogger())
	if err := backend.Close(); err != nil {
		t.Fatalf("closing the shared counter store: %v", err)
	}

	if ok, _ := rl.allow("source-a"); !ok {
		t.Fatal("expected the first call from source-a allowed under the fallback budget")
	}
	if ok, _ := rl.allow("source-b"); !ok {
		t.Fatal("expected source-b to have its own fallback bucket, independent of source-a")
	}
	if ok, _ := rl.allow("source-a"); ok {
		t.Fatal("expected source-a's second call denied — its own fallback budget is exhausted")
	}
}

// TestSourceRateLimiter_SharedCounterFailsClosedAtStoreCapacity proves the shared
// path keeps the in-memory path's maxTrackedKeys guarantee: when the store declines
// to begin tracking a key because it is at its tracked-key cap, the request is denied
// rather than allowed — and, unlike an outage, is not handed a fresh node-local
// budget either, since a rotating source address is exactly what filled the store.
// The capacity condition is reached by genuinely filling a real store, not by
// injecting its error.
func TestSourceRateLimiter_SharedCounterFailsClosedAtStoreCapacity(t *testing.T) {
	rl := newSourceRateLimiter(5, time.Minute)
	backend := pkgtesting.SetupTestRateCounterStoreWithMaxKeys(1)
	rl.useSharedCounter("test-route", backend, logging.NewNoopLogger())

	// Fill the store's single tracked-key slot with an unrelated key, so the
	// limiter's own key is the brand-new one the store must decline.
	if _, _, err := backend.Increment(context.Background(), "other-route:occupant", time.Minute); err != nil {
		t.Fatalf("seeding the store's only tracked-key slot: %v", err)
	}

	ok, retryAfter := rl.allow("flood-key")
	if ok {
		t.Fatal("expected a denial once the shared counter store reports its tracked-key capacity exhausted")
	}
	if retryAfter < time.Second {
		t.Fatalf("expected a retry-after of at least a second on a capacity denial, got %s", retryAfter)
	}
	if got := rl.trackedKeys(); got != 0 {
		t.Fatalf("a capacity denial must not fall back to a fresh node-local bucket, got %d tracked keys", got)
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
	store := pkgtesting.SetupTestRateCounterStore()
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
		s.SetRateCounterStore(pkgtesting.SetupTestRateCounterStore())
		if s.enrolmentTokenMintLimiter.sharedCounter != nil {
			t.Fatal("expected the limiter to stay on its in-memory default with no haManager configured")
		}
	})

	t.Run("SingleServerMode", func(t *testing.T) {
		s := newTestServer(newAuthoritativeHAManager(t))
		s.SetRateCounterStore(pkgtesting.SetupTestRateCounterStore())
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
		s.SetRateCounterStore(pkgtesting.SetupTestRateCounterStore())
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
