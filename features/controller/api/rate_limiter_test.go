// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
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
