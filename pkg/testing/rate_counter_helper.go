// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package testing

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// ErrRateCounterStoreClosed is returned by every operation on a store that has
// been closed. Tests use a closed store to reproduce a genuine counter-store
// outage — the condition a clustered controller hits when its database pool is
// exhausted or failing over — without an injectable "return this error" field:
// the store really is unusable, and it reports that the way the PostgreSQL
// implementation reports a dead pool.
var ErrRateCounterStoreClosed = errors.New("rate counter store: closed")

// defaultTestRateCounterMaxKeys mirrors the shape of
// DatabaseRateCounterStore's row cap, at a size no test will reach by accident.
const defaultTestRateCounterMaxKeys = 10_000

// inMemRateCounterStore is a complete, mutex-guarded implementation of
// business.RateCounterStore for tests that need two or more callers standing in
// for controller nodes (e.g. two api.Server instances, or a limiter plus a sign
// throttle) to contend over one fixed-window counter without a live PostgreSQL
// instance (CLAUDE.md's no-mocks rule — this implements the interface's whole
// contract, including window reset and the tracked-key backstop, rather than
// recording expectations). It is in-process only: sufficient to prove callers
// enforce a shared count correctly, not evidence of node-shared storage — see
// pkg/storage/providers/database's DatabaseRateCounterStore for the
// implementation that actually makes a counter cluster-visible, and
// features/controller/api/rate_counter_cross_node_test.go for the two-node
// test that runs against it.
type inMemRateCounterStore struct {
	mu      sync.Mutex
	entries map[string]*inMemRateCounterWindow
	maxKeys int
	closed  bool
	now     func() time.Time
}

type inMemRateCounterWindow struct {
	windowStart time.Time
	// window is the duration the key that created this record was counted
	// over, kept per record so one store serving callers with different
	// windows (a one-minute route limiter and the fifteen-minute sign
	// throttle share one store in production) never reclaims a record early.
	window time.Duration
	count  int
}

// SetupTestRateCounterStore returns a real (not mocked) business.RateCounterStore
// backed by an in-process fixed-window map.
func SetupTestRateCounterStore() business.RateCounterStore {
	return SetupTestRateCounterStoreWithMaxKeys(defaultTestRateCounterMaxKeys)
}

// SetupTestRateCounterStoreWithMaxKeys returns a real business.RateCounterStore
// that tracks at most maxKeys distinct keys at once, so a test can reach the
// tracked-key backstop — and observe the ErrRateCounterCapacityExhausted denial
// callers must fail closed on — by genuinely filling the store rather than by
// asking it to return an error.
func SetupTestRateCounterStoreWithMaxKeys(maxKeys int) business.RateCounterStore {
	if maxKeys <= 0 {
		maxKeys = defaultTestRateCounterMaxKeys
	}
	return &inMemRateCounterStore{
		entries: make(map[string]*inMemRateCounterWindow),
		maxKeys: maxKeys,
		now:     time.Now,
	}
}

// Increment implements business.RateCounterStore.Increment: one attempt is
// recorded against key's current window, a window whose duration has fully
// elapsed restarts at 1, and a brand-new key is declined once maxKeys distinct
// keys are tracked.
func (s *inMemRateCounterStore) Increment(_ context.Context, key string, window time.Duration) (int, time.Duration, error) {
	if key == "" {
		return 0, 0, fmt.Errorf("rate counter store: key cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, ErrRateCounterStoreClosed
	}

	now := s.now()
	s.pruneExpiredLocked(now)

	entry, tracked := s.entries[key]
	if !tracked {
		if len(s.entries) >= s.maxKeys {
			return 0, window, fmt.Errorf("rate counter store: at its %d-key cap: %w",
				s.maxKeys, business.ErrRateCounterCapacityExhausted)
		}
		entry = &inMemRateCounterWindow{windowStart: now, window: window}
		s.entries[key] = entry
	}
	if now.Sub(entry.windowStart) >= window {
		entry.windowStart = now
		entry.count = 0
	}
	entry.window = window
	entry.count++

	return entry.count, retryAfterFor(entry.windowStart, now, window), nil
}

// Peek implements business.RateCounterStore.Peek: it reports the live count for
// key without recording an attempt, and reports a key whose window has fully
// elapsed as absent rather than as a stale count.
func (s *inMemRateCounterStore) Peek(_ context.Context, key string, window time.Duration) (int, time.Duration, bool, error) {
	if key == "" {
		return 0, 0, false, fmt.Errorf("rate counter store: key cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, 0, false, ErrRateCounterStoreClosed
	}

	entry, tracked := s.entries[key]
	if !tracked {
		return 0, 0, false, nil
	}
	now := s.now()
	if now.Sub(entry.windowStart) >= window {
		return 0, 0, false, nil
	}
	return entry.count, retryAfterFor(entry.windowStart, now, window), true, nil
}

// Close makes every subsequent operation report ErrRateCounterStoreClosed. It
// is idempotent.
func (s *inMemRateCounterStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

// pruneExpiredLocked reclaims windows that have fully elapsed, so a flood of
// distinct keys cannot grow the store past the keys currently live — the same
// bound business.RateCounterStore requires of durable implementations.
func (s *inMemRateCounterStore) pruneExpiredLocked(now time.Time) {
	for key, entry := range s.entries {
		if now.Sub(entry.windowStart) >= entry.window {
			delete(s.entries, key)
		}
	}
}

func retryAfterFor(windowStart, now time.Time, window time.Duration) time.Duration {
	retryAfter := window - now.Sub(windowStart)
	if retryAfter < 0 {
		return 0
	}
	return retryAfter
}

// Compile-time assertion.
var _ business.RateCounterStore = (*inMemRateCounterStore)(nil)
