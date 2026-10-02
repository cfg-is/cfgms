// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
// Package database implements business.RateCounterStore using PostgreSQL
// (Issue #3896, ADR-031 Decision 1: abuse-budget counters must be
// cluster-visible so any-node service enforces a configured budget against the
// fleet-wide count, replacing the clusterBudgetDivisor even-distribution
// approximation an adversary targeting one node could defeat).
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.RateCounterStore = (*DatabaseRateCounterStore)(nil)

const (
	// defaultRateCounterMaxRows bounds how many distinct keys the shared table
	// tracks at once — the shared-store equivalent of the in-memory limiter's
	// sourceRateLimiterDefaultMaxTrackedKeys, set an order of magnitude higher
	// because one table serves the whole fleet rather than one process. Once
	// reached, a brand-new key is declined (Increment returns
	// business.ErrRateCounterCapacityExhausted and the caller denies the
	// request) while keys already tracked keep incrementing, so a flood of
	// distinct source addresses cannot grow the shared database without bound.
	// Override with config["rate_counter_max_rows"].
	defaultRateCounterMaxRows = 100_000

	// defaultRateCounterSweepInterval is how often, at most, one process runs
	// the prune sweep. The sweep is driven by Increment rather than by a
	// background goroutine so it has no lifecycle of its own to leak, and so
	// it runs exactly when rows are being created. It also sets how stale the
	// row count behind the cap's fast path can be, which is why it is seconds
	// rather than minutes: new keys can be inserted without an exact check
	// only for this long after a sweep found the table under
	// rateCounterCapacityGuardBand. Override with
	// config["rate_counter_sweep_interval"].
	defaultRateCounterSweepInterval = 5 * time.Second

	// rateCounterCapacityGuardBand is the fraction of the cap (a tenth) kept
	// as headroom: once a sweep finds the table within that band, every
	// subsequent insert of a new key carries the exact row-count check into
	// SQL. The band absorbs the inserts that can land between two sweeps, so
	// the table reaches the exact check before it can reach the cap itself.
	rateCounterCapacityGuardBand = 10
)

// DatabaseRateCounterStore implements business.RateCounterStore using
// PostgreSQL. Increment is a single INSERT ... ON CONFLICT DO UPDATE ...
// RETURNING statement: PostgreSQL's own row-level locking on the targeted row
// serializes concurrent callers — including callers on different controller
// nodes sharing this store — so a concurrent increment race from two nodes
// against the same key never loses an attempt, following the same
// no-application-mutex idiom as
// DatabaseModuleApprovalStore.CompareAndSetApprovalStatus.
//
// Growth is bounded on both axes required by business.RateCounterStore:
// PruneExpired reclaims rows whose window has fully elapsed, and maxRows caps
// the number of distinct keys tracked at once, declining new keys past the cap
// instead of letting attacker-chosen keys accumulate.
type DatabaseRateCounterStore struct {
	db *sql.DB

	// maxRows is the tracked-key cap; sweepInterval is the minimum spacing
	// between prune sweeps this process triggers.
	maxRows       int
	sweepInterval time.Duration

	// lastSweepUnixNano gates sweepIfDue so only one caller per interval pays
	// for a sweep.
	lastSweepUnixNano atomic.Int64

	// capacityGuard is set when the last sweep found the table at or near its
	// cap — or could not determine the row count at all. While set, every
	// Increment that would insert a brand-new key carries the exact row-count
	// check into SQL; while clear, that check is skipped entirely, so the cap
	// costs nothing on the traffic that is nowhere near it.
	capacityGuard atomic.Bool

	mu           sync.Mutex
	lastPruneErr error
}

// NewDatabaseRateCounterStore initialises the schema on the given shared
// connection pool and returns a ready-to-use RateCounterStore. Rows left
// behind by a previous process are pruned before the store serves any caller,
// so a restart never inherits another run's dead keys.
func NewDatabaseRateCounterStore(db *sql.DB, config map[string]interface{}) (*DatabaseRateCounterStore, error) {
	store := &DatabaseRateCounterStore{
		db:            db,
		maxRows:       defaultRateCounterMaxRows,
		sweepInterval: defaultRateCounterSweepInterval,
	}
	if raw, present := config["rate_counter_max_rows"]; present {
		maxRows := getIntFromConfig(config, "rate_counter_max_rows", 0)
		if maxRows <= 0 {
			return nil, fmt.Errorf("database: rate_counter_max_rows must be a positive integer, got %T", raw)
		}
		store.maxRows = maxRows
	}
	if raw, present := config["rate_counter_sweep_interval"]; present {
		interval, err := parseRateCounterSweepInterval(raw)
		if err != nil {
			return nil, err
		}
		store.sweepInterval = interval
	}
	if err := NewDatabaseSchemas().CreateRateCountersTable(context.Background(), db); err != nil {
		return nil, fmt.Errorf("database: failed to initialise rate counter schema: %w", err)
	}
	if _, err := store.PruneExpired(context.Background()); err != nil {
		return nil, fmt.Errorf("database: failed initial rate counter prune: %w", err)
	}
	return store, nil
}

// parseRateCounterSweepInterval accepts either a time.Duration or a duration
// string ("5s"), the two shapes the provider config arrives in. A present but
// unusable value is an error rather than a silent fall back to the default: a
// sweep interval that was configured and ignored is how a growth bound quietly
// stops holding.
func parseRateCounterSweepInterval(raw interface{}) (time.Duration, error) {
	var interval time.Duration
	switch v := raw.(type) {
	case time.Duration:
		interval = v
	case string:
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return 0, fmt.Errorf("database: rate_counter_sweep_interval is not a valid duration: %w", err)
		}
		interval = parsed
	default:
		return 0, fmt.Errorf("database: rate_counter_sweep_interval must be a duration or duration string, got %T", raw)
	}
	if interval <= 0 {
		return 0, fmt.Errorf("database: rate_counter_sweep_interval must be positive")
	}
	return interval, nil
}

// Close is a no-op — DatabaseProvider.Close() owns the shared pool's lifecycle.
func (s *DatabaseRateCounterStore) Close() error {
	return nil
}

// clampRetryAfter bounds a computed remaining-window duration to [0, window].
//
// The lower bound covers a window that elapsed between the read and the
// arithmetic. The upper bound covers clock-domain skew: window_start is a
// PostgreSQL timestamptz, which stores microseconds, while now is a Go
// time.Time carrying nanoseconds. Writing now into window_start rounds it to
// the nearest microsecond, so the value read back can be up to 500ns *later*
// than now. now.Sub(windowStart) is then negative and the subtraction yields
// slightly more than a full window — observed as a 96ns overshoot in CI
// (Issue #3896). Callers surface this as Retry-After, whose contract is at
// most one window, so the excess is clamped here rather than left to leak into
// a response header.
func clampRetryAfter(retryAfter, window time.Duration) time.Duration {
	if retryAfter < 0 {
		return 0
	}
	if retryAfter > window {
		return window
	}
	return retryAfter
}

// Increment implements business.RateCounterStore.Increment. The CASE
// expressions inside the UPDATE reset count, window_start and expires_at
// together exactly when the existing row's window has fully elapsed
// (window_start at or before staleBefore, i.e. now-window_start >= window) —
// the same fixed-window-reset condition the in-memory sourceRateLimiter record
// this store backs applies, kept atomic within one statement so no other
// caller can observe (or race) a torn reset.
//
// The WHERE clause is the tracked-key cap. Its first disjunct is the fast
// path: while the last sweep found the table comfortably under the cap it is
// true and PostgreSQL never evaluates the rest. Otherwise a key already
// tracked still passes (EXISTS), so live budgets keep being enforced under
// pressure, and a brand-new key passes only while the exact row count is below
// the cap. When no disjunct holds, nothing is inserted, RETURNING yields no
// row, and the call is reported as business.ErrRateCounterCapacityExhausted so
// the caller fails closed — the shared-store form of the in-memory limiter's
// "deny without ever storing this one" backstop.
//
// The count and the insert are one statement but not one lock, so N inserts of
// distinct new keys running concurrently at the cap can each see room and land:
// the cap is exceeded by at most the number of in-flight statements, itself
// bounded by the connection pool. The property that matters — growth bounded by
// a constant rather than by the number of distinct keys ever seen — holds.
func (s *DatabaseRateCounterStore) Increment(ctx context.Context, key string, window time.Duration) (int, time.Duration, error) {
	if key == "" {
		return 0, 0, fmt.Errorf("database: rate counter key cannot be empty")
	}
	now := time.Now().UTC()
	staleBefore := now.Add(-window)
	expiresAt := now.Add(window)

	s.sweepIfDue(ctx, now)

	var count int
	var windowStart time.Time
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO cfgms_rate_counters (key, window_start, expires_at, count)
		SELECT $1::text, $2::timestamptz, $4::timestamptz, 1
		WHERE $5::boolean
			OR EXISTS (SELECT 1 FROM cfgms_rate_counters WHERE key = $1::text)
			OR (SELECT count(*) FROM cfgms_rate_counters) < $6::int
		ON CONFLICT (key) DO UPDATE SET
			count = CASE WHEN cfgms_rate_counters.window_start <= $3 THEN 1 ELSE cfgms_rate_counters.count + 1 END,
			window_start = CASE WHEN cfgms_rate_counters.window_start <= $3 THEN $2 ELSE cfgms_rate_counters.window_start END,
			expires_at = CASE WHEN cfgms_rate_counters.window_start <= $3 THEN $4 ELSE cfgms_rate_counters.expires_at END
		RETURNING count, window_start`,
		key, now, staleBefore, expiresAt, !s.capacityGuard.Load(), s.maxRows,
	).Scan(&count, &windowStart)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// The key is untracked and the table is full. Deny for a whole
			// window; the key itself is never echoed back to the caller.
			return 0, window, fmt.Errorf("database: rate counter table is at its %d-row cap: %w",
				s.maxRows, business.ErrRateCounterCapacityExhausted)
		}
		return 0, 0, fmt.Errorf("database: failed to increment rate counter: %w", err)
	}

	retryAfter := clampRetryAfter(window-now.Sub(windowStart), window)
	return count, retryAfter, nil
}

// Peek implements business.RateCounterStore.Peek. A row whose window has
// fully elapsed is reported as found=false rather than as a stale count,
// mirroring the reset condition Increment applies — the row itself is left
// untouched; only the next Increment or PruneExpired removes it.
func (s *DatabaseRateCounterStore) Peek(ctx context.Context, key string, window time.Duration) (int, time.Duration, bool, error) {
	if key == "" {
		return 0, 0, false, fmt.Errorf("database: rate counter key cannot be empty")
	}
	now := time.Now().UTC()
	staleBefore := now.Add(-window)

	var count int
	var windowStart time.Time
	err := s.db.QueryRowContext(ctx,
		"SELECT count, window_start FROM cfgms_rate_counters WHERE key = $1", key,
	).Scan(&count, &windowStart)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, 0, false, nil
		}
		return 0, 0, false, fmt.Errorf("database: failed to read rate counter: %w", err)
	}
	if !windowStart.After(staleBefore) {
		return 0, 0, false, nil
	}

	retryAfter := clampRetryAfter(window-now.Sub(windowStart), window)
	return count, retryAfter, true, nil
}

// PruneExpired deletes every row whose window has fully elapsed — rows that
// Increment and Peek already treat as absent — and refreshes the row count
// that decides whether Increment can skip the cap check. It returns the number
// of rows deleted. Safe to run concurrently on any number of nodes: the DELETE
// only ever removes rows no caller can still observe as a live count.
func (s *DatabaseRateCounterStore) PruneExpired(ctx context.Context) (int, error) {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM cfgms_rate_counters WHERE expires_at <= $1", time.Now().UTC())
	if err != nil {
		s.setLastPruneErr(err)
		return 0, fmt.Errorf("database: failed to prune expired rate counters: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		s.setLastPruneErr(err)
		return 0, fmt.Errorf("database: failed to read pruned rate counter count: %w", err)
	}

	var rows int
	if err := s.db.QueryRowContext(ctx, "SELECT count(*) FROM cfgms_rate_counters").Scan(&rows); err != nil {
		s.setLastPruneErr(err)
		return int(deleted), fmt.Errorf("database: failed to count rate counter rows: %w", err)
	}

	// Arm the exact per-insert cap check once the table is inside the headroom
	// band, so the gap between sweeps cannot be used to overshoot the cap.
	s.capacityGuard.Store(rows >= s.maxRows-s.maxRows/rateCounterCapacityGuardBand)
	s.lastSweepUnixNano.Store(time.Now().UnixNano())
	s.setLastPruneErr(nil)
	return int(deleted), nil
}

// LastPruneError reports the error from the most recent prune sweep, or nil
// when it succeeded. Increment's opportunistic sweeps have no caller to return
// an error to — a prune failure must not fail an otherwise-successful
// increment — so the error is retained here rather than discarded, and it also
// changes behaviour: see sweepIfDue.
func (s *DatabaseRateCounterStore) LastPruneError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPruneErr
}

func (s *DatabaseRateCounterStore) setLastPruneErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPruneErr = err
}

// sweepIfDue runs PruneExpired at most once per sweepInterval per process. The
// compare-and-swap claims the sweep before it runs, so concurrent Increments
// produce one sweep between them rather than one each.
//
// A failed sweep arms capacityGuard: without a fresh row count the cheap
// under-cap fast path is an unverified assumption, and the safe response is to
// make every subsequent insert carry the exact count check in SQL until a
// sweep succeeds. The error itself is kept for LastPruneError.
func (s *DatabaseRateCounterStore) sweepIfDue(ctx context.Context, now time.Time) {
	last := s.lastSweepUnixNano.Load()
	if now.UnixNano()-last < int64(s.sweepInterval) {
		return
	}
	if !s.lastSweepUnixNano.CompareAndSwap(last, now.UnixNano()) {
		return
	}
	if _, err := s.PruneExpired(ctx); err != nil {
		s.capacityGuard.Store(true)
	}
}
