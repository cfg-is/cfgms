// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIsBusyErr(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"sqlite_busy", errors.New("sqlite: SQLITE_BUSY: database is locked (5)"), true},
		{"database is locked", errors.New("database is locked (5)"), true},
		{"table locked", errors.New("database table is locked: stewards"), true},
		{"unique constraint not retried", errors.New("UNIQUE constraint failed: stewards.id"), false},
		{"unrelated", errors.New("no such table: stewards"), false},
	}
	for _, tc := range cases {
		if got := isBusyErr(tc.err); got != tc.want {
			t.Errorf("%s: isBusyErr=%v want %v", tc.name, got, tc.want)
		}
	}
}

// TestRetryOnBusy_RetriesThenSucceeds: a write that reports BUSY twice then
// succeeds must succeed (the single-writer contention clears) — and fn is
// invoked exactly the number of times it took.
func TestRetryOnBusy_RetriesThenSucceeds(t *testing.T) {
	calls := 0
	err := retryOnBusy(context.Background(), func() error {
		calls++
		if calls < 3 {
			return errors.New("SQLITE_BUSY: database is locked (5)")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

// TestRetryOnBusy_NonBusyReturnsImmediately: a semantic error (e.g. UNIQUE
// violation) must be returned on the first attempt, never retried.
func TestRetryOnBusy_NonBusyReturnsImmediately(t *testing.T) {
	calls := 0
	sentinel := errors.New("UNIQUE constraint failed: stewards.id")
	err := retryOnBusy(context.Background(), func() error {
		calls++
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel returned unchanged, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly 1 attempt for a non-busy error, got %d", calls)
	}
}

// TestRetryOnBusy_GivesUpAfterMaxAttempts: persistent BUSY surfaces the last
// error after busyMaxAttempts (does not loop forever).
func TestRetryOnBusy_GivesUpAfterMaxAttempts(t *testing.T) {
	calls := 0
	err := retryOnBusy(context.Background(), func() error {
		calls++
		return errors.New("SQLITE_BUSY: database is locked (5)")
	})
	if !isBusyErr(err) {
		t.Fatalf("expected a busy error after exhausting retries, got %v", err)
	}
	if calls != busyMaxAttempts {
		t.Fatalf("expected %d attempts, got %d", busyMaxAttempts, calls)
	}
}

// TestRetryOnBusy_RespectsContextCancellation: a cancelled context stops the
// retry loop promptly with the context error.
func TestRetryOnBusy_RespectsContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := retryOnBusy(ctx, func() error {
		return errors.New("SQLITE_BUSY: database is locked (5)")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// Guard: backoff math stays bounded and small.
func TestRetryOnBusy_BackoffBounded(t *testing.T) {
	start := time.Now()
	_ = retryOnBusy(context.Background(), func() error {
		return errors.New("database is locked")
	})
	// 10+20+40+80+160+ (5 sleeps after the first 5 failures; last attempt no sleep)
	// ~310ms worst case; allow generous ceiling to avoid CI flakiness.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("retry backoff took too long: %v", elapsed)
	}
}
