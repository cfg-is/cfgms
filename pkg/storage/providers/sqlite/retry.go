// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"strings"
	"time"
)

// busyMaxAttempts and busyBaseBackoff bound the Go-level retry that backstops
// the connection-level busy_timeout pragma (see openDB). Six attempts with
// 10ms→320ms exponential backoff (~630ms worst case) is ample headroom for the
// single-writer contention SQLite serialises: the contending writer's commit
// is sub-millisecond, so a retry almost always succeeds on the next attempt.
const (
	busyMaxAttempts = 6
	busyBaseBackoff = 10 * time.Millisecond
)

// isBusyErr reports whether err is a SQLite lock-contention error
// (SQLITE_BUSY / SQLITE_LOCKED). modernc.org/sqlite surfaces these as text;
// match on the documented substrings rather than a numeric code so the check
// is driver-version-stable.
func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") ||
		strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked")
}

// retryOnBusy runs fn, retrying with bounded exponential backoff while it
// returns a SQLite lock-contention error. It is a Go-level backstop for the
// residual SQLITE_BUSY that modernc.org/sqlite can surface under heavy
// concurrent writers on slow I/O (observed on Windows CI runners — Issue
// #2068) even with busy_timeout=15s set per connection: the C busy handler is
// not always honored across the database/sql pool. SQLite is single-writer, so
// the contending lock is always released promptly and a retry converges.
//
// Only lock-contention errors are retried; every other error (and success)
// returns immediately, so semantic errors like a UNIQUE-constraint violation
// are surfaced to the caller unchanged on the first attempt. fn MUST be
// idempotent under a BUSY failure — true for a single autocommit statement,
// which does not partially apply when it returns BUSY.
func retryOnBusy(ctx context.Context, fn func() error) error {
	backoff := busyBaseBackoff
	var err error
	for attempt := 0; attempt < busyMaxAttempts; attempt++ {
		err = fn()
		if !isBusyErr(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return err
}
