// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package flatfile

import (
	"errors"
	"math/rand/v2"
	"os"
	"syscall"
	"time"
)

// atomicRename renames src → dst on Windows with a short retry loop that
// outlasts a concurrent reader's open-read-close cycle.
//
// Why a retry: Windows differs from POSIX in that MoveFileEx /
// MOVEFILE_REPLACE_EXISTING (the path os.Rename takes on Windows for
// existing-target replacement) fails with ERROR_ACCESS_DENIED (errno 5)
// or ERROR_SHARING_VIOLATION (errno 32) when ANY other handle has the
// destination file open — even just for reading. POSIX has no such
// restriction: rename(2) decouples the directory entry from the open
// handle so concurrent readers continue reading the orphaned inode.
//
// The blue/green substrate (Issue #1919) requires a controller writer
// to be able to replace a config file while a peer controller is reading
// it. We achieve this by retrying the rename on EACCES /
// ERROR_SHARING_VIOLATION with a randomised-jitter exponential backoff.
//
// Worst-case schedule across 12 attempts: ~63ms exponential ramp
// (1→2→4→8→16→32→ saturate at 50) + 6 × 50ms saturated tail = ~363ms
// pre-jitter. Jitter doubles the cumulative ceiling so an absolute
// maximum hold time is ~750ms before surfacing the error to the caller.
// That budget is intentionally generous: a stuck reader past that point
// is a real fault, not normal contention.
//
// Jitter rationale: without it, every Windows process retrying against
// the same target file fires on identical millisecond boundaries. Under
// sustained blue/green load (peer reading from a file while we replace
// it), correlated retries become a self-amplifying contention storm.
// Randomising each sleep by ±50% de-correlates retry attempts across
// processes and prevents the livelock failure mode.
//
// Note: ReplaceFileW would be a more elegant solution because it allows
// the replace to proceed even with open readers (the readers keep their
// view of the old file, just like POSIX). But ReplaceFileW also requires
// the destination to already exist, so the "first-write" path would
// need separate code anyway. The retry strategy works uniformly for
// both first-write (uncontested rename) and replace (contested rename).
func atomicRename(src, dst string) error {
	const (
		maxAttempts = 12
		baseDelay   = 1 * time.Millisecond
		maxDelay    = 50 * time.Millisecond
	)
	var lastErr error
	delay := baseDelay
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := os.Rename(src, dst)
		if err == nil {
			return nil
		}
		if !isRetryableRenameError(err) {
			return err
		}
		lastErr = err
		time.Sleep(jitter(delay))
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	return lastErr
}

// jitter returns d randomised by ±50% so concurrent writers/readers
// retrying against the same target don't fire on aligned millisecond
// boundaries. Uses math/rand/v2 (Go 1.22+) which is seeded automatically
// — fine for jitter, NOT for cryptographic purposes.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	// Random factor in [0.5, 1.5).
	factor := 0.5 + rand.Float64() //nolint:gosec // jitter, not crypto
	return time.Duration(float64(d) * factor)
}

// isRetryableRenameError reports whether err is the specific Windows
// failure mode that occurs when a concurrent reader holds the destination
// file open. Any other failure (permission denied at the directory
// level, disk full, path invalid) is non-retryable and surfaces
// immediately.
func isRetryableRenameError(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ERROR_ACCESS_DENIED = 5, ERROR_SHARING_VIOLATION = 32
		return errno == syscall.Errno(5) || errno == syscall.Errno(32)
	}
	return false
}
