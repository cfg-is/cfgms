// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package flatfile

import (
	"errors"
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
// ERROR_SHARING_VIOLATION with an exponential-ish backoff bounded by
// renameMaxWait. A reasonable single os.ReadFile completes in
// micro-to-milliseconds, so a budget of ~250 ms across ~10 attempts
// covers any sane concurrent-read load. Beyond that, returning the
// error to the caller is the right behaviour — that's a stuck reader,
// not normal contention.
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
		time.Sleep(delay)
		if delay < maxDelay {
			delay *= 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	return lastErr
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
