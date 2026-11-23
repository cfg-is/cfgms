// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package atomicfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// lockRetryInterval is the wait between non-blocking lock attempts.
const lockRetryInterval = 5 * time.Millisecond

// LockFile takes an exclusive cross-process advisory lock on the file at path
// and returns a function that releases it. See the package documentation for
// the contract. On Windows the lock is LockFileEx on byte 0 with
// LOCKFILE_FAIL_IMMEDIATELY, retried until ctx ends: a blocking LockFileEx
// cannot honour a context.
func LockFile(ctx context.Context, path string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var f *os.File
	if err := RetryOnSharingViolation(func() error {
		var openErr error
		// #nosec G304 -- callers pass a path built from their own private directory
		f, openErr = os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		return openErr
	}); err != nil {
		return nil, fmt.Errorf("failed to open lock file: %w", err)
	}
	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)
	for {
		err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			_ = f.Close()
			return nil, fmt.Errorf("failed to lock file: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(lockRetryInterval):
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
			_ = f.Close()
		})
	}, nil
}
