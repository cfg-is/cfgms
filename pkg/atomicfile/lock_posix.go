// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package atomicfile

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// lockRetryInterval is the wait between non-blocking lock attempts.
const lockRetryInterval = 5 * time.Millisecond

// LockFile takes an exclusive cross-process advisory lock on the file at path
// and returns a function that releases it. See the package documentation for
// the contract. On Unix the lock is flock(2) with LOCK_NB, retried until ctx
// ends: a blocking flock cannot honour a context. flock locks belong to the open
// file description, so two handles in one process exclude each other too, which
// POSIX fcntl record locks would not.
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
	fd := int(f.Fd()) // #nosec G115 -- fd fits in int
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if err == unix.EINTR {
			continue
		}
		if err != unix.EWOULDBLOCK && err != unix.EAGAIN {
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
			_ = unix.Flock(fd, unix.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}
