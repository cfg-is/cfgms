// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// refusingRemover refuses its first refusals calls with an error shaped like the
// sharing violation Windows returns while another process holds a handle on the
// file, then removes for real.
func refusingRemover(refusals int) (remove func(string) error, calls *int) {
	n := new(int)
	return func(path string) error {
		*n++
		if *n <= refusals {
			return &os.PathError{Op: "remove", Path: path, Err: errors.New("sharing violation")}
		}
		return os.Remove(path)
	}, n
}

// A release whose first removals fail must still free the lock: the next acquirer
// gets it at once instead of waiting out atomicLockAcquireTimeout.
func TestReleaseAtomicLock_RetriesFailedRemoval(t *testing.T) {
	dir := filepath.Join(t.TempDir(), atomicLockSubdir)
	key := &ConfigKey{TenantID: "t", Namespace: "n", Name: "k"}

	_, err := acquireAtomicLock(context.Background(), dir, key)
	require.NoError(t, err)

	remove, calls := refusingRemover(3)
	releaseAtomicLock(atomicLockPath(dir, key), remove)
	assert.Equal(t, 4, *calls, "three refused removals are retried until one succeeds")

	start := time.Now()
	next, err := acquireAtomicLock(context.Background(), dir, key)
	require.NoError(t, err, "the lock must be free after a release that had to retry")
	assert.Less(t, time.Since(start), atomicLockAcquireTimeout/2)
	next()
}

// A lock file that is already gone is released, not retried.
func TestReleaseAtomicLock_AbsentFileIsReleased(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.lock")
	calls := 0
	releaseAtomicLock(path, func(p string) error {
		calls++
		return os.Remove(p)
	})
	assert.Equal(t, 1, calls)
}

// A removal that never succeeds is abandoned after atomicLockReleaseTimeout, which
// is shorter than the acquire timeout, so the holder is never blocked forever.
func TestReleaseAtomicLock_GivesUpAfterBound(t *testing.T) {
	calls := 0
	start := time.Now()
	releaseAtomicLock("unused", func(string) error {
		calls++
		return errors.New("sharing violation")
	})
	assert.Greater(t, calls, 1)
	assert.GreaterOrEqual(t, time.Since(start), atomicLockReleaseTimeout)
	assert.Less(t, atomicLockReleaseTimeout, atomicLockAcquireTimeout)
}
