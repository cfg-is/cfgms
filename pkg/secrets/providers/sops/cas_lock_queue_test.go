// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package sops

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCASLock_QueueLongerThanTimeoutSucceeds proves the acquire timeout bounds a
// lack of progress, not total queueing time: 24 callers each holding ~300 ms take
// longer in total than casLockAcquireTimeout, and every one still acquires.
func TestCASLock_QueueLongerThanTimeoutSucceeds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), casLockSubdir)
	const callers = 24
	const hold = 300 * time.Millisecond

	counter := 0 // plain int, written only under the lock: -race catches broken exclusion
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := time.Now()
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			release, err := acquireCASLock(context.Background(), dir, "tenant", "key")
			if err != nil {
				errs[i] = err
				return
			}
			counter++
			time.Sleep(hold)
			release()
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for i, err := range errs {
		assert.NoError(t, err, "caller %d", i)
	}
	assert.Equal(t, callers, counter)
	assert.Greater(t, elapsed, casLockAcquireTimeout,
		"the queue must outlast the no-progress timeout for this test to prove anything")
}

func TestCASLock_LockFilePersistsAfterRelease(t *testing.T) {
	dir := filepath.Join(t.TempDir(), casLockSubdir)

	release, err := acquireCASLock(context.Background(), dir, "tenant", "key")
	require.NoError(t, err)
	release()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "exactly one lock file must remain after release")
	assert.Equal(t, filepath.Base(lockFilePath(dir, "tenant", "key")), entries[0].Name())

	if runtime.GOOS != "windows" {
		fi, err := entries[0].Info()
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
		di, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())
	}

	release2, err := acquireCASLock(context.Background(), dir, "tenant", "key")
	require.NoError(t, err)
	release2()
}

// TestCASLock_AgedLockFileIsNotStolen proves a lock file's age confers no right to
// take it: a live holder (another process, so the waiter reaches the OS lock and
// not just the in-process queue) keeps the lock however old the file looks.
func TestCASLock_AgedLockFileIsNotStolen(t *testing.T) {
	dir := filepath.Join(t.TempDir(), casLockSubdir)
	startHoldingHelper(t, dir)

	require.NoError(t, setLockFileModTime(lockFilePath(dir, casHelperTenant, casHelperKey), time.Now().Add(-time.Hour)))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	release, err := acquireCASLock(ctx, dir, casHelperTenant, casHelperKey)
	assert.Nil(t, release)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestCASLock_StuckHolderFailsClosed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), casLockSubdir)
	release, err := acquireCASLock(context.Background(), dir, "tenant", "key")
	require.NoError(t, err)
	defer release()

	start := time.Now()
	second, err := acquireCASLock(context.Background(), dir, "tenant", "key")
	assert.Nil(t, second)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timed out waiting for compare-and-swap lock")
	assert.Less(t, time.Since(start), casLockAcquireTimeout+2*time.Second)
}

func TestCASLock_CancelledContextReturnsCtxErr(t *testing.T) {
	dir := filepath.Join(t.TempDir(), casLockSubdir)
	holder, err := acquireCASLock(context.Background(), dir, "tenant", "key")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan error, 1)
	go func() {
		rel, err := acquireCASLock(ctx, dir, "tenant", "key")
		if rel != nil {
			rel()
		}
		cancelled <- err
	}()
	time.Sleep(100 * time.Millisecond) // let it queue behind the holder

	behind := make(chan error, 1)
	go func() {
		rel, err := acquireCASLock(context.Background(), dir, "tenant", "key")
		if err == nil {
			rel()
		}
		behind <- err
	}()
	time.Sleep(100 * time.Millisecond)

	cancel()
	select {
	case err := <-cancelled:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled waiter did not return")
	}

	holder()
	select {
	case err := <-behind:
		assert.NoError(t, err, "the waiter behind the cancelled one must still acquire")
	case <-time.After(casLockAcquireTimeout):
		t.Fatal("waiter behind the cancelled one did not acquire")
	}
}

func TestCASLock_AlreadyCancelledContextWritesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), casLockSubdir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := acquireCASLock(ctx, dir, "tenant", "key")
	assert.Nil(t, release)
	assert.ErrorIs(t, err, context.Canceled)
}
