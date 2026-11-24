// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package atomicfile

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func queueLen(path string) (int, bool) {
	lockQueuesMu.Lock()
	defer lockQueuesMu.Unlock()
	q, ok := lockQueues[filepath.Clean(path)]
	if !ok {
		return 0, false
	}
	return len(q.waiters), true
}

func TestQueuedLock_NoProgressReturnsSentinel(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	unlock, err := QueuedLockFile(context.Background(), path, 5*time.Second)
	require.NoError(t, err)
	defer unlock()

	start := time.Now()
	second, err := QueuedLockFile(context.Background(), path, 200*time.Millisecond)
	assert.Nil(t, second)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrLockNoProgress), "got %v", err)
	assert.GreaterOrEqual(t, time.Since(start), 150*time.Millisecond)

	n, ok := queueLen(path)
	assert.True(t, ok)
	assert.Equal(t, 1, n, "the timed-out waiter must have left the queue")
}

func TestQueuedLock_QueueRemovedWhenEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			unlock, err := QueuedLockFile(context.Background(), path, 5*time.Second)
			if !assert.NoError(t, err) {
				return
			}
			time.Sleep(10 * time.Millisecond)
			unlock()
		}()
	}
	wg.Wait()

	_, ok := queueLen(path)
	assert.False(t, ok, "no queue entry may remain once every holder has released")
}

func TestQueuedLock_QueueRemovedAfterFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unlock, err := QueuedLockFile(ctx, path, time.Second)
	assert.Nil(t, unlock)
	assert.ErrorIs(t, err, context.Canceled)
	_, ok := queueLen(path)
	assert.False(t, ok)

	// Cancelled while queued behind a holder.
	held, err := QueuedLockFile(context.Background(), path, 5*time.Second)
	require.NoError(t, err)
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel2)
	_, err = QueuedLockFile(ctx2, path, 5*time.Second)
	assert.ErrorIs(t, err, context.Canceled)
	held()
	_, ok = queueLen(path)
	assert.False(t, ok)
}

func TestQueuedLock_FIFOAndProgressRestartsTimer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.lock")
	const n = 6
	const hold = 100 * time.Millisecond
	const noProgress = 250 * time.Millisecond // total queue time (~600ms) exceeds it

	first, err := QueuedLockFile(context.Background(), path, noProgress)
	require.NoError(t, err)

	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			unlock, err := QueuedLockFile(context.Background(), path, noProgress)
			if !assert.NoError(t, err, "waiter %d", i) {
				return
			}
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			time.Sleep(hold)
			unlock()
		}(i)
		// Enqueue in a known order.
		require.Eventually(t, func() bool {
			l, _ := queueLen(path)
			return l == i+2
		}, 2*time.Second, time.Millisecond)
	}
	time.Sleep(hold)
	first()
	wg.Wait()

	assert.Equal(t, []int{0, 1, 2, 3, 4, 5}, order, "waiters acquire in arrival order")
}

func TestQueuedLock_CleansPathSpellings(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "k.lock")
	b := filepath.Join(dir, ".", "sub", "..", "k.lock")
	unlock, err := QueuedLockFile(context.Background(), a, 5*time.Second)
	require.NoError(t, err)
	defer unlock()

	// Same queue: the second spelling is a waiter, so the queue holds two.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = QueuedLockFile(context.Background(), b, 100*time.Millisecond)
	}()
	require.Eventually(t, func() bool { l, _ := queueLen(a); return l == 2 }, 2*time.Second, time.Millisecond)
	<-done
}

func TestQueuedLock_UnopenableLockFileIsHardFailure(t *testing.T) {
	// The parent directory does not exist, so the OS lock cannot be taken.
	path := filepath.Join(t.TempDir(), "missing", "k.lock")
	unlock, err := QueuedLockFile(context.Background(), path, 2*time.Second)
	assert.Nil(t, unlock)
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrLockNoProgress), "a hard open error is not a no-progress timeout: %v", err)
	_, ok := queueLen(path)
	assert.False(t, ok)
}
