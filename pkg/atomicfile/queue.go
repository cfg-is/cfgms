// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package atomicfile

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"
)

// ErrLockNoProgress reports that QueuedLockFile gave up because the lock made
// no progress for the no-progress duration: either the holder ahead of the
// caller in this process did not release, or the head of the queue could not
// take the OS lock, within that duration. Callers match it with errors.Is.
var ErrLockNoProgress = errors.New("lock holder made no progress")

// keyQueue orders the goroutines of this process that want one lock file. The
// goroutine at the head holds, or is acquiring, the cross-process lock; the
// others wait in arrival order and never touch the filesystem.
type keyQueue struct {
	waiters []*lockWaiter
	// changed is closed, and replaced, whenever the head changes. Waiters use it
	// to restart their no-progress timer.
	changed chan struct{}
}

type lockWaiter struct {
	head chan struct{} // closed when this waiter becomes the head
}

var (
	lockQueuesMu sync.Mutex
	lockQueues   = map[string]*keyQueue{}
)

// enqueue appends a waiter for path. The first waiter is the head at once.
func enqueue(path string) (*lockWaiter, <-chan struct{}) {
	lockQueuesMu.Lock()
	defer lockQueuesMu.Unlock()
	q := lockQueues[path]
	if q == nil {
		q = &keyQueue{changed: make(chan struct{})}
		lockQueues[path] = q
	}
	w := &lockWaiter{head: make(chan struct{})}
	q.waiters = append(q.waiters, w)
	if len(q.waiters) == 1 {
		close(w.head)
	}
	return w, q.changed
}

// currentChanged returns the channel closed at the next head change.
func currentChanged(path string) <-chan struct{} {
	lockQueuesMu.Lock()
	defer lockQueuesMu.Unlock()
	if q := lockQueues[path]; q != nil {
		return q.changed
	}
	return nil
}

// dequeue removes w from path's queue. When w was the head the next waiter
// becomes head and every waiter's no-progress timer restarts. An empty queue is
// dropped from the map so it does not grow.
func dequeue(path string, w *lockWaiter) {
	lockQueuesMu.Lock()
	defer lockQueuesMu.Unlock()
	q := lockQueues[path]
	if q == nil {
		return
	}
	for i, x := range q.waiters {
		if x != w {
			continue
		}
		q.waiters = append(q.waiters[:i], q.waiters[i+1:]...)
		if i == 0 {
			close(q.changed)
			q.changed = make(chan struct{})
			if len(q.waiters) > 0 {
				close(q.waiters[0].head)
			}
		}
		break
	}
	if len(q.waiters) == 0 {
		delete(lockQueues, path)
	}
}

// waitForHead blocks until w is the head of its queue. It returns the caller's
// ctx error if ctx ends first, and ErrLockNoProgress if the head did not change
// for noProgress.
func waitForHead(ctx context.Context, path string, w *lockWaiter, changed <-chan struct{}, noProgress time.Duration) error {
	for {
		timer := time.NewTimer(noProgress)
		select {
		case <-w.head:
			timer.Stop()
			return nil
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-changed:
			timer.Stop()
			changed = currentChanged(path)
		case <-timer.C:
			return ErrLockNoProgress
		}
	}
}

// QueuedLockFile takes the exclusive lock on path for one goroutine at a time.
// Goroutines of this process queue by path in arrival order; only the head
// calls LockFile, so waiters never touch the filesystem. The wait is bounded by
// lack of progress, not total time: a waiter fails with ErrLockNoProgress when
// the head of its queue has not changed for noProgress, and the head fails the
// same way when it cannot take the OS lock within noProgress. Waiting behind
// holders that keep releasing is therefore not a timeout.
//
// It returns ctx.Err() when ctx ends first. On any error nothing is held and
// the caller is out of the queue. The returned unlock releases the OS lock and
// then hands the head to the next waiter; call it exactly once. The lock file
// is persistent and never deleted. The caller creates path's directory.
func QueuedLockFile(ctx context.Context, path string, noProgress time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Two spellings of one path must share one queue.
	key := filepath.Clean(path)

	w, changed := enqueue(key)
	if err := waitForHead(ctx, key, w, changed, noProgress); err != nil {
		dequeue(key, w)
		return nil, err
	}

	// The head waits for the cross-process lock for at most noProgress from the
	// moment it became head.
	lockCtx, cancel := context.WithTimeout(ctx, noProgress)
	unlock, err := LockFile(lockCtx, path)
	cancel()
	if err != nil {
		dequeue(key, w)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, ErrLockNoProgress
		}
		return nil, fmt.Errorf("failed to acquire lock: %w", err)
	}
	return func() {
		unlock()
		dequeue(key, w)
	}, nil
}
