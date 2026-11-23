// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/atomicfile"
)

const (
	// atomicLockSubdir is the directory per-key lock files live under, inside the
	// store's own directory.
	atomicLockSubdir = ".atomic-locks"

	// atomicLockAcquireTimeout bounds a lack of progress, not total queueing
	// time: a waiter fails closed when the holder ahead of it has not released
	// within this long. Its timer restarts whenever the head of the key's queue
	// changes, so waiting behind holders that keep releasing is not a timeout.
	atomicLockAcquireTimeout = 5 * time.Second
)

var errAtomicLockTimeout = errors.New("timed out waiting for atomic-update lock")

// ErrNoAtomicLockDir reports that a store which is not conditional exposes no
// private directory to place lock files in. It is fatal rather than a fallback:
// a lock under a shared location such as os.TempDir() can be pre-created or
// deleted by any local user, which defeats mutual exclusion.
var ErrNoAtomicLockDir = errors.New(
	"config store exposes no private directory for atomic-update lock files")

// AtomicLockDirProvider is implemented by a ConfigStore that has its own private
// on-disk directory (created mode 0700/0750 by the store, not writable by other
// local users) in which per-key lock files can be placed.
type AtomicLockDirProvider interface {
	// AtomicLockRoot returns the store's own data directory.
	AtomicLockRoot() string
}

// atomicLockDir resolves the lock directory for store: always a subdirectory of
// the store's own directory, never os.TempDir().
func atomicLockDir(store ConfigStore) (string, error) {
	if p, ok := store.(AtomicLockDirProvider); ok {
		if root := strings.TrimSpace(p.AtomicLockRoot()); root != "" {
			return filepath.Join(root, atomicLockSubdir), nil
		}
	}
	return "", ErrNoAtomicLockDir
}

func atomicLockPath(dir string, key *ConfigKey) string {
	h := sha256.Sum256([]byte(key.TenantID + "\x00" + key.Namespace + "\x00" + key.Scope + "\x00" + key.Name))
	return filepath.Join(dir, hex.EncodeToString(h[:])+".lock")
}

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
// ctx error if ctx ends first, and errAtomicLockTimeout if the head did not
// change for atomicLockAcquireTimeout.
func waitForHead(ctx context.Context, path string, w *lockWaiter, changed <-chan struct{}) error {
	for {
		timer := time.NewTimer(atomicLockAcquireTimeout)
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
			return errAtomicLockTimeout
		}
	}
}

// acquireAtomicLock takes a mutual-exclusion lock for one key: an in-process
// FIFO queue orders goroutines of this process, and only the head takes the
// cross-process OS advisory lock (atomicfile.LockFile) on a persistent per-key
// lock file. The kernel releases that lock when the holder process exits, so
// there is no stale-lock steal, and the file is never deleted. The caller must
// call the returned release func.
func acquireAtomicLock(ctx context.Context, dir string, key *ConfigKey) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create atomic-update lock directory: %w", err)
	}
	path := atomicLockPath(dir, key)

	w, changed := enqueue(path)
	if err := waitForHead(ctx, path, w, changed); err != nil {
		dequeue(path, w)
		return nil, err
	}

	// The head waits for the cross-process lock for at most
	// atomicLockAcquireTimeout from the moment it became head.
	lockCtx, cancel := context.WithTimeout(ctx, atomicLockAcquireTimeout)
	unlock, err := atomicfile.LockFile(lockCtx, path)
	cancel()
	if err != nil {
		dequeue(path, w)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, errAtomicLockTimeout
		}
		return nil, fmt.Errorf("failed to acquire atomic-update lock: %w", err)
	}
	return func() {
		unlock()
		dequeue(path, w)
	}, nil
}
