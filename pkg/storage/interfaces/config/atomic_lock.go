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

	unlock, err := atomicfile.QueuedLockFile(ctx, path, atomicLockAcquireTimeout)
	if err != nil {
		if errors.Is(err, atomicfile.ErrLockNoProgress) {
			return nil, errAtomicLockTimeout
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("failed to acquire atomic-update lock: %w", err)
	}
	return unlock, nil
}
