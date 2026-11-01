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
)

const (
	// atomicLockSubdir is the directory per-key lock files live under, inside the
	// store's own directory.
	atomicLockSubdir = ".atomic-locks"

	atomicLockAcquireTimeout = 5 * time.Second
	atomicLockPollInterval   = 5 * time.Millisecond

	// atomicLockStaleAfter is how long an unreleased lock is honoured before a
	// waiter treats its holder as crashed and steals it.
	atomicLockStaleAfter = 30 * time.Second
)

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

// acquireAtomicLock takes a cross-process mutual-exclusion lock for one key using
// atomic O_CREATE|O_EXCL creation. The caller must call the returned release func.
func acquireAtomicLock(ctx context.Context, dir string, key *ConfigKey) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create atomic-update lock directory: %w", err)
	}
	path := atomicLockPath(dir, key)
	deadline := time.Now().Add(atomicLockAcquireTimeout)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- path derived from the store's own root, hashed key
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !isRetryableLockError(err) {
			return nil, fmt.Errorf("failed to acquire atomic-update lock: %w", err)
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > atomicLockStaleAfter {
			_ = os.Remove(path) // holder crashed; steal on the next iteration
		}
		if time.Now().After(deadline) {
			return nil, errors.New("timed out waiting for atomic-update lock")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(atomicLockPollInterval):
		}
	}
}
