// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

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
	// casLockSubdir is the directory CompareAndSwapSecret lock files live under,
	// relative to the resolved lock root.
	casLockSubdir = ".cas-locks"

	// casLockAcquireTimeout bounds how long CompareAndSwapSecret waits for a
	// contended lock before giving up.
	casLockAcquireTimeout = 5 * time.Second

	// casLockPollInterval is the spin-wait interval between lock attempts.
	casLockPollInterval = 5 * time.Millisecond

	// casLockStaleAfter is how long an unreleased lock file is honoured before a
	// waiter treats its holder as crashed and steals it. Without this, a process
	// that dies mid-critical-section would deadlock every future
	// CompareAndSwapSecret call on that key forever.
	casLockStaleAfter = 30 * time.Second
)

// errNoCASLockRoot reports that no lock directory could be derived from the
// backend configuration. It is deliberately fatal to the CompareAndSwapSecret
// call rather than a fallback: see casLockDir.
var errNoCASLockRoot = errors.New(
	"no private lock directory can be derived from the secret store's backend configuration")

// casLockDir resolves the directory to place CompareAndSwapSecret lock files in,
// derived from the same storage configuration the underlying ConfigStore was
// created from — the store's own data root, which is created by the store at mode
// 0700 and is not writable by other local users. Real, OS-visible file locking on
// that root is what coordinates CompareAndSwapSecret across independent
// SOPSSecretStore instances pointed at the same flatfile root.
//
// It fails closed when the backend exposes no such root. There is deliberately no
// fallback to a shared location such as os.TempDir(): a lock directory under a
// world-writable path can be pre-created by any local user, who can then delete
// lock files to defeat mutual exclusion outright — re-enabling the double-spend
// this lock exists to prevent, on a single node — or hold them to stall every
// caller. A lock whose security depends on winning a race against a local
// unprivileged user is not a lock, and silently substituting one for the real
// thing is exactly the "configuration that silently degrades security when it is
// absent" footgun (Story #396).
//
// A backend with no local filesystem root (e.g. "database") is not expected to
// reach this function at all: such backends provide their own conditional-write
// primitive and SOPSSecretStore uses that instead (see casStrategy in store.go).
func casLockDir(cfg *SOPSSecretStoreConfig) (string, error) {
	if cfg != nil && cfg.StorageConfig != nil {
		if root, ok := cfg.StorageConfig["root"].(string); ok && strings.TrimSpace(root) != "" {
			return filepath.Join(strings.TrimSpace(root), casLockSubdir), nil
		}
		if path, ok := cfg.StorageConfig["path"].(string); ok && strings.TrimSpace(path) != "" {
			return filepath.Join(filepath.Dir(strings.TrimSpace(path)), casLockSubdir), nil
		}
	}
	return "", errNoCASLockRoot
}

// lockFilePath maps a tenant+key pair to a lock file path. The key name itself is
// never embedded verbatim in the filename — it may contain path separators.
func lockFilePath(dir, tenantID, key string) string {
	h := sha256.Sum256([]byte(tenantID + "\x00" + key))
	return filepath.Join(dir, hex.EncodeToString(h[:])+".lock")
}

// acquireCASLock acquires a real, cross-process mutual-exclusion lock scoped to
// one tenant+key pair, using atomic O_CREATE|O_EXCL file creation — guaranteed
// atomic by the OS on every platform CFGMS targets. The caller must call the
// returned release func exactly once to release the lock.
func acquireCASLock(ctx context.Context, dir, tenantID, key string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create compare-and-swap lock directory: %w", err)
	}
	path := lockFilePath(dir, tenantID, key)
	deadline := time.Now().Add(casLockAcquireTimeout)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //#nosec G304 -- path derived from configured storage root, hashed key
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("failed to acquire compare-and-swap lock: %w", err)
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > casLockStaleAfter {
			_ = os.Remove(path) // abandoned lock (holder crashed); steal it on the next iteration
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for compare-and-swap lock")
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(casLockPollInterval):
		}
	}
}
