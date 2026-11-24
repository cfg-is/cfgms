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

	"github.com/cfgis/cfgms/pkg/atomicfile"
)

const (
	// casLockSubdir is the directory CompareAndSwapSecret lock files live under,
	// relative to the resolved lock root.
	casLockSubdir = ".cas-locks"

	// casLockAcquireTimeout bounds a lack of progress, not total queueing time: a
	// waiter fails closed when the holder ahead of it has not released within this
	// long. Waiting behind holders that keep releasing is not a timeout.
	casLockAcquireTimeout = 5 * time.Second
)

var errCASLockTimeout = errors.New("timed out waiting for compare-and-swap lock")

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
// one tenant+key pair. An in-process FIFO queue orders the goroutines of this
// process, and only the head takes the OS advisory lock (flock on Unix,
// LockFileEx on Windows) on a persistent per-key lock file, through
// atomicfile.QueuedLockFile. The kernel releases that lock when the holder
// process exits, so there is no stale-lock steal, and the lock file is never
// deleted. The wait is bounded by casLockAcquireTimeout of no progress, not of
// total queueing time. It fails closed: a timeout, a cancelled context or a lock
// directory that cannot be created returns an error and no release func. The
// caller must call the returned release func exactly once.
func acquireCASLock(ctx context.Context, dir, tenantID, key string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create compare-and-swap lock directory: %w", err)
	}
	release, err := atomicfile.QueuedLockFile(ctx, lockFilePath(dir, tenantID, key), casLockAcquireTimeout)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, atomicfile.ErrLockNoProgress) {
			return nil, errCASLockTimeout
		}
		return nil, fmt.Errorf("failed to acquire compare-and-swap lock: %w", err)
	}
	return release, nil
}
