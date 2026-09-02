// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sops

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCASLockDir_DerivesFromPrivateStorageRoot proves the lock directory is placed
// inside the secret store's own data root — a directory the store creates 0700 and
// no other local user can write to — for both shapes of file-backed configuration.
func TestCASLockDir_DerivesFromPrivateStorageRoot(t *testing.T) {
	dir, err := casLockDir(&SOPSSecretStoreConfig{
		StorageConfig: map[string]interface{}{"root": "/var/lib/cfgms/secrets"},
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/var/lib/cfgms/secrets", casLockSubdir), dir)

	dir, err = casLockDir(&SOPSSecretStoreConfig{
		StorageConfig: map[string]interface{}{"path": "/var/lib/cfgms/secrets.db"},
	})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("/var/lib/cfgms", casLockSubdir), dir)
}

// TestCASLockDir_FailsClosedWithoutPrivateRoot is the regression proof for the
// silent-degradation footgun: a backend that exposes no filesystem root — the
// database/cluster shape, whose storage_config carries only a dsn — must produce an
// error, never a path under a shared location such as os.TempDir().
//
// A lock directory under a world-writable path can be pre-created by any local
// unprivileged user, who can then delete the lock files at will and defeat mutual
// exclusion outright. That would silently re-enable the double-collect/double-mint
// race this lock exists to prevent, on a single node, with no warning anywhere.
func TestCASLockDir_FailsClosedWithoutPrivateRoot(t *testing.T) {
	cases := []struct {
		name string
		cfg  *SOPSSecretStoreConfig
	}{
		{"nil config", nil},
		{"nil storage config", &SOPSSecretStoreConfig{}},
		{"empty storage config", &SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{}}},
		{
			"database backend exposes only a dsn",
			&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{
				"dsn": "postgres://cfgms@db.example.internal:5432/cfgms?sslmode=verify-full",
			}},
		},
		{
			"blank root",
			&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"root": "   "}},
		},
		{
			"non-string root",
			&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"root": 42}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := casLockDir(tc.cfg)
			require.ErrorIs(t, err, errNoCASLockRoot)
			assert.Empty(t, dir)
		})
	}
}

// TestCASLockDir_NeverReturnsSharedTempDir asserts the specific degraded path that
// used to exist can no longer be produced by any configuration shape, including one
// that names the temp directory only incidentally.
func TestCASLockDir_NeverReturnsSharedTempDir(t *testing.T) {
	_, err := casLockDir(&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"dsn": "postgres://x"}})
	require.Error(t, err)

	// A configuration that genuinely points at a directory under os.TempDir() is a
	// caller's explicit choice (the ephemeral-secrets dev override), not a silent
	// fallback: it yields that directory, not the shared, predictable
	// os.TempDir()/cfgms-sops.cas-locks any local user could pre-create.
	explicit := filepath.Join(t.TempDir(), "secrets")
	dir, err := casLockDir(&SOPSSecretStoreConfig{StorageConfig: map[string]interface{}{"root": explicit}})
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(explicit, casLockSubdir), dir)
	assert.NotEqual(t, filepath.Join(os.TempDir(), "cfgms-sops"+casLockSubdir), dir)
	assert.True(t, strings.HasPrefix(dir, explicit))
}

// The retry-classification coverage is split across three files because the
// syscall error constants it turns on are themselves build-tagged. This file holds
// the assertions that must hold on every platform; the two platform halves —
// including the Windows ERROR_ACCESS_DENIED true-positive that is the entire
// reason lock_windows.go exists — live in lock_windows_test.go and
// lock_other_test.go alongside the implementations they cover (Issue #3817).

// TestIsRetryableCASLockError_ExistIsRetryable proves the ordinary case — the lock
// file already exists — is classified as retryable on every platform, exactly as
// before this story: os.IsExist(err) alone drove the acquire loop's poll-vs-fail
// decision.
func TestIsRetryableCASLockError_ExistIsRetryable(t *testing.T) {
	err := &fs.PathError{Op: "open", Path: "x.lock", Err: fs.ErrExist}
	assert.True(t, isRetryableCASLockError(err))
}

// TestIsRetryableCASLockError_UnrelatedErrorIsHardFailure proves an error that is
// neither os.IsExist nor the Windows pending-delete access-denied case is still
// classified as a hard failure on every platform — the fix must not widen the retry
// path to swallow arbitrary errors (permission denied on the lock directory itself,
// a vanished parent directory, and so on).
func TestIsRetryableCASLockError_UnrelatedErrorIsHardFailure(t *testing.T) {
	err := &fs.PathError{Op: "open", Path: "x.lock", Err: fs.ErrNotExist}
	assert.False(t, isRetryableCASLockError(err))

	permErr := &fs.PathError{Op: "open", Path: "x.lock", Err: fs.ErrPermission}
	assert.False(t, isRetryableCASLockError(permErr))
}

// TestAcquireCASLock_UnrelatedOpenErrorIsHardFailure is the AC2 cross-platform
// regression proof: an open error unrelated to lock contention must return
// immediately as a hard failure rather than spin-poll until the acquire timeout.
// The lock directory's parent is a regular file rather than a directory — as if the
// parent directory had been removed and replaced out from under the caller — which
// makes os.MkdirAll (and, were it to get that far, the O_CREATE|O_EXCL open) fail
// with an error that is neither os.IsExist nor the Windows access-denied case on any
// platform.
func TestAcquireCASLock_UnrelatedOpenErrorIsHardFailure(t *testing.T) {
	base := t.TempDir()
	blocker := filepath.Join(base, "not-a-directory")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0o600))
	dir := filepath.Join(blocker, "locks")

	start := time.Now()
	release, err := acquireCASLock(context.Background(), dir, "tenant", "key")
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.Nil(t, release)
	assert.Less(t, elapsed, casLockAcquireTimeout,
		"an unrelated open error must fail fast, not poll until the acquire timeout")
}
