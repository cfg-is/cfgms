// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err, path)
	require.Equal(t, want, info.Mode().Perm(), path)
}

// No umask is set: a umask only clears bits, so exact equality proves the
// mode requested by the code.
func TestSQLiteProvider_CreatesOwnerOnlyDatabaseFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfgms.db")
	store := newTestNonceStoreAt(t, path)
	require.NoError(t, store.PutNonce(context.Background(), "k", []byte("v"), time.Minute))

	// -wal and -shm exist only while the connection is open.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		requireMode(t, p, 0o600)
	}
}

func TestSQLiteUpgradeStore_CreatesOwnerOnlyDatabaseFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "upgrade.db")
	store, err := NewUpgradeStoreSQLFromDSN("file:" + path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	require.NoError(t, store.Initialize(ctx))
	require.NoError(t, store.HealthCheck(ctx))

	requireMode(t, path, 0o600)
}

func TestSQLiteProvider_ExistingDatabaseModeUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing.db")
	require.NoError(t, os.WriteFile(path, nil, 0o644))
	require.NoError(t, os.Chmod(path, 0o644))

	store := newTestNonceStoreAt(t, path)
	require.NoError(t, store.PutNonce(context.Background(), "k", []byte("v"), time.Minute))

	requireMode(t, path, 0o644)
}
