// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package run

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunStoreSQL_CreatesOwnerOnly(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "runs.db")
	store, err := NewRunStoreSQLFromDSN(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Init(context.Background()))
	require.NoError(t, store.CreateRun(sampleRun("run-perm-1", "tenant-perm")))

	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(dbPath + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err, suffix)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "runs.db%s", suffix)
	}
}
