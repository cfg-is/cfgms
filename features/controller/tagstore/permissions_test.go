// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package tagstore_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestTagStore_CreatesOwnerOnly(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tags.db")
	store, err := tagstore.NewFromDSN("file:"+dbPath, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.Initialize(context.Background()))
	require.NoError(t, store.Set(context.Background(), "steward-perm", []string{"env-prod"}))

	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(dbPath + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err, suffix)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "tags.db%s", suffix)
	}
}
