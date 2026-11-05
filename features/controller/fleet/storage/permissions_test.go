// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestFleetDNAStorage_CreatesOwnerOnly(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "fleet-data")
	b, err := NewSQLiteBackend(&Config{DataDir: dataDir}, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = b.Close() })

	require.NoError(t, b.StoreRecord(context.Background(), &DNARecord{
		DeviceID:    "dev-1",
		DNA:         &commonpb.DNA{Id: "dev-1"},
		StoredAt:    time.Now().UTC(),
		ContentHash: "h1",
		Version:     1,
	}, nil))

	di, err := os.Stat(dataDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm())

	for _, suffix := range []string{"", "-wal", "-shm"} {
		fi, err := os.Stat(filepath.Join(dataDir, "dna.db") + suffix)
		if suffix != "" && os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err, suffix)
		assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm(), "dna.db%s", suffix)
	}
}
