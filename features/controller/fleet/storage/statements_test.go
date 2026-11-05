// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"database/sql"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSQLiteStatements_Characterization exercises every prepared statement on the
// SQLite backend (insert record, insert reference, get record, has content, get
// next version), including the idempotent upsert on UNIQUE(device_id, version).
// The Postgres backend shares the preparation routine; its tests run in CI.
func TestSQLiteStatements_Characterization(t *testing.T) {
	b := newTimestampTestBackend(t)
	ctx := context.Background()
	const device = "stmt-device"
	now := time.Now().UTC()

	mk := func(hash string, version int64) *DNARecord {
		return &DNARecord{
			DeviceID:         device,
			DNA:              &commonpb.DNA{Id: device},
			StoredAt:         now,
			ContentHash:      hash,
			Version:          version,
			OriginalSize:     200,
			CompressedSize:   100,
			CompressionRatio: 0.5,
			ShardID:          "default",
		}
	}

	next, err := b.GetNextVersion(ctx, device)
	require.NoError(t, err)
	assert.Equal(t, int64(1), next)

	has, err := b.HasContent(ctx, "hash-A")
	require.NoError(t, err)
	assert.False(t, has)

	require.NoError(t, b.StoreRecord(ctx, mk("hash-A", 1), []byte("A")))
	has, err = b.HasContent(ctx, "hash-A")
	require.NoError(t, err)
	assert.True(t, has)

	got, err := b.GetRecord(ctx, "hash-A", "default")
	require.NoError(t, err)
	assert.Equal(t, device, got.DeviceID)
	assert.Equal(t, int64(1), got.Version)

	// Same (device_id, version) with new content: upsert, latest wins, no error.
	require.NoError(t, b.StoreRecord(ctx, mk("hash-B", 1), []byte("B")))
	has, err = b.HasContent(ctx, "hash-B")
	require.NoError(t, err)
	assert.True(t, has)
	has, err = b.HasContent(ctx, "hash-A")
	require.NoError(t, err)
	assert.False(t, has)

	// References upsert on the same key too.
	require.NoError(t, b.StoreReference(ctx, mk("hash-B", 2)))
	require.NoError(t, b.StoreReference(ctx, mk("hash-C", 2)))

	next, err = b.GetNextVersion(ctx, device)
	require.NoError(t, err)
	assert.Equal(t, int64(2), next)
}

// TestPrepareStatements_ErrorText pins the per-statement error wrapping for both
// dialect prefixes, and that handles prepared before the failure are kept.
func TestPrepareStatements_ErrorText(t *testing.T) {
	b := newTimestampTestBackend(t)

	for _, tc := range []struct{ dialect, want string }{
		{"", "failed to prepare broken one statement: "},
		{"PostgreSQL ", "failed to prepare PostgreSQL broken one statement: "},
	} {
		var ok, bad *sql.Stmt
		err := prepareStatements(b.db, tc.dialect, []statementSpec{
			{&ok, "fine", "SELECT 1"},
			{&bad, "broken one", "SELECT FROM NOWHERE ((("},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.want)
		assert.NotNil(t, ok)
		assert.Nil(t, bad)
		_ = ok.Close()
	}
}
