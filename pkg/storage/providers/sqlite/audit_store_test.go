// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

func newAuditStore(t *testing.T) business.AuditStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	store, err := p.CreateAuditStore(map[string]interface{}{"path": filepath.Join(dir, "audit.db")})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleAuditEntry(id string) *business.AuditEntry {
	return &business.AuditEntry{
		ID:           id,
		TenantID:     "tenant-audit",
		Timestamp:    time.Now().UTC().Truncate(time.Millisecond),
		EventType:    business.AuditEventAuthentication,
		Action:       "login",
		UserID:       "user-1",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "session",
		ResourceID:   "sess-1",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityLow,
		Source:       "controller",
		Checksum:     "",
	}
}

func TestAuditStore_StoreAndGet(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	entry := sampleAuditEntry("audit-001")
	require.NoError(t, store.StoreAuditEntry(ctx, entry))

	got, err := store.GetAuditEntry(ctx, "audit-001")
	require.NoError(t, err)
	assert.Equal(t, entry.ID, got.ID)
	assert.Equal(t, entry.TenantID, got.TenantID)
	assert.Equal(t, entry.Action, got.Action)
	assert.Equal(t, entry.Result, got.Result)
	assert.NotEmpty(t, got.Checksum, "checksum must be auto-computed")
}

func TestAuditStore_GetNotFound(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()
	_, err := store.GetAuditEntry(ctx, "nonexistent")
	assert.Error(t, err)
}

func TestAuditStore_Immutability(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	entry := sampleAuditEntry("audit-immutable")
	require.NoError(t, store.StoreAuditEntry(ctx, entry))

	// Attempting to store the same ID again must return ErrImmutable
	err := store.StoreAuditEntry(ctx, sampleAuditEntry("audit-immutable"))
	assert.ErrorIs(t, err, business.ErrImmutable)
}

func TestAuditStore_ArchivePurgeReturnImmutable(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	_, err := store.ArchiveAuditEntries(ctx, time.Now())
	assert.ErrorIs(t, err, business.ErrImmutable)

	_, err = store.PurgeAuditEntries(ctx, time.Now())
	assert.ErrorIs(t, err, business.ErrImmutable)
}

func TestAuditStore_ListByTimeRange(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	base := time.Now().UTC()
	for i, ts := range []time.Time{
		base.Add(-3 * time.Hour),
		base.Add(-2 * time.Hour),
		base.Add(-1 * time.Hour),
		base.Add(0),
	} {
		e := sampleAuditEntry(string(rune('a' + i)))
		e.Timestamp = ts
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}

	start := base.Add(-2*time.Hour - 1*time.Minute)
	end := base.Add(-30 * time.Minute)
	results, err := store.ListAuditEntries(ctx, &business.AuditFilter{
		TimeRange: &business.TimeRange{Start: &start, End: &end},
	})
	require.NoError(t, err)
	// Should include entries at -2h and -1h
	assert.Len(t, results, 2)
}

func TestAuditStore_Batch(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	entries := []*business.AuditEntry{
		sampleAuditEntry("batch-1"),
		sampleAuditEntry("batch-2"),
		sampleAuditEntry("batch-3"),
	}
	require.NoError(t, store.StoreAuditBatch(ctx, entries))

	all, err := store.ListAuditEntries(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, all, 3)
}

func TestAuditStore_GetAuditsByUser(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	e1 := sampleAuditEntry("u-1")
	e1.UserID = "alice"
	e2 := sampleAuditEntry("u-2")
	e2.UserID = "bob"
	require.NoError(t, store.StoreAuditEntry(ctx, e1))
	require.NoError(t, store.StoreAuditEntry(ctx, e2))

	results, err := store.GetAuditsByUser(ctx, "alice", nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "alice", results[0].UserID)
}

func TestAuditStore_GetStats(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		e := sampleAuditEntry(string(rune('0' + i)))
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}

	stats, err := store.GetAuditStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(5), stats.TotalEntries)
}

func TestAuditStore_GetFailedActions(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	ok := sampleAuditEntry("ok-1")
	fail := sampleAuditEntry("fail-1")
	fail.Result = business.AuditResultFailure

	require.NoError(t, store.StoreAuditEntry(ctx, ok))
	require.NoError(t, store.StoreAuditEntry(ctx, fail))

	results, err := store.GetFailedActions(ctx, nil, 10)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, business.AuditResultFailure, results[0].Result)
}
