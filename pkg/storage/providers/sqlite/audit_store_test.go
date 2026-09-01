// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
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

func TestAuditStore_GetLastAuditEntry_Empty(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	last, err := store.GetLastAuditEntry(ctx, "no-such-tenant")
	require.NoError(t, err)
	assert.Nil(t, last, "empty store must return nil, nil")
}

func TestAuditStore_GetLastAuditEntry_Single(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	e := sampleAuditEntry("single-1")
	e.SequenceNumber = 1
	require.NoError(t, store.StoreAuditEntry(ctx, e))

	last, err := store.GetLastAuditEntry(ctx, e.TenantID)
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, e.ID, last.ID)
	assert.Equal(t, uint64(1), last.SequenceNumber)
}

func TestAuditStore_GetLastAuditEntry_ReturnsHighestSequence(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	for i := uint64(1); i <= 3; i++ {
		e := sampleAuditEntry(string(rune('a' + i - 1)))
		e.SequenceNumber = i
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}

	last, err := store.GetLastAuditEntry(ctx, "tenant-audit")
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, uint64(3), last.SequenceNumber, "must return entry with highest sequence_number")
}

func TestAuditStore_GetLastAuditEntry_TenantIsolation(t *testing.T) {
	store := newAuditStore(t)
	ctx := context.Background()

	e1 := sampleAuditEntry("t1-1")
	e1.TenantID = "tenant-a"
	e1.SequenceNumber = 5
	e2 := sampleAuditEntry("t2-1")
	e2.TenantID = "tenant-b"
	e2.SequenceNumber = 1
	require.NoError(t, store.StoreAuditEntry(ctx, e1))
	require.NoError(t, store.StoreAuditEntry(ctx, e2))

	lastA, err := store.GetLastAuditEntry(ctx, "tenant-a")
	require.NoError(t, err)
	require.NotNil(t, lastA)
	assert.Equal(t, uint64(5), lastA.SequenceNumber)

	lastB, err := store.GetLastAuditEntry(ctx, "tenant-b")
	require.NoError(t, err)
	require.NotNil(t, lastB)
	assert.Equal(t, uint64(1), lastB.SequenceNumber)
}

// TestAuditStore_AppendChainedEntry_FileBacked_ConcurrentAppenders is the
// regression test for the deferred-transaction defect in AppendChainedEntry.
//
// It must be file-backed: in-memory databases are pinned to a single connection
// (openDB), which hides the defect entirely. A file-backed database keeps the
// default multi-connection pool in WAL mode and every store opens its own pool
// over the file, so several store handles here reproduce what several stores in
// one controller — or several controller processes sharing the file — do.
//
// With a deferred transaction each appender takes its read snapshot at the head
// SELECT; any other connection committing before its INSERT invalidates that
// snapshot, the read-to-write upgrade fails with SQLITE_BUSY, and busy_timeout
// does not retry a snapshot-invalidation busy. Measured on this workload against
// the deferred implementation: 10 of 200 appends succeeded. Because
// audit.Manager only logs a failed append and moves on, the other 190 would be
// silently destroyed audit evidence — and undetectable afterwards, since the
// surviving chain remains gap-free and correctly linked.
//
// Every append must therefore succeed, and the persisted chain must be 1..N with
// no gaps and no sequence number issued twice.
func TestAuditStore_AppendChainedEntry_FileBacked_ConcurrentAppenders(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit-concurrent.db")
	p := sqlite.NewSQLiteProvider(dir)

	newStore := func() business.AuditStore {
		store, err := p.CreateAuditStore(map[string]interface{}{"path": dbPath})
		require.NoError(t, err)
		t.Cleanup(func() { _ = store.Close() })
		return store
	}

	ctx := context.Background()
	checksum := func(e *business.AuditEntry) string {
		return fmt.Sprintf("chk-%d-%s", e.SequenceNumber, e.PreviousChecksum)
	}

	// An unrelated writer on its own pool: ordinary concurrent controller
	// activity against the same database, which is all the deferred
	// implementation needed to start losing appends.
	unrelated := newStore()
	stopUnrelated := make(chan struct{})
	unrelatedErr := make(chan error, 1)
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stopUnrelated:
				unrelatedErr <- nil
				return
			default:
			}
			e := sampleAuditEntry(fmt.Sprintf("unrelated-%d", i))
			e.TenantID = "tenant-unrelated"
			if err := unrelated.StoreAuditEntry(ctx, e); err != nil {
				unrelatedErr <- fmt.Errorf("unrelated writer failed on entry %d: %w", i, err)
				return
			}
		}
	}()

	const appenders = 4
	const perAppender = 25
	const totalAppends = appenders * perAppender
	const chainTenant = "tenant-chain"

	var wg sync.WaitGroup
	appendErrs := make(chan error, totalAppends)
	for a := 0; a < appenders; a++ {
		store := newStore()
		wg.Add(1)
		go func(a int, store business.AuditStore) {
			defer wg.Done()
			for i := 0; i < perAppender; i++ {
				entry := sampleAuditEntry(fmt.Sprintf("chained-%d-%d", a, i))
				entry.TenantID = ""
				entry.Checksum = ""
				if err := store.AppendChainedEntry(ctx, chainTenant, entry, checksum); err != nil {
					appendErrs <- fmt.Errorf("appender %d entry %d: %w", a, i, err)
				}
			}
		}(a, store)
	}
	wg.Wait()
	close(appendErrs)
	close(stopUnrelated)

	for err := range appendErrs {
		require.NoError(t, err, "no chain append may be lost to concurrent writers")
	}
	require.NoError(t, <-unrelatedErr, "the unrelated writer must also complete without lock failures")

	// The durable chain must be complete: 1..N, gap-free, each sequence issued once.
	entries, err := chainStoreEntries(ctx, t, newStore(), chainTenant, totalAppends)
	require.NoError(t, err)
	require.Len(t, entries, totalAppends, "every appended entry must be durably persisted")

	bySequence := make(map[uint64]*business.AuditEntry, totalAppends)
	for _, e := range entries {
		require.Nil(t, bySequence[e.SequenceNumber], "sequence %d assigned twice", e.SequenceNumber)
		bySequence[e.SequenceNumber] = e
	}
	for i := uint64(1); i <= totalAppends; i++ {
		e := bySequence[i]
		require.NotNil(t, e, "sequence %d missing from the persisted chain", i)
		if i == 1 {
			assert.Empty(t, e.PreviousChecksum, "the first entry must have an empty PreviousChecksum")
			continue
		}
		assert.Equal(t, bySequence[i-1].Checksum, e.PreviousChecksum,
			"entry %d must link to entry %d's checksum", i, i-1)
	}
}

// chainStoreEntries reads back every entry stored for tenantID.
func chainStoreEntries(ctx context.Context, t *testing.T, store business.AuditStore, tenantID string, limit int) ([]*business.AuditEntry, error) {
	t.Helper()
	return store.ListAuditEntries(ctx, &business.AuditFilter{
		TenantID: tenantID,
		SortBy:   "timestamp",
		Order:    "asc",
		Limit:    limit + 1,
	})
}
