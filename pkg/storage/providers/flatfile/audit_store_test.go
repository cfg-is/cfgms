// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package flatfile_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
)

// newTestAuditStore creates a FlatFileAuditStore backed by a temporary directory.
func newTestAuditStore(t *testing.T) *flatfile.FlatFileAuditStore {
	t.Helper()
	store, err := flatfile.NewFlatFileAuditStore(t.TempDir(), 90)
	require.NoError(t, err)
	return store
}

// minimalEntry returns a minimal valid AuditEntry with the given timestamp.
func minimalEntry(id, tenantID string, ts time.Time) *business.AuditEntry {
	return &business.AuditEntry{
		ID:           id,
		TenantID:     tenantID,
		Timestamp:    ts,
		Action:       "read",
		UserID:       "user1",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "config",
		ResourceID:   "cfg-1",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityLow,
		Source:       "test",
		EventType:    business.AuditEventDataAccess,
	}
}

// TestStoreAndGetAuditEntry verifies a round-trip store and retrieve by ID.
func TestStoreAndGetAuditEntry(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	entry := minimalEntry("entry-1", "tenant1", time.Now().UTC())
	require.NoError(t, store.StoreAuditEntry(ctx, entry))

	got, err := store.GetAuditEntry(ctx, "entry-1")
	require.NoError(t, err)
	assert.Equal(t, "entry-1", got.ID)
	assert.Equal(t, "tenant1", got.TenantID)
	assert.Equal(t, "read", got.Action)
}

// TestGetAuditEntryNotFound verifies ErrAuditNotFound for missing entries.
func TestGetAuditEntryNotFound(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	_, err := store.GetAuditEntry(ctx, "nonexistent")
	assert.Equal(t, business.ErrAuditNotFound, err)
}

// TestStoreAuditEntryValidation verifies required field validation.
func TestStoreAuditEntryValidation(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	t.Run("missing tenant", func(t *testing.T) {
		e := minimalEntry("e1", "", now)
		err := store.StoreAuditEntry(ctx, e)
		assert.Error(t, err)
	})

	t.Run("missing user", func(t *testing.T) {
		e := minimalEntry("e2", "t1", now)
		e.UserID = ""
		err := store.StoreAuditEntry(ctx, e)
		assert.Error(t, err)
	})

	t.Run("missing action", func(t *testing.T) {
		e := minimalEntry("e3", "t1", now)
		e.Action = ""
		err := store.StoreAuditEntry(ctx, e)
		assert.Error(t, err)
	})

	t.Run("missing resource type", func(t *testing.T) {
		e := minimalEntry("e4", "t1", now)
		e.ResourceType = ""
		err := store.StoreAuditEntry(ctx, e)
		assert.Error(t, err)
	})

	t.Run("missing resource ID", func(t *testing.T) {
		e := minimalEntry("e5", "t1", now)
		e.ResourceID = ""
		err := store.StoreAuditEntry(ctx, e)
		assert.Error(t, err)
	})
}

// TestStoreAuditEntryErrImmutable verifies that entries older than retention period are rejected.
func TestStoreAuditEntryErrImmutable(t *testing.T) {
	// Use a 10-day retention window for this test
	store, err := flatfile.NewFlatFileAuditStore(t.TempDir(), 10)
	require.NoError(t, err)
	ctx := context.Background()

	// Entry 11 days old — beyond retention
	oldTS := time.Now().UTC().AddDate(0, 0, -11)
	entry := minimalEntry("old-entry", "tenant1", oldTS)

	err = store.StoreAuditEntry(ctx, entry)
	assert.ErrorIs(t, err, flatfile.ErrImmutable, "expected ErrImmutable for expired-retention entry")
}

// TestStoreAuditEntryWithinRetention verifies that entries inside retention are accepted.
func TestStoreAuditEntryWithinRetention(t *testing.T) {
	store, err := flatfile.NewFlatFileAuditStore(t.TempDir(), 10)
	require.NoError(t, err)
	ctx := context.Background()

	// Entry 5 days old — within retention
	ts := time.Now().UTC().AddDate(0, 0, -5)
	entry := minimalEntry("recent-entry", "tenant1", ts)
	assert.NoError(t, store.StoreAuditEntry(ctx, entry))
}

// TestListAuditEntries verifies filtering by tenant.
func TestListAuditEntries(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 3; i++ {
		e := minimalEntry(fmt.Sprintf("e-%d", i), "t1", now)
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}
	// Entry for a different tenant
	require.NoError(t, store.StoreAuditEntry(ctx, minimalEntry("e-other", "t2", now)))

	results, err := store.ListAuditEntries(ctx, &business.AuditFilter{TenantID: "t1"})
	require.NoError(t, err)
	assert.Len(t, results, 3)
}

// TestListAuditEntriesByTimeRange verifies time-range filtering.
func TestListAuditEntriesByTimeRange(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	today := time.Now().UTC()

	require.NoError(t, store.StoreAuditEntry(ctx, minimalEntry("yesterday", "t1", yesterday)))
	require.NoError(t, store.StoreAuditEntry(ctx, minimalEntry("today", "t1", today)))

	// Filter: only today
	start := today.Add(-time.Minute)
	results, err := store.ListAuditEntries(ctx, &business.AuditFilter{
		TenantID:  "t1",
		TimeRange: &business.TimeRange{Start: &start},
	})
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "today", results[0].ID)
}

// TestGetAuditsByUser verifies user-based query.
func TestGetAuditsByUser(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	e1 := minimalEntry("u1-e1", "t1", now)
	e1.UserID = "alice"
	e2 := minimalEntry("u1-e2", "t1", now)
	e2.UserID = "bob"

	require.NoError(t, store.StoreAuditEntry(ctx, e1))
	require.NoError(t, store.StoreAuditEntry(ctx, e2))

	results, err := store.GetAuditsByUser(ctx, "alice", nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "alice", results[0].UserID)
}

// TestGetAuditsByResource verifies resource-based query.
func TestGetAuditsByResource(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	e := minimalEntry("res-entry", "t1", now)
	e.ResourceType = "certificate"
	e.ResourceID = "cert-123"
	require.NoError(t, store.StoreAuditEntry(ctx, e))

	results, err := store.GetAuditsByResource(ctx, "certificate", "cert-123", nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "cert-123", results[0].ResourceID)
}

// TestGetAuditsByAction verifies action-based query.
func TestGetAuditsByAction(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	e1 := minimalEntry("act-1", "t1", now)
	e1.Action = "write"
	e2 := minimalEntry("act-2", "t1", now)
	e2.Action = "read"
	require.NoError(t, store.StoreAuditEntry(ctx, e1))
	require.NoError(t, store.StoreAuditEntry(ctx, e2))

	results, err := store.GetAuditsByAction(ctx, "write", nil)
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "write", results[0].Action)
}

// TestGetFailedActions verifies that failure, error, and denied entries are all returned.
func TestGetFailedActions(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	succeed := minimalEntry("s1", "t1", now)
	succeed.Result = business.AuditResultSuccess

	fail := minimalEntry("f1", "t1", now)
	fail.Result = business.AuditResultFailure

	errEntry := minimalEntry("e1", "t1", now)
	errEntry.Result = business.AuditResultError

	denied := minimalEntry("d1", "t1", now)
	denied.Result = business.AuditResultDenied

	require.NoError(t, store.StoreAuditEntry(ctx, succeed))
	require.NoError(t, store.StoreAuditEntry(ctx, fail))
	require.NoError(t, store.StoreAuditEntry(ctx, errEntry))
	require.NoError(t, store.StoreAuditEntry(ctx, denied))

	results, err := store.GetFailedActions(ctx, nil, 100)
	require.NoError(t, err)
	// All three failure variants must be returned; success must not be
	assert.Len(t, results, 3, "expected failure, error, and denied entries")
	for _, r := range results {
		assert.NotEqual(t, business.AuditResultSuccess, r.Result,
			"success entries must not appear in GetFailedActions")
	}

	// Verify each variant is present
	resultIDs := make(map[string]bool)
	for _, r := range results {
		resultIDs[r.ID] = true
	}
	assert.True(t, resultIDs["f1"], "AuditResultFailure entry must be included")
	assert.True(t, resultIDs["e1"], "AuditResultError entry must be included")
	assert.True(t, resultIDs["d1"], "AuditResultDenied entry must be included")
}

// TestGetSuspiciousActivity verifies high/critical severity filter.
func TestGetSuspiciousActivity(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	low := minimalEntry("low-1", "t1", now)
	low.Severity = business.AuditSeverityLow

	high := minimalEntry("high-1", "t1", now)
	high.Severity = business.AuditSeverityHigh

	crit := minimalEntry("crit-1", "t1", now)
	crit.Severity = business.AuditSeverityCritical

	require.NoError(t, store.StoreAuditEntry(ctx, low))
	require.NoError(t, store.StoreAuditEntry(ctx, high))
	require.NoError(t, store.StoreAuditEntry(ctx, crit))

	results, err := store.GetSuspiciousActivity(ctx, "t1", nil)
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// TestStoreAuditBatch verifies batch storage.
func TestStoreAuditBatch(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	entries := []*business.AuditEntry{
		minimalEntry("b1", "t1", now),
		minimalEntry("b2", "t1", now),
		minimalEntry("b3", "t1", now),
	}
	require.NoError(t, store.StoreAuditBatch(ctx, entries))

	for _, e := range entries {
		got, err := store.GetAuditEntry(ctx, e.ID)
		require.NoError(t, err)
		assert.Equal(t, e.ID, got.ID)
	}
}

// TestGetAuditStats verifies aggregate statistics computation.
func TestGetAuditStats(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	entries := []*business.AuditEntry{
		minimalEntry("s1", "t1", now),
		minimalEntry("s2", "t2", now),
	}
	for _, e := range entries {
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}

	stats, err := store.GetAuditStats(ctx)
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.TotalEntries)
	assert.Greater(t, stats.TotalSize, int64(0))
	assert.NotNil(t, stats.NewestEntry)
}

// TestListAuditEntriesPagination verifies limit and offset.
func TestListAuditEntriesPagination(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	for i := 0; i < 5; i++ {
		e := minimalEntry(fmt.Sprintf("page-%d", i), "t1", now)
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}

	results, err := store.ListAuditEntries(ctx, &business.AuditFilter{
		TenantID: "t1",
		Limit:    2,
		Offset:   1,
	})
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

// TestAuditStorePathTraversalPrevention ensures directory traversal is rejected.
func TestAuditStorePathTraversalPrevention(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	e := minimalEntry("traversal", "../../../escaped", time.Now().UTC())
	err := store.StoreAuditEntry(ctx, e)
	require.Error(t, err)
}

// TestPurgeAuditEntries verifies that old files are deleted by PurgeAuditEntries.
func TestPurgeAuditEntries(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	// Store an entry from 5 days ago
	oldTS := time.Now().UTC().AddDate(0, 0, -5)
	old := minimalEntry("old", "t1", oldTS)
	require.NoError(t, store.StoreAuditEntry(ctx, old))

	// Store a recent entry
	recent := minimalEntry("recent", "t1", time.Now().UTC())
	require.NoError(t, store.StoreAuditEntry(ctx, recent))

	// Purge everything older than 2 days ago
	cutoff := time.Now().UTC().AddDate(0, 0, -2)
	count, err := store.PurgeAuditEntries(ctx, cutoff)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0))

	// The old entry should no longer be found
	_, err = store.GetAuditEntry(ctx, "old")
	assert.Error(t, err)

	// The recent entry should still be present
	got, err := store.GetAuditEntry(ctx, "recent")
	require.NoError(t, err)
	assert.Equal(t, "recent", got.ID)
}

// TestArchiveAuditEntries verifies that old files are moved to archive.
func TestArchiveAuditEntries(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	// Store an entry from 5 days ago
	oldTS := time.Now().UTC().AddDate(0, 0, -5)
	old := minimalEntry("archive-old", "t1", oldTS)
	require.NoError(t, store.StoreAuditEntry(ctx, old))

	cutoff := time.Now().UTC().AddDate(0, 0, -2)
	count, err := store.ArchiveAuditEntries(ctx, cutoff)
	require.NoError(t, err)
	assert.Greater(t, count, int64(0))
}

// TestConcurrentAuditWrites verifies no data corruption with 10 goroutines appending entries.
func TestConcurrentAuditWrites(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	const numGoroutines = 10
	var wg sync.WaitGroup
	errs := make([]error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		i := i
		go func() {
			defer wg.Done()
			e := minimalEntry(fmt.Sprintf("concurrent-%d", i), "concurrent-tenant", now)
			errs[i] = store.StoreAuditEntry(ctx, e)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		assert.NoError(t, err, "goroutine %d returned error", i)
	}

	// Verify all entries are readable and not corrupted
	results, err := store.ListAuditEntries(ctx, &business.AuditFilter{TenantID: "concurrent-tenant"})
	require.NoError(t, err)
	assert.Len(t, results, numGoroutines, "all concurrent entries must be persisted")

	for _, r := range results {
		assert.NotEmpty(t, r.ID)
		assert.Equal(t, "concurrent-tenant", r.TenantID)
	}
}

// TestListAuditEntriesEmptyStore returns empty slice, not error.
func TestListAuditEntriesEmptyStore(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	results, err := store.ListAuditEntries(ctx, &business.AuditFilter{TenantID: "t1"})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestAuditDefaultTimestamp verifies zero timestamp is filled with now.
func TestAuditDefaultTimestamp(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	e := minimalEntry("ts-default", "t1", time.Time{}) // zero time
	require.NoError(t, store.StoreAuditEntry(ctx, e))

	got, err := store.GetAuditEntry(ctx, "ts-default")
	require.NoError(t, err)
	assert.False(t, got.Timestamp.IsZero(), "timestamp must be set automatically")
}

// TestGetLastAuditEntry_Empty verifies that an empty store returns nil, nil.
func TestGetLastAuditEntry_Empty(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	last, err := store.GetLastAuditEntry(ctx, "no-such-tenant")
	require.NoError(t, err)
	assert.Nil(t, last, "empty store must return nil, nil")
}

// TestGetLastAuditEntry_Single verifies that a single entry is returned.
func TestGetLastAuditEntry_Single(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	e := minimalEntry("last-1", "tenant-last", time.Now().UTC())
	e.SequenceNumber = 1
	require.NoError(t, store.StoreAuditEntry(ctx, e))

	last, err := store.GetLastAuditEntry(ctx, "tenant-last")
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, "last-1", last.ID)
	assert.Equal(t, uint64(1), last.SequenceNumber)
}

// TestGetLastAuditEntry_ReturnsHighestSequence verifies that the entry with
// the highest SequenceNumber is returned when multiple entries exist.
func TestGetLastAuditEntry_ReturnsHighestSequence(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	for i := uint64(1); i <= 3; i++ {
		e := minimalEntry(fmt.Sprintf("seq-%d", i), "tenant-seq", now)
		e.SequenceNumber = i
		require.NoError(t, store.StoreAuditEntry(ctx, e))
	}

	last, err := store.GetLastAuditEntry(ctx, "tenant-seq")
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, uint64(3), last.SequenceNumber, "must return entry with highest sequence_number")
}

// TestGetLastAuditEntry_TenantIsolation verifies that entries from different
// tenants do not bleed across tenant boundaries.
func TestGetLastAuditEntry_TenantIsolation(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	now := time.Now().UTC()
	ea := minimalEntry("ta-1", "tenant-a", now)
	ea.SequenceNumber = 5
	eb := minimalEntry("tb-1", "tenant-b", now)
	eb.SequenceNumber = 1
	require.NoError(t, store.StoreAuditEntry(ctx, ea))
	require.NoError(t, store.StoreAuditEntry(ctx, eb))

	lastA, err := store.GetLastAuditEntry(ctx, "tenant-a")
	require.NoError(t, err)
	require.NotNil(t, lastA)
	assert.Equal(t, uint64(5), lastA.SequenceNumber)

	lastB, err := store.GetLastAuditEntry(ctx, "tenant-b")
	require.NoError(t, err)
	require.NotNil(t, lastB)
	assert.Equal(t, uint64(1), lastB.SequenceNumber)
}
