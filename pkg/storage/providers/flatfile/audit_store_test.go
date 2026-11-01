// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// TestGetAuditEntry_HierarchicalTenantID verifies that GetAuditEntry finds entries
// stored under hierarchical tenant IDs (e.g. "fleet-root/fleet-child-a") whose audit
// files live in nested subdirectories rather than directly under root.
func TestGetAuditEntry_HierarchicalTenantID(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()

	e := minimalEntry("hier-get-1", "fleet-root/fleet-child-a", time.Now().UTC())
	require.NoError(t, store.StoreAuditEntry(ctx, e))

	got, err := store.GetAuditEntry(ctx, "hier-get-1")
	require.NoError(t, err)
	assert.Equal(t, "hier-get-1", got.ID)
	assert.Equal(t, "fleet-root/fleet-child-a", got.TenantID)
}

// TestListAuditEntries_HierarchicalTenantID verifies that ListAuditEntries with no
// TenantID filter correctly finds entries stored under hierarchical tenant IDs
// (e.g. "fleet-root/fleet-child-a"). The store persists them under nested subdirectories;
// the no-filter path must walk the tree to discover them rather than only listing
// top-level directories under root.
func TestListAuditEntries_HierarchicalTenantID(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	childA := "fleet-root/fleet-child-a"
	childB := "fleet-root/fleet-child-b"

	eA1 := minimalEntry("hier-a1", childA, now)
	eA1.Action = "refresh_cert_issued"
	eA1.UserID = "device-aaa"
	eA2 := minimalEntry("hier-a2", childA, now)
	eA2.Action = "refresh_cert_issued"
	eA2.UserID = "device-aaa"
	eB1 := minimalEntry("hier-b1", childB, now)
	eB1.Action = "refresh_queued"
	eB1.UserID = "device-bbb"

	require.NoError(t, store.StoreAuditEntry(ctx, eA1))
	require.NoError(t, store.StoreAuditEntry(ctx, eA2))
	require.NoError(t, store.StoreAuditEntry(ctx, eB1))

	// Query with no TenantID — must find entries across all nested tenants.
	all, err := store.ListAuditEntries(ctx, &business.AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, all, 3, "all three hierarchical-tenant entries must be visible without a TenantID filter")

	// Filter by action: only childA's entries.
	byAction, err := store.ListAuditEntries(ctx, &business.AuditFilter{
		Actions: []string{"refresh_cert_issued"},
	})
	require.NoError(t, err)
	assert.Len(t, byAction, 2)

	// Filter by user_id without specifying tenant: must still find them.
	byUser, err := store.ListAuditEntries(ctx, &business.AuditFilter{
		UserIDs: []string{"device-bbb"},
	})
	require.NoError(t, err)
	require.Len(t, byUser, 1)
	assert.Equal(t, "hier-b1", byUser[0].ID)

	// Filter with specific TenantID still works.
	byTenant, err := store.ListAuditEntries(ctx, &business.AuditFilter{TenantID: childA})
	require.NoError(t, err)
	assert.Len(t, byTenant, 2)
}

// seqChecksum is a deterministic stand-in for audit.Manager's HMAC checksum whose
// output depends on the chain fields the store assigns.
func seqChecksum(e *business.AuditEntry) string {
	return fmt.Sprintf("chk-%d-%s", e.SequenceNumber, e.ID)
}

// chainedEntry returns a valid entry with its chain fields left unset, as
// AppendChainedEntry callers supply them.
func chainedEntry(id, tenantID string) *business.AuditEntry {
	return minimalEntry(id, tenantID, time.Now().UTC())
}

// appendRawAuditLine writes entry directly into the tenant's daily JSONL file,
// bypassing the store entirely, so a test can distinguish a cached chain head
// from one re-read off disk.
func appendRawAuditLine(t *testing.T, root string, entry *business.AuditEntry) {
	t.Helper()
	dir := filepath.Join(root, entry.TenantID, "audit")
	require.NoError(t, os.MkdirAll(dir, 0750))
	path := filepath.Join(dir, entry.Timestamp.UTC().Format("2006-01-02")+".jsonl")

	raw, err := json.Marshal(entry)
	require.NoError(t, err)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	require.NoError(t, err)
	defer func() { require.NoError(t, f.Close()) }()
	_, err = f.Write(append(raw, '\n'))
	require.NoError(t, err)
}

// TestAppendChainedEntry_ChainHeadIsCachedNotRescanned verifies that after the
// first append for a tenant the chain head comes from the store's in-process
// cache rather than a re-scan of the tenant's audit files.
//
// The proof is deterministic rather than timing-based: a line carrying a much
// higher SequenceNumber is written straight into the tenant's daily file behind
// the store's back. A re-scanning implementation would chain the next append off
// that line; the cached implementation chains off what this store last wrote.
// FlatFileAuditStore is documented as a single-process, single-writer store, so
// out-of-band file mutation is outside its contract — this test pins the
// consequence (Issue #3797: the per-append re-scan made N appends O(N^2), which
// stalled the audit drain goroutine past a 60s Flush deadline).
func TestAppendChainedEntry_ChainHeadIsCachedNotRescanned(t *testing.T) {
	root := t.TempDir()
	store, err := flatfile.NewFlatFileAuditStore(root, 90)
	require.NoError(t, err)
	ctx := context.Background()
	const tenantID = "tenant-cache"

	first := chainedEntry("cache-1", tenantID)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, first, seqChecksum))
	require.Equal(t, uint64(1), first.SequenceNumber)

	// Write an out-of-band line with a far higher sequence number into the same
	// daily file. Only a re-scanning implementation would observe it.
	interloper := minimalEntry("cache-interloper", tenantID, first.Timestamp)
	interloper.SequenceNumber = 500
	interloper.Checksum = "interloper-checksum"
	appendRawAuditLine(t, root, interloper)

	second := chainedEntry("cache-2", tenantID)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, second, seqChecksum))
	assert.Equal(t, uint64(2), second.SequenceNumber,
		"chain head must come from the in-process cache, not a re-scan of the tenant's audit files")
	assert.Equal(t, first.Checksum, second.PreviousChecksum,
		"cached head must supply the previous checksum")
}

// TestAppendChainedEntry_StoreAuditEntryInvalidatesChainHead verifies that a
// direct StoreAuditEntry write — which carries a caller-assigned sequence number
// and so can move the durable chain head — drops the cached head, making the
// next chained append re-read it from disk.
func TestAppendChainedEntry_StoreAuditEntryInvalidatesChainHead(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	const tenantID = "tenant-invalidate"

	first := chainedEntry("inv-1", tenantID)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, first, seqChecksum))
	require.Equal(t, uint64(1), first.SequenceNumber)

	direct := minimalEntry("inv-direct", tenantID, time.Now().UTC())
	direct.SequenceNumber = 42
	direct.Checksum = "direct-checksum"
	require.NoError(t, store.StoreAuditEntry(ctx, direct))

	next := chainedEntry("inv-2", tenantID)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, next, seqChecksum))
	assert.Equal(t, uint64(43), next.SequenceNumber,
		"a direct store write must invalidate the cached chain head")
	assert.Equal(t, "direct-checksum", next.PreviousChecksum,
		"the re-read head must link to the entry written directly")
}

// TestAppendChainedEntry_PurgeInvalidatesChainHead verifies that purging daily
// files drops the cached chain head, so the next append derives its sequence
// from what remains on disk instead of a head that no longer exists.
func TestAppendChainedEntry_PurgeInvalidatesChainHead(t *testing.T) {
	store := newTestAuditStore(t)
	ctx := context.Background()
	const tenantID = "tenant-purge"

	// Both entries are dated five days ago so they share one daily file and the
	// purge below removes every file this tenant has.
	fiveDaysAgo := time.Now().UTC().AddDate(0, 0, -5)
	old := minimalEntry("purge-old", tenantID, fiveDaysAgo)
	old.SequenceNumber = 7
	old.Checksum = "old-checksum"
	require.NoError(t, store.StoreAuditEntry(ctx, old))

	seeded := minimalEntry("purge-seed", tenantID, fiveDaysAgo)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, seeded, seqChecksum))
	require.Equal(t, uint64(8), seeded.SequenceNumber)

	// Purge everything older than yesterday: the tenant's only file predates that
	// cutoff, so nothing of its chain survives.
	purged, err := store.PurgeAuditEntries(ctx, time.Now().UTC().AddDate(0, 0, -1))
	require.NoError(t, err)
	require.Greater(t, purged, int64(0))

	restarted := chainedEntry("purge-after", tenantID)
	require.NoError(t, store.AppendChainedEntry(ctx, tenantID, restarted, seqChecksum))
	assert.Equal(t, uint64(1), restarted.SequenceNumber,
		"purging the tenant's files must invalidate the cached chain head")
	assert.Empty(t, restarted.PreviousChecksum)
}

// TestAppendChainedEntry_HighVolumeChainIsGapFreeOnDisk appends the volume that
// exposed the O(N^2) re-scan (Issue #3797) and verifies the durable result: every
// sequence number 1..N present exactly once, each entry linked to its
// predecessor, and a store opened fresh on the same root reporting head N.
func TestAppendChainedEntry_HighVolumeChainIsGapFreeOnDisk(t *testing.T) {
	root := t.TempDir()
	store, err := flatfile.NewFlatFileAuditStore(root, 90)
	require.NoError(t, err)
	ctx := context.Background()
	const tenantID = "tenant-volume"
	const writeCount = 1100

	prevChecksum := ""
	for i := 0; i < writeCount; i++ {
		entry := chainedEntry(fmt.Sprintf("vol-%d", i), tenantID)
		require.NoError(t, store.AppendChainedEntry(ctx, tenantID, entry, seqChecksum))
		require.Equal(t, uint64(i+1), entry.SequenceNumber, "append %d must be gap-free", i)
		require.Equal(t, prevChecksum, entry.PreviousChecksum, "append %d must link to its predecessor", i)
		prevChecksum = entry.Checksum
	}

	// A store opened fresh on the same root has an empty cache, so this asserts
	// what actually reached disk.
	reopened, err := flatfile.NewFlatFileAuditStore(root, 90)
	require.NoError(t, err)
	last, err := reopened.GetLastAuditEntry(ctx, tenantID)
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, uint64(writeCount), last.SequenceNumber,
		"durable chain head must reflect all %d appends", writeCount)
	assert.Equal(t, prevChecksum, last.Checksum)

	entries, err := reopened.ListAuditEntries(ctx, &business.AuditFilter{TenantID: tenantID, Limit: writeCount + 100})
	require.NoError(t, err)
	require.Len(t, entries, writeCount)
	seen := make(map[uint64]bool, writeCount)
	for _, e := range entries {
		assert.False(t, seen[e.SequenceNumber], "sequence number %d assigned twice", e.SequenceNumber)
		seen[e.SequenceNumber] = true
	}
	for i := uint64(1); i <= writeCount; i++ {
		assert.True(t, seen[i], "sequence number %d missing from durable chain", i)
	}
}
