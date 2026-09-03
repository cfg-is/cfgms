// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides tests for the PostgreSQL AuditStore provider
package database

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// concurrencyChecksum is a deterministic stand-in for audit.Manager's HMAC
// checksum (pkg/audit is not imported here — this package sits below it in the
// dependency graph). Its output depends on SequenceNumber and PreviousChecksum,
// so a correct chain requires AppendChainedEntry to have assigned both before
// invoking it.
//
// The real checksum (audit.Manager's HMAC-SHA256, hex-encoded) is a fixed 64
// hex characters regardless of chain length — it fits the checksum column's
// varchar(64) exactly. This stand-in must preserve that property: hashing the
// input (rather than embedding PreviousChecksum verbatim) keeps the output at
// a fixed 64 hex chars even though PreviousChecksum grows with every chain
// entry. Embedding it verbatim previously overflowed varchar(64) on Postgres
// after a handful of chained entries (Issue #3871) — invisible on SQLite,
// which does not enforce declared column widths.
func concurrencyChecksum(e *business.AuditEntry) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("chk-%s-%d-%s", e.ID, e.SequenceNumber, e.PreviousChecksum)))
	return hex.EncodeToString(sum[:])
}

// TestDatabaseAuditStore_AppendChainedEntry_ConcurrentWriters is the regression
// test for the bug ADR-031 named as a casualty: pkg/audit/manager.go's old
// drainLoop assigned SequenceNumber from an in-process map under the comment
// "no concurrent writer can interleave" — an assumption that becomes false the
// moment more than one controller node runs this manager against one database
// (Issue #3754).
//
// Two DatabaseAuditStore instances — separate *sql.DB connections, exactly what
// two controller processes each connecting to the same Postgres would have — are
// driven from separate goroutines, each appending to the SAME tenant's chain.
// If AppendChainedEntry's row lock is anything less than a real serializing
// construct (e.g. a bug that read the head outside the lock, or locked the
// wrong row), this test observes it as a duplicate or out-of-order
// SequenceNumber or a PreviousChecksum that fails to link — the exact failure
// mode ADR-031 Decision 1 requires closed.
func TestDatabaseAuditStore_AppendChainedEntry_ConcurrentWriters(t *testing.T) {
	// setupTestDatabase both skips cleanly without Postgres and drops any
	// leftover tables from a prior run so the schema is created fresh below.
	_ = setupTestDatabase(t)

	dbA := getTestDB(t)
	t.Cleanup(func() { _ = dbA.Close() })
	dbB := getTestDB(t)
	t.Cleanup(func() { _ = dbB.Close() })

	storeA, err := NewDatabaseAuditStore(dbA, map[string]interface{}{})
	require.NoError(t, err)

	storeB, err := NewDatabaseAuditStore(dbB, map[string]interface{}{})
	require.NoError(t, err)

	const tenantID = "concurrent-chain-tenant"
	const perWriter = 25
	stores := []*DatabaseAuditStore{storeA, storeB}

	var wg sync.WaitGroup
	errCh := make(chan error, len(stores)*perWriter)
	for w, store := range stores {
		wg.Add(1)
		go func(store *DatabaseAuditStore, writerID int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < perWriter; i++ {
				entry := &business.AuditEntry{
					ID:           fmt.Sprintf("concurrent-entry-w%d-%d", writerID, i),
					EventType:    business.AuditEventConfiguration,
					Action:       "concurrent_action",
					UserID:       "concurrent-user",
					UserType:     business.AuditUserTypeHuman,
					ResourceType: "concurrent-resource",
					ResourceID:   fmt.Sprintf("res-w%d-%d", writerID, i),
					Result:       business.AuditResultSuccess,
					Severity:     business.AuditSeverityMedium,
					Source:       "concurrency-test",
					Version:      "1.0",
				}
				if err := store.AppendChainedEntry(ctx, tenantID, entry, concurrencyChecksum); err != nil {
					errCh <- err
				}
			}
		}(store, w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		assert.NoError(t, err, "concurrent AppendChainedEntry call must not fail")
	}

	total := len(stores) * perWriter
	entries, err := storeA.ListAuditEntries(context.Background(), &business.AuditFilter{
		TenantID: tenantID,
		Limit:    total + 10,
	})
	require.NoError(t, err)
	require.Len(t, entries, total, "every concurrent append must be durably persisted exactly once")

	// ListAuditEntries has no sequence_number sort option (see buildOrderByClause),
	// and entries from two concurrent writers can share a timestamp — sort by the
	// field under test instead of trusting query order.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].SequenceNumber < entries[j].SequenceNumber
	})

	seen := make(map[uint64]bool, len(entries))
	for i, e := range entries {
		require.False(t, seen[e.SequenceNumber], "duplicate SequenceNumber %d", e.SequenceNumber)
		seen[e.SequenceNumber] = true
		assert.Equal(t, uint64(i+1), e.SequenceNumber, "sequence must be gap-free 1..N when sorted ascending")
		if i == 0 {
			assert.Empty(t, e.PreviousChecksum, "first entry in the chain must have empty PreviousChecksum")
		} else {
			assert.Equal(t, entries[i-1].Checksum, e.PreviousChecksum,
				"entry %d PreviousChecksum must equal entry %d's Checksum even when the two were written by different store instances", i, i-1)
		}
		assert.Equal(t, concurrencyChecksum(e), e.Checksum,
			"Checksum must be computeChecksum's output computed after sequence assignment")
	}
}

// TestDatabaseAuditStore_AppendChainedEntry_SeedsChainHeadOnPostgres is the
// regression test for Issue #3863: the audit_chain_heads seed statement in
// AppendChainedEntry (audit_store.go) used its $1 placeholder in both an
// INSERT assignment context and two WHERE-clause operator contexts without a
// cast. Postgres deduces a type for each occurrence independently and, when
// the two contexts disagree, rejects the statement at parse time with
// SQLSTATE 42P08 ("inconsistent types deduced for parameter $1") on every
// call — a real Postgres is required to observe this; SQLite never rejects
// unmatched parameter types, so a test run only against SQLite cannot fail
// this way and would not have caught the bug.
//
// This also exercises the seeding semantics the fix must preserve exactly
// (Issue #3863 AC3): a tenant with audit_entries rows written before
// audit_chain_heads existed keeps its sequence continuity, and the seed
// INSERT — which runs on every call — is a no-op on the second call via
// ON CONFLICT (tenant_id) DO NOTHING rather than resetting the chain.
func TestDatabaseAuditStore_AppendChainedEntry_SeedsChainHeadOnPostgres(t *testing.T) {
	// setupTestDatabase both skips cleanly without Postgres and drops any
	// leftover tables from a prior run so the schema is created fresh below.
	_ = setupTestDatabase(t)

	db := getTestDB(t)
	t.Cleanup(func() { _ = db.Close() })

	store, err := NewDatabaseAuditStore(db, map[string]interface{}{})
	require.NoError(t, err)

	const tenantID = "seed-chain-head-tenant"

	// Simulate a tenant that wrote audit_entries rows before audit_chain_heads
	// existed: insert a legacy row directly, bypassing AppendChainedEntry (and
	// therefore the broken seed statement) entirely.
	_, err = db.Exec(`
		INSERT INTO audit_entries (
			id, tenant_id, timestamp, event_type, action, user_id, user_type,
			resource_type, resource_id, result, severity, source, version,
			checksum, sequence_number, previous_checksum
		) VALUES (
			'legacy-entry-1', $1, NOW(), 'configuration', 'legacy_action', 'legacy-user', 'human',
			'legacy-resource', 'res-1', 'success', 'low', 'legacy-writer', '1.0',
			'legacy-checksum', 5, ''
		)
	`, tenantID)
	require.NoError(t, err, "failed to seed legacy audit_entries row")

	entry := &business.AuditEntry{
		EventType:    business.AuditEventConfiguration,
		Action:       "seed_action",
		UserID:       "seed-user",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "seed-resource",
		ResourceID:   "res-seed",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityMedium,
		Source:       "seed-test",
		Version:      "1.0",
	}

	err = store.AppendChainedEntry(context.Background(), tenantID, entry, concurrencyChecksum)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "42P08" {
		t.Fatalf("chain-head seed statement failed with Postgres 42P08 (inconsistent parameter type deduction): %v", pqErr)
	}
	require.NoError(t, err, "AppendChainedEntry must seed audit_chain_heads without error on Postgres")

	assert.Equal(t, uint64(6), entry.SequenceNumber,
		"seeding must continue sequence numbers from pre-existing audit_entries rows written before audit_chain_heads existed")
	assert.Equal(t, "legacy-checksum", entry.PreviousChecksum,
		"seeding must carry forward the checksum of the last pre-existing audit_entries row")

	// The seed INSERT runs again on this second call; it must be a no-op via
	// ON CONFLICT DO NOTHING and the chain must continue from the locked head
	// rather than re-seeding from audit_entries.
	entry2 := &business.AuditEntry{
		EventType:    business.AuditEventConfiguration,
		Action:       "seed_action_2",
		UserID:       "seed-user",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "seed-resource",
		ResourceID:   "res-seed-2",
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityMedium,
		Source:       "seed-test",
		Version:      "1.0",
	}
	require.NoError(t, store.AppendChainedEntry(context.Background(), tenantID, entry2, concurrencyChecksum))
	assert.Equal(t, uint64(7), entry2.SequenceNumber,
		"ON CONFLICT DO NOTHING must make the second seed attempt a no-op, continuing the chain rather than resetting it")
}
