// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides tests for the PostgreSQL AuditStore provider
package database

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// concurrencyChecksum is a deterministic stand-in for audit.Manager's HMAC
// checksum (pkg/audit is not imported here — this package sits below it in the
// dependency graph). Its output depends on SequenceNumber and PreviousChecksum,
// so a correct chain requires AppendChainedEntry to have assigned both before
// invoking it.
func concurrencyChecksum(e *business.AuditEntry) string {
	return fmt.Sprintf("chk-%s-%d-%s", e.ID, e.SequenceNumber, e.PreviousChecksum)
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
