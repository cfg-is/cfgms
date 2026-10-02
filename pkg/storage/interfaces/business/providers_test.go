// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Package business_test — real-provider contract tests for StewardStore.
//
// This file deliberately diverges from every other *_test.go in this package.
// All other files use in-memory fixture doubles implementing the interface.
// This file requires the real provider implementations so that a new provider
// that fails the invariant is caught — an in-memory double written to pass
// would not catch a provider-layer bug.
//
// Direct pkg/storage/providers/* imports are allowlisted exclusively in files
// whose basename is providers_test.go by scripts/check-providers.sh:43. Any
// other filename here would fail make check-architecture.
package business_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/database"
	"github.com/cfgis/cfgms/pkg/storage/providers/flatfile"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newContractFlatFileStewardStore returns a fresh FlatFileStewardStore backed
// by a temporary directory. The cleanup is registered on t.
func newContractFlatFileStewardStore(t *testing.T) business.StewardStore {
	t.Helper()
	store, err := flatfile.NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newContractSQLiteStewardStore returns a fresh in-memory SQLiteStewardStore.
func newContractSQLiteStewardStore(t *testing.T) business.StewardStore {
	t.Helper()
	store, err := (&sqlite.SQLiteProvider{}).CreateStewardStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newContractDatabaseStewardStoreOrSkip returns a live DatabaseStewardStore, or
// skips when PostgreSQL is not available. The skip is intentional: the database
// provider's own integration tests gate the PR merge, so skipping here on a
// machine without PostgreSQL is safe. The test must still pass in CI, where the
// merge-queue run has a real database and CFGMS_TEST_DB_PASSWORD is set.
func newContractDatabaseStewardStoreOrSkip(t *testing.T) business.StewardStore {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping database provider: short mode")
	}
	password := os.Getenv("CFGMS_TEST_DB_PASSWORD")
	if password == "" {
		t.Skip("CFGMS_TEST_DB_PASSWORD not set — skipping database provider for contract test")
	}
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	dsn := fmt.Sprintf("host=localhost port=%d dbname=cfgms_test user=cfgms_test password=%s sslmode=disable",
		port, password)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("PostgreSQL not available for contract test: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("PostgreSQL not available for contract test: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := database.NewDatabaseStewardStore(db, map[string]interface{}{})
	if err != nil {
		t.Skipf("PostgreSQL not available for contract test: %v", err)
	}
	return store
}

// contractStewardRec returns a StewardRecord with sensible defaults.
func contractStewardRec(id, tenantID, deviceID string) *business.StewardRecord {
	return &business.StewardRecord{
		ID:        id,
		TenantID:  tenantID,
		Hostname:  "host-" + id,
		Platform:  "linux",
		Arch:      "amd64",
		Version:   "1.0.0",
		IPAddress: "10.0.0.1",
		Status:    business.StewardStatusRegistered,
		DeviceID:  deviceID,
	}
}

// assertStewardDeviceIDUniquePerTenant is the shared invariant body. It runs
// against whatever StewardStore the caller provides and asserts:
//
//   - A different steward in the same tenant claiming an already-held device_id
//     is rejected with ErrStewardDeviceIDConflict.
//   - The same device_id in a DIFFERENT tenant succeeds (cross-tenant namespacing).
//   - An empty DeviceID is exempt from the uniqueness constraint (multiple stewards
//     may have DeviceID == "").
//   - Re-registering the SAME steward returns the benign ErrStewardAlreadyExists,
//     not ErrStewardDeviceIDConflict, so idempotent retries remain safe.
//   - GetStewardByDeviceID is unambiguous after conflict rejection — the property
//     the revocation gate in handlers_registration_refresh.go depends on.
func assertStewardDeviceIDUniquePerTenant(t *testing.T, store business.StewardStore) {
	t.Helper()
	ctx := context.Background()

	// Use a unique suffix per call so that concurrent or repeated runs against a
	// live database (database provider) never collide.
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	devID := "contract-device-shared-1"
	tenantA := "contract-tenant-a-" + suffix
	tenantB := "contract-tenant-b-" + suffix
	firstID := "contract-steward-a-" + suffix
	secondID := "contract-steward-b-" + suffix
	otherID := "contract-steward-c-" + suffix
	blankAID := "contract-steward-blank-a-" + suffix
	blankBID := "contract-steward-blank-b-" + suffix

	// First steward claims devID in tenantA.
	first := contractStewardRec(firstID, tenantA, devID)
	require.NoError(t, store.RegisterSteward(ctx, first))

	// A different steward asserting the same device_id in the same tenant.
	second := contractStewardRec(secondID, tenantA, devID)
	err := store.RegisterSteward(ctx, second)
	require.Error(t, err, "a second steward must not take a device_id already held in the tenant")
	assert.ErrorIs(t, err, business.ErrStewardDeviceIDConflict,
		"the conflict must be ErrStewardDeviceIDConflict, not the benign ErrStewardAlreadyExists")

	// Cross-tenant: the same device_id in a different tenant is a separate namespace.
	other := contractStewardRec(otherID, tenantB, devID)
	assert.NoError(t, store.RegisterSteward(ctx, other),
		"same device_id under a different tenant must be allowed")

	// Empty DeviceID means "not yet asserted" and must not collide with itself.
	blankA := contractStewardRec(blankAID, tenantA, "")
	blankB := contractStewardRec(blankBID, tenantA, "")
	require.NoError(t, store.RegisterSteward(ctx, blankA))
	assert.NoError(t, store.RegisterSteward(ctx, blankB),
		"rows with empty DeviceID must be excluded from the uniqueness constraint")

	// Re-registering the SAME steward stays the benign ErrStewardAlreadyExists so
	// idempotent claim retries remain safe.
	dupSelf := contractStewardRec(firstID, tenantA, devID)
	selfErr := store.RegisterSteward(ctx, dupSelf)
	require.Error(t, selfErr)
	assert.ErrorIs(t, selfErr, business.ErrStewardAlreadyExists,
		"the same steward written twice must remain ErrStewardAlreadyExists")

	// GetStewardByDeviceID must be unambiguous within the tenant — the revocation
	// gate depends on this lookup returning exactly one record.
	got, getErr := store.GetStewardByDeviceID(ctx, devID)
	require.NoError(t, getErr)
	require.NotNil(t, got)
}

// TestStewardStoreContract_DeviceIDUniquePerTenant asserts tenant-scoped device_id
// uniqueness and is parametrized across all three StewardStore providers.
//
// A provider that does not enforce the invariant fails this test. The invariant is
// required because buildClaimResponse (features/controller/api/handlers_registration.go)
// uses a check-then-act sequence: two concurrent claims can both pass the
// GetStewardByDeviceID guard before either commits, and only the store-level
// backstop decides the winner (Issue #3403, Issue #3508).
func TestStewardStoreContract_DeviceIDUniquePerTenant(t *testing.T) {
	t.Run("flatfile", func(t *testing.T) {
		store := newContractFlatFileStewardStore(t)
		assertStewardDeviceIDUniquePerTenant(t, store)
	})
	t.Run("sqlite", func(t *testing.T) {
		store := newContractSQLiteStewardStore(t)
		assertStewardDeviceIDUniquePerTenant(t, store)
	})
	t.Run("database", func(t *testing.T) {
		store := newContractDatabaseStewardStoreOrSkip(t)
		assertStewardDeviceIDUniquePerTenant(t, store)
	})
}

// ---------------------------------------------------------------------------
// AuditStore.AppendChainedEntry contract (Issue #3754)
// ---------------------------------------------------------------------------

// newContractFlatFileAuditStore returns a fresh FlatFileAuditStore backed by a
// temporary directory.
func newContractFlatFileAuditStore(t *testing.T) business.AuditStore {
	t.Helper()
	store, err := flatfile.NewFlatFileAuditStore(t.TempDir(), 90)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newContractSQLiteAuditStore returns a fresh in-memory SQLiteAuditStore.
func newContractSQLiteAuditStore(t *testing.T) business.AuditStore {
	t.Helper()
	store, err := (&sqlite.SQLiteProvider{}).CreateAuditStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// newContractDatabaseAuditStoreOrSkip returns a live DatabaseAuditStore, or skips
// when PostgreSQL is not available — see newContractDatabaseStewardStoreOrSkip
// above for why skipping here (rather than failing) is safe.
func newContractDatabaseAuditStoreOrSkip(t *testing.T) business.AuditStore {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping database provider: short mode")
	}
	password := os.Getenv("CFGMS_TEST_DB_PASSWORD")
	if password == "" {
		t.Skip("CFGMS_TEST_DB_PASSWORD not set — skipping database provider for contract test")
	}
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	dsn := fmt.Sprintf("host=localhost port=%d dbname=cfgms_test user=cfgms_test password=%s sslmode=disable",
		port, password)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("PostgreSQL not available for contract test: %v", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Skipf("PostgreSQL not available for contract test: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store, err := database.NewDatabaseAuditStore(db, map[string]interface{}{})
	if err != nil {
		t.Skipf("PostgreSQL not available for contract test: %v", err)
	}
	return store
}

// contractAuditEntry returns an AuditEntry with every AppendChainedEntry-required
// field set. Chain fields (SequenceNumber, PreviousChecksum, Checksum) are
// deliberately left zero — the story's core contract is that the store, not the
// caller, assigns them.
func contractAuditEntry(id, action, resourceID string) *business.AuditEntry {
	return &business.AuditEntry{
		ID:           id,
		Timestamp:    time.Now().UTC(),
		EventType:    business.AuditEventConfiguration,
		Action:       action,
		UserID:       "contract-user",
		UserType:     business.AuditUserTypeHuman,
		ResourceType: "contract-resource",
		ResourceID:   resourceID,
		Result:       business.AuditResultSuccess,
		Severity:     business.AuditSeverityMedium,
		Source:       "contract-test",
		Version:      "1.0",
	}
}

// contractChecksum is a deterministic stand-in for audit.Manager's HMAC checksum.
// Its output depends on SequenceNumber and PreviousChecksum, so asserting on it
// proves AppendChainedEntry invokes computeChecksum AFTER assigning those fields,
// not before — the interface's other hard requirement (checksums come from the
// manager's key, not the store, so the store can never compute Checksum itself).
func contractChecksum(e *business.AuditEntry) string {
	return fmt.Sprintf("chk-%d-%s-%s", e.SequenceNumber, e.PreviousChecksum, e.ID)
}

// assertAuditChainAppendGapFreeAndLinked is the shared invariant body for
// AppendChainedEntry, run against every AuditStore provider. It asserts:
//   - Sequential appends for one tenant receive SequenceNumbers 1..N, no gaps.
//   - Each entry's PreviousChecksum equals the prior entry's Checksum.
//   - computeChecksum runs after SequenceNumber/PreviousChecksum are assigned.
//   - A different tenant's chain starts at SequenceNumber 1 independently
//     (tenant isolation — the story's chain-head lock must be per-tenant).
//   - entry.TenantID is set to the tenantID argument.
//   - The assignment is durably persisted, not just mutated on the caller's
//     pointer, verified via a GetLastAuditEntry round trip.
func assertAuditChainAppendGapFreeAndLinked(t *testing.T, store business.AuditStore) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA := "contract-audit-tenant-a-" + suffix
	tenantB := "contract-audit-tenant-b-" + suffix

	const n = 5
	var checksums []string
	for i := 0; i < n; i++ {
		entry := contractAuditEntry(fmt.Sprintf("contract-entry-a-%s-%d", suffix, i), "contract_action", fmt.Sprintf("res-%d", i))
		require.NoError(t, store.AppendChainedEntry(ctx, tenantA, entry, contractChecksum))

		assert.Equal(t, uint64(i+1), entry.SequenceNumber, "entry %d must get SequenceNumber %d", i, i+1)
		assert.Equal(t, tenantA, entry.TenantID, "AppendChainedEntry must set entry.TenantID to the tenantID argument")
		if i == 0 {
			assert.Empty(t, entry.PreviousChecksum, "first entry in a tenant's chain must have empty PreviousChecksum")
		} else {
			assert.Equal(t, checksums[i-1], entry.PreviousChecksum,
				"entry %d PreviousChecksum must equal entry %d's Checksum", i, i-1)
		}
		assert.Equal(t, contractChecksum(entry), entry.Checksum,
			"Checksum must be computeChecksum's output, called after sequence assignment")
		checksums = append(checksums, entry.Checksum)
	}

	// Tenant isolation: a different tenant's chain starts at 1 independently.
	otherEntry := contractAuditEntry("contract-entry-b-"+suffix, "contract_action", "res-other")
	require.NoError(t, store.AppendChainedEntry(ctx, tenantB, otherEntry, contractChecksum))
	assert.Equal(t, uint64(1), otherEntry.SequenceNumber, "a different tenant's chain must start at SequenceNumber 1")
	assert.Empty(t, otherEntry.PreviousChecksum, "a different tenant's first entry must have empty PreviousChecksum")

	// Round-trip through GetLastAuditEntry to prove the assignment was durably
	// persisted, not just mutated on the caller's pointer.
	last, err := store.GetLastAuditEntry(ctx, tenantA)
	require.NoError(t, err)
	require.NotNil(t, last)
	assert.Equal(t, uint64(n), last.SequenceNumber)
	assert.Equal(t, checksums[n-1], last.Checksum)
}

// TestAuditStoreContract_AppendChainedEntry is parametrized across all three
// AuditStore providers per CLAUDE.md's central-provider testing rule: a new
// provider (or a regression in an existing one) that fails to serialize chain
// assignment correctly fails this test.
func TestAuditStoreContract_AppendChainedEntry(t *testing.T) {
	t.Run("flatfile", func(t *testing.T) {
		store := newContractFlatFileAuditStore(t)
		assertAuditChainAppendGapFreeAndLinked(t, store)
	})
	t.Run("sqlite", func(t *testing.T) {
		store := newContractSQLiteAuditStore(t)
		assertAuditChainAppendGapFreeAndLinked(t, store)
	})
	t.Run("database", func(t *testing.T) {
		store := newContractDatabaseAuditStoreOrSkip(t)
		assertAuditChainAppendGapFreeAndLinked(t, store)
	})
}
