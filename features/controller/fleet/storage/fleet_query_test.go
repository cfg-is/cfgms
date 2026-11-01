// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// makeTestDNA builds a DNA proto carrying the given attributes as a fragment
// (Issue #3331 — the flat DNA.Attributes map no longer exists).
func makeTestDNA(t *testing.T, id string, attrs map[string]string) *commonpb.DNA {
	t.Helper()
	return attachTestFragment(t, &commonpb.DNA{
		Id:              id,
		SyncFingerprint: "fp-" + id,
	}, attrs)
}

// newTestFleetStorage creates an ephemeral SQLite storage manager for tests.
func newTestFleetStorage(t *testing.T) *Manager {
	t.Helper()
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.EnableDeduplication = false

	mgr, err := NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

func TestFleetQuery_EmptyFilter(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	// Store two devices
	dna1 := makeTestDNA(t, "dev-1", map[string]string{"os": "linux", "architecture": "amd64", "hostname": "host-1"})
	dna2 := makeTestDNA(t, "dev-2", map[string]string{"os": "windows", "architecture": "amd64", "hostname": "host-2"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "tenant-b", Status: "offline"}))

	result, err := mgr.QueryFleet(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.TotalCount)
	assert.Len(t, result.Records, 2)
}

func TestFleetQuery_FilterByTenantID(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna1 := makeTestDNA(t, "dev-1", map[string]string{"os": "linux"})
	dna2 := makeTestDNA(t, "dev-2", map[string]string{"os": "linux"})
	dna3 := makeTestDNA(t, "dev-3", map[string]string{"os": "linux"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-3", dna3, &StoreOptions{TenantID: "tenant-b", Status: "online"}))

	result, err := mgr.QueryFleet(ctx, &FleetFilter{TenantID: "tenant-a"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.TotalCount)
	for _, rec := range result.Records {
		assert.Equal(t, "tenant-a", rec.TenantID)
	}
}

// TestFleetQuery_FilterByOS and TestFleetQuery_FilterByArchitecture are retired:
// the os/architecture SQLite columns are no longer populated from flat DNA attributes
// after Issue #3329. Fleet filtering by OS/arch will be re-enabled via the fragment
// model in a future story.

func TestFleetQuery_FilterByStatus(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna1 := makeTestDNA(t, "dev-1", map[string]string{"os": "linux"})
	dna2 := makeTestDNA(t, "dev-2", map[string]string{"os": "linux"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "t1", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "t1", Status: "offline"}))

	result, err := mgr.QueryFleet(ctx, &FleetFilter{Status: "online"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.TotalCount)
	assert.Equal(t, "online", result.Records[0].Status)
}

func TestFleetQuery_FilterByDeviceIDs(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	for _, id := range []string{"dev-1", "dev-2", "dev-3"} {
		dna := makeTestDNA(t, id, map[string]string{"os": "linux"})
		require.NoError(t, mgr.Store(ctx, id, dna, &StoreOptions{TenantID: "t1", Status: "online"}))
	}

	result, err := mgr.QueryFleet(ctx, &FleetFilter{DeviceIDs: []string{"dev-1", "dev-3"}})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.TotalCount)
	ids := []string{result.Records[0].DeviceID, result.Records[1].DeviceID}
	assert.Contains(t, ids, "dev-1")
	assert.Contains(t, ids, "dev-3")
	assert.NotContains(t, ids, "dev-2")
}

func TestFleetQuery_CombinedFilters(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna1 := makeTestDNA(t, "dev-1", map[string]string{"os": "linux"})
	dna2 := makeTestDNA(t, "dev-2", map[string]string{"os": "linux"})
	dna3 := makeTestDNA(t, "dev-3", map[string]string{"os": "linux"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "tenant-a", Status: "offline"}))
	require.NoError(t, mgr.Store(ctx, "dev-3", dna3, &StoreOptions{TenantID: "tenant-b", Status: "online"}))

	// tenant-a + online: only dev-1
	result, err := mgr.QueryFleet(ctx, &FleetFilter{
		TenantID: "tenant-a",
		Status:   "online",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.TotalCount)
	assert.Equal(t, "dev-1", result.Records[0].DeviceID)
}

func TestFleetQuery_Pagination(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	for i := 1; i <= 5; i++ {
		id := "dev-" + string(rune('0'+i))
		dna := makeTestDNA(t, id, map[string]string{"os": "linux"})
		require.NoError(t, mgr.Store(ctx, id, dna, &StoreOptions{TenantID: "t1", Status: "online"}))
	}

	result, err := mgr.QueryFleet(ctx, &FleetFilter{Limit: 2, Offset: 0})
	require.NoError(t, err)
	assert.Equal(t, int64(5), result.TotalCount)
	assert.Len(t, result.Records, 2)

	result2, err := mgr.QueryFleet(ctx, &FleetFilter{Limit: 2, Offset: 2})
	require.NoError(t, err)
	assert.Len(t, result2.Records, 2)
	// Ensure different pages return different records
	assert.NotEqual(t, result.Records[0].DeviceID, result2.Records[0].DeviceID)
}

func TestFleetQuery_OnlyLatestVersionReturned(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	// Store two versions for the same device
	dna1 := makeTestDNA(t, "dev-1", map[string]string{"os": "linux", "version": "1"})
	dna2 := makeTestDNA(t, "dev-1", map[string]string{"os": "linux", "version": "2"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "t1", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-1", dna2, &StoreOptions{TenantID: "t1", Status: "online"}))

	// QueryFleet should return exactly 1 record per device (the latest)
	result, err := mgr.QueryFleet(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.TotalCount)
	assert.Len(t, result.Records, 1)
	// Latest version should have "version": "2" in DNA attributes
	require.NotNil(t, result.Records[0].DNA)
	assert.Equal(t, "2", dnaAttrs(result.Records[0].DNA)["version"])
}

func TestListAllDeviceIDs(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	for _, id := range []string{"dev-a", "dev-b", "dev-c"} {
		dna := makeTestDNA(t, id, map[string]string{"os": "linux"})
		require.NoError(t, mgr.Store(ctx, id, dna, &StoreOptions{TenantID: "t1", Status: "online"}))
	}

	ids, err := mgr.ListAllDeviceIDs(ctx)
	require.NoError(t, err)
	assert.Len(t, ids, 3)
	assert.Contains(t, ids, "dev-a")
	assert.Contains(t, ids, "dev-b")
	assert.Contains(t, ids, "dev-c")
}

func TestFleetQuery_NoResults(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	result, err := mgr.QueryFleet(ctx, &FleetFilter{OS: "amiga-os"})
	require.NoError(t, err)
	assert.Equal(t, int64(0), result.TotalCount)
	assert.Empty(t, result.Records)
}

func TestStore_WithOptions(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna := makeTestDNA(t, "dev-x", map[string]string{
		"os":           "linux",
		"architecture": "amd64",
		"hostname":     "host-x",
	})

	err := mgr.Store(ctx, "dev-x", dna, &StoreOptions{
		TenantID: "my-tenant",
		Status:   "online",
	})
	require.NoError(t, err)

	// Verify via fleet query that stored indexable fields (TenantID, Status) are queryable.
	// OS/architecture/hostname SQLite columns are no longer populated from flat DNA attributes
	// (Issue #3329); the full DNA (including attributes) is still preserved in dna_json.
	result, err := mgr.QueryFleet(ctx, &FleetFilter{TenantID: "my-tenant", Status: "online"})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	assert.Equal(t, "dev-x", result.Records[0].DeviceID)
	assert.Equal(t, "my-tenant", result.Records[0].TenantID)
	assert.Equal(t, "online", result.Records[0].Status)
	// DNA attributes are preserved in dna_json and accessible on the returned record.
	require.NotNil(t, result.Records[0].DNA)
	recordAttrs := dnaAttrs(result.Records[0].DNA)
	assert.Equal(t, "linux", recordAttrs["os"])
	assert.Equal(t, "amd64", recordAttrs["architecture"])
}

func TestQueryFleet_NonSQLiteBackendReturnsError(t *testing.T) {
	// Verify QueryFleet returns an error when the underlying backend is not SQLite.
	// This covers the error branch in fleet_query.go:73.
	cfg := DefaultConfig()
	cfg.Backend = BackendMemory // Non-SQLite backend
	cfg.DataDir = t.TempDir()

	// Memory backend does not support fleet queries — construct Manager manually
	// to bypass backend type assertion.
	mgr := &Manager{
		logger:     logging.NewNoopLogger(),
		config:     cfg,
		storage:    &noopBackend{},
		compressor: &noopCompressor{},
		indexer:    &noopIndexer{},
	}

	_, err := mgr.QueryFleet(context.Background(), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "fleet query requires SQLite or database backend")

	_, err = mgr.ListAllDeviceIDs(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ListAllDeviceIDs requires SQLite or database backend")

	_, err = mgr.GetLatestByDeviceID(context.Background(), "dev-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetLatestByDeviceID requires SQLite or database backend")

	err = mgr.Ping(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Ping requires SQLite or database backend")

	_, _, err = mgr.GetHistoryByDeviceID(context.Background(), "dev-1", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GetHistoryByDeviceID requires SQLite backend")
}

// noopBackend is a minimal Backend implementation used to exercise error paths.
type noopBackend struct{}

func (n *noopBackend) StoreRecord(_ context.Context, _ *DNARecord, _ []byte) error { return nil }
func (n *noopBackend) StoreReference(_ context.Context, _ *DNARecord) error        { return nil }
func (n *noopBackend) GetRecord(_ context.Context, _, _ string) (*DNARecord, error) {
	return nil, nil
}
func (n *noopBackend) HasContent(_ context.Context, _ string) (bool, error) { return false, nil }
func (n *noopBackend) GetStats(_ context.Context) (*StorageStats, error)    { return &StorageStats{}, nil }
func (n *noopBackend) Flush() error                                         { return nil }
func (n *noopBackend) Optimize() error                                      { return nil }
func (n *noopBackend) Close() error                                         { return nil }

// noopCompressor is a minimal Compressor for error-path tests.
type noopCompressor struct{}

func (n *noopCompressor) Compress(_ *commonpb.DNA) ([]byte, int64, error) { return nil, 0, nil }
func (n *noopCompressor) Decompress(_ []byte) (*commonpb.DNA, error)      { return nil, nil }
func (n *noopCompressor) GetCompressionRatio() float64                    { return 1.0 }
func (n *noopCompressor) GetStats() *CompressionStats                     { return &CompressionStats{} }
func (n *noopCompressor) Close() error                                    { return nil }

// noopIndexer is a minimal Indexer for error-path tests.
type noopIndexer struct{}

func (n *noopIndexer) IndexRecord(_ context.Context, _ *DNARecord) error { return nil }
func (n *noopIndexer) QueryRecords(_ context.Context, _ string, _ *QueryOptions) ([]*RecordRef, int64, error) {
	return nil, 0, nil
}
func (n *noopIndexer) GetNextVersion(_ context.Context, _ string) (int64, error) { return 1, nil }
func (n *noopIndexer) GetDeviceStats(_ context.Context, _ string) (*DeviceStats, error) {
	return &DeviceStats{}, nil
}
func (n *noopIndexer) GetGlobalStats(_ context.Context) (*IndexStats, error) {
	return &IndexStats{}, nil
}
func (n *noopIndexer) Close() error { return nil }

func TestStore_WithNilOptions(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna := makeTestDNA(t, "dev-y", map[string]string{"os": "linux"})
	// nil opts should not panic
	err := mgr.Store(ctx, "dev-y", dna, nil)
	require.NoError(t, err)

	ids, err := mgr.ListAllDeviceIDs(ctx)
	require.NoError(t, err)
	assert.Contains(t, ids, "dev-y")
}

func TestGetHistoryByDeviceID(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	const deviceID = "hist-device"

	// Store 3 versions.
	for i := 1; i <= 3; i++ {
		dna := makeTestDNA(t, deviceID, map[string]string{"os": "linux", "v": fmt.Sprintf("%d", i)})
		require.NoError(t, mgr.Store(ctx, deviceID, dna, nil))
	}

	t.Run("returns all records in version-descending order", func(t *testing.T) {
		records, total, err := mgr.GetHistoryByDeviceID(ctx, deviceID, nil)
		require.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Len(t, records, 3)
		// Verify newest-first ordering.
		for i := 0; i+1 < len(records); i++ {
			assert.Greater(t, records[i].Version, records[i+1].Version,
				"records should be version-descending")
		}
	})

	t.Run("respects Limit and Offset", func(t *testing.T) {
		records, total, err := mgr.GetHistoryByDeviceID(ctx, deviceID, &QueryOptions{Limit: 2, Offset: 1})
		require.NoError(t, err)
		assert.Equal(t, int64(3), total, "TotalCount must reflect all matching rows, not just the page")
		assert.Len(t, records, 2)
	})

	t.Run("unknown device returns empty with zero total", func(t *testing.T) {
		records, total, err := mgr.GetHistoryByDeviceID(ctx, "no-such-device", nil)
		require.NoError(t, err)
		assert.Equal(t, int64(0), total)
		assert.Empty(t, records)
	})
}

// TestDeviceTenant_SetGetList exercises the Manager-level SetDeviceTenant,
// GetDeviceTenant, and ListDeviceTenants operations end-to-end through the
// SQLite backend. These methods are the authoritative device→tenant mapping
// path introduced in Issue #3324.
func TestDeviceTenant_SetGetList(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	// Initially no mapping exists for an unknown device.
	tid, found, err := mgr.GetDeviceTenant(ctx, "dev-unknown")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, tid)

	// Write mappings for two devices.
	require.NoError(t, mgr.SetDeviceTenant(ctx, "dev-1", "tenant-a"))
	require.NoError(t, mgr.SetDeviceTenant(ctx, "dev-2", "tenant-b"))

	// GetDeviceTenant returns the correct tenant for each.
	tid1, found1, err1 := mgr.GetDeviceTenant(ctx, "dev-1")
	require.NoError(t, err1)
	require.True(t, found1)
	assert.Equal(t, "tenant-a", tid1)

	tid2, found2, err2 := mgr.GetDeviceTenant(ctx, "dev-2")
	require.NoError(t, err2)
	require.True(t, found2)
	assert.Equal(t, "tenant-b", tid2)

	// ListDeviceTenants returns all pairs.
	all, err := mgr.ListDeviceTenants(ctx)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"dev-1": "tenant-a", "dev-2": "tenant-b"}, all)

	// SetDeviceTenant is idempotent (upsert on conflict).
	require.NoError(t, mgr.SetDeviceTenant(ctx, "dev-1", "tenant-a-moved"))
	tidUpdated, foundUpdated, errUpdated := mgr.GetDeviceTenant(ctx, "dev-1")
	require.NoError(t, errUpdated)
	require.True(t, foundUpdated)
	assert.Equal(t, "tenant-a-moved", tidUpdated)
}

// TestMigrationV2_SeedsDeviceTenantFromDNAHistory proves that the v2 migration
// correctly seeds device_tenant from dna_history, selecting the LATEST version's
// tenant for each device (not an arbitrary one from SELECT DISTINCT).
//
// Uses SQLiteMigrator directly to exercise the migration SQL against a real
// SQLite database, independently of the Manager lifecycle.
func TestMigrationV2_SeedsDeviceTenantFromDNAHistory(t *testing.T) {
	dbPath := t.TempDir() + "/migration_test.db"
	db, err := sql.Open("sqlite", "file:"+dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	migrator := NewSQLiteMigrator(db, logging.NewNoopLogger())

	// InitializeSchema runs the base schema (including PRAGMA journal_mode=WAL,
	// which must be outside a transaction). This is the v1 equivalent.
	require.NoError(t, migrator.InitializeSchema())

	// Create migrations tracking table and record v1 as applied, so ApplyMigrations
	// skips v1 and only applies v2.
	require.NoError(t, migrator.createMigrationsTable())
	_, err = db.Exec(`INSERT INTO migrations (version, description) VALUES (1, 'v1 already applied')`)
	require.NoError(t, err)

	// Seed dna_history with two versions of the same device across different tenants,
	// simulating a tenant move. Version 1 → old-tenant; version 2 (latest) → new-tenant.
	_, err = db.Exec(`
		INSERT INTO dna_history (device_id, tenant_id, version, content_hash,
		                         original_size, compressed_size, compression_ratio,
		                         shard_id, dna_json)
		VALUES
		  ('moved-device', 'old-tenant', 1, 'hash1', 10, 10, 1.0, 'default', '{}'),
		  ('moved-device', 'new-tenant', 2, 'hash2', 10, 10, 1.0, 'default', '{}'),
		  ('stable-device','tenant-x',   1, 'hash3', 10, 10, 1.0, 'default', '{}')
	`)
	require.NoError(t, err)

	// Apply migration v2 (creates device_tenant, seeds from latest dna_history rows).
	require.NoError(t, migrator.ApplyMigrations())

	// moved-device must resolve to the LATEST tenant (version 2 → new-tenant).
	var tid string
	require.NoError(t, db.QueryRow(
		`SELECT tenant_id FROM device_tenant WHERE device_id = 'moved-device'`).Scan(&tid))
	assert.Equal(t, "new-tenant", tid, "migration must select the latest tenant, not the oldest")

	// stable-device must resolve normally.
	var tid2 string
	require.NoError(t, db.QueryRow(
		`SELECT tenant_id FROM device_tenant WHERE device_id = 'stable-device'`).Scan(&tid2))
	assert.Equal(t, "tenant-x", tid2)

	// No rows with an empty tenant must appear in device_tenant.
	var rowCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM device_tenant WHERE tenant_id = ''`).Scan(&rowCount))
	assert.Zero(t, rowCount, "migration must not seed rows with empty tenant")
}
