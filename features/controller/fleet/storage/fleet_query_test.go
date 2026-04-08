// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"
)

// makeTestDNA builds a DNA proto with the given attributes for testing.
func makeTestDNA(id string, attrs map[string]string) *commonpb.DNA {
	return &commonpb.DNA{
		Id:              id,
		Attributes:      attrs,
		SyncFingerprint: "fp-" + id,
	}
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
	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux", "architecture": "amd64", "hostname": "host-1"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "windows", "architecture": "amd64", "hostname": "host-2"})

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

	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "linux"})
	dna3 := makeTestDNA("dev-3", map[string]string{"os": "linux"})

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

func TestFleetQuery_FilterByOS(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux", "architecture": "amd64"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "windows", "architecture": "amd64"})
	dna3 := makeTestDNA("dev-3", map[string]string{"os": "linux", "architecture": "arm64"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "t1", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "t1", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-3", dna3, &StoreOptions{TenantID: "t1", Status: "online"}))

	result, err := mgr.QueryFleet(ctx, &FleetFilter{OS: "linux"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), result.TotalCount)
	for _, rec := range result.Records {
		assert.Equal(t, "linux", rec.OS)
	}
}

func TestFleetQuery_FilterByArchitecture(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux", "architecture": "amd64"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "linux", "architecture": "arm64"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "t1", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "t1", Status: "online"}))

	result, err := mgr.QueryFleet(ctx, &FleetFilter{Architecture: "arm64"})
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.TotalCount)
	assert.Equal(t, "dev-2", result.Records[0].DeviceID)
}

func TestFleetQuery_FilterByStatus(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "linux"})

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
		dna := makeTestDNA(id, map[string]string{"os": "linux"})
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

	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux", "architecture": "amd64"})
	dna2 := makeTestDNA("dev-2", map[string]string{"os": "linux", "architecture": "arm64"})
	dna3 := makeTestDNA("dev-3", map[string]string{"os": "windows", "architecture": "amd64"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-2", dna2, &StoreOptions{TenantID: "tenant-a", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-3", dna3, &StoreOptions{TenantID: "tenant-a", Status: "online"}))

	// linux + amd64 in tenant-a: only dev-1
	result, err := mgr.QueryFleet(ctx, &FleetFilter{
		TenantID:     "tenant-a",
		OS:           "linux",
		Architecture: "amd64",
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
		dna := makeTestDNA(id, map[string]string{"os": "linux"})
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
	dna1 := makeTestDNA("dev-1", map[string]string{"os": "linux", "version": "1"})
	dna2 := makeTestDNA("dev-1", map[string]string{"os": "linux", "version": "2"})

	require.NoError(t, mgr.Store(ctx, "dev-1", dna1, &StoreOptions{TenantID: "t1", Status: "online"}))
	require.NoError(t, mgr.Store(ctx, "dev-1", dna2, &StoreOptions{TenantID: "t1", Status: "online"}))

	// QueryFleet should return exactly 1 record per device (the latest)
	result, err := mgr.QueryFleet(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, int64(1), result.TotalCount)
	assert.Len(t, result.Records, 1)
	// Latest version should have "version": "2" in DNA attributes
	require.NotNil(t, result.Records[0].DNA)
	assert.Equal(t, "2", result.Records[0].DNA.Attributes["version"])
}

func TestListAllDeviceIDs(t *testing.T) {
	mgr := newTestFleetStorage(t)
	ctx := context.Background()

	for _, id := range []string{"dev-a", "dev-b", "dev-c"} {
		dna := makeTestDNA(id, map[string]string{"os": "linux"})
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

	dna := makeTestDNA("dev-x", map[string]string{
		"os":           "linux",
		"architecture": "amd64",
		"hostname":     "host-x",
	})

	err := mgr.Store(ctx, "dev-x", dna, &StoreOptions{
		TenantID: "my-tenant",
		Status:   "online",
	})
	require.NoError(t, err)

	// Verify via fleet query that stored fields are queryable
	result, err := mgr.QueryFleet(ctx, &FleetFilter{TenantID: "my-tenant", Status: "online"})
	require.NoError(t, err)
	require.Len(t, result.Records, 1)
	assert.Equal(t, "dev-x", result.Records[0].DeviceID)
	assert.Equal(t, "my-tenant", result.Records[0].TenantID)
	assert.Equal(t, "linux", result.Records[0].OS)
	assert.Equal(t, "amd64", result.Records[0].Architecture)
	assert.Equal(t, "host-x", result.Records[0].Hostname)
	assert.Equal(t, "online", result.Records[0].Status)
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
	assert.Contains(t, err.Error(), "fleet query requires SQLite backend")

	_, err = mgr.ListAllDeviceIDs(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ListAllDeviceIDs requires SQLite backend")
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

	dna := makeTestDNA("dev-y", map[string]string{"os": "linux"})
	// nil opts should not panic
	err := mgr.Store(ctx, "dev-y", dna, nil)
	require.NoError(t, err)

	ids, err := mgr.ListAllDeviceIDs(ctx)
	require.NoError(t, err)
	assert.Contains(t, ids, "dev-y")
}
