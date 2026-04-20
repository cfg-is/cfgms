// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package database provides tests for ConfigStore PostgreSQL implementation
package database

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

func TestDatabaseConfigStore_CRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Create test configuration
	config := &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  "tenant-123",
			Namespace: "templates",
			Name:      "firewall",
			Scope:     "production",
		},
		Data:      []byte("rules:\n  - allow_http: true\n  - allow_https: true"),
		CreatedBy: "admin@test.com",
		UpdatedBy: "admin@test.com",
		Tags:      []string{"security", "firewall", "production"},
		Source:    "manual",
		Metadata: map[string]interface{}{
			"environment": "production",
			"priority":    "high",
		},
	}

	// Test StoreConfig
	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)
	assert.Greater(t, config.Version, int64(0))
	assert.NotEmpty(t, config.Checksum)
	assert.False(t, config.CreatedAt.IsZero())
	assert.False(t, config.UpdatedAt.IsZero())

	// Test GetConfig
	retrieved, err := store.GetConfig(ctx, config.Key)
	require.NoError(t, err)
	assert.Equal(t, config.Key.TenantID, retrieved.Key.TenantID)
	assert.Equal(t, config.Key.Namespace, retrieved.Key.Namespace)
	assert.Equal(t, config.Key.Name, retrieved.Key.Name)
	assert.Equal(t, config.Key.Scope, retrieved.Key.Scope)
	assert.Equal(t, string(config.Data), string(retrieved.Data))
	assert.Equal(t, config.Version, retrieved.Version)
	assert.Equal(t, config.Tags, retrieved.Tags)
	assert.Equal(t, config.Metadata["environment"], retrieved.Metadata["environment"])
	assert.Equal(t, config.Metadata["priority"], retrieved.Metadata["priority"])

	// Test update (should increment version)
	config.Data = []byte("rules:\n  - allow_http: true\n  - allow_https: true\n  - allow_ssh: true")
	config.UpdatedBy = "admin2@test.com"
	originalVersion := config.Version

	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)
	assert.Equal(t, originalVersion+1, config.Version)

	// Verify update
	updated, err := store.GetConfig(ctx, config.Key)
	require.NoError(t, err)
	assert.Equal(t, config.Version, updated.Version)
	assert.Equal(t, "admin2@test.com", updated.UpdatedBy)
	assert.Contains(t, string(updated.Data), "allow_ssh")

	// Test DeleteConfig
	err = store.DeleteConfig(ctx, config.Key)
	require.NoError(t, err)

	// Verify deletion
	_, err = store.GetConfig(ctx, config.Key)
	assert.Error(t, err)
	assert.Equal(t, cfgconfig.ErrConfigNotFound, err)
}

func TestDatabaseConfigStore_ListConfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Create multiple test configurations
	configs := []*cfgconfig.ConfigEntry{
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "tenant-a",
				Namespace: "templates",
				Name:      "firewall",
			},
			Data:      []byte("firewall config"),
			CreatedBy: "admin@tenant-a.com",
			Tags:      []string{"security", "firewall"},
		},
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "tenant-a",
				Namespace: "certificates",
				Name:      "ssl-cert",
			},
			Data:      []byte("certificate data"),
			CreatedBy: "admin@tenant-a.com",
			Tags:      []string{"security", "ssl"},
		},
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "tenant-b",
				Namespace: "templates",
				Name:      "firewall",
			},
			Data:      []byte("different firewall config"),
			CreatedBy: "admin@tenant-b.com",
			Tags:      []string{"security", "firewall"},
		},
	}

	// Store all configurations
	for _, config := range configs {
		err := store.StoreConfig(ctx, config)
		require.NoError(t, err)
	}

	// Test ListConfigs without filter
	allConfigs, err := store.ListConfigs(ctx, nil)
	require.NoError(t, err)
	assert.Len(t, allConfigs, 3)

	// Test filter by tenant
	tenantAFilter := &cfgconfig.ConfigFilter{
		TenantID: "tenant-a",
	}
	tenantAConfigs, err := store.ListConfigs(ctx, tenantAFilter)
	require.NoError(t, err)
	assert.Len(t, tenantAConfigs, 2)

	// Test filter by namespace
	templatesFilter := &cfgconfig.ConfigFilter{
		Namespace: "templates",
	}
	templateConfigs, err := store.ListConfigs(ctx, templatesFilter)
	require.NoError(t, err)
	assert.Len(t, templateConfigs, 2)

	// Test filter by tags
	firewallTagFilter := &cfgconfig.ConfigFilter{
		Tags: []string{"firewall"},
	}
	firewallConfigs, err := store.ListConfigs(ctx, firewallTagFilter)
	require.NoError(t, err)
	assert.Len(t, firewallConfigs, 2)

	// Test combined filters
	combinedFilter := &cfgconfig.ConfigFilter{
		TenantID:  "tenant-a",
		Namespace: "templates",
	}
	combinedConfigs, err := store.ListConfigs(ctx, combinedFilter)
	require.NoError(t, err)
	assert.Len(t, combinedConfigs, 1)
	assert.Equal(t, "firewall", combinedConfigs[0].Key.Name)

	// Test pagination
	paginatedFilter := &cfgconfig.ConfigFilter{
		Limit:  2,
		Offset: 0,
	}
	page1, err := store.ListConfigs(ctx, paginatedFilter)
	require.NoError(t, err)
	assert.Len(t, page1, 2)

	paginatedFilter.Offset = 2
	page2, err := store.ListConfigs(ctx, paginatedFilter)
	require.NoError(t, err)
	assert.Len(t, page2, 1)

	// Test sorting
	sortedFilter := &cfgconfig.ConfigFilter{
		SortBy: "name",
		Order:  "asc",
	}
	sorted, err := store.ListConfigs(ctx, sortedFilter)
	require.NoError(t, err)
	assert.Len(t, sorted, 3)
	// Should be: firewall, firewall, ssl-cert
	assert.Equal(t, "firewall", sorted[0].Key.Name)
	assert.Equal(t, "ssl-cert", sorted[2].Key.Name)
}

func TestDatabaseConfigStore_VersionHistory(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	key := &cfgconfig.ConfigKey{
		TenantID:  "tenant-version",
		Namespace: "templates",
		Name:      "test-config",
	}

	// Create initial version
	config := &cfgconfig.ConfigEntry{
		Key:  key,
		Data: []byte("version 1 data"),
	}
	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)
	assert.Equal(t, int64(1), config.Version)

	// Create second version
	config.Data = []byte("version 2 data")
	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)
	assert.Equal(t, int64(2), config.Version)

	// Create third version
	config.Data = []byte("version 3 data")
	err = store.StoreConfig(ctx, config)
	require.NoError(t, err)
	assert.Equal(t, int64(3), config.Version)

	// Test GetConfigHistory
	history, err := store.GetConfigHistory(ctx, key, 10)
	require.NoError(t, err)
	assert.Len(t, history, 3)

	// History should be in descending order by version
	assert.Equal(t, int64(3), history[0].Version)
	assert.Equal(t, int64(2), history[1].Version)
	assert.Equal(t, int64(1), history[2].Version)

	// Test limited history
	limitedHistory, err := store.GetConfigHistory(ctx, key, 2)
	require.NoError(t, err)
	assert.Len(t, limitedHistory, 2)
	assert.Equal(t, int64(3), limitedHistory[0].Version)
	assert.Equal(t, int64(2), limitedHistory[1].Version)

	// Test GetConfigVersion
	version2, err := store.GetConfigVersion(ctx, key, 2)
	require.NoError(t, err)
	assert.Equal(t, int64(2), version2.Version)
	assert.Equal(t, "version 2 data", string(version2.Data))

	// Test non-existent version
	_, err = store.GetConfigVersion(ctx, key, 999)
	assert.Error(t, err)
	assert.Equal(t, cfgconfig.ErrConfigNotFound, err)
}

func TestDatabaseConfigStore_BatchOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Create batch of configurations
	configs := []*cfgconfig.ConfigEntry{
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "batch-tenant",
				Namespace: "batch",
				Name:      "config-1",
			},
			Data: []byte("batch config 1"),
		},
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "batch-tenant",
				Namespace: "batch",
				Name:      "config-2",
			},
			Data: []byte("batch config 2"),
		},
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "batch-tenant",
				Namespace: "batch",
				Name:      "config-3",
			},
			Data: []byte("batch config 3"),
		},
	}

	// Test StoreConfigBatch
	err = store.StoreConfigBatch(ctx, configs)
	require.NoError(t, err)

	// Verify all configs were stored
	for _, config := range configs {
		retrieved, err := store.GetConfig(ctx, config.Key)
		require.NoError(t, err)
		assert.Equal(t, string(config.Data), string(retrieved.Data))
		assert.Equal(t, int64(1), retrieved.Version)
	}

	// Test DeleteConfigBatch
	keys := make([]*cfgconfig.ConfigKey, len(configs))
	for i, config := range configs {
		keys[i] = config.Key
	}

	err = store.DeleteConfigBatch(ctx, keys)
	require.NoError(t, err)

	// Verify all configs were deleted
	for _, key := range keys {
		_, err := store.GetConfig(ctx, key)
		assert.Error(t, err)
		assert.Equal(t, cfgconfig.ErrConfigNotFound, err)
	}
}

func TestDatabaseConfigStore_Statistics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Create test configurations with different attributes
	configs := []*cfgconfig.ConfigEntry{
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "stats-tenant-a",
				Namespace: "templates",
				Name:      "config-1",
			},
			Data:      []byte("config data 1"),
			CreatedBy: "user1",
		},
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "stats-tenant-a",
				Namespace: "certificates",
				Name:      "config-2",
			},
			Data:      []byte("config data 2"),
			CreatedBy: "user2",
		},
		{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "stats-tenant-b",
				Namespace: "templates",
				Name:      "config-3",
			},
			Data:      []byte("longer config data 3 with more content"),
			CreatedBy: "user1",
		},
	}

	// Store all configurations
	for _, config := range configs {
		err := store.StoreConfig(ctx, config)
		require.NoError(t, err)
	}

	// Get statistics
	stats, err := store.GetConfigStats(ctx)
	require.NoError(t, err)

	// Verify basic statistics
	assert.Equal(t, int64(3), stats.TotalConfigs)
	assert.Greater(t, stats.TotalSize, int64(0))
	assert.Greater(t, stats.AverageSize, int64(0))
	assert.NotNil(t, stats.OldestConfig)
	assert.NotNil(t, stats.NewestConfig)

	// Verify tenant statistics
	assert.Equal(t, int64(2), stats.ConfigsByTenant["stats-tenant-a"])
	assert.Equal(t, int64(1), stats.ConfigsByTenant["stats-tenant-b"])

	// Verify format statistics (all should be YAML)
	assert.Equal(t, int64(3), stats.ConfigsByFormat["yaml"])

	// Verify namespace statistics
	assert.Equal(t, int64(2), stats.ConfigsByNamespace["templates"])
	assert.Equal(t, int64(1), stats.ConfigsByNamespace["certificates"])
}

func TestDatabaseConfigStore_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Test validation errors
	tests := []struct {
		name        string
		config      *cfgconfig.ConfigEntry
		expectedErr error
	}{
		{
			name:        "nil key",
			config:      &cfgconfig.ConfigEntry{Key: nil, Data: []byte("data")},
			expectedErr: cfgconfig.ErrNameRequired,
		},
		{
			name: "empty tenant ID",
			config: &cfgconfig.ConfigEntry{
				Key:  &cfgconfig.ConfigKey{TenantID: "", Namespace: "ns", Name: "name"},
				Data: []byte("data"),
			},
			expectedErr: cfgconfig.ErrTenantRequired,
		},
		{
			name: "empty namespace",
			config: &cfgconfig.ConfigEntry{
				Key:  &cfgconfig.ConfigKey{TenantID: "tenant", Namespace: "", Name: "name"},
				Data: []byte("data"),
			},
			expectedErr: cfgconfig.ErrNamespaceRequired,
		},
		{
			name: "empty name",
			config: &cfgconfig.ConfigEntry{
				Key:  &cfgconfig.ConfigKey{TenantID: "tenant", Namespace: "ns", Name: ""},
				Data: []byte("data"),
			},
			expectedErr: cfgconfig.ErrNameRequired,
		},
		{
			name: "empty data",
			config: &cfgconfig.ConfigEntry{
				Key:  &cfgconfig.ConfigKey{TenantID: "tenant", Namespace: "ns", Name: "name"},
				Data: []byte{},
			},
			expectedErr: nil, // Should have a specific error for empty data
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.StoreConfig(ctx, tt.config)
			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err)
			} else {
				if tt.name == "empty data" {
					assert.Error(t, err) // Should error on empty data
					assert.Contains(t, err.Error(), "empty")
				}
			}
		})
	}
}

func TestDatabaseConfigStore_ConcurrentAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping database integration tests in short mode")
	}

	db := setupTestDatabase(t)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Test concurrent writes to different configurations
	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer func() { done <- true }()

			config := &cfgconfig.ConfigEntry{
				Key: &cfgconfig.ConfigKey{
					TenantID:  "concurrent-tenant",
					Namespace: "test",
					Name:      fmt.Sprintf("config-%d", id),
				},
				Data: []byte(fmt.Sprintf("concurrent data %d", id)),
			}

			err := store.StoreConfig(ctx, config)
			assert.NoError(t, err, "Goroutine %d should not error", id)
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	// Verify all configurations were stored
	filter := &cfgconfig.ConfigFilter{
		TenantID:  "concurrent-tenant",
		Namespace: "test",
	}
	configs, err := store.ListConfigs(ctx, filter)
	require.NoError(t, err)
	assert.Len(t, configs, numGoroutines)
}

// Benchmark tests for performance validation

// Helper interface for both testing.T and testing.B
type testingTB interface {
	Skip(args ...interface{})
}

func setupTestDatabaseForBench(tb testingTB) *sql.DB {
	if testing.Short() {
		tb.Skip("Skipping database tests in short mode")
	}

	// Check if test database is available
	dsn := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=%s",
		getTestConfig()["host"], getTestConfig()["port"], getTestConfig()["database"],
		getTestConfig()["username"], getTestConfig()["password"], getTestConfig()["sslmode"])

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		tb.Skip("PostgreSQL test database not available:", err)
	}

	if err := db.Ping(); err != nil {
		_ = db.Close()
		tb.Skip("PostgreSQL test database not reachable:", err)
	}

	// Clean up any existing tables
	schemas := NewDatabaseSchemas()
	ctx := context.Background()

	if err := schemas.DropAllTables(ctx, db); err != nil {
		// Ignore errors on cleanup
		_ = err
	}

	return db
}

func BenchmarkDatabaseConfigStore_StoreConfig(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	db := setupTestDatabaseForBench(b)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(b, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	config := &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  "bench-tenant",
			Namespace: "bench",
			Name:      "config",
		},
		Data: []byte("benchmark config data"),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config.Key.Name = fmt.Sprintf("config-%d", i)
		err := store.StoreConfig(ctx, config)
		if err != nil {
			b.Fatalf("Store failed: %v", err)
		}
	}
}

func BenchmarkDatabaseConfigStore_GetConfig(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	db := setupTestDatabaseForBench(b)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(b, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Setup test data
	key := &cfgconfig.ConfigKey{
		TenantID:  "bench-tenant",
		Namespace: "bench",
		Name:      "config",
	}

	config := &cfgconfig.ConfigEntry{
		Key:  key,
		Data: []byte("benchmark config data"),
	}

	err = store.StoreConfig(ctx, config)
	require.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := store.GetConfig(ctx, key)
		if err != nil {
			b.Fatalf("Get failed: %v", err)
		}
	}
}

func BenchmarkDatabaseConfigStore_ListConfigs(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	db := setupTestDatabaseForBench(b)
	defer func() { _ = db.Close() }()

	store, err := NewDatabaseConfigStore(buildTestDSN(), getTestConfig())
	require.NoError(b, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Setup test data
	for i := 0; i < 100; i++ {
		config := &cfgconfig.ConfigEntry{
			Key: &cfgconfig.ConfigKey{
				TenantID:  "bench-tenant",
				Namespace: "bench",
				Name:      fmt.Sprintf("config-%d", i),
			},
			Data: []byte(fmt.Sprintf("benchmark config data %d", i)),
		}
		err := store.StoreConfig(ctx, config)
		require.NoError(b, err)
	}

	filter := &cfgconfig.ConfigFilter{
		TenantID: "bench-tenant",
		Limit:    50,
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := store.ListConfigs(ctx, filter)
		if err != nil {
			b.Fatalf("List failed: %v", err)
		}
	}
}
