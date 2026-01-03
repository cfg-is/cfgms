// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
// Package storage_test provides comprehensive tests for DNA storage system.

package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// skipWithoutCGO skips the test if CGO is not enabled (SQLite requires CGO).
// This is a local version to avoid circular imports with testutil.
func skipWithoutCGO(t *testing.T) {
	t.Helper()
	config := DefaultConfig()
	config.Backend = BackendSQLite
	config.DataDir = t.TempDir() // Use temp directory to avoid file conflicts
	logger := logging.NewLogger("error")

	manager, err := NewManager(config, logger)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "CGO_ENABLED=0") ||
			strings.Contains(errStr, "go-sqlite3 requires cgo") ||
			strings.Contains(errStr, "This is a stub") {
			t.Skip("Skipping test: SQLite requires CGO which is not enabled (no C compiler available)")
		}
	}
	// Close the manager if it was successfully created
	if manager != nil {
		_ = manager.Close()
	}
}

// createTestConfig creates a test configuration with unique database path
func createTestConfig(t *testing.T, backendType BackendType) *Config {
	config := DefaultConfig()
	config.Backend = backendType

	// Use t.TempDir() for test isolation - each test gets its own temp directory
	// that Go will automatically clean up after the test completes.
	// This ensures proper isolation on all platforms, especially Windows where
	// SQLite WAL files can't be deleted while the database is open.
	config.DataDir = t.TempDir()

	return config
}

func TestStorageManager(t *testing.T) {
	skipWithoutCGO(t)
	logger := logging.NewLogger("debug")
	config := createTestConfig(t, BackendSQLite)

	// t.TempDir() automatically creates and cleans up the directory,
	// no manual cleanup needed

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create storage manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Logf("Failed to close manager: %v", err)
		}
	}()

	t.Run("StoreAndRetrieve", func(t *testing.T) {
		testStoreAndRetrieve(t, manager)
	})

	t.Run("Deduplication", func(t *testing.T) {
		testDeduplication(t, manager)
	})

	t.Run("HistoricalQueries", func(t *testing.T) {
		testHistoricalQueries(t, manager)
	})

	t.Run("Compression", func(t *testing.T) {
		testCompression(t, manager)
	})

	t.Run("StorageStats", func(t *testing.T) {
		testStorageStats(t, manager)
	})
}

func testStoreAndRetrieve(t *testing.T, manager *Manager) {
	ctx := context.Background()
	deviceID := "test-device-001"

	// Create test DNA
	dna := createTestDNA(deviceID, map[string]string{
		"os":           "linux",
		"arch":         "amd64",
		"hostname":     "test-host",
		"cpu_count":    "4",
		"memory_total": "8GB",
	})

	// Store DNA
	err := manager.Store(ctx, deviceID, dna)
	if err != nil {
		t.Fatalf("Failed to store DNA: %v", err)
	}

	// Retrieve current DNA
	current, err := manager.GetCurrent(ctx, deviceID)
	if err != nil {
		t.Fatalf("Failed to get current DNA: %v", err)
	}

	// Verify stored data
	if current.DeviceID != deviceID {
		t.Errorf("Expected device ID %s, got %s", deviceID, current.DeviceID)
	}

	if current.DNA.Id != dna.Id {
		t.Errorf("Expected DNA ID %s, got %s", dna.Id, current.DNA.Id)
	}

	if len(current.DNA.Attributes) != len(dna.Attributes) {
		t.Errorf("Expected %d attributes, got %d", len(dna.Attributes), len(current.DNA.Attributes))
	}

	// Verify specific attributes
	for key, expectedValue := range dna.Attributes {
		if actualValue, exists := current.DNA.Attributes[key]; !exists {
			t.Errorf("Missing attribute %s", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected attribute %s=%s, got %s", key, expectedValue, actualValue)
		}
	}
}

func testDeduplication(t *testing.T, manager *Manager) {
	ctx := context.Background()

	device1ID := "device-001"
	device2ID := "device-002"

	// For proper deduplication testing, create DNA with shared content but different device context
	// Both DNA records have identical attributes but represent different devices with the same configuration
	sharedDNAAttributes := map[string]string{
		"os":        "windows",
		"arch":      "amd64",
		"hostname":  "shared-config",
		"cpu_count": "8",
	}

	// Create identical DNA objects for deduplication (same content hash)
	dna1 := &commonpb.DNA{
		Id:              "shared-system-id", // Same system configuration
		Attributes:      sharedDNAAttributes,
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "shared-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(sharedDNAAttributes)),
		SyncFingerprint: "shared-sync-fingerprint",
	}

	dna2 := &commonpb.DNA{
		Id:              "shared-system-id", // Same system configuration
		Attributes:      sharedDNAAttributes,
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "shared-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(sharedDNAAttributes)),
		SyncFingerprint: "shared-sync-fingerprint",
	}

	// Store both DNA records
	err := manager.Store(ctx, device1ID, dna1)
	if err != nil {
		t.Fatalf("Failed to store DNA for device 1: %v", err)
	}

	err = manager.Store(ctx, device2ID, dna2)
	if err != nil {
		t.Fatalf("Failed to store DNA for device 2: %v", err)
	}

	// Get storage stats to verify deduplication
	stats, err := manager.GetStorageStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get storage stats: %v", err)
	}

	// With deduplication, we should have more total blocks than unique blocks
	if stats.DeduplicationRatio <= 0 {
		t.Logf("Deduplication ratio: %f (may be 0 for memory backend)", stats.DeduplicationRatio)
	}

	// Verify both devices can retrieve their data
	current1, err := manager.GetCurrent(ctx, device1ID)
	if err != nil {
		t.Fatalf("Failed to get current DNA for device 1: %v", err)
	}

	current2, err := manager.GetCurrent(ctx, device2ID)
	if err != nil {
		t.Fatalf("Failed to get current DNA for device 2: %v", err)
	}

	// Both should have the same content but different device IDs
	if current1.DeviceID == current2.DeviceID {
		t.Error("Device IDs should be different")
	}

	if current1.ContentHash != current2.ContentHash {
		t.Error("Content hashes should be identical for deduplicated content")
	}
}

func testHistoricalQueries(t *testing.T, manager *Manager) {
	ctx := context.Background()
	deviceID := "history-test-device"

	// Store multiple DNA versions over time
	baseTime := time.Now().Add(-24 * time.Hour)

	for i := 0; i < 5; i++ {
		attributes := map[string]string{
			"os":           "linux",
			"arch":         "amd64",
			"hostname":     "test-host",
			"cpu_count":    "4",
			"memory_total": "8GB",
			"version":      fmt.Sprintf("v%d", i+1),
		}

		dna := createTestDNA(deviceID, attributes)
		// Simulate time progression
		dna.LastUpdated = timestamppb.New(baseTime.Add(time.Duration(i) * time.Hour))

		err := manager.Store(ctx, deviceID, dna)
		if err != nil {
			t.Fatalf("Failed to store DNA version %d: %v", i+1, err)
		}

		// Small delay to ensure different timestamps
		time.Sleep(10 * time.Millisecond)
	}

	// Query historical records
	options := &QueryOptions{
		TimeRange: &TimeRange{
			Start: baseTime,
			End:   time.Now(),
		},
		IncludeData: true,
		Limit:       10,
	}

	history, err := manager.GetHistory(ctx, deviceID, options)
	if err != nil {
		t.Fatalf("Failed to get history: %v", err)
	}

	// Verify we got all records
	if len(history.Records) != 5 {
		t.Errorf("Expected 5 historical records, got %d", len(history.Records))
	}

	if history.TotalCount != 5 {
		t.Errorf("Expected total count of 5, got %d", history.TotalCount)
	}

	// Verify records are in correct order (should be newest first)
	for i := 0; i < len(history.Records)-1; i++ {
		if history.Records[i].Version < history.Records[i+1].Version {
			t.Error("Records should be ordered by version (newest first)")
		}
	}

	// Test pagination
	options.Limit = 2
	options.Offset = 1

	pagedHistory, err := manager.GetHistory(ctx, deviceID, options)
	if err != nil {
		t.Fatalf("Failed to get paged history: %v", err)
	}

	if len(pagedHistory.Records) != 2 {
		t.Errorf("Expected 2 paged records, got %d", len(pagedHistory.Records))
	}

	if pagedHistory.TotalCount != 5 {
		t.Errorf("Expected total count of 5 for paged query, got %d", pagedHistory.TotalCount)
	}
}

func testCompression(t *testing.T, manager *Manager) {
	ctx := context.Background()
	deviceID := "compression-test-device"

	// Create DNA with large attribute values to test compression
	largeAttributes := make(map[string]string)
	for i := 0; i < 50; i++ {
		key := fmt.Sprintf("large_attr_%d", i)
		// Create a large value with repetitive content (compresses well)
		value := ""
		for j := 0; j < 100; j++ {
			value += fmt.Sprintf("repeated_content_%d_", i)
		}
		largeAttributes[key] = value
	}

	dna := createTestDNA(deviceID, largeAttributes)

	// Store DNA
	err := manager.Store(ctx, deviceID, dna)
	if err != nil {
		t.Fatalf("Failed to store DNA: %v", err)
	}

	// Get storage stats to check compression
	stats, err := manager.GetStorageStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get storage stats: %v", err)
	}

	// Verify compression occurred
	if stats.CompressionRatio <= 0 {
		t.Error("Expected compression ratio > 0")
	}

	if stats.CompressionRatio >= 1.0 {
		t.Error("Expected compression ratio < 1.0 (compressed should be smaller)")
	}

	t.Logf("Compression ratio: %.3f (%.1f%% space savings)",
		stats.CompressionRatio,
		(1.0-stats.CompressionRatio)*100)

	// Verify we can still retrieve the data correctly
	current, err := manager.GetCurrent(ctx, deviceID)
	if err != nil {
		t.Fatalf("Failed to get current DNA after compression: %v", err)
	}

	// Verify all large attributes are intact
	for key, expectedValue := range largeAttributes {
		if actualValue, exists := current.DNA.Attributes[key]; !exists {
			t.Errorf("Missing large attribute %s after compression/decompression", key)
		} else if actualValue != expectedValue {
			t.Errorf("Large attribute %s corrupted during compression/decompression", key)
		}
	}
}

func testStorageStats(t *testing.T, manager *Manager) {
	ctx := context.Background()

	// Store DNA for multiple devices
	devices := []string{"stats-device-1", "stats-device-2", "stats-device-3"}

	for _, deviceID := range devices {
		attributes := map[string]string{
			"os":        "linux",
			"arch":      "amd64",
			"hostname":  deviceID,
			"device_id": deviceID,
		}

		dna := createTestDNA(deviceID, attributes)
		err := manager.Store(ctx, deviceID, dna)
		if err != nil {
			t.Fatalf("Failed to store DNA for device %s: %v", deviceID, err)
		}
	}

	// Get storage statistics
	stats, err := manager.GetStorageStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get storage stats: %v", err)
	}

	// Verify basic statistics
	if stats.TotalDevices < int64(len(devices)) {
		t.Errorf("Expected at least %d devices, got %d", len(devices), stats.TotalDevices)
	}

	if stats.TotalSize <= 0 {
		t.Error("Expected total size > 0")
	}

	if stats.CollectedAt.IsZero() {
		t.Error("Expected collected timestamp to be set")
	}

	// Verify shard statistics
	if stats.TotalShards <= 0 {
		t.Error("Expected total shards > 0")
	}

	if stats.ShardSizes == nil {
		t.Error("Expected shard sizes to be populated")
	}

	t.Logf("Storage Stats:")
	t.Logf("  Total Size: %d bytes", stats.TotalSize)
	t.Logf("  Total Devices: %d", stats.TotalDevices)
	t.Logf("  Compression Ratio: %.3f", stats.CompressionRatio)
	t.Logf("  Deduplication Ratio: %.3f", stats.DeduplicationRatio)
	t.Logf("  Total Shards: %d", stats.TotalShards)
}

func TestCompressionAlgorithms(t *testing.T) {
	algorithms := []string{"gzip", "zstd", "lz4"}

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			testCompressionAlgorithm(t, algorithm)
		})
	}
}

func testCompressionAlgorithm(t *testing.T, algorithm string) {
	compressor, err := NewCompressor(algorithm, 6)
	if err != nil {
		t.Fatalf("Failed to create %s compressor: %v", algorithm, err)
	}
	defer func() {
		if err := compressor.Close(); err != nil {
			t.Logf("Failed to close compressor: %v", err)
		}
	}()

	// Create test DNA with repetitive content
	attributes := make(map[string]string)
	for i := 0; i < 20; i++ {
		key := fmt.Sprintf("attr_%d", i)
		value := fmt.Sprintf("value_%d_repeated_content", i)
		for j := 0; j < 10; j++ {
			value += "_more_repeated_content"
		}
		attributes[key] = value
	}

	dna := createTestDNA("test-device", attributes)

	// Test compression
	compressed, originalSize, err := compressor.Compress(dna)
	if err != nil {
		t.Fatalf("Failed to compress with %s: %v", algorithm, err)
	}

	compressedSize := int64(len(compressed))
	ratio := float64(compressedSize) / float64(originalSize)

	t.Logf("%s compression: %d -> %d bytes (ratio: %.3f)",
		algorithm, originalSize, compressedSize, ratio)

	// Verify compression achieved some space savings
	if ratio >= 1.0 {
		t.Errorf("Expected compression ratio < 1.0 for %s, got %.3f", algorithm, ratio)
	}

	// Test decompression
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Fatalf("Failed to decompress with %s: %v", algorithm, err)
	}

	// Verify decompressed data matches original
	if decompressed.Id != dna.Id {
		t.Errorf("Decompressed DNA ID mismatch: expected %s, got %s", dna.Id, decompressed.Id)
	}

	if len(decompressed.Attributes) != len(dna.Attributes) {
		t.Errorf("Decompressed attributes count mismatch: expected %d, got %d",
			len(dna.Attributes), len(decompressed.Attributes))
	}

	for key, expectedValue := range dna.Attributes {
		if actualValue, exists := decompressed.Attributes[key]; !exists {
			t.Errorf("Missing attribute %s after %s decompression", key, algorithm)
		} else if actualValue != expectedValue {
			t.Errorf("Attribute %s corrupted during %s compression/decompression", key, algorithm)
		}
	}

	// Test compression statistics
	stats := compressor.GetStats()
	if stats.Algorithm != algorithm && stats.Algorithm != "optimized_"+algorithm {
		t.Errorf("Expected algorithm %s, got %s", algorithm, stats.Algorithm)
	}

	if stats.TotalOperations == 0 {
		t.Error("Expected total operations > 0")
	}

	if stats.CompressionRatio <= 0 {
		t.Error("Expected compression ratio > 0")
	}
}

func TestStorageBackends(t *testing.T) {
	logger := logging.NewLogger("debug")

	backends := []BackendType{BackendSQLite, BackendFile}

	for _, backendType := range backends {
		t.Run(string(backendType), func(t *testing.T) {
			// Skip SQLite tests if CGO is not available
			if backendType == BackendSQLite {
				skipWithoutCGO(t)
			}
			// Use createTestConfig to get proper temp directory isolation
			testConfig := createTestConfig(t, backendType)
			testStorageBackend(t, backendType, testConfig, logger)
		})
	}
}

func testStorageBackend(t *testing.T, backendType BackendType, config *Config, logger logging.Logger) {
	config.Backend = backendType

	backend, err := NewBackend(backendType, config, logger)
	if err != nil {
		t.Fatalf("Failed to create %s backend: %v", backendType, err)
	}
	defer func() {
		if err := backend.Close(); err != nil {
			t.Logf("Failed to close backend: %v", err)
		}
	}()

	ctx := context.Background()

	// Create test record
	dna := createTestDNA("backend-test-device", map[string]string{
		"os":   "linux",
		"arch": "amd64",
		"test": "backend_" + string(backendType),
	})

	// Use appropriate shard ID for the backend
	shardID := "default"
	if config.EnableSharding {
		shardID = "shard_0" // Use first shard for testing
	}

	record := &DNARecord{
		DeviceID:         "backend-test-device",
		DNA:              dna,
		StoredAt:         time.Now(),
		ContentHash:      "test-hash-123",
		CompressedSize:   1000,
		OriginalSize:     2000,
		CompressionRatio: 0.5,
		Version:          1,
		ShardID:          shardID,
	}

	compressedData := []byte("mock-compressed-data")

	// Test store
	err = backend.StoreRecord(ctx, record, compressedData)
	if err != nil {
		t.Fatalf("Failed to store record in %s backend: %v", backendType, err)
	}

	// Test has content
	exists, err := backend.HasContent(ctx, record.ContentHash)
	if err != nil {
		t.Fatalf("Failed to check content existence in %s backend: %v", backendType, err)
	}

	if !exists {
		t.Errorf("Content should exist in %s backend after storing", backendType)
	}

	// Test retrieve
	retrieved, err := backend.GetRecord(ctx, record.ContentHash, record.ShardID)
	if err != nil {
		t.Fatalf("Failed to retrieve record from %s backend: %v", backendType, err)
	}

	// Verify retrieved record
	if retrieved.DeviceID != record.DeviceID {
		t.Errorf("Device ID mismatch: expected %s, got %s", record.DeviceID, retrieved.DeviceID)
	}

	if retrieved.ContentHash != record.ContentHash {
		t.Errorf("Content hash mismatch: expected %s, got %s", record.ContentHash, retrieved.ContentHash)
	}

	// Test stats
	stats, err := backend.GetStats(ctx)
	if err != nil {
		t.Fatalf("Failed to get stats from %s backend: %v", backendType, err)
	}

	if stats == nil {
		t.Errorf("Expected non-nil stats from %s backend", backendType)
	}

	// Test flush and optimize
	err = backend.Flush()
	if err != nil {
		t.Fatalf("Failed to flush %s backend: %v", backendType, err)
	}

	err = backend.Optimize()
	if err != nil {
		t.Fatalf("Failed to optimize %s backend: %v", backendType, err)
	}
}

func TestIndexer(t *testing.T) {
	logger := logging.NewLogger("debug")
	config := DefaultConfig()

	indexer, err := NewIndexer(config, logger)
	if err != nil {
		t.Fatalf("Failed to create indexer: %v", err)
	}
	defer func() {
		if err := indexer.Close(); err != nil {
			t.Logf("Failed to close indexer: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("IndexAndQuery", func(t *testing.T) {
		testIndexAndQuery(t, indexer, ctx)
	})

	t.Run("VersionTracking", func(t *testing.T) {
		testVersionTracking(t, indexer, ctx)
	})

	t.Run("DeviceStats", func(t *testing.T) {
		testDeviceStats(t, indexer, ctx)
	})
}

func testIndexAndQuery(t *testing.T, indexer Indexer, ctx context.Context) {
	deviceID := "index-test-device"

	// Create and index multiple records
	for i := 0; i < 5; i++ {
		dna := createTestDNA(deviceID, map[string]string{
			"os":      "linux",
			"version": fmt.Sprintf("v%d", i+1),
			"seq":     fmt.Sprintf("%d", i),
		})

		record := &DNARecord{
			DeviceID:    deviceID,
			DNA:         dna,
			StoredAt:    time.Now().Add(time.Duration(i) * time.Minute),
			ContentHash: fmt.Sprintf("hash-%d", i),
			Version:     int64(i + 1),
			ShardID:     "default",
		}

		err := indexer.IndexRecord(ctx, record)
		if err != nil {
			t.Fatalf("Failed to index record %d: %v", i, err)
		}
	}

	// Query all records
	options := &QueryOptions{
		IncludeData: true,
		Limit:       10,
	}

	refs, totalCount, err := indexer.QueryRecords(ctx, deviceID, options)
	if err != nil {
		t.Fatalf("Failed to query records: %v", err)
	}

	if len(refs) != 5 {
		t.Errorf("Expected 5 records, got %d", len(refs))
	}

	if totalCount != 5 {
		t.Errorf("Expected total count 5, got %d", totalCount)
	}

	// Verify records are sorted by version (newest first)
	for i := 0; i < len(refs)-1; i++ {
		if refs[i].Version < refs[i+1].Version {
			t.Error("Records should be sorted by version (newest first)")
		}
	}

	// Test pagination
	options.Limit = 2
	options.Offset = 1

	pagedRefs, pagedTotal, err := indexer.QueryRecords(ctx, deviceID, options)
	if err != nil {
		t.Fatalf("Failed to query paged records: %v", err)
	}

	if len(pagedRefs) != 2 {
		t.Errorf("Expected 2 paged records, got %d", len(pagedRefs))
	}

	if pagedTotal != 5 {
		t.Errorf("Expected total count 5 for paged query, got %d", pagedTotal)
	}
}

func testVersionTracking(t *testing.T, indexer Indexer, ctx context.Context) {
	deviceID := "version-test-device"

	// Get next version (should be 1 for new device)
	version1, err := indexer.GetNextVersion(ctx, deviceID)
	if err != nil {
		t.Fatalf("Failed to get next version: %v", err)
	}

	if version1 != 1 {
		t.Errorf("Expected first version to be 1, got %d", version1)
	}

	// Get next version again (should be 2)
	version2, err := indexer.GetNextVersion(ctx, deviceID)
	if err != nil {
		t.Fatalf("Failed to get next version: %v", err)
	}

	if version2 != 2 {
		t.Errorf("Expected second version to be 2, got %d", version2)
	}

	// Verify versions are sequential
	if version2 != version1+1 {
		t.Errorf("Versions should be sequential: %d -> %d", version1, version2)
	}
}

func testDeviceStats(t *testing.T, indexer Indexer, ctx context.Context) {
	deviceID := "stats-test-device"

	// Index multiple records with different timestamps
	baseTime := time.Now().Add(-2 * time.Hour)
	totalSize := int64(0)

	for i := 0; i < 3; i++ {
		dna := createTestDNA(deviceID, map[string]string{
			"os":    "linux",
			"index": fmt.Sprintf("%d", i),
		})

		size := int64(1000 + i*500) // Varying sizes
		totalSize += size

		record := &DNARecord{
			DeviceID:       deviceID,
			DNA:            dna,
			StoredAt:       baseTime.Add(time.Duration(i) * time.Hour),
			ContentHash:    fmt.Sprintf("stats-hash-%d", i),
			CompressedSize: size,
			Version:        int64(i + 1),
			ShardID:        "default",
		}

		err := indexer.IndexRecord(ctx, record)
		if err != nil {
			t.Fatalf("Failed to index record %d: %v", i, err)
		}
	}

	// Get device statistics
	stats, err := indexer.GetDeviceStats(ctx, deviceID)
	if err != nil {
		t.Fatalf("Failed to get device stats: %v", err)
	}

	// Verify statistics
	if stats.DeviceID != deviceID {
		t.Errorf("Expected device ID %s, got %s", deviceID, stats.DeviceID)
	}

	if stats.TotalRecords != 3 {
		t.Errorf("Expected 3 total records, got %d", stats.TotalRecords)
	}

	if stats.TotalSize != totalSize {
		t.Errorf("Expected total size %d, got %d", totalSize, stats.TotalSize)
	}

	expectedAverage := totalSize / 3
	if stats.AverageSize != expectedAverage {
		t.Errorf("Expected average size %d, got %d", expectedAverage, stats.AverageSize)
	}

	if stats.OldestRecord.After(stats.NewestRecord) {
		t.Error("Oldest record should be before newest record")
	}

	if stats.UpdateFrequency <= 0 {
		t.Error("Expected update frequency > 0")
	}
}

// Helper functions

func createTestDNA(deviceID string, attributes map[string]string) *commonpb.DNA {
	return &commonpb.DNA{
		Id:              deviceID,
		Attributes:      attributes,
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "test-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(attributes)),
		SyncFingerprint: "test-sync-fingerprint",
	}
}

// Benchmark tests

func BenchmarkDNAStorage(b *testing.B) {
	logger := logging.NewLogger("error") // Reduce logging noise
	config := DefaultConfig()
	config.Backend = BackendSQLite

	manager, err := NewManager(config, logger)
	if err != nil {
		b.Fatalf("Failed to create storage manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			b.Logf("Failed to close manager: %v", err)
		}
	}()

	ctx := context.Background()

	// Pre-create DNA records for benchmarking
	dnas := make([]*commonpb.DNA, b.N)
	for i := 0; i < b.N; i++ {
		dnas[i] = createTestDNA(fmt.Sprintf("bench-device-%d", i), map[string]string{
			"os":     "linux",
			"arch":   "amd64",
			"seq":    fmt.Sprintf("%d", i),
			"common": "repeated-value",
		})
	}

	b.ResetTimer()

	// Benchmark storage operations
	for i := 0; i < b.N; i++ {
		deviceID := fmt.Sprintf("bench-device-%d", i)
		err := manager.Store(ctx, deviceID, dnas[i])
		if err != nil {
			b.Fatalf("Failed to store DNA: %v", err)
		}
	}
}

func BenchmarkDNARetrieval(b *testing.B) {
	logger := logging.NewLogger("error")
	config := DefaultConfig()
	config.Backend = BackendSQLite

	manager, err := NewManager(config, logger)
	if err != nil {
		b.Fatalf("Failed to create storage manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			b.Logf("Failed to close manager: %v", err)
		}
	}()

	ctx := context.Background()

	// Pre-populate with data
	numDevices := 1000
	for i := 0; i < numDevices; i++ {
		deviceID := fmt.Sprintf("bench-device-%d", i)
		dna := createTestDNA(deviceID, map[string]string{
			"os":   "linux",
			"arch": "amd64",
			"seq":  fmt.Sprintf("%d", i),
		})

		err := manager.Store(ctx, deviceID, dna)
		if err != nil {
			b.Fatalf("Failed to store DNA: %v", err)
		}
	}

	b.ResetTimer()

	// Benchmark retrieval operations
	for i := 0; i < b.N; i++ {
		deviceID := fmt.Sprintf("bench-device-%d", i%numDevices)
		_, err := manager.GetCurrent(ctx, deviceID)
		if err != nil {
			b.Fatalf("Failed to retrieve DNA: %v", err)
		}
	}
}

func BenchmarkCompression(b *testing.B) {
	compressor, err := NewCompressor("gzip", 6)
	if err != nil {
		b.Fatalf("Failed to create compressor: %v", err)
	}
	defer func() {
		if err := compressor.Close(); err != nil {
			b.Logf("Failed to close compressor: %v", err)
		}
	}()

	// Create test DNA with varying sizes
	dna := createTestDNA("bench-device", map[string]string{
		"os":          "linux",
		"arch":        "amd64",
		"large_field": string(make([]byte, 10000)), // 10KB field
		"repeated":    "this content repeats " + string(make([]byte, 1000)),
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _, err := compressor.Compress(dna)
		if err != nil {
			b.Fatalf("Compression failed: %v", err)
		}
	}
}
