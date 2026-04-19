// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package storage_test provides integration tests for DNA storage system.

package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/logging"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDNAStorageIntegration(t *testing.T) {
	logger := logging.NewLogger("info")

	// Create a simplified config for integration testing
	// Use t.TempDir() for proper test isolation on all platforms
	config := &Config{
		Backend:                BackendSQLite,
		DataDir:                t.TempDir(), // Isolated temp directory per test
		CompressionLevel:       6,
		CompressionType:        "gzip",
		TargetCompressionRatio: 0.7, // More relaxed target for testing
		EnableDeduplication:    true,
		BlockSize:              64 * 1024,
		HashAlgorithm:          "sha256",
		RetentionPeriod:        24 * time.Hour,
		ArchivalPeriod:         1 * time.Hour,
		MaxRecordsPerDevice:    100,
		EnableSharding:         false, // Disable sharding for simplicity
		ShardCount:             1,
		ShardingStrategy:       "device_id",
		BatchSize:              10,
		FlushInterval:          1 * time.Minute,
		CacheSize:              100,
		MaxStoragePerMonth:     10 * 1024 * 1024, // 10MB
	}

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("Failed to create storage manager: %v", err)
	}
	defer func() {
		if err := manager.Close(); err != nil {
			t.Logf("Failed to close manager: %v", err)
		}
	}()

	ctx := context.Background()

	t.Run("BasicStorageAndRetrieval", func(t *testing.T) {
		deviceID := "integration-test-device"

		// Create test DNA
		dna := &commonpb.DNA{
			Id: deviceID,
			Attributes: map[string]string{
				"os":           "linux",
				"arch":         "amd64",
				"hostname":     "test-host",
				"cpu_count":    "8",
				"memory_total": "16GB",
				"disk_total":   "500GB",
			},
			LastUpdated:     timestamppb.New(time.Now()),
			ConfigHash:      "test-config-hash",
			LastSyncTime:    timestamppb.New(time.Now()),
			AttributeCount:  6,
			SyncFingerprint: "test-sync-fingerprint",
		}

		// Store DNA
		err := manager.Store(ctx, deviceID, dna, nil)
		if err != nil {
			t.Fatalf("Failed to store DNA: %v", err)
		}

		// Retrieve current DNA
		current, err := manager.GetCurrent(ctx, deviceID)
		if err != nil {
			t.Fatalf("Failed to get current DNA: %v", err)
		}

		// Verify data integrity
		if current.DeviceID != deviceID {
			t.Errorf("Expected device ID %s, got %s", deviceID, current.DeviceID)
		}

		if current.DNA.Id != dna.Id {
			t.Errorf("Expected DNA ID %s, got %s", dna.Id, current.DNA.Id)
		}

		// Verify all attributes
		for key, expectedValue := range dna.Attributes {
			if actualValue, exists := current.DNA.Attributes[key]; !exists {
				t.Errorf("Missing attribute %s", key)
			} else if actualValue != expectedValue {
				t.Errorf("Attribute %s: expected %s, got %s", key, expectedValue, actualValue)
			}
		}

		t.Logf("✅ Successfully stored and retrieved DNA with %d attributes", len(dna.Attributes))
	})

	t.Run("CompressionEfficiency", func(t *testing.T) {
		deviceID := "compression-test-device"

		// Create DNA with larger, repetitive content
		attributes := make(map[string]string)
		for i := 0; i < 30; i++ {
			key := fmt.Sprintf("large_attr_%d", i)
			// Create repetitive content that compresses well
			value := fmt.Sprintf("repeated_value_%d", i%5) // Only 5 unique patterns
			for j := 0; j < 50; j++ {
				value += "_more_content"
			}
			attributes[key] = value
		}

		dna := &commonpb.DNA{
			Id:              deviceID,
			Attributes:      attributes,
			LastUpdated:     timestamppb.New(time.Now()),
			ConfigHash:      "compression-config-hash",
			LastSyncTime:    timestamppb.New(time.Now()),
			AttributeCount:  int32(len(attributes)),
			SyncFingerprint: "compression-sync-fingerprint",
		}

		// Store DNA
		err := manager.Store(ctx, deviceID, dna, nil)
		if err != nil {
			t.Fatalf("Failed to store DNA: %v", err)
		}

		// Get storage stats to check compression
		stats, err := manager.GetStorageStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get storage stats: %v", err)
		}

		if stats.CompressionRatio <= 0 || stats.CompressionRatio >= 1.0 {
			t.Errorf("Invalid compression ratio: %f", stats.CompressionRatio)
		}

		compressionSavings := (1.0 - stats.CompressionRatio) * 100
		t.Logf("✅ Achieved %.1f%% compression savings (ratio: %.3f)", compressionSavings, stats.CompressionRatio)

		// Verify data integrity after compression
		retrieved, err := manager.GetCurrent(ctx, deviceID)
		if err != nil {
			t.Fatalf("Failed to retrieve compressed DNA: %v", err)
		}

		if len(retrieved.DNA.Attributes) != len(attributes) {
			t.Errorf("Attribute count mismatch after compression: expected %d, got %d",
				len(attributes), len(retrieved.DNA.Attributes))
		}
	})

	t.Run("HistoricalData", func(t *testing.T) {
		deviceID := "history-test-device"

		// Store multiple versions over time
		versions := 5
		for i := 0; i < versions; i++ {
			attributes := map[string]string{
				"os":      "linux",
				"arch":    "amd64",
				"version": fmt.Sprintf("1.%d.0", i),
				"uptime":  fmt.Sprintf("%d hours", i*24),
			}

			dna := &commonpb.DNA{
				Id:              deviceID,
				Attributes:      attributes,
				LastUpdated:     timestamppb.New(time.Now().Add(time.Duration(i) * time.Minute)),
				ConfigHash:      fmt.Sprintf("config-hash-v%d", i+1),
				LastSyncTime:    timestamppb.New(time.Now().Add(time.Duration(i) * time.Minute)),
				AttributeCount:  int32(len(attributes)),
				SyncFingerprint: fmt.Sprintf("sync-fp-v%d", i+1),
			}

			err := manager.Store(ctx, deviceID, dna, nil)
			if err != nil {
				t.Fatalf("Failed to store DNA version %d: %v", i+1, err)
			}

			// Small delay between versions
			time.Sleep(10 * time.Millisecond)
		}

		// Query historical data
		options := &QueryOptions{
			TimeRange: &TimeRange{
				Start: time.Now().Add(-1 * time.Hour),
				End:   time.Now().Add(1 * time.Hour),
			},
			IncludeData: true,
			Limit:       10,
		}

		history, err := manager.GetHistory(ctx, deviceID, options)
		if err != nil {
			t.Fatalf("Failed to get history: %v", err)
		}

		if len(history.Records) != versions {
			t.Errorf("Expected %d historical records, got %d", versions, len(history.Records))
		}

		if history.TotalCount != int64(versions) {
			t.Errorf("Expected total count %d, got %d", versions, history.TotalCount)
		}

		// Verify records are properly ordered and contain correct data
		for i, record := range history.Records {
			expectedVersion := fmt.Sprintf("1.%d.0", versions-1-i) // Newest first
			if actualVersion := record.DNA.Attributes["version"]; actualVersion != expectedVersion {
				t.Errorf("Record %d: expected version %s, got %s", i, expectedVersion, actualVersion)
			}
		}

		t.Logf("✅ Successfully stored and retrieved %d historical records", len(history.Records))
	})

	t.Run("StorageStatistics", func(t *testing.T) {
		// Get final storage statistics
		stats, err := manager.GetStorageStats(ctx)
		if err != nil {
			t.Fatalf("Failed to get storage stats: %v", err)
		}

		// Verify basic statistics make sense
		if stats.TotalSize <= 0 {
			t.Error("Expected total size > 0")
		}

		if stats.TotalDevices <= 0 {
			t.Error("Expected total devices > 0")
		}

		// Display comprehensive statistics
		t.Logf("📊 Storage Statistics:")
		t.Logf("   Total Size: %d bytes", stats.TotalSize)
		t.Logf("   Compressed Size: %d bytes", stats.CompressedSize)
		t.Logf("   Uncompressed Size: %d bytes", stats.UncompressedSize)
		t.Logf("   Compression Ratio: %.3f (%.1f%% savings)",
			stats.CompressionRatio, (1.0-stats.CompressionRatio)*100)
		t.Logf("   Total Devices: %d", stats.TotalDevices)
		t.Logf("   Active Devices: %d", stats.ActiveDevices)
		t.Logf("   Unique Blocks: %d", stats.UniqueBlocks)
		t.Logf("   Total Blocks: %d", stats.TotalBlocks)
		if stats.TotalBlocks > 0 {
			t.Logf("   Deduplication Ratio: %.3f", stats.DeduplicationRatio)
		}
		t.Logf("   Average Records/Device: %.1f", stats.AverageRecordsPerDevice)
	})

	t.Logf("🎉 DNA Storage Integration Test Completed Successfully!")
}

func TestCompressionBenchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping compression benchmark in short mode")
	}

	algorithms := []string{"gzip"}
	levels := []int{1, 6, 9}

	for _, algorithm := range algorithms {
		for _, level := range levels {
			t.Run(fmt.Sprintf("%s_level_%d", algorithm, level), func(t *testing.T) {
				testCompressionPerformance(t, algorithm, level)
			})
		}
	}
}

func testCompressionPerformance(t *testing.T, algorithm string, level int) {
	compressor, err := NewCompressor(algorithm, level)
	if err != nil {
		t.Fatalf("Failed to create compressor: %v", err)
	}
	defer func() {
		if err := compressor.Close(); err != nil {
			t.Logf("Failed to close compressor: %v", err)
		}
	}()

	// Create test DNA with varying content patterns
	attributes := make(map[string]string)

	// Add some highly compressible content
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("repeated_%d", i)
		value := fmt.Sprintf("value_%d", i%3) // Only 3 unique patterns
		for j := 0; j < 100; j++ {
			value += "_repeated_content"
		}
		attributes[key] = value
	}

	// Add some less compressible content
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("unique_%d", i)
		value := fmt.Sprintf("unique_value_%d_%d", i, time.Now().UnixNano())
		attributes[key] = value
	}

	dna := &commonpb.DNA{
		Id:              "benchmark-device",
		Attributes:      attributes,
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "benchmark-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(attributes)),
		SyncFingerprint: "benchmark-sync-fingerprint",
	}

	// Perform compression benchmark
	iterations := 100
	start := time.Now()

	var totalOriginalSize, totalCompressedSize int64

	for i := 0; i < iterations; i++ {
		compressed, originalSize, err := compressor.Compress(dna)
		if err != nil {
			t.Fatalf("Compression failed on iteration %d: %v", i, err)
		}

		totalOriginalSize += originalSize
		totalCompressedSize += int64(len(compressed))

		// Verify decompression works
		if i == 0 { // Only test decompression on first iteration for speed
			decompressed, err := compressor.Decompress(compressed)
			if err != nil {
				t.Fatalf("Decompression failed: %v", err)
			}

			if decompressed.Id != dna.Id {
				t.Errorf("Decompressed DNA ID mismatch")
			}
		}
	}

	duration := time.Since(start)
	avgOriginalSize := totalOriginalSize / int64(iterations)
	avgCompressedSize := totalCompressedSize / int64(iterations)
	compressionRatio := float64(totalCompressedSize) / float64(totalOriginalSize)
	throughputMBs := float64(totalOriginalSize) / (1024 * 1024) / duration.Seconds()

	t.Logf("🔧 %s Level %d Performance:", algorithm, level)
	t.Logf("   Iterations: %d", iterations)
	t.Logf("   Total Time: %v", duration)
	t.Logf("   Avg Original Size: %d bytes", avgOriginalSize)
	t.Logf("   Avg Compressed Size: %d bytes", avgCompressedSize)
	t.Logf("   Compression Ratio: %.3f (%.1f%% savings)", compressionRatio, (1.0-compressionRatio)*100)
	t.Logf("   Throughput: %.2f MB/s", throughputMBs)
	t.Logf("   Avg Time per Compression: %v", duration/time.Duration(iterations))

	// Verify compression targets
	if compressionRatio >= 0.7 { // Should achieve at least 30% compression
		t.Errorf("Poor compression ratio: %.3f (expected < 0.7)", compressionRatio)
	}

	if throughputMBs < 1.0 { // Should process at least 1 MB/s
		t.Errorf("Low throughput: %.2f MB/s (expected >= 1.0)", throughputMBs)
	}
}
