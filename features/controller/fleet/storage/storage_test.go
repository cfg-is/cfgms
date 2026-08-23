// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage_test provides comprehensive tests for DNA storage system.

package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	sdna "github.com/cfgis/cfgms/features/steward/dna"
	"github.com/cfgis/cfgms/pkg/logging"

	"google.golang.org/protobuf/types/known/timestamppb"
)

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

// validAggregateRoot returns a well-formed (64 lowercase hex) aggregate root
// built from seed, so tests exercise the accepted shape rather than the
// arbitrary strings a steward could also put in DNA.aggregate_root.
func validAggregateRoot(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return fmt.Sprintf("%x", sum[:])
}

// TestContentHash_PrefersAggregateRoot is the REQUIRED TEST for the #2906
// aggregate-root-first branch of generateContentHash/ContentHash (Issue #3329):
// when DNA.AggregateRoot is set to a well-formed digest, it must be returned
// verbatim rather than falling back to the ID+ConfigHash+SyncFingerprint hash.
// Before this test, every existing case in this file left AggregateRoot unset,
// so only the fallback branch was ever exercised.
func TestContentHash_PrefersAggregateRoot(t *testing.T) {
	root := validAggregateRoot("aggregate-root-value")
	dna := &commonpb.DNA{
		Id:              "device-1",
		ConfigHash:      "cfg-hash",
		SyncFingerprint: "fp",
		AggregateRoot:   root,
	}

	hash, err := ContentHash(dna)
	if err != nil {
		t.Fatalf("ContentHash returned error: %v", err)
	}
	if hash != root {
		t.Errorf("ContentHash must return AggregateRoot verbatim when set, got %q", hash)
	}

	// Changing the fallback-only fields must not change the result while
	// AggregateRoot is set — proving the branch takes priority, not just that
	// it happens to agree with the fallback.
	dna.ConfigHash = "different-cfg-hash"
	dna.SyncFingerprint = "different-fp"
	hash2, err := ContentHash(dna)
	if err != nil {
		t.Fatalf("ContentHash returned error: %v", err)
	}
	if hash2 != root {
		t.Errorf("ContentHash must ignore ConfigHash/SyncFingerprint once AggregateRoot is set, got %q", hash2)
	}
}

// TestContentHash_RejectsMalformedAggregateRoot pins the boundary validation
// added for the Story #396 finding: DNA.aggregate_root arrives from the steward
// as an arbitrary string (common.proto field 10) and reaches ContentHash
// unvalidated via RegisterSteward -> storeDNA -> Manager.Store. Anything that is
// not the exact shape sdna.AggregateRoot produces must be discarded in favour of
// the derived digest, because the return value becomes a log field, a database
// key and a filesystem path component.
func TestContentHash_RejectsMalformedAggregateRoot(t *testing.T) {
	malformed := map[string]string{
		"too short (panics the log slice)": "abc",
		"path traversal":                   "../../../../etc/cron.d/x",
		"uppercase hex":                    strings.ToUpper(validAggregateRoot("upper")),
		"non-hex characters":               strings.Repeat("g", 64),
		"one char short":                   validAggregateRoot("short")[:63],
		"one char long":                    validAggregateRoot("long") + "a",
		"log injection":                    strings.Repeat("a", 62) + "\r\n",
		"nul byte":                         strings.Repeat("a", 63) + "\x00",
	}

	fallback, err := ContentHash(&commonpb.DNA{
		Id:              "device-1",
		ConfigHash:      "cfg-hash",
		SyncFingerprint: "fp",
	})
	if err != nil {
		t.Fatalf("ContentHash returned error for fallback baseline: %v", err)
	}

	for name, root := range malformed {
		t.Run(name, func(t *testing.T) {
			hash, err := ContentHash(&commonpb.DNA{
				Id:              "device-1",
				ConfigHash:      "cfg-hash",
				SyncFingerprint: "fp",
				AggregateRoot:   root,
			})
			if err != nil {
				t.Fatalf("ContentHash returned error: %v", err)
			}
			if hash == root {
				t.Errorf("ContentHash returned malformed steward-supplied root %q verbatim", root)
			}
			if hash != fallback {
				t.Errorf("ContentHash must fall back to the derived digest, got %q want %q", hash, fallback)
			}
			if len(hash) != 64 {
				t.Errorf("ContentHash must always return a 64-character digest, got %d characters", len(hash))
			}
		})
	}
}

// TestContentHash_RecomputesRootFromManifest proves the strongest branch: when
// the DNA carries a manifest, the content address is derived server-side from
// that manifest, so a steward claiming a different (but well-formed) root cannot
// steer its record onto another steward's content address.
func TestContentHash_RecomputesRootFromManifest(t *testing.T) {
	manifest := []*commonpb.ManifestEntry{
		{FragmentId: "service:sshd", FragmentHash: validAggregateRoot("sshd")},
		{FragmentId: "host:cpu", FragmentHash: validAggregateRoot("cpu")},
	}
	computed, err := sdna.AggregateRoot(manifest)
	if err != nil {
		t.Fatalf("sdna.AggregateRoot returned error: %v", err)
	}

	lying := validAggregateRoot("someone-elses-content")
	hash, err := ContentHash(&commonpb.DNA{
		Id:            "device-1",
		AggregateRoot: lying,
		Manifest:      manifest,
	})
	if err != nil {
		t.Fatalf("ContentHash returned error: %v", err)
	}
	if hash == lying {
		t.Error("ContentHash used the claimed aggregate root instead of recomputing from the manifest")
	}
	if hash != computed {
		t.Errorf("ContentHash must recompute the root from the manifest, got %q want %q", hash, computed)
	}
}

// TestStore_ShortAggregateRootDoesNotPanic reproduces the remote-DoS finding
// against the real manager: before the fix, Store's eager "content_hash",
// contentHash[:16] log argument was evaluated regardless of log level, so a
// steward registering with a three-character aggregate_root crashed the
// controller process (no gRPC panic-recovery interceptor exists on the control
// plane).
func TestStore_ShortAggregateRootDoesNotPanic(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create storage manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	for _, root := range []string{"abc", "", "..", strings.Repeat("a", 15)} {
		dna := &commonpb.DNA{Id: "steward-1", AggregateRoot: root}
		if err := manager.Store(context.Background(), "steward-1", dna, nil); err != nil {
			t.Fatalf("Store failed for aggregate_root %q: %v", root, err)
		}
	}
}

// TestContentHash_FallsBackWithoutAggregateRoot verifies the deterministic
// fallback path used for DNA that has not been migrated to the fragment model.
func TestContentHash_FallsBackWithoutAggregateRoot(t *testing.T) {
	dna := &commonpb.DNA{
		Id:              "device-1",
		ConfigHash:      "cfg-hash",
		SyncFingerprint: "fp",
	}

	hash, err := ContentHash(dna)
	if err != nil {
		t.Fatalf("ContentHash returned error: %v", err)
	}
	if hash == "" {
		t.Fatal("ContentHash fallback must not return an empty string")
	}

	hash2, err := ContentHash(dna)
	if err != nil {
		t.Fatalf("ContentHash returned error: %v", err)
	}
	if hash != hash2 {
		t.Errorf("ContentHash fallback must be deterministic for identical input, got %q then %q", hash, hash2)
	}

	dna.ConfigHash = "different-cfg-hash"
	hash3, err := ContentHash(dna)
	if err != nil {
		t.Fatalf("ContentHash returned error: %v", err)
	}
	if hash3 == hash {
		t.Error("ContentHash fallback must change when ConfigHash changes")
	}
}

// TestDeduplication_UsesAggregateRoot proves Store()'s deduplication keys off
// AggregateRoot when present, not just the ID+ConfigHash+SyncFingerprint
// fallback: two DNA records with the same AggregateRoot but otherwise
// different identity fields must still dedup together.
func TestDeduplication_UsesAggregateRoot(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)
	config.EnableDeduplication = true

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create dedup-enabled manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	device1ID := "aggroot-device-001"
	device2ID := "aggroot-device-002"

	sharedRoot := validAggregateRoot("shared-aggregate-root")
	dna1 := &commonpb.DNA{
		Id:              "system-a",
		ConfigHash:      "config-hash-a",
		SyncFingerprint: "sync-fingerprint-a",
		AggregateRoot:   sharedRoot,
	}
	// Differs in every fallback-only field, but shares AggregateRoot.
	dna2 := &commonpb.DNA{
		Id:              "system-b",
		ConfigHash:      "config-hash-b",
		SyncFingerprint: "sync-fingerprint-b",
		AggregateRoot:   sharedRoot,
	}

	if err := manager.Store(ctx, device1ID, dna1, nil); err != nil {
		t.Fatalf("Failed to store DNA for device 1: %v", err)
	}
	if err := manager.Store(ctx, device2ID, dna2, nil); err != nil {
		t.Fatalf("Failed to store DNA for device 2: %v", err)
	}

	sqlBackend := manager.storage.(*SQLiteBackend)
	sqlBackend.mutex.RLock()
	var refCount int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_references WHERE device_id = ?`, device2ID,
	).Scan(&refCount); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to count dna_references for device2: %v", err)
	}
	sqlBackend.mutex.RUnlock()

	if refCount != 1 {
		t.Errorf("deduplication by AggregateRoot failed: expected device2 to have 1 row in "+
			"dna_references (content hash keyed off shared AggregateRoot), got %d", refCount)
	}
}

// TestStore_RetentionPolicyGoroutine verifies that Store's fire-and-forget
// enforceRetentionPolicy goroutine (storage.go line ~301) actually prunes records.
// The goroutine is called directly in this test to avoid timing races, which is safe
// because enforceRetentionPolicy is an exported-to-package method and the production
// go call remains unchanged.
func TestStore_RetentionPolicyGoroutine(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)
	config.MaxRecordsPerDevice = 2
	config.EnableDeduplication = false

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	const deviceID = "goroutine-prune-device"

	// Store 4 records — double the cap.
	for i := 1; i <= 4; i++ {
		dna := createTestDNA(t, deviceID, map[string]string{
			"version": fmt.Sprintf("v%d", i),
		})
		if err := manager.Store(ctx, deviceID, dna, nil); err != nil {
			t.Fatalf("Store v%d failed: %v", i, err)
		}
	}

	// Invoke the same method Store dispatches as a goroutine, but synchronously so
	// the test outcome is deterministic. This confirms the body does real pruning.
	manager.enforceRetentionPolicy(deviceID)

	history, err := manager.GetHistory(ctx, deviceID, &QueryOptions{IncludeData: true, Limit: 100})
	if err != nil {
		t.Fatalf("GetHistory after synchronous enforceRetentionPolicy failed: %v", err)
	}
	if len(history.Records) > config.MaxRecordsPerDevice {
		t.Errorf("expected <= %d records after enforceRetentionPolicy, got %d",
			config.MaxRecordsPerDevice, len(history.Records))
	}

	// Most recent record must survive.
	current, err := manager.GetCurrent(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetCurrent after enforceRetentionPolicy failed: %v", err)
	}
	if got := dnaAttrs(current.DNA)["version"]; got != "v4" {
		t.Errorf("expected most recent version v4 to survive pruning, got %q", got)
	}
}

func testStoreAndRetrieve(t *testing.T, manager *Manager) {
	ctx := context.Background()
	deviceID := "test-device-001"

	// Create test DNA
	dna := createTestDNA(t, deviceID, map[string]string{
		"os":           "linux",
		"arch":         "amd64",
		"hostname":     "test-host",
		"cpu_count":    "4",
		"memory_total": "8GB",
	})

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

	// Verify stored data
	if current.DeviceID != deviceID {
		t.Errorf("Expected device ID %s, got %s", deviceID, current.DeviceID)
	}

	if current.DNA.Id != dna.Id {
		t.Errorf("Expected DNA ID %s, got %s", dna.Id, current.DNA.Id)
	}

	storedAttrs := dnaAttrs(dna)
	currentAttrs := dnaAttrs(current.DNA)

	if len(currentAttrs) != len(storedAttrs) {
		t.Errorf("Expected %d attributes, got %d", len(storedAttrs), len(currentAttrs))
	}

	// Verify specific attributes
	for key, expectedValue := range storedAttrs {
		if actualValue, exists := currentAttrs[key]; !exists {
			t.Errorf("Missing attribute %s", key)
		} else if actualValue != expectedValue {
			t.Errorf("Expected attribute %s=%s, got %s", key, expectedValue, actualValue)
		}
	}
}

// testDeduplication creates its own manager with EnableDeduplication=true so that
// deduplication behavior is actually exercised. The shared manager passed as a
// parameter uses DefaultConfig (EnableDeduplication=false) and is intentionally
// ignored here; a dedicated manager is required so assertions are meaningful.
func testDeduplication(t *testing.T, _ *Manager) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)
	config.EnableDeduplication = true

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create dedup-enabled manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	device1ID := "device-001"
	device2ID := "device-002"

	// Create identical DNA objects so both devices share the same content hash.
	sharedDNAAttributes := map[string]string{
		"os":        "windows",
		"arch":      "amd64",
		"hostname":  "shared-config",
		"cpu_count": "8",
	}
	dna1 := attachTestFragment(t, &commonpb.DNA{
		Id:              "shared-system-id",
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "shared-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(sharedDNAAttributes)),
		SyncFingerprint: "shared-sync-fingerprint",
	}, sharedDNAAttributes)
	dna2 := attachTestFragment(t, &commonpb.DNA{
		Id:              "shared-system-id",
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "shared-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(sharedDNAAttributes)),
		SyncFingerprint: "shared-sync-fingerprint",
	}, sharedDNAAttributes)

	// Store device1 — full record lands in dna_history (no prior content exists).
	if err := manager.Store(ctx, device1ID, dna1, nil); err != nil {
		t.Fatalf("Failed to store DNA for device 1: %v", err)
	}

	// Store device2 with identical DNA — HasContent=true → storeReference path →
	// only a dna_references row is written (no full copy stored).
	if err := manager.Store(ctx, device2ID, dna2, nil); err != nil {
		t.Fatalf("Failed to store DNA for device 2: %v", err)
	}

	// Verify deduplication: device2 must have a row in dna_references (not dna_history).
	// This is the core deduplication invariant: identical DNA content must not be stored
	// as a second full copy.
	sqlBackend := manager.storage.(*SQLiteBackend)
	sqlBackend.mutex.RLock()
	var histCount int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_history WHERE device_id = ?`, device2ID,
	).Scan(&histCount); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to count dna_history for device2: %v", err)
	}
	var refCount int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_references WHERE device_id = ?`, device2ID,
	).Scan(&refCount); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to count dna_references for device2: %v", err)
	}
	sqlBackend.mutex.RUnlock()

	if histCount != 0 {
		t.Errorf("deduplication failed: device2 has %d row(s) in dna_history — "+
			"identical DNA content should be stored as a reference, not a full copy", histCount)
	}
	if refCount != 1 {
		t.Errorf("deduplication failed: expected device2 to have 1 row in dna_references, got %d", refCount)
	}

	// device1's record must remain accessible via GetCurrent (stored as full content in dna_history).
	current1, err := manager.GetCurrent(ctx, device1ID)
	if err != nil {
		t.Fatalf("Failed to get current DNA for device 1: %v", err)
	}
	if current1.DeviceID != device1ID {
		t.Errorf("expected device ID %s, got %s", device1ID, current1.DeviceID)
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

		dna := createTestDNA(t, deviceID, attributes)
		// Simulate time progression
		dna.LastUpdated = timestamppb.New(baseTime.Add(time.Duration(i) * time.Hour))

		err := manager.Store(ctx, deviceID, dna, nil)
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

	dna := createTestDNA(t, deviceID, largeAttributes)

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
	currentAttrs := dnaAttrs(current.DNA)
	for key, expectedValue := range largeAttributes {
		if actualValue, exists := currentAttrs[key]; !exists {
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

		dna := createTestDNA(t, deviceID, attributes)
		err := manager.Store(ctx, deviceID, dna, nil)
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

	dna := createTestDNA(t, "test-device", attributes)

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

	originalAttrs := dnaAttrs(dna)
	decompressedAttrs := dnaAttrs(decompressed)

	if len(decompressedAttrs) != len(originalAttrs) {
		t.Errorf("Decompressed attributes count mismatch: expected %d, got %d",
			len(originalAttrs), len(decompressedAttrs))
	}

	for key, expectedValue := range originalAttrs {
		if actualValue, exists := decompressedAttrs[key]; !exists {
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
	dna := createTestDNA(t, "backend-test-device", map[string]string{
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
		DeviceID: "backend-test-device",
		DNA:      dna,
		StoredAt: time.Now(),
		// A content hash is always a 64-character lowercase hex digest
		// (ContentHash guarantees the shape, and FileBackend rejects anything
		// else before interpolating it into a filesystem path).
		ContentHash:      validAggregateRoot("backend-test-device"),
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
		dna := createTestDNA(t, deviceID, map[string]string{
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
		dna := createTestDNA(t, deviceID, map[string]string{
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

// testFragmentID and testFragmentAuthority identify the single fragment that
// test fixtures use to carry their attribute set.
const (
	testFragmentID        = "host:test"
	testFragmentAuthority = "test"
)

// newTestFragment builds an ADR-017 fragment whose canonical state is attrs.
// DNA carries attributes as fragments since the flat DNA.Attributes map was
// removed (Issue #3331), so every fixture that used to set Attributes sets a
// fragment instead.
func newTestFragment(tb testing.TB, attrs map[string]string) *commonpb.Fragment {
	tb.Helper()

	state := make(sdna.MapState, len(attrs))
	for k, v := range attrs {
		state[k] = v
	}

	frag, err := sdna.NewFragment(testFragmentID, testFragmentAuthority, state)
	if err != nil {
		tb.Fatalf("sdna.NewFragment(%q) failed: %v", testFragmentID, err)
	}
	return frag
}

// attachTestFragment appends attrs to dna as a single fragment and returns dna.
// An empty attribute set attaches no fragment, matching the previous behaviour
// of an empty Attributes map: the flattened projection is empty either way.
func attachTestFragment(tb testing.TB, dna *commonpb.DNA, attrs map[string]string) *commonpb.DNA {
	tb.Helper()

	if len(attrs) == 0 {
		return dna
	}
	dna.Fragments = append(dna.Fragments, newTestFragment(tb, attrs))
	return dna
}

// dnaAttrs returns the flat attribute projection of a DNA's fragments — the
// read path that replaced DNA.Attributes (Issue #3331).
//
// This delegates to the same sdna.FlattenFragments that
// service.FlattenDNAFragments wraps. The service wrapper cannot be called from
// here: features/controller/service imports this package, so importing it back
// into these in-package tests would be an import cycle.
func dnaAttrs(dna *commonpb.DNA) map[string]string {
	return sdna.FlattenFragments(dna.GetFragments())
}

func createTestDNA(tb testing.TB, deviceID string, attributes map[string]string) *commonpb.DNA {
	tb.Helper()

	dna := &commonpb.DNA{
		Id:              deviceID,
		LastUpdated:     timestamppb.New(time.Now()),
		ConfigHash:      "test-config-hash",
		LastSyncTime:    timestamppb.New(time.Now()),
		AttributeCount:  int32(len(attributes)),
		SyncFingerprint: "test-sync-fingerprint",
	}
	return attachTestFragment(tb, dna, attributes)
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
		dnas[i] = createTestDNA(b, fmt.Sprintf("bench-device-%d", i), map[string]string{
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
		err := manager.Store(ctx, deviceID, dnas[i], nil)
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
		dna := createTestDNA(b, deviceID, map[string]string{
			"os":   "linux",
			"arch": "amd64",
			"seq":  fmt.Sprintf("%d", i),
		})

		err := manager.Store(ctx, deviceID, dna, nil)
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
	dna := createTestDNA(b, "bench-device", map[string]string{
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
