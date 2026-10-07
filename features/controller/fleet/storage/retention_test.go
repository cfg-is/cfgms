// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestRetention_MaxRecordsPerDevice verifies that enforceRetentionPolicy prunes
// a device's dna_history rows beyond MaxRecordsPerDevice, keeping the newest N by
// version, and that GetCurrent returns the most recent record after pruning.
func TestRetention_MaxRecordsPerDevice(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)
	config.MaxRecordsPerDevice = 3
	config.EnableDeduplication = false

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	const deviceID = "retention-count-device"

	// Insert 5 records directly via SQLiteBackend with distinct version numbers to
	// avoid races with the goroutine that Store fires after every write.
	sqlBackend := manager.storage.(*SQLiteBackend)
	for i := 1; i <= 5; i++ {
		dna := createTestDNA(t, deviceID, map[string]string{
			"os":      "linux",
			"version": fmt.Sprintf("v%d", i),
		})
		rec := &DNARecord{
			DeviceID:         deviceID,
			DNA:              dna,
			StoredAt:         time.Now(),
			ContentHash:      fmt.Sprintf("count-hash-%d", i),
			CompressedSize:   100,
			OriginalSize:     200,
			CompressionRatio: 0.5,
			Version:          int64(i),
			ShardID:          "default",
		}
		if err := sqlBackend.StoreRecord(ctx, rec, []byte("compressed")); err != nil {
			t.Fatalf("StoreRecord v%d failed: %v", i, err)
		}
	}

	// Call enforceRetentionPolicy synchronously. Production Store fires it as a goroutine;
	// calling it directly here avoids timing races in tests without removing the go call.
	manager.enforceRetentionPolicy(deviceID)

	// Confirm count is now at the cap.
	history, err := manager.GetHistory(ctx, deviceID, &QueryOptions{IncludeData: true, Limit: 100})
	if err != nil {
		t.Fatalf("GetHistory after prune failed: %v", err)
	}
	if len(history.Records) != config.MaxRecordsPerDevice {
		t.Errorf("expected %d records after pruning, got %d", config.MaxRecordsPerDevice, len(history.Records))
	}

	// Most recent record must still be queryable.
	current, err := manager.GetCurrent(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetCurrent after prune failed: %v", err)
	}
	if got := dnaAttrs(current.DNA)["version"]; got != "v5" {
		t.Errorf("expected newest version v5 after prune, got %q", got)
	}

	// Oldest versions (1, 2) must have been pruned; newest (3, 4, 5) kept.
	for _, rec := range history.Records {
		if rec.Version < 3 {
			t.Errorf("expected only versions >= 3 to be kept, found version %d in results", rec.Version)
		}
	}
}

// TestRetention_AgeBasedPruning verifies that enforceRetentionPolicy prunes
// dna_history rows older than RetentionPeriod while leaving recent records intact.
func TestRetention_AgeBasedPruning(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)
	// Retention window of 30 minutes. The two "old" records are backdated 1h (well
	// before the cutoff, so prunable); the "recent" record is stored at time.Now()
	// (well after the cutoff, so retained). The 30-minute margin is intentional: the
	// cutoff is computed as time.Now()-RetentionPeriod at prune time, which is a few
	// microseconds-to-milliseconds after the recent record's stored-at timestamp. A
	// tight window (e.g. 50ms) would let ordinary scheduling/DB-query latency between
	// storing the recent record and computing the cutoff push the recent record's
	// timestamp before the cutoff, pruning it too — a wall-clock race. The wide margin
	// makes the old-vs-recent discrimination deterministic without altering behavior.
	config.RetentionPeriod = 30 * time.Minute
	config.MaxRecordsPerDevice = 0 // disable count cap — only age applies
	config.EnableDeduplication = false

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	const deviceID = "retention-age-device"

	// Insert two "old" records directly via SQLiteBackend with backdated timestamps,
	// bypassing Manager.Store (which always uses time.Now()).
	sqlBackend := manager.storage.(*SQLiteBackend)
	oldTime := time.Now().Add(-1 * time.Hour)

	for i := 1; i <= 2; i++ {
		dna := createTestDNA(t, deviceID, map[string]string{
			"os":      "linux",
			"version": fmt.Sprintf("old-v%d", i),
		})
		rec := &DNARecord{
			DeviceID:         deviceID,
			DNA:              dna,
			StoredAt:         oldTime,
			ContentHash:      fmt.Sprintf("old-hash-%d", i),
			CompressedSize:   100,
			OriginalSize:     200,
			CompressionRatio: 0.5,
			Version:          int64(i),
			ShardID:          "default",
		}
		if err := sqlBackend.StoreRecord(ctx, rec, []byte("compressed")); err != nil {
			t.Fatalf("StoreRecord old v%d failed: %v", i, err)
		}
	}

	// Insert recent record directly via SQLiteBackend for the same reason the old records
	// were inserted directly: manager.Store fires go m.enforceRetentionPolicy(deviceID)
	// after every write, and that goroutine is immediately eligible to prune the two
	// backdated records (stored at -1h, cutoff at -30m) before the pre-prune count
	// assertion at line 145 runs. Bypassing manager.Store keeps the goroutine out of
	// the picture entirely and makes the pre-prune count deterministic.
	recentDNA := createTestDNA(t, deviceID, map[string]string{
		"os":      "linux",
		"version": "recent-v3",
	})
	recentRec := &DNARecord{
		DeviceID:         deviceID,
		DNA:              recentDNA,
		StoredAt:         time.Now(),
		ContentHash:      "recent-hash-3",
		CompressedSize:   100,
		OriginalSize:     200,
		CompressionRatio: 0.5,
		Version:          3,
		ShardID:          "default",
	}
	if err := sqlBackend.StoreRecord(ctx, recentRec, []byte("compressed")); err != nil {
		t.Fatalf("StoreRecord recent v3 failed: %v", err)
	}

	// Confirm 3 records exist before pruning.
	history, err := manager.GetHistory(ctx, deviceID, &QueryOptions{IncludeData: true, Limit: 100})
	if err != nil {
		t.Fatalf("GetHistory before age prune failed: %v", err)
	}
	if len(history.Records) != 3 {
		t.Fatalf("expected 3 records before age pruning, got %d", len(history.Records))
	}

	// Run pruning. cutoff = now - 30m, so old records (1h ago) are pruned while the
	// recent record (stored at now) is safely retained.
	manager.enforceRetentionPolicy(deviceID)

	// Old records must be gone; recent record must remain.
	history, err = manager.GetHistory(ctx, deviceID, &QueryOptions{IncludeData: true, Limit: 100})
	if err != nil {
		t.Fatalf("GetHistory after age prune failed: %v", err)
	}
	if len(history.Records) != 1 {
		t.Errorf("expected 1 record after age pruning, got %d", len(history.Records))
	}
	if len(history.Records) > 0 {
		if got := dnaAttrs(history.Records[0].DNA)["version"]; got != "recent-v3" {
			t.Errorf("expected remaining record to be recent-v3, got %q", got)
		}
	}

	// GetCurrent must still return the recent record.
	current, err := manager.GetCurrent(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetCurrent after age prune failed: %v", err)
	}
	if got := dnaAttrs(current.DNA)["version"]; got != "recent-v3" {
		t.Errorf("expected GetCurrent to return recent-v3, got %q", got)
	}
}

// TestRetention_DedupSafeAlgorithm verifies the core dedup-safety invariant:
// a dna_history row must NOT be deleted while any live dna_references row from
// another device still points at its content_hash.
//
// Scenario:
//   - device A's dna_history row owns content_hash H (written via StoreRecord).
//   - device B has only a dna_references row pointing at H (written via StoreReference,
//     which is what Manager.Store takes when EnableDeduplication=true and HasContent=true).
//   - Both rows have timestamps old enough to exceed the age cutoff.
//   - PruneDevice(deviceA, ...) must NOT delete device A's dna_history row because
//     device B's reference is still live.
//   - Only after PruneDevice(deviceB, ...) removes B's reference is A's history row
//     eligible for deletion on the next PruneDevice(deviceA, ...) call.
func TestRetention_DedupSafeAlgorithm(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)

	manager, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	const deviceA = "dedup-device-a"
	const deviceB = "dedup-device-b"
	const sharedHash = "shared-content-hash-dedup-test-abc123"

	// All rows are 1 hour old — well beyond any reasonable retention cutoff.
	oldTime := time.Now().Add(-1 * time.Hour)
	// Cutoff: prune anything older than 30 minutes.
	cutoff := time.Now().Add(-30 * time.Minute)

	sqlBackend := manager.storage.(*SQLiteBackend)

	// Device A stores its DNA — creates a dna_history row.
	recA := &DNARecord{
		DeviceID:         deviceA,
		DNA:              createTestDNA(t, deviceA, map[string]string{"version": "shared-v1"}),
		StoredAt:         oldTime,
		ContentHash:      sharedHash,
		CompressedSize:   100,
		OriginalSize:     200,
		CompressionRatio: 0.5,
		Version:          1,
		ShardID:          "default",
	}
	if err := sqlBackend.StoreRecord(ctx, recA, []byte("compressed")); err != nil {
		t.Fatalf("StoreRecord deviceA failed: %v", err)
	}

	// Device B deduplicates onto A's content — creates only a dna_references row.
	refB := &DNARecord{
		DeviceID:    deviceB,
		ContentHash: sharedHash,
		Version:     1,
		StoredAt:    oldTime,
		ShardID:     "default",
	}
	if err := sqlBackend.StoreReference(ctx, refB); err != nil {
		t.Fatalf("StoreReference deviceB failed: %v", err)
	}

	// Prune device A with age cutoff. Device A's version 1 is old, BUT device B's
	// dna_references row still points at its content_hash — must NOT be deleted.
	deleted, err := sqlBackend.PruneDevice(ctx, deviceA, 0, cutoff)
	if err != nil {
		t.Fatalf("PruneDevice deviceA (first pass) failed: %v", err)
	}
	if deleted != 0 {
		t.Errorf("expected 0 rows deleted (protected by B's live reference), got %d", deleted)
	}

	// Verify device A's dna_history row still exists.
	sqlBackend.mutex.RLock()
	var histCount int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_history WHERE device_id = ? AND version = 1`, deviceA,
	).Scan(&histCount); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to check dna_history for deviceA version 1: %v", err)
	}
	sqlBackend.mutex.RUnlock()
	if histCount == 0 {
		t.Error("DEDUP-SAFETY VIOLATION: dna_history row for deviceA was deleted " +
			"while deviceB's dna_references row still points at its content_hash")
	}

	// Verify device B's reference row is still intact.
	sqlBackend.mutex.RLock()
	var bRefCount int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_references WHERE device_id = ?`, deviceB,
	).Scan(&bRefCount); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to count deviceB refs before B prune: %v", err)
	}
	sqlBackend.mutex.RUnlock()
	if bRefCount == 0 {
		t.Fatal("deviceB dna_references row was incorrectly deleted during deviceA prune pass")
	}

	// GetCurrent for device B must still resolve (content is accessible via GetRecord).
	rec, err := sqlBackend.GetRecord(ctx, sharedHash, "default")
	if err != nil {
		t.Fatalf("GetRecord for shared content_hash failed after pruning A: %v", err)
	}
	if rec.DNA == nil {
		t.Error("GetRecord returned nil DNA for shared content after pruning A")
	}

	// Now prune device B — this releases B's reference to A's shared content.
	deleted, err = sqlBackend.PruneDevice(ctx, deviceB, 0, cutoff)
	if err != nil {
		t.Fatalf("PruneDevice deviceB failed: %v", err)
	}
	if deleted == 0 {
		t.Error("expected PruneDevice(deviceB) to delete B's reference row, got 0 deleted")
	}

	sqlBackend.mutex.RLock()
	var bRefAfter int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_references WHERE device_id = ?`, deviceB,
	).Scan(&bRefAfter); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to count deviceB refs after B prune: %v", err)
	}
	sqlBackend.mutex.RUnlock()
	if bRefAfter != 0 {
		t.Errorf("expected deviceB dna_references to be empty after pruning B, got %d", bRefAfter)
	}

	// Now prune device A again — with no live references remaining, device A's
	// version 1 dna_history row is now safe to delete.
	deleted, err = sqlBackend.PruneDevice(ctx, deviceA, 0, cutoff)
	if err != nil {
		t.Fatalf("PruneDevice deviceA (second pass) failed: %v", err)
	}
	if deleted == 0 {
		t.Error("expected PruneDevice(deviceA) second pass to delete the now-orphaned dna_history row")
	}

	sqlBackend.mutex.RLock()
	var histAfter int
	if err := sqlBackend.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM dna_history WHERE device_id = ? AND version = 1`, deviceA,
	).Scan(&histAfter); err != nil {
		sqlBackend.mutex.RUnlock()
		t.Fatalf("failed to count deviceA v1 after second prune: %v", err)
	}
	sqlBackend.mutex.RUnlock()
	if histAfter != 0 {
		t.Errorf("expected deviceA version 1 dna_history row deleted after all references pruned, got count=%d", histAfter)
	}
}

// TestRetention_GlobalSweep verifies that enforceGlobalRetentionPolicy sweeps all
// devices and prunes records that exceed the retention bounds.
func TestRetention_GlobalSweep(t *testing.T) {
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

	devices := []string{"global-device-1", "global-device-2", "global-device-3"}
	for _, deviceID := range devices {
		for i := 1; i <= 4; i++ {
			dna := createTestDNA(t, deviceID, map[string]string{
				"device":  deviceID,
				"version": fmt.Sprintf("v%d", i),
			})
			if err := manager.Store(ctx, deviceID, dna, nil); err != nil {
				t.Fatalf("Store %s v%d failed: %v", deviceID, i, err)
			}
		}
	}

	// Run global sweep (calls enforceGlobalRetentionPolicy internally).
	if err := manager.enforceGlobalRetentionPolicy(); err != nil {
		t.Fatalf("enforceGlobalRetentionPolicy failed: %v", err)
	}

	// Each device should now have at most MaxRecordsPerDevice records.
	for _, deviceID := range devices {
		history, err := manager.GetHistory(ctx, deviceID, &QueryOptions{IncludeData: true, Limit: 100})
		if err != nil {
			t.Fatalf("GetHistory for %s after global sweep failed: %v", deviceID, err)
		}
		if len(history.Records) > config.MaxRecordsPerDevice {
			t.Errorf("device %s: expected <= %d records after global sweep, got %d",
				deviceID, config.MaxRecordsPerDevice, len(history.Records))
		}
		// Newest record must still be accessible.
		current, err := manager.GetCurrent(ctx, deviceID)
		if err != nil {
			t.Fatalf("GetCurrent for %s after global sweep failed: %v", deviceID, err)
		}
		if got := dnaAttrs(current.DNA)["version"]; got != "v4" {
			t.Errorf("device %s: expected newest version v4, got %q", deviceID, got)
		}
	}
}
