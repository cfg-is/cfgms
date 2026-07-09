// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"fmt"
	"testing"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestControllerRestart_DurableQueryPath verifies that a freshly-constructed Manager
// correctly serves GetHistory/GetCurrent for DNA records written by a previous process,
// and that Store assigns the next version without colliding or resetting to 1.
//
// Simulates a controller restart by closing a Manager and constructing a second one
// against the same DataDir, which is the exact sequence that happens on every restart.
func TestControllerRestart_DurableQueryPath(t *testing.T) {
	logger := logging.NewLogger("error")
	dataDir := t.TempDir()

	config := DefaultConfig()
	config.DataDir = dataDir

	const deviceID = "restart-test-device"
	ctx := context.Background()

	// Phase 1: write 3 versions and close (simulating a pre-restart controller).
	manager1, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create first manager: %v", err)
	}

	for i := 1; i <= 3; i++ {
		dna := createTestDNA(deviceID, map[string]string{
			"os":      "linux",
			"version": fmt.Sprintf("v%d", i),
		})
		if err := manager1.Store(ctx, deviceID, dna, nil); err != nil {
			t.Fatalf("Store v%d failed before restart: %v", i, err)
		}
	}

	if err := manager1.Close(); err != nil {
		t.Fatalf("failed to close first manager: %v", err)
	}

	// Phase 2: new Manager on the same DataDir — simulates a controller restart.
	// The in-memory indexer starts empty; only the durable SQLite store carries
	// the pre-restart records.
	manager2, err := NewManager(config, logger)
	if err != nil {
		t.Fatalf("failed to create second manager: %v", err)
	}
	t.Cleanup(func() {
		if err := manager2.Close(); err != nil {
			t.Errorf("second manager Close() failed: %v", err)
		}
	})

	t.Run("GetHistory returns pre-restart records", func(t *testing.T) {
		history, err := manager2.GetHistory(ctx, deviceID, &QueryOptions{
			IncludeData: true,
			Limit:       10,
		})
		if err != nil {
			t.Fatalf("GetHistory failed after restart: %v", err)
		}
		if got := len(history.Records); got != 3 {
			t.Fatalf("expected 3 records after restart, got %d", got)
		}
		if history.TotalCount != 3 {
			t.Errorf("expected TotalCount=3 after restart, got %d", history.TotalCount)
		}
		// Records must be version-descending (newest first).
		for i := 0; i+1 < len(history.Records); i++ {
			if history.Records[i].Version < history.Records[i+1].Version {
				t.Errorf("records not version-descending after restart: [%d].Version=%d < [%d].Version=%d",
					i, history.Records[i].Version, i+1, history.Records[i+1].Version)
			}
		}
	})

	t.Run("GetHistoryByDeviceID returns pre-restart records via Manager wrapper", func(t *testing.T) {
		// Exercises the Manager.GetHistoryByDeviceID wrapper (fleet_query.go),
		// which routes directly to SQLiteBackend and bypasses the in-memory index.
		// This is the path that returns correct results after a restart when the
		// index starts empty, and is distinct from GetHistory's index-backed path.
		records, total, err := manager2.GetHistoryByDeviceID(ctx, deviceID, &QueryOptions{
			IncludeData: true,
			Limit:       10,
		})
		if err != nil {
			t.Fatalf("GetHistoryByDeviceID failed after restart: %v", err)
		}
		if got := len(records); got != 3 {
			t.Fatalf("expected 3 records from GetHistoryByDeviceID, got %d", got)
		}
		if total != 3 {
			t.Errorf("expected total count=3 from GetHistoryByDeviceID, got %d", total)
		}
		// Records must be version-descending (newest first).
		for i := 0; i+1 < len(records); i++ {
			if records[i].Version < records[i+1].Version {
				t.Errorf("GetHistoryByDeviceID records not version-descending: [%d].Version=%d < [%d].Version=%d",
					i, records[i].Version, i+1, records[i+1].Version)
			}
		}
		if records[0].Version != 3 {
			t.Errorf("expected newest record version=3, got %d", records[0].Version)
		}
	})

	t.Run("GetCurrent returns latest pre-restart record", func(t *testing.T) {
		current, err := manager2.GetCurrent(ctx, deviceID)
		if err != nil {
			t.Fatalf("GetCurrent failed after restart: %v", err)
		}
		if current.Version != 3 {
			t.Errorf("expected current version=3 after restart, got %d", current.Version)
		}
		if current.DNA == nil {
			t.Fatal("expected non-nil DNA on current record")
		}
		if got := current.DNA.Attributes["version"]; got != "v3" {
			t.Errorf("expected version attribute=v3, got %q", got)
		}
	})

	t.Run("Store after restart increments version without collision or reset", func(t *testing.T) {
		dna := createTestDNA(deviceID, map[string]string{
			"os":      "linux",
			"version": "v4",
		})
		if err := manager2.Store(ctx, deviceID, dna, nil); err != nil {
			t.Fatalf("Store after restart failed: %v", err)
		}

		current, err := manager2.GetCurrent(ctx, deviceID)
		if err != nil {
			t.Fatalf("GetCurrent after post-restart Store failed: %v", err)
		}
		// Must be 4, not 1 (reset) or collide with an existing version.
		if current.Version != 4 {
			t.Errorf("expected version=4 after post-restart Store, got %d (reset or collision)",
				current.Version)
		}
		if got := current.DNA.Attributes["version"]; got != "v4" {
			t.Errorf("expected version attribute=v4 on post-restart record, got %q", got)
		}
	})
}
