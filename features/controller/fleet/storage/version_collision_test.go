// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package storage

import (
	"context"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestSQLiteBackend_DuplicateVersionUpserts reproduces the DNA-persist regression
// where two DNA snapshots for the same device land on the same (device_id, version).
// GetNextVersion (MAX(version)+1) is computed outside the backend insert lock, so a
// concurrent/duplicate publish — e.g. the heartbeat path and the ring-subscription
// store path both firing on reconnect — assigns the same version to two snapshots.
// The plain INSERT then failed with
//
//	UNIQUE constraint failed: dna_history.device_id, dna_history.version
//
// which crashed the DNA persist ("Failed to persist DNA to fleet storage") and churned
// the steward control channel fleet-wide. StoreRecord must be idempotent on
// (device_id, version): upsert the latest snapshot rather than erroring.
func TestSQLiteBackend_DuplicateVersionUpserts(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)

	backend, err := NewBackend(BackendSQLite, config, logger)
	if err != nil {
		t.Fatalf("failed to create sqlite backend: %v", err)
	}
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	const device = "collision-device"

	mk := func(hash string) *DNARecord {
		return &DNARecord{
			DeviceID:         device,
			DNA:              createTestDNA(t, device, map[string]string{"os": "linux", "hostname": "h-" + hash}),
			StoredAt:         time.Now(),
			ContentHash:      hash,
			CompressedSize:   100,
			OriginalSize:     200,
			CompressionRatio: 0.5,
			Version:          1, // identical version — the racing/duplicate publish
			ShardID:          "default",
		}
	}

	if err := backend.StoreRecord(ctx, mk("hash-A"), []byte("A")); err != nil {
		t.Fatalf("first store failed: %v", err)
	}

	// Second snapshot lands on the same (device_id, version). Before the fix this
	// returned the UNIQUE constraint violation that crashed the live fleet.
	if err := backend.StoreRecord(ctx, mk("hash-B"), []byte("B")); err != nil {
		t.Fatalf("duplicate (device_id, version) must upsert, not error: %v", err)
	}

	// Upsert semantics: the latest snapshot wins; the row now carries hash-B, and the
	// superseded hash-A row must be gone (one row per (device_id, version)).
	if _, err := backend.GetRecord(ctx, "hash-B", "default"); err != nil {
		t.Fatalf("record with latest content hash-B not found after upsert: %v", err)
	}
	if _, err := backend.GetRecord(ctx, "hash-A", "default"); err == nil {
		t.Fatalf("superseded hash-A row still present — upsert should have replaced it")
	}
}

// TestSQLiteBackend_DuplicateReferenceVersionUpserts covers the deduplication path:
// dna_references carries the same UNIQUE(device_id, version) constraint, and
// Manager.Store takes the storeReference branch when a republished snapshot's content
// already exists — the likely collision path on reconnect double-fires (identical DNA
// = dedup hit). StoreReference must be idempotent on (device_id, version) too.
func TestSQLiteBackend_DuplicateReferenceVersionUpserts(t *testing.T) {
	logger := logging.NewLogger("error")
	config := createTestConfig(t, BackendSQLite)

	backend, err := NewBackend(BackendSQLite, config, logger)
	if err != nil {
		t.Fatalf("failed to create sqlite backend: %v", err)
	}
	defer func() { _ = backend.Close() }()

	ctx := context.Background()
	const device = "collision-ref-device"

	ref := func(hash string) *DNARecord {
		return &DNARecord{
			DeviceID:    device,
			DNA:         createTestDNA(t, device, map[string]string{"os": "linux"}),
			StoredAt:    time.Now(),
			ContentHash: hash,
			Version:     1, // identical version — the racing/duplicate dedup publish
			ShardID:     "default",
		}
	}

	if err := backend.StoreReference(ctx, ref("ref-hash-A")); err != nil {
		t.Fatalf("first StoreReference failed: %v", err)
	}
	// Second reference lands on the same (device_id, version). Before the fix this
	// returned "UNIQUE constraint failed: dna_references.device_id, dna_references.version".
	if err := backend.StoreReference(ctx, ref("ref-hash-B")); err != nil {
		t.Fatalf("duplicate (device_id, version) reference must upsert, not error: %v", err)
	}
}
