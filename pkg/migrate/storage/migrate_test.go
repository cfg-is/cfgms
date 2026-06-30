//go:build integration

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage_test contains integration tests for the storage migrator.
//
// Prerequisites:
//
//	docker compose --profile database -f docker-compose.test.yml up -d postgres-test
//
// Run with:
//
//	go test -tags integration ./pkg/migrate/storage/...
package storage_test

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	migratestorage "github.com/cfgis/cfgms/pkg/migrate/storage"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
)

// buildTestDSN builds the Postgres DSN for the test database.
func buildTestDSN() string {
	password := testutil.GetTestDBPassword()
	port := 5432
	if portStr := os.Getenv("CFGMS_TEST_DB_PORT"); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			port = p
		}
	}
	return fmt.Sprintf("host=localhost port=%d dbname=cfgms_test user=cfgms_test password=%s sslmode=disable", port, password)
}

// newDatabaseManager creates a StorageManager backed by the test Postgres database.
// It skips the test when the database is unavailable.
func newDatabaseManager(t *testing.T) *interfaces.StorageManager {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping database test in short mode")
	}
	dsn := buildTestDSN()
	mgr, err := interfaces.CreateClusterStorageManager(dsn, nil)
	if err != nil {
		t.Skipf("postgres test database not available: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// TestStorageMigrate_FlatfileToDatabaseRoundTrip exercises the complete round-trip:
//
//  1. Seed an OSS source with one record per store kind.
//  2. Migrate OSS → Postgres (database provider).
//  3. Migrate Postgres → fresh OSS target.
//  4. Assert record counts equal the source in both directions.
func TestStorageMigrate_FlatfileToDatabaseRoundTrip(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)

	pg := newDatabaseManager(t)
	dst := newOSSManager(t)

	// Phase 1: OSS → Postgres
	m1 := migratestorage.NewStorageMigrator(src, pg)
	report1, err := m1.Run(ctx)
	require.NoError(t, err, "OSS→Postgres migration must succeed")

	assertMigrationCounts(t, report1.Counts, "OSS→Postgres")

	// Phase 2: Postgres → OSS
	m2 := migratestorage.NewStorageMigrator(pg, dst)
	report2, err := m2.Run(ctx)
	require.NoError(t, err, "Postgres→OSS migration must succeed")

	assertMigrationCounts(t, report2.Counts, "Postgres→OSS")

	// Both directions must produce identical per-kind counts.
	for kind, c1 := range report1.Counts {
		c2, ok := report2.Counts[kind]
		assert.True(t, ok, "Postgres→OSS report must include kind %q", kind)
		assert.Equal(t, c1, c2, "count mismatch for kind %q between OSS→DB and DB→OSS", kind)
	}
}

// TestStorageMigrate_DatabaseIdempotent verifies that running the Postgres
// migration twice produces identical counts and no duplicate records.
func TestStorageMigrate_DatabaseIdempotent(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	pg := newDatabaseManager(t)

	m := migratestorage.NewStorageMigrator(src, pg)

	report1, err := m.Run(ctx)
	require.NoError(t, err, "first run must succeed")

	report2, err := m.Run(ctx)
	require.NoError(t, err, "second run must succeed (idempotent)")

	for kind, c1 := range report1.Counts {
		c2, ok := report2.Counts[kind]
		assert.True(t, ok, "second run must include kind %q", kind)
		assert.Equal(t, c1, c2, "second run count for kind %q must match first run", kind)
	}
}

// TestStorageMigrate_DatabasePlan verifies that Plan reports counts without
// writing to Postgres.
func TestStorageMigrate_DatabasePlan(t *testing.T) {
	ctx := context.Background()

	src := newOSSManager(t)
	seedOSSManager(t, src)
	pg := newDatabaseManager(t)

	m := migratestorage.NewStorageMigrator(src, pg)
	plan, err := m.Plan(ctx)
	require.NoError(t, err, "Plan must succeed")
	require.NotEmpty(t, plan.Counts, "Plan must report non-zero counts")

	// After Plan, Postgres target must still be empty.
	m2 := migratestorage.NewStorageMigrator(pg, newOSSManager(t))
	planAfter, err := m2.Plan(ctx)
	require.NoError(t, err, "second Plan must succeed")
	total := 0
	for _, c := range planAfter.Counts {
		total += c
	}
	assert.Equal(t, 0, total, "Postgres target must be empty after Plan (no writes)")
}

// assertMigrationCounts checks that all expected store kinds appear in the
// report with at least one record.
func assertMigrationCounts(t *testing.T, counts map[string]int, label string) {
	t.Helper()
	wantKinds := []string{
		"tenant",
		"config",
		"audit",
		"registration_token",
		"session",
		"steward",
		"command",
		"trigger",
		"push",
		"ip_trust",
	}
	for _, kind := range wantKinds {
		c, ok := counts[kind]
		assert.True(t, ok, "%s: expected kind %q in report", label, kind)
		assert.Greater(t, c, 0, "%s: expected at least one %q record", label, kind)
	}
}
