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
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	migratestorage "github.com/cfgis/cfgms/pkg/migrate/storage"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/testutil"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/database"
	_ "github.com/lib/pq" // Postgres driver for the truncation helper
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
	hmacKey := os.Getenv("CFGMS_TEST_SESSION_HMAC_KEY")
	if hmacKey == "" {
		hmacKey = "test-hmac-key-for-storage-migrate-tests-only"
	}
	mgr, err := interfaces.CreateClusterStorageManager(dsn, hmacKey, nil)
	if err != nil {
		t.Skipf("postgres test database not available: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })

	// The migrator's integrity check compares destination counts against source
	// counts, so it only holds against an empty destination. The test database is
	// shared across tests and across runs, and nothing here truncates it — these
	// tests were referenced by no Makefile target and no workflow (Issue #3402), so
	// they had only ever been run, if at all, against a pristine database. Truncate
	// after the manager has created its schema, so the tables exist to be emptied.
	truncateAllPostgresTables(t, dsn)
	return mgr
}

// truncateAllPostgresTables empties every base table in the test database.
//
// It deliberately does NOT filter on schemaname = 'public'. Postgres resolves
// unqualified names through search_path, which defaults to "$user", public — the
// test role is cfgms_test, so every table this suite creates lands in a cfgms_test
// schema and a public-only sweep silently matches nothing. Names are schema
// qualified below for the same reason. CASCADE handles the foreign keys between the
// tenant, RBAC and steward tables; RESTART IDENTITY resets sequences so IDs do not
// drift between runs.
func truncateAllPostgresTables(t *testing.T, dsn string) {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skipf("postgres test database not available for truncation: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows, err := db.Query(`
		SELECT schemaname, tablename FROM pg_tables
		WHERE schemaname NOT IN ('pg_catalog', 'information_schema')`)
	require.NoError(t, err, "listing test database tables")
	defer func() { _ = rows.Close() }()

	var tables []string
	for rows.Next() {
		var schema, name string
		require.NoError(t, rows.Scan(&schema, &name))
		// Identifiers come from pg_tables in a database this test controls, and are
		// quoted below; no caller-supplied input reaches this statement.
		tables = append(tables, fmt.Sprintf("%q.%q", schema, name))
	}
	require.NoError(t, rows.Err())
	if len(tables) == 0 {
		return
	}

	stmt := "TRUNCATE TABLE " + strings.Join(tables, ", ") + " RESTART IDENTITY CASCADE"
	_, err = db.Exec(stmt) // #nosec G202 -- identifiers read from pg_tables and quoted, not user input
	require.NoError(t, err, "truncating test database tables")
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

	// Phase 1: OSS → Postgres, with nothing skipped. Issue #3402 gave the database
	// provider a TriggerStore and a PushStore, so skipping those kinds is no longer
	// an acknowledged loss — checkDestinationCapability now rejects it outright as a
	// superfluous skip, which is what makes this call the real test of that change.
	m1 := migratestorage.NewStorageMigrator(src, pg)
	report1, err := m1.Run(ctx)
	require.NoError(t, err, "OSS→Postgres migration must succeed")

	assertMigrationCounts(t, report1.Counts, "OSS→Postgres")

	// Read the destination back independently. report1.Counts is always the
	// pre-filter source count (Run returns srcCounts), so asserting on it alone
	// would pass even if nothing had been written to Postgres. Planning with pg as
	// the SOURCE counts what Postgres actually holds.
	assertDestinationHolds(t, ctx, pg, report1.Counts, "Postgres after OSS→Postgres")

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
// report with at least one record. Only kinds that all tested backends support
// are listed here.
// assertDestinationHolds re-reads the destination and asserts it holds the same
// per-kind counts the source did. This is the assertion that would fail if import
// were silently broken: MigrationReport.Counts is the source-side count, so it
// cannot distinguish "migrated everything" from "wrote nothing".
//
// Planning with dst as the migrator SOURCE is the read-back — Plan exports without
// writing, so its counts describe what dst currently contains.
func assertDestinationHolds(t *testing.T, ctx context.Context, dst *interfaces.StorageManager, srcCounts map[string]int, label string) {
	t.Helper()
	probe := migratestorage.NewStorageMigrator(dst, newOSSManager(t))
	plan, err := probe.Plan(ctx)
	require.NoError(t, err, "%s: read-back plan must succeed", label)

	for kind, want := range srcCounts {
		got := plan.Counts[kind]
		assert.Equal(t, want, got,
			"%s: destination holds %d %q record(s), source had %d", label, got, kind, want)
	}
	// trigger and push are the kinds Issue #3402 added to the database provider —
	// name them explicitly so a regression that drops them cannot pass by absence.
	for _, kind := range []string{"trigger", "push"} {
		assert.Greater(t, plan.Counts[kind], 0,
			"%s: destination must hold at least one %q record — the store this issue added", label, kind)
	}
}

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
		"refresh_policy",
		"pending_refresh",
		"pending_registration",
	}
	for _, kind := range wantKinds {
		c, ok := counts[kind]
		assert.True(t, ok, "%s: expected kind %q in report", label, kind)
		assert.Greater(t, c, 0, "%s: expected at least one %q record", label, kind)
	}
}
