// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package storage tests the SQLite schema migration runner.

package storage

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// openMigrationTestDB opens an empty SQLite database at a temp path using the
// same driver the production backend uses.
func openMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "dna.db")
	db, err := sql.Open("sqlite", "file:"+dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// readDeviceTenants returns the full device_tenant table as a map.
func readDeviceTenants(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	rows, err := db.Query(`SELECT device_id, tenant_id FROM device_tenant`)
	require.NoError(t, err)
	defer rows.Close() //nolint:errcheck // rows.Close() error is non-actionable after row iteration completes

	got := make(map[string]string)
	for rows.Next() {
		var deviceID, tenantID string
		require.NoError(t, rows.Scan(&deviceID, &tenantID))
		got[deviceID] = tenantID
	}
	require.NoError(t, rows.Err())
	return got
}

// insertDNAHistoryRow writes one dna_history row with an explicit version and tenant.
func insertDNAHistoryRow(t *testing.T, db *sql.DB, deviceID string, version int, tenantID string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO dna_history
			(device_id, version, dna_json, content_hash, original_size, compressed_size, compression_ratio, tenant_id)
		VALUES (?, ?, '{}', ?, 0, 0, 1.0, ?)`,
		deviceID, version, deviceID+"-hash-"+tenantID, tenantID)
	require.NoError(t, err)
}

// TestMigration_DeviceTenantSeedUsesLatestVersion pins the seeding rule for the
// device_tenant migration (Issue #3324). dna_history keeps one row per DNA
// version, each stamped with the tenant that owned the device when it was
// written, so a device that has been moved between tenants has rows for both.
// The seed must take the tenant from the LATEST version: seeding an older row
// would hand the now-authoritative mapping a former tenant and serve that
// device another tenant's configuration.
func TestMigration_DeviceTenantSeedUsesLatestVersion(t *testing.T) {
	db := openMigrationTestDB(t)
	migrator := NewSQLiteMigrator(db, logging.NewNoopLogger())

	require.NoError(t, migrator.InitializeSchema())

	// Simulate a database created before this migration: the tenant exists only
	// on dna_history rows, with no device_tenant table.
	_, err := db.Exec(`DROP TABLE IF EXISTS device_tenant`)
	require.NoError(t, err)

	// dev-moved was registered under tenant-a and later moved to tenant-b, so the
	// older (lower rowid) row names the former tenant.
	insertDNAHistoryRow(t, db, "dev-moved", 1, "tenant-a")
	insertDNAHistoryRow(t, db, "dev-moved", 2, "tenant-b")
	// dev-stable never moved.
	insertDNAHistoryRow(t, db, "dev-stable", 1, "tenant-c")
	insertDNAHistoryRow(t, db, "dev-stable", 2, "tenant-c")
	// dev-notenant has no tenant recorded at all and must not be seeded: an empty
	// tenant mapping is worse than no mapping, which resolves as "tenant unknown".
	insertDNAHistoryRow(t, db, "dev-notenant", 1, "")

	require.NoError(t, migrator.ApplyMigrations())
	require.NoError(t, migrator.ValidateSchema())

	got := readDeviceTenants(t, db)
	assert.Equal(t, "tenant-b", got["dev-moved"],
		"seed must take the tenant from the latest DNA version, not the oldest row")
	assert.Equal(t, "tenant-c", got["dev-stable"])
	assert.NotContains(t, got, "dev-notenant",
		"devices with no recorded tenant must be left unmapped")
	assert.Len(t, got, 2)
}

// TestMigration_DeviceTenantSeedUsesLatestTenantedVersion covers a device whose
// latest DNA row carries no tenant while an older row does. A blank tenant_id is
// a write-path artifact (the DNA was stored while the registry had no tenant for
// the device), never a de-tenanting — devices are not moved to "no tenant". The
// most recent row that does name a tenant is therefore the best available
// evidence, and seeding a blank tenant would instead assert that the device
// belongs to none (Issue #3324).
func TestMigration_DeviceTenantSeedUsesLatestTenantedVersion(t *testing.T) {
	db := openMigrationTestDB(t)
	migrator := NewSQLiteMigrator(db, logging.NewNoopLogger())

	require.NoError(t, migrator.InitializeSchema())
	_, err := db.Exec(`DROP TABLE IF EXISTS device_tenant`)
	require.NoError(t, err)

	insertDNAHistoryRow(t, db, "dev-blank-latest", 1, "tenant-a")
	insertDNAHistoryRow(t, db, "dev-blank-latest", 2, "")

	require.NoError(t, migrator.ApplyMigrations())

	got := readDeviceTenants(t, db)
	assert.Equal(t, "tenant-a", got["dev-blank-latest"],
		"seed must fall back to the most recent row that names a tenant, never to a blank one")
}

// TestMigration_DeviceTenantIsIdempotent verifies that re-running the migrator
// against an already-migrated database neither fails nor overwrites mappings
// that have since been updated (e.g. by a tenant move after the migration ran).
func TestMigration_DeviceTenantIsIdempotent(t *testing.T) {
	db := openMigrationTestDB(t)
	migrator := NewSQLiteMigrator(db, logging.NewNoopLogger())

	require.NoError(t, migrator.InitializeSchema())
	insertDNAHistoryRow(t, db, "dev-1", 1, "tenant-a")
	require.NoError(t, migrator.ApplyMigrations())

	// A tenant move after the migration rewrites the mapping.
	_, err := db.Exec(`UPDATE device_tenant SET tenant_id = ? WHERE device_id = ?`, "tenant-b", "dev-1")
	require.NoError(t, err)

	// Re-running migrations must not re-seed the stale dna_history tenant.
	require.NoError(t, migrator.ApplyMigrations())

	version, err := migrator.GetCurrentVersion()
	require.NoError(t, err)
	assert.Equal(t, 2, version)

	got := readDeviceTenants(t, db)
	assert.Equal(t, "tenant-b", got["dev-1"],
		"re-running migrations must not revert a mapping updated by a tenant move")
}
