// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite" // driver for the raw sqlite_master inspection below

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	"github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// TestInit verifies that a blank import registers the "sqlite" provider.
func TestInit(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	require.NotNil(t, p)
	assert.Equal(t, "sqlite", p.Name())
}

// TestAvailable_DefaultProvider verifies the default registered provider (no path) is available.
func TestAvailable_DefaultProvider(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	avail, err := p.Available()
	assert.True(t, avail)
	assert.NoError(t, err)
}

// TestAvailable_WritableDir returns true for a writable temporary directory.
func TestAvailable_WritableDir(t *testing.T) {
	dir := t.TempDir()
	p := sqlite.NewSQLiteProvider(dir)
	avail, err := p.Available()
	assert.True(t, avail)
	assert.NoError(t, err)
}

// TestAvailable_NonExistentPath returns false for a path that does not exist.
func TestAvailable_NonExistentPath(t *testing.T) {
	p := sqlite.NewSQLiteProvider("/nonexistent/path/that/does/not/exist")
	avail, err := p.Available()
	assert.False(t, avail)
	assert.Error(t, err)
}

// TestAvailable_InMemory always returns true for in-memory databases.
func TestAvailable_InMemory(t *testing.T) {
	p := sqlite.NewSQLiteProvider(":memory:")
	avail, err := p.Available()
	assert.True(t, avail)
	assert.NoError(t, err)
}

// TestAvailable_NonWritableDir returns false for a non-writable directory.
func TestAvailable_NonWritableDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("os.Chmod does not enforce POSIX directory permissions on Windows")
	}
	if os.Getuid() == 0 {
		t.Skip("skipping non-writable dir test when running as root")
	}
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o500)) // read+execute only
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	p := sqlite.NewSQLiteProvider(dir)
	avail, err := p.Available()
	assert.False(t, avail)
	assert.Error(t, err)
}

// TestGetCapabilities verifies capabilities are sensible.
func TestGetCapabilities(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	caps := p.GetCapabilities()
	assert.True(t, caps.SupportsTransactions)
	assert.Greater(t, caps.MaxBatchSize, 0)
}

// TestCreateConfigStore_NotSupported verifies config store is not supported.
func TestCreateConfigStore_NotSupported(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	_, err = p.CreateConfigStore(map[string]interface{}{})
	assert.ErrorIs(t, err, business.ErrNotSupported)
}

// TestCreateTenantStore_InMemory verifies tenant store can be created.
func TestCreateTenantStore_InMemory(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := p.CreateTenantStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	require.NotNil(t, store)
	t.Cleanup(func() { _ = store.Close() })
}

// TestCreateSessionStore_InMemory verifies session store can be created.
func TestCreateSessionStore_InMemory(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := p.CreateSessionStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	require.NotNil(t, store)
	t.Cleanup(func() { _ = store.Close() })
}

// TestCreateAuditStore_FileDB verifies audit store with a file-based SQLite DB.
func TestCreateAuditStore_FileDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_audit.db")

	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := p.CreateAuditStore(map[string]interface{}{"path": dbPath})
	require.NoError(t, err)
	require.NotNil(t, store)
	t.Cleanup(func() { _ = store.Close() })
}

// TestSQLiteProvider_ClusterCapable_False verifies SQLite is not cluster-capable.
func TestSQLiteProvider_ClusterCapable_False(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	assert.False(t, p.ClusterCapable(), "SQLiteProvider must not be cluster-capable (single-file DB cannot serve as shared state across controller nodes)")
}

// TestSQLiteSchema_NoClientTenantTables verifies that a fresh store, opened with
// the provider's real schema, creates neither the client_tenants nor the
// admin_consent_requests table.
func TestSQLiteSchema_NoClientTenantTables(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "schema.db")

	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := p.CreateTenantStore(map[string]interface{}{"path": dbPath})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	db, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	var tableCount int
	require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'`).Scan(&tableCount))
	require.Greater(t, tableCount, 0, "precondition: the provider schema must have been applied")

	for _, table := range []string{"client_tenants", "admin_consent_requests"} {
		var n int
		require.NoError(t, db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = ?`, table).Scan(&n))
		assert.Zero(t, n, "table %s must not be created", table)
	}
}
