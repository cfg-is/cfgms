// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/cfgis/cfgms/pkg/storage/providers/sqlite" // blank import triggers init()

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
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
	assert.ErrorIs(t, err, interfaces.ErrNotSupported)
}

// TestCreateRuntimeStore_NotSupported verifies runtime store is not supported.
func TestCreateRuntimeStore_NotSupported(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	_, err = p.CreateRuntimeStore(map[string]interface{}{})
	assert.ErrorIs(t, err, interfaces.ErrNotSupported)
}

// TestCreateTenantStore_InMemory verifies tenant store can be created.
func TestCreateTenantStore_InMemory(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := p.CreateTenantStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	require.NotNil(t, store)
}

// TestCreateSessionStore_InMemory verifies session store can be created.
func TestCreateSessionStore_InMemory(t *testing.T) {
	p, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err)
	store, err := p.CreateSessionStore(map[string]interface{}{"path": ":memory:"})
	require.NoError(t, err)
	require.NotNil(t, store)
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
}
