// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package tenantsync_test — real TenantStore factory for the writer tests.
// Kept in a file named providers_test.go so that the check-providers.sh
// architecture script allows the direct sqlite import (*/providers_test.go
// exception); no other file in this package may import a storage provider.
package tenantsync_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	sqlitestorage "github.com/cfgis/cfgms/pkg/storage/providers/sqlite"
)

// newTenantStore creates an in-process SQLite tenant store for tests.
func newTenantStore(t *testing.T) business.TenantStore {
	t.Helper()
	dir := t.TempDir()
	p := sqlitestorage.NewSQLiteProvider(dir)
	store, err := p.CreateTenantStore(map[string]interface{}{
		"path": filepath.Join(dir, "tenants.db"),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}
