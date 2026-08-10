// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestTenantCrossingStore opens an in-memory SQLite store for testing.
func newTestTenantCrossingStore(t *testing.T) business.TenantCrossingStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteTenantCrossingStore{db: db}
}

// TestTenantCrossingStore_Contract runs the full shared TenantCrossingStore contract
// (ADR-025 Decision 2) against the SQLite provider.
func TestTenantCrossingStore_Contract(t *testing.T) {
	business.TenantCrossingStoreContract(t, newTestTenantCrossingStore(t))
}
