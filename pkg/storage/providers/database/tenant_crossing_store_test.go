// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package database provides unit tests for the PostgreSQL TenantCrossingStore (ADR-025).
package database

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// newTestTenantCrossingStore creates a TenantCrossingStore backed by the test Postgres
// database. The schema is initialised fresh via the store constructor; the test is
// skipped when Postgres is unavailable (setupTestDatabase's convention).
func newTestTenantCrossingStore(t *testing.T) *DatabaseTenantCrossingStore {
	t.Helper()
	db := setupTestDatabase(t)
	t.Cleanup(func() { _ = db.Close() })
	schemas := NewDatabaseSchemas()
	ctx := context.Background()
	require.NoError(t, schemas.CreateTenantCrossingsTable(ctx, db))

	store, err := NewDatabaseTenantCrossingStore(buildTestDSN(), getTestConfig())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

// TestTenantCrossingStore_Contract runs the full shared TenantCrossingStore contract
// (ADR-025 Decision 2) against the PostgreSQL provider.
func TestTenantCrossingStore_Contract(t *testing.T) {
	business.TenantCrossingStoreContract(t, newTestTenantCrossingStore(t))
}
