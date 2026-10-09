// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

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

// TestTenantCrossingStore_UpgradeFromOldShape opens a database whose tenant_crossings
// table predates the approval columns and verifies the idempotent upgrade.
func TestTenantCrossingStore_UpgradeFromOldShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = raw.Exec(`CREATE TABLE tenant_crossings (
		id TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, principal_id TEXT NOT NULL, kind TEXT NOT NULL,
		granted_by TEXT NOT NULL, justification TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL,
		expires_at TEXT NOT NULL, revoked_at TEXT)`)
	require.NoError(t, err)
	created := formatTime(nowUTC())
	expires := formatTime(nowUTC().Add(time.Hour))
	_, err = raw.Exec(`INSERT INTO tenant_crossings VALUES
		('old-grant','msp','root-op','grant','admin','',?,?,NULL),
		('old-bg','msp','root-op','break-glass','root-op','why',?,?,NULL)`, created, expires, created, expires)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	// Open twice: the upgrade must be idempotent.
	for i := 0; i < 2; i++ {
		db, err := openAndInit(path)
		require.NoError(t, err)
		store := &SQLiteTenantCrossingStore{db: db}
		ctx := context.Background()

		grant, err := store.GetTenantCrossing(ctx, "old-grant")
		require.NoError(t, err)
		require.Equal(t, business.TenantCrossingApprovalApproved, grant.ApprovalState)
		require.Empty(t, grant.ReasonCategory)
		require.Empty(t, grant.PrincipalID, "an old grant row loses its principal")

		bg, err := store.GetTenantCrossing(ctx, "old-bg")
		require.NoError(t, err)
		require.Equal(t, business.TenantCrossingApprovalApproved, bg.ApprovalState)
		require.Empty(t, bg.ReasonCategory)
		require.Equal(t, "root-op", bg.PrincipalID)

		active, err := store.HasActiveTenantCrossing(ctx, "anyone", "msp")
		require.NoError(t, err)
		require.True(t, active)
		require.NoError(t, db.Close())
	}
}
