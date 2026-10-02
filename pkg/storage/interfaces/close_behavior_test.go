// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Behavioural half of the StorageManager.Close coverage guard.
//
// close_completeness_test.go (Issue #3894) is a static check: it parses
// provider.go and asserts every StorageManager store field appears in Close's
// slots list. It deliberately constructs no manager, so it proves the list is
// complete but not that being on the list does anything. This test supplies the
// other half against a real SQLite store — the store that made the omission
// matter, since sqlite.SQLiteBlastRadiusPolicyStore owns its own *sql.DB and a
// missed slot leaks that pool (invisible on Linux, a locked temp file on
// Windows).
//
// It lives in the external interfaces_test package because it drives the real
// SQLite provider, which imports pkg/storage/interfaces.
package interfaces_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestStorageManagerClose_ClosesStoreOwningItsOwnHandle gives the manager a real
// blast-radius policy store opened from its own database file, so it shares no
// connection pool with the manager's other stores, and asserts Close shuts that
// pool down. With sm.blastRadiusPolicyStore absent from Close's slots the query
// after Close succeeds instead of reporting a closed database.
func TestStorageManagerClose_ClosesStoreOwningItsOwnHandle(t *testing.T) {
	provider, err := interfaces.GetStorageProvider("sqlite")
	require.NoError(t, err, "sqlite provider must be registered")

	opener, ok := provider.(interfaces.BusinessStoreOpener)
	require.True(t, ok, "sqlite provider must implement BusinessStoreOpener")

	bundle, err := opener.OpenBusinessStores(filepath.Join(t.TempDir(), "blast-radius.db"))
	require.NoError(t, err)
	require.NotNil(t, bundle.BlastRadiusPolicy)

	sm := interfaces.NewStorageManagerFromStores(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	sm.SetBlastRadiusPolicyStore(bundle.BlastRadiusPolicy)

	ctx := context.Background()

	// Sanity: the store works while the manager is open.
	require.NoError(t, sm.GetBlastRadiusPolicyStore().SetPolicy(ctx,
		&business.BlastRadiusPolicy{TenantID: "root/tenant-a"}))

	require.NoError(t, sm.Close())

	_, err = sm.GetBlastRadiusPolicyStore().GetPolicy(ctx, "root/tenant-a")
	require.Error(t, err, "Close must shut down the blast-radius store's own connection pool")
	assert.Contains(t, err.Error(), "database is closed")
}
