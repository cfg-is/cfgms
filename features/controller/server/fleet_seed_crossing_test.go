// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// TestSeedFleetCascadeTestData_GrantsCrossingIntoChildTenants covers the fleet E2E seed:
// the system admin bundle is bound to a root-scope account and so is subject to the
// root<->MSP crossing boundary (ADR-025 Amendment 3), so the seed must leave an active
// access grant on each seeded child tenant — and nowhere else.
func TestSeedFleetCascadeTestData_GrantsCrossingIntoChildTenants(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "fleet-seed.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	ctx := context.Background()
	logger := logging.NewNoopLogger()
	seedFleetCascadeTestData(ctx, sm, logger)
	// A controller restart seeds again; the second pass must not stack records.
	seedFleetCascadeTestData(ctx, sm, logger)

	store := sm.GetTenantCrossingStore()
	require.NotNil(t, store, "the storage tier must provide a tenant crossing store")

	for _, tenantID := range []string{"fleet-root/fleet-child-a", "fleet-root/fleet-child-b"} {
		// A grant admits any root-scoped principal, so the probing principal ID is arbitrary.
		active, err := store.HasActiveTenantCrossing(ctx, "any-root-principal", tenantID)
		require.NoError(t, err)
		assert.True(t, active, "%s must carry an active grant", tenantID)

		records, err := store.ListTenantCrossings(ctx, tenantID)
		require.NoError(t, err)
		require.Len(t, records, 1, "restart must not accumulate grants for %s", tenantID)
		assert.Equal(t, business.TenantCrossingKindGrant, records[0].Kind)
		assert.WithinDuration(t, time.Now().Add(fleetSeedGrantDuration), records[0].ExpiresAt, time.Minute)
	}

	rootActive, err := store.HasActiveTenantCrossing(ctx, "any-root-principal", "fleet-root")
	require.NoError(t, err)
	assert.False(t, rootActive, "the seed must not record a crossing on the root tenant")
}

// TestSeedFleetCrossingGrants_NoStoreIsNoop: a storage manager with no crossing store
// must not panic; the seed just logs that the fleet admin cannot cross.
func TestSeedFleetCrossingGrants_NoStoreIsNoop(t *testing.T) {
	sm := &interfaces.StorageManager{}
	assert.NotPanics(t, func() {
		seedFleetCrossingGrants(context.Background(), sm, logging.NewNoopLogger(), []string{"fleet-root/fleet-child-a"})
	})
}
