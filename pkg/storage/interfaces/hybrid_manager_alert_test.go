// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// Alert-store wiring tests (Issue #3266). These live in the external
// interfaces_test package because the real AlertStore implementations ship in
// pkg/storage/providers/*, which import pkg/storage/interfaces — an in-package
// test importing them would be an import cycle.
package interfaces_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// TestCreateOSSStorageManager_AlertStore verifies that the OSS storage manager wires
// the real flat-file AlertStore and that state round-trips through the accessor.
func TestCreateOSSStorageManager_AlertStore(t *testing.T) {
	sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "oss-alerts.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = sm.Close() })

	store := sm.GetAlertStore()
	require.NotNil(t, store, "GetAlertStore must be wired — the flat-file provider supplies it")

	ctx := context.Background()
	ackAt := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, store.AcknowledgeAlert(ctx, "tenant-oss", "alert-oss-1", "alice", ackAt))

	st, err := store.GetAlertState(ctx, "tenant-oss", "alert-oss-1")
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Acknowledged)
	assert.Equal(t, "alice", st.AcknowledgedBy)

	states, err := store.ListAlertStates(ctx, "tenant-oss")
	require.NoError(t, err)
	require.Len(t, states, 1)
	assert.Equal(t, "alert-oss-1", states[0].AlertID)
}

// TestHybridStorageManager_GetAlertStore verifies that NewHybridStorageManager wires
// GetAlertStore from the operational provider using real providers: PostgreSQL for the
// operational tier (the only provider with a database-backed AlertStore) and flat-file
// for the configuration tier. Skipped when PostgreSQL is not reachable.
func TestHybridStorageManager_GetAlertStore(t *testing.T) {
	dsn := skipIfNoPostgres(t)

	manager, err := interfaces.NewHybridStorageManager(interfaces.HybridStorageConfig{
		Operational: interfaces.StorageBackendConfig{
			Provider: "database",
			Config: map[string]interface{}{
				"dsn":              dsn,
				"session_hmac_key": testSessionHMACKey(),
			},
		},
		Configuration: interfaces.StorageBackendConfig{
			Provider: "flatfile",
			Config:   map[string]interface{}{"root": t.TempDir()},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, manager)

	store := manager.GetAlertStore()
	require.NotNil(t, store, "GetAlertStore must be wired from the operational provider")

	ctx := context.Background()
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	tenantID := "tenant-hybrid-alert"
	alertID := "alert-hybrid-1"
	require.NoError(t, store.SilenceAlert(ctx, tenantID, alertID, "bob", until))

	st, err := store.GetAlertState(ctx, tenantID, alertID)
	require.NoError(t, err)
	require.NotNil(t, st)
	assert.True(t, st.Silenced)
	assert.Equal(t, "bob", st.SilencedBy)
	assert.WithinDuration(t, until, st.SilencedUntil, time.Second)
}
