// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// These tests need the live PostgreSQL instance used by the other store tests
// (newTestStewardStore skips them in short mode or when it is unreachable).

func TestDatabaseStewardStore_Capabilities_ResetDeclareRead(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, makeSampleSteward("sw-cap", "tenant-cap")))

	got, err := store.GetSteward(ctx, "sw-cap")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities, "a record that never connected has no capability record")

	require.NoError(t, store.ResetCapabilities(ctx, "sw-cap", "conn-A"))
	got, err = store.GetSteward(ctx, "sw-cap")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
	assert.Equal(t, "conn-A", got.Capabilities.ConnectionID)
	assert.False(t, got.Capabilities.ConnectedAt.IsZero())
	connectedAt := got.Capabilities.ConnectedAt

	applied, err := store.DeclareCapabilities(ctx, "sw-cap", "conn-A", business.StewardCapabilityRecord{
		CommandTypes:           []int32{1, 7},
		SigningPayloadVersions: []uint32{2, 3},
	})
	require.NoError(t, err)
	assert.True(t, applied)

	got, err = store.GetSteward(ctx, "sw-cap")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, business.StewardCapabilityDeclared, got.Capabilities.State)
	assert.Equal(t, "conn-A", got.Capabilities.ConnectionID)
	assert.Equal(t, []int32{1, 7}, got.Capabilities.CommandTypes)
	assert.Equal(t, []uint32{2, 3}, got.Capabilities.SigningPayloadVersions)
	assert.True(t, connectedAt.Equal(got.Capabilities.ConnectedAt), "declare keeps the connect time")
	assert.False(t, got.Capabilities.UpdatedAt.IsZero())
}

func TestDatabaseStewardStore_Capabilities_StaleConnectionDoesNotOverwrite(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, makeSampleSteward("sw-stale", "tenant-cap")))

	require.NoError(t, store.ResetCapabilities(ctx, "sw-stale", "conn-A"))
	require.NoError(t, store.ResetCapabilities(ctx, "sw-stale", "conn-B"))

	applied, err := store.DeclareCapabilities(ctx, "sw-stale", "conn-A", business.StewardCapabilityRecord{
		CommandTypes: []int32{9},
	})
	require.NoError(t, err)
	assert.False(t, applied, "a late write from the old connection must not apply")

	got, err := store.GetSteward(ctx, "sw-stale")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
	assert.Equal(t, "conn-B", got.Capabilities.ConnectionID)
	assert.Empty(t, got.Capabilities.CommandTypes)
}

func TestDatabaseStewardStore_Capabilities_ErrorPaths(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, makeSampleSteward("sw-err", "tenant-cap")))

	assert.ErrorIs(t, store.ResetCapabilities(ctx, "missing", "conn-A"), business.ErrStewardNotFound)
	_, err := store.DeclareCapabilities(ctx, "missing", "conn-A", business.StewardCapabilityRecord{})
	assert.ErrorIs(t, err, business.ErrStewardNotFound)

	assert.Error(t, store.ResetCapabilities(ctx, "sw-err", ""), "empty connection ID is rejected")
	_, err = store.DeclareCapabilities(ctx, "sw-err", "", business.StewardCapabilityRecord{})
	assert.Error(t, err)

	applied, err := store.DeclareCapabilities(ctx, "sw-err", "conn-A", business.StewardCapabilityRecord{})
	require.NoError(t, err)
	assert.False(t, applied, "never reset: no declare can apply")
	got, err := store.GetSteward(ctx, "sw-err")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities)

	require.NoError(t, store.ResetCapabilities(ctx, "sw-err", "conn-A"))
	_, err = store.DeclareCapabilities(ctx, "sw-err", "conn-A", business.StewardCapabilityRecord{State: "bogus"})
	assert.Error(t, err, "an undefined state is rejected")
	got, err = store.GetSteward(ctx, "sw-err")
	require.NoError(t, err)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
}

// TestDatabaseStewardStore_Capabilities_LegacyColumnReadsAbsent covers a
// steward_records row written before the capabilities column existed: the column
// is added with an empty default and the row reads back with no capability record.
func TestDatabaseStewardStore_Capabilities_LegacyColumnReadsAbsent(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, makeSampleSteward("sw-legacy", "tenant-cap")))

	// test-only schema surgery: recreate the pre-capabilities shape.
	_, err := store.db.ExecContext(ctx, `ALTER TABLE steward_records DROP COLUMN capabilities`)
	require.NoError(t, err)
	require.NoError(t, NewDatabaseSchemas().CreateStewardRecordsTable(ctx, store.db))

	got, err := store.GetSteward(ctx, "sw-legacy")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities)

	// An explicit empty column value (what the default writes) is also absent.
	_, err = store.db.ExecContext(ctx, `UPDATE steward_records SET capabilities = '' WHERE id = 'sw-legacy'`)
	require.NoError(t, err)
	got, err = store.GetSteward(ctx, "sw-legacy")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities)

	require.NoError(t, store.ResetCapabilities(ctx, "sw-legacy", "conn-A"))
	got, err = store.GetSteward(ctx, "sw-legacy")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
}

func TestDatabaseStewardStore_Capabilities_ConcurrentDeclareAndReset(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, makeSampleSteward("sw-race", "tenant-cap")))
	require.NoError(t, store.ResetCapabilities(ctx, "sw-race", "conn-A"))

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.DeclareCapabilities(ctx, "sw-race", "conn-A", business.StewardCapabilityRecord{CommandTypes: []int32{1}})
			assert.NoError(t, err)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, store.ResetCapabilities(ctx, "sw-race", "conn-B"))
	}()
	wg.Wait()

	got, err := store.GetSteward(ctx, "sw-race")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, "conn-B", got.Capabilities.ConnectionID)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
}
