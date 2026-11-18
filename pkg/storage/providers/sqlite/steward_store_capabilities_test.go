// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func TestSQLiteStewardStore_Capabilities_ResetDeclareRead(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-cap")))

	got, err := store.GetSteward(ctx, "s-cap")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities, "a record that never connected has no capability record")

	require.NoError(t, store.ResetCapabilities(ctx, "s-cap", "conn-A"))
	got, err = store.GetSteward(ctx, "s-cap")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
	assert.Equal(t, "conn-A", got.Capabilities.ConnectionID)
	assert.False(t, got.Capabilities.ConnectedAt.IsZero())
	connectedAt := got.Capabilities.ConnectedAt

	applied, err := store.DeclareCapabilities(ctx, "s-cap", "conn-A", business.StewardCapabilityRecord{
		CommandTypes:           []int32{1, 7},
		SigningPayloadVersions: []uint32{2, 3},
	})
	require.NoError(t, err)
	assert.True(t, applied)

	got, err = store.GetSteward(ctx, "s-cap")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, business.StewardCapabilityDeclared, got.Capabilities.State)
	assert.Equal(t, "conn-A", got.Capabilities.ConnectionID)
	assert.Equal(t, []int32{1, 7}, got.Capabilities.CommandTypes)
	assert.Equal(t, []uint32{2, 3}, got.Capabilities.SigningPayloadVersions)
	assert.True(t, connectedAt.Equal(got.Capabilities.ConnectedAt), "declare keeps the connect time")
	assert.False(t, got.Capabilities.UpdatedAt.IsZero())

	all, err := store.ListStewards(ctx)
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.NotNil(t, all[0].Capabilities, "list reads the capability record too")
	assert.Equal(t, "conn-A", all[0].Capabilities.ConnectionID)
}

func TestSQLiteStewardStore_Capabilities_StaleConnectionDoesNotOverwrite(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-stale")))

	require.NoError(t, store.ResetCapabilities(ctx, "s-stale", "conn-A"))
	require.NoError(t, store.ResetCapabilities(ctx, "s-stale", "conn-B"))

	applied, err := store.DeclareCapabilities(ctx, "s-stale", "conn-A", business.StewardCapabilityRecord{
		CommandTypes: []int32{9},
	})
	require.NoError(t, err)
	assert.False(t, applied, "a late write from the old connection must not apply")

	got, err := store.GetSteward(ctx, "s-stale")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
	assert.Equal(t, "conn-B", got.Capabilities.ConnectionID)
	assert.Empty(t, got.Capabilities.CommandTypes)
}

func TestSQLiteStewardStore_Capabilities_ErrorPaths(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-err")))

	assert.ErrorIs(t, store.ResetCapabilities(ctx, "missing", "conn-A"), business.ErrStewardNotFound)
	_, err := store.DeclareCapabilities(ctx, "missing", "conn-A", business.StewardCapabilityRecord{})
	assert.ErrorIs(t, err, business.ErrStewardNotFound)

	assert.Error(t, store.ResetCapabilities(ctx, "s-err", ""), "empty connection ID is rejected")
	_, err = store.DeclareCapabilities(ctx, "s-err", "", business.StewardCapabilityRecord{})
	assert.Error(t, err)

	// Never reset: no stored connection ID, so no declare can apply.
	applied, err := store.DeclareCapabilities(ctx, "s-err", "conn-A", business.StewardCapabilityRecord{})
	require.NoError(t, err)
	assert.False(t, applied)
	got, err := store.GetSteward(ctx, "s-err")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities)

	require.NoError(t, store.ResetCapabilities(ctx, "s-err", "conn-A"))
	_, err = store.DeclareCapabilities(ctx, "s-err", "conn-A", business.StewardCapabilityRecord{State: "bogus"})
	assert.Error(t, err, "an undefined state is rejected")
	got, err = store.GetSteward(ctx, "s-err")
	require.NoError(t, err)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
}

func TestSQLiteStewardStore_Capabilities_FloorState(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-floor")))
	require.NoError(t, store.ResetCapabilities(ctx, "s-floor", "conn-A"))

	applied, err := store.DeclareCapabilities(ctx, "s-floor", "conn-A", business.StewardCapabilityRecord{
		State: business.StewardCapabilityFloor,
	})
	require.NoError(t, err)
	assert.True(t, applied)
	got, err := store.GetSteward(ctx, "s-floor")
	require.NoError(t, err)
	assert.Equal(t, business.StewardCapabilityFloor, got.Capabilities.State)
}

func TestSQLiteStewardStore_Capabilities_RegisterPersistsRecord(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	rec := testStewardRec("s-reg")
	rec.Capabilities = &business.StewardCapabilityRecord{
		State: business.StewardCapabilityDeclared, ConnectionID: "conn-X", CommandTypes: []int32{4},
	}
	require.NoError(t, store.RegisterSteward(ctx, rec))
	got, err := store.GetSteward(ctx, "s-reg")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, "conn-X", got.Capabilities.ConnectionID)
	assert.Equal(t, []int32{4}, got.Capabilities.CommandTypes)
}

// TestSQLiteStewardStore_Capabilities_LegacyRowReadsAbsent covers a stewards
// table created before the capabilities column existed: the column is added with
// an empty default and the existing row reads back with no capability record.
func TestSQLiteStewardStore_Capabilities_LegacyRowReadsAbsent(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-legacy")))

	// test-only schema surgery: recreate the pre-capabilities shape.
	_, err := store.db.ExecContext(ctx, `ALTER TABLE stewards DROP COLUMN capabilities`)
	require.NoError(t, err)
	require.NoError(t, backfillStewardColumns(ctx, store.db))

	got, err := store.GetSteward(ctx, "s-legacy")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities)

	// The restored column is writable through the normal path.
	require.NoError(t, store.ResetCapabilities(ctx, "s-legacy", "conn-A"))
	got, err = store.GetSteward(ctx, "s-legacy")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
}

// TestSQLiteStewardStore_Capabilities_ConcurrentDeclareAndReset races declares
// for an old connection against a reset to a new one: whatever the interleaving,
// the final record belongs to the new connection and is never a declared record
// of the old one.
func TestSQLiteStewardStore_Capabilities_ConcurrentDeclareAndReset(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-race")))
	require.NoError(t, store.ResetCapabilities(ctx, "s-race", "conn-A"))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := store.DeclareCapabilities(ctx, "s-race", "conn-A", business.StewardCapabilityRecord{CommandTypes: []int32{1}})
			assert.NoError(t, err)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		assert.NoError(t, store.ResetCapabilities(ctx, "s-race", "conn-B"))
	}()
	wg.Wait()

	got, err := store.GetSteward(ctx, "s-race")
	require.NoError(t, err)
	require.NotNil(t, got.Capabilities)
	assert.Equal(t, "conn-B", got.Capabilities.ConnectionID)
	assert.Equal(t, business.StewardCapabilityPending, got.Capabilities.State)
}
