// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

func newCapabilityTestStore(t *testing.T, id string) *FlatFileStewardStore {
	t.Helper()
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.NoError(t, store.RegisterSteward(context.Background(), testStewardRecord(id)))
	return store
}

func TestFlatFileStewardStore_Capabilities_ResetDeclareRead(t *testing.T) {
	store := newCapabilityTestStore(t, "s-cap")
	ctx := context.Background()

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
}

func TestFlatFileStewardStore_Capabilities_StaleConnectionDoesNotOverwrite(t *testing.T) {
	store := newCapabilityTestStore(t, "s-stale")
	ctx := context.Background()

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

func TestFlatFileStewardStore_Capabilities_ErrorPaths(t *testing.T) {
	store := newCapabilityTestStore(t, "s-err")
	ctx := context.Background()

	assert.ErrorIs(t, store.ResetCapabilities(ctx, "missing", "conn-A"), business.ErrStewardNotFound)
	_, err := store.DeclareCapabilities(ctx, "missing", "conn-A", business.StewardCapabilityRecord{})
	assert.ErrorIs(t, err, business.ErrStewardNotFound)

	assert.Error(t, store.ResetCapabilities(ctx, "s-err", ""), "empty connection ID is rejected")
	_, err = store.DeclareCapabilities(ctx, "s-err", "", business.StewardCapabilityRecord{})
	assert.Error(t, err)

	applied, err := store.DeclareCapabilities(ctx, "s-err", "conn-A", business.StewardCapabilityRecord{})
	require.NoError(t, err)
	assert.False(t, applied, "never reset: no declare can apply")
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

func TestFlatFileStewardStore_Capabilities_FloorState(t *testing.T) {
	store := newCapabilityTestStore(t, "s-floor")
	ctx := context.Background()
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

// TestFlatFileStewardStore_Capabilities_LegacyFileReadsAbsent reads a record file
// written before the field existed.
func TestFlatFileStewardStore_Capabilities_LegacyFileReadsAbsent(t *testing.T) {
	root := t.TempDir()
	store, err := NewFlatFileStewardStore(root)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	legacy := `{"id":"s-legacy","tenant_id":"","hostname":"h","platform":"linux","status":"registered"}`
	require.NoError(t, os.WriteFile(filepath.Join(root, "stewards", "s-legacy.json"), []byte(legacy), 0o600))

	got, err := store.GetSteward(context.Background(), "s-legacy")
	require.NoError(t, err)
	assert.Nil(t, got.Capabilities)
}

func TestFlatFileStewardStore_Capabilities_ConcurrentDeclareAndReset(t *testing.T) {
	store := newCapabilityTestStore(t, "s-race")
	ctx := context.Background()
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
