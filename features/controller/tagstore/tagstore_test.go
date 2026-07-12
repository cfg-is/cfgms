// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package tagstore_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/tagstore"
	"github.com/cfgis/cfgms/pkg/logging"
)

func newTestStore(t *testing.T) *tagstore.Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tags_test.db")
	store, err := tagstore.NewFromDSN("file:"+dbPath, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store.Initialize(context.Background()))
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestStore_SetAndGet(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-1", []string{"env-prod", "region-us"}))

	tags, err := store.Get(ctx, "steward-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"env-prod", "region-us"}, tags)
}

func TestStore_Get_NotFound(t *testing.T) {
	store := newTestStore(t)
	tags, err := store.Get(context.Background(), "no-such-steward")
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestStore_Set_ReplacesExisting(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-1", []string{"tag-a", "tag-b"}))
	require.NoError(t, store.Set(ctx, "steward-1", []string{"tag-c"}))

	tags, err := store.Get(ctx, "steward-1")
	require.NoError(t, err)
	assert.Equal(t, []string{"tag-c"}, tags)
}

func TestStore_Set_EmptySlice_ClearsTags(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-1", []string{"env-prod"}))
	require.NoError(t, store.Set(ctx, "steward-1", []string{}))

	tags, err := store.Get(ctx, "steward-1")
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestStore_Delete(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-1", []string{"env-prod"}))
	require.NoError(t, store.Delete(ctx, "steward-1"))

	tags, err := store.Get(ctx, "steward-1")
	require.NoError(t, err)
	assert.Empty(t, tags)
}

func TestStore_Delete_Idempotent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	// Deleting a non-existent entry must not error.
	assert.NoError(t, store.Delete(ctx, "no-such-steward"))
}

func TestStore_GetAll(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-a", []string{"env-prod", "region-us"}))
	require.NoError(t, store.Set(ctx, "steward-b", []string{"env-staging"}))

	all, err := store.GetAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, []string{"env-prod", "region-us"}, all["steward-a"])
	assert.Equal(t, []string{"env-staging"}, all["steward-b"])
}

func TestStore_GetAll_Empty(t *testing.T) {
	store := newTestStore(t)
	all, err := store.GetAll(context.Background())
	require.NoError(t, err)
	assert.Empty(t, all)
}

func TestStore_TagsFor(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-1", []string{"env-prod"}))

	tags := store.TagsFor("steward-1")
	assert.Equal(t, []string{"env-prod"}, tags)
}

func TestStore_TagsFor_NotFound(t *testing.T) {
	store := newTestStore(t)
	tags := store.TagsFor("no-such-steward")
	assert.Empty(t, tags)
}

func TestStore_Set_InvalidTag_Rejected(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	cases := []struct {
		name string
		tag  string
	}{
		{"uppercase", "Env-Prod"},
		{"starts-with-hyphen", "-env"},
		{"contains-underscore", "env_prod"},
		{"contains-space", "env prod"},
		{"empty-string", ""},
		{"too-long-65-chars", "a" + string(make([]byte, 64))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.Set(ctx, "steward-1", []string{tc.tag})
			assert.ErrorIs(t, err, tagstore.ErrInvalidTag, "tag %q should be rejected", tc.tag)
		})
	}
}

func TestStore_Set_ValidTagBoundaries(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// single lowercase letter — minimum valid tag
	require.NoError(t, store.Set(ctx, "steward-1", []string{"a"}))
	// single digit
	require.NoError(t, store.Set(ctx, "steward-1", []string{"0"}))
	// 64-char tag (max allowed)
	longTag := "a" + string(make([]rune, 63))
	for i := range longTag {
		longTag = longTag[:i] + "a" + longTag[i+1:]
	}
	require.NoError(t, store.Set(ctx, "steward-1", []string{longTag[:64]}))
	// hyphen in middle
	require.NoError(t, store.Set(ctx, "steward-1", []string{"env-prod"}))
	// ends with digit
	require.NoError(t, store.Set(ctx, "steward-1", []string{"zone1"}))
}

func TestStore_Set_DuplicateTag_Rejected(t *testing.T) {
	store := newTestStore(t)
	err := store.Set(context.Background(), "steward-1", []string{"env-prod", "env-prod"})
	assert.Error(t, err, "duplicate tags must be rejected")
}

func TestStore_Initialize_Idempotent(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()
	// Initialize was already called in newTestStore; calling again must not error.
	assert.NoError(t, store.Initialize(ctx))
	assert.NoError(t, store.Initialize(ctx))
}

// TestStore_DurabilityAcrossRestart is the [REQUIRED TEST] from Issue #2542:
// tags must survive a modeled controller restart (close + new store instance over same DSN).
func TestStore_DurabilityAcrossRestart(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tags_persist.db")
	dsn := "file:" + dbPath
	ctx := context.Background()

	// First "controller instance": write tags and close.
	store1, err := tagstore.NewFromDSN(dsn, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store1.Initialize(ctx))

	require.NoError(t, store1.Set(ctx, "steward-persist", []string{"env-prod", "region-eu"}))
	require.NoError(t, store1.Set(ctx, "steward-other", []string{"env-staging"}))
	require.NoError(t, store1.Close())

	// Second "controller instance": reopen and verify tags survived.
	store2, err := tagstore.NewFromDSN(dsn, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NoError(t, store2.Initialize(ctx))
	defer func() { _ = store2.Close() }()

	tags, err := store2.Get(ctx, "steward-persist")
	require.NoError(t, err, "tags must survive a controller restart (SQLite durability)")
	assert.Equal(t, []string{"env-prod", "region-eu"}, tags)

	all, err := store2.GetAll(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)
	assert.Equal(t, []string{"env-prod", "region-eu"}, all["steward-persist"])
	assert.Equal(t, []string{"env-staging"}, all["steward-other"])

	// TagsFor must also return durable results.
	assert.Equal(t, []string{"env-prod", "region-eu"}, store2.TagsFor("steward-persist"))
}

// TestStore_MultiSteward verifies that Set/Get/Delete are correctly scoped to steward IDs.
func TestStore_MultiSteward(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	require.NoError(t, store.Set(ctx, "steward-a", []string{"role-web"}))
	require.NoError(t, store.Set(ctx, "steward-b", []string{"role-db"}))

	// Deleting steward-a must not affect steward-b.
	require.NoError(t, store.Delete(ctx, "steward-a"))

	tagsA, err := store.Get(ctx, "steward-a")
	require.NoError(t, err)
	assert.Empty(t, tagsA)

	tagsB, err := store.Get(ctx, "steward-b")
	require.NoError(t, err)
	assert.Equal(t, []string{"role-db"}, tagsB)
}
