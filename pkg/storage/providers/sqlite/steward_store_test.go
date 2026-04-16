// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// newTestStewardStore creates an in-memory SQLite StewardStore for tests.
func newTestStewardStore(t *testing.T) *SQLiteStewardStore {
	t.Helper()
	db, err := openAndInit(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return &SQLiteStewardStore{db: db}
}

// testStewardRec returns a StewardRecord with sensible defaults.
func testStewardRec(id string) *interfaces.StewardRecord {
	return &interfaces.StewardRecord{
		ID:        id,
		Hostname:  "host-" + id,
		Platform:  "linux",
		Arch:      "amd64",
		Version:   "1.0.0",
		IPAddress: "10.0.0.1",
		Status:    interfaces.StewardStatusRegistered,
	}
}

func TestSQLiteStewardStore_RegisterAndGet(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-001")
	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetSteward(ctx, "s-001")
	require.NoError(t, err)
	assert.Equal(t, "s-001", got.ID)
	assert.Equal(t, "linux", got.Platform)
	assert.Equal(t, interfaces.StewardStatusRegistered, got.Status)
	assert.False(t, got.RegisteredAt.IsZero())
	assert.False(t, got.LastSeen.IsZero())
}

func TestSQLiteStewardStore_RegisterDuplicate(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	rec := testStewardRec("s-dup")
	require.NoError(t, store.RegisterSteward(ctx, rec))
	err := store.RegisterSteward(ctx, rec)
	assert.ErrorIs(t, err, interfaces.ErrStewardAlreadyExists)
}

func TestSQLiteStewardStore_GetNotFound(t *testing.T) {
	store := newTestStewardStore(t)
	_, err := store.GetSteward(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, interfaces.ErrStewardNotFound)
}

func TestSQLiteStewardStore_UpdateHeartbeat(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-hb")))

	before := time.Now().Add(-time.Second)
	require.NoError(t, store.UpdateHeartbeat(ctx, "s-hb"))

	got, err := store.GetSteward(ctx, "s-hb")
	require.NoError(t, err)
	assert.True(t, got.LastHeartbeatAt.After(before), "LastHeartbeatAt should be updated")
	assert.True(t, got.LastSeen.After(before), "LastSeen should be updated")
}

func TestSQLiteStewardStore_UpdateHeartbeat_NotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.UpdateHeartbeat(context.Background(), "ghost")
	assert.ErrorIs(t, err, interfaces.ErrStewardNotFound)
}

func TestSQLiteStewardStore_ListStewards(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	for _, id := range []string{"s-a", "s-b", "s-c"} {
		require.NoError(t, store.RegisterSteward(ctx, testStewardRec(id)))
	}

	records, err := store.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, records, 3)
}

func TestSQLiteStewardStore_ListStewardsByStatus(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-reg")))

	active := testStewardRec("s-active")
	active.Status = interfaces.StewardStatusActive
	require.NoError(t, store.RegisterSteward(ctx, active))

	regs, err := store.ListStewardsByStatus(ctx, interfaces.StewardStatusRegistered)
	require.NoError(t, err)
	assert.Len(t, regs, 1)
	assert.Equal(t, "s-reg", regs[0].ID)

	acts, err := store.ListStewardsByStatus(ctx, interfaces.StewardStatusActive)
	require.NoError(t, err)
	assert.Len(t, acts, 1)
	assert.Equal(t, "s-active", acts[0].ID)
}

func TestSQLiteStewardStore_UpdateStewardStatus(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-upd")))
	require.NoError(t, store.UpdateStewardStatus(ctx, "s-upd", interfaces.StewardStatusActive))

	got, err := store.GetSteward(ctx, "s-upd")
	require.NoError(t, err)
	assert.Equal(t, interfaces.StewardStatusActive, got.Status)
}

func TestSQLiteStewardStore_DeregisterSteward(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-dereg")))
	require.NoError(t, store.DeregisterSteward(ctx, "s-dereg"))

	got, err := store.GetSteward(ctx, "s-dereg")
	require.NoError(t, err)
	// Record retained but status changed
	assert.Equal(t, interfaces.StewardStatusDeregistered, got.Status)
}

func TestSQLiteStewardStore_GetStewardsSeen(t *testing.T) {
	store := newTestStewardStore(t)
	ctx := context.Background()

	require.NoError(t, store.RegisterSteward(ctx, testStewardRec("s-seen")))

	cutoff := time.Now().Add(-time.Minute)
	seen, err := store.GetStewardsSeen(ctx, cutoff)
	require.NoError(t, err)
	assert.Len(t, seen, 1)

	futureCutoff := time.Now().Add(time.Minute)
	notSeen, err := store.GetStewardsSeen(ctx, futureCutoff)
	require.NoError(t, err)
	assert.Empty(t, notSeen)
}

// TestSQLiteStewardStore_RestartPersistence verifies that records survive a store restart.
// Uses a real SQLite file to simulate controller restart.
func TestSQLiteStewardStore_RestartPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "stewards.db")
	ctx := context.Background()

	// First store instance — populate data
	db1, err := openAndInit(dbPath)
	require.NoError(t, err)
	store1 := &SQLiteStewardStore{db: db1}

	require.NoError(t, store1.RegisterSteward(ctx, testStewardRec("s-persist")))
	require.NoError(t, store1.UpdateHeartbeat(ctx, "s-persist"))
	require.NoError(t, store1.UpdateStewardStatus(ctx, "s-persist", interfaces.StewardStatusActive))
	require.NoError(t, store1.Close())

	// Second store instance — same file, simulates controller restart
	db2, err := openAndInit(dbPath)
	require.NoError(t, err)
	store2 := &SQLiteStewardStore{db: db2}
	defer func() { _ = store2.Close() }()

	got, err := store2.GetSteward(ctx, "s-persist")
	require.NoError(t, err)
	assert.Equal(t, "s-persist", got.ID)
	assert.Equal(t, interfaces.StewardStatusActive, got.Status)
	assert.False(t, got.LastHeartbeatAt.IsZero())

	all, err := store2.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)
}

func TestSQLiteStewardStore_HealthCheck(t *testing.T) {
	store := newTestStewardStore(t)
	assert.NoError(t, store.HealthCheck(context.Background()))
}

func TestSQLiteStewardStore_Initialize(t *testing.T) {
	store := newTestStewardStore(t)
	// Safe to call multiple times
	assert.NoError(t, store.Initialize(context.Background()))
	assert.NoError(t, store.Initialize(context.Background()))
}

func TestSQLiteStewardStore_RegisterNilRecord(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.RegisterSteward(context.Background(), nil)
	assert.Error(t, err)
}

func TestSQLiteStewardStore_RegisterEmptyID(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.RegisterSteward(context.Background(), &interfaces.StewardRecord{})
	assert.Error(t, err)
}

func TestSQLiteStewardStore_UpdateStatusNotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.UpdateStewardStatus(context.Background(), "ghost", interfaces.StewardStatusLost)
	assert.ErrorIs(t, err, interfaces.ErrStewardNotFound)
}

func TestSQLiteStewardStore_DeregisterNotFound(t *testing.T) {
	store := newTestStewardStore(t)
	err := store.DeregisterSteward(context.Background(), "ghost")
	assert.ErrorIs(t, err, interfaces.ErrStewardNotFound)
}
