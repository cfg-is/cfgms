// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// testStewardRecord returns a StewardRecord with sensible defaults for tests.
func testStewardRecord(id string) *business.StewardRecord {
	return &business.StewardRecord{
		ID:        id,
		Hostname:  "host-" + id,
		Platform:  "linux",
		Arch:      "amd64",
		Version:   "1.0.0",
		IPAddress: "10.0.0.1",
		Status:    business.StewardStatusRegistered,
	}
}

func TestFlatFileStewardStore_RegisterAndGet(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	rec := testStewardRecord("s-001")

	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetSteward(ctx, "s-001")
	require.NoError(t, err)
	assert.Equal(t, "s-001", got.ID)
	assert.Equal(t, "linux", got.Platform)
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
	assert.False(t, got.RegisteredAt.IsZero())
	assert.False(t, got.LastSeen.IsZero())
}

func TestFlatFileStewardStore_RegisterDuplicate(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	rec := testStewardRecord("s-dup")

	require.NoError(t, store.RegisterSteward(ctx, rec))
	err = store.RegisterSteward(ctx, rec)
	assert.ErrorIs(t, err, business.ErrStewardAlreadyExists)
}

func TestFlatFileStewardStore_GetNotFound(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	_, err = store.GetSteward(context.Background(), "does-not-exist")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestFlatFileStewardStore_UpdateHeartbeat(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRecord("s-hb")))

	before := time.Now().Add(-time.Second)
	require.NoError(t, store.UpdateHeartbeat(ctx, "s-hb"))

	got, err := store.GetSteward(ctx, "s-hb")
	require.NoError(t, err)
	assert.True(t, got.LastHeartbeatAt.After(before), "LastHeartbeatAt should be updated")
	assert.True(t, got.LastSeen.After(before), "LastSeen should be updated")
}

func TestFlatFileStewardStore_UpdateHeartbeat_NotFound(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	err = store.UpdateHeartbeat(context.Background(), "ghost")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestFlatFileStewardStore_ListStewards(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	for _, id := range []string{"s-a", "s-b", "s-c"} {
		require.NoError(t, store.RegisterSteward(ctx, testStewardRecord(id)))
	}

	records, err := store.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, records, 3)
}

func TestFlatFileStewardStore_ListStewardsByStatus(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRecord("s-reg")))

	active := testStewardRecord("s-active")
	active.Status = business.StewardStatusActive
	require.NoError(t, store.RegisterSteward(ctx, active))

	regs, err := store.ListStewardsByStatus(ctx, business.StewardStatusRegistered)
	require.NoError(t, err)
	assert.Len(t, regs, 1)
	assert.Equal(t, "s-reg", regs[0].ID)

	acts, err := store.ListStewardsByStatus(ctx, business.StewardStatusActive)
	require.NoError(t, err)
	assert.Len(t, acts, 1)
	assert.Equal(t, "s-active", acts[0].ID)
}

func TestFlatFileStewardStore_UpdateStewardStatus(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRecord("s-upd")))

	require.NoError(t, store.UpdateStewardStatus(ctx, "s-upd", business.StewardStatusActive))

	got, err := store.GetSteward(ctx, "s-upd")
	require.NoError(t, err)
	assert.Equal(t, business.StewardStatusActive, got.Status)
}

func TestFlatFileStewardStore_DeregisterSteward(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRecord("s-dereg")))
	require.NoError(t, store.DeregisterSteward(ctx, "s-dereg"))

	got, err := store.GetSteward(ctx, "s-dereg")
	require.NoError(t, err)
	// Record retained but status changed
	assert.Equal(t, business.StewardStatusDeregistered, got.Status)
}

func TestFlatFileStewardStore_GetStewardsSeen(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRecord("s-seen")))

	cutoff := time.Now().Add(-time.Minute)
	seen, err := store.GetStewardsSeen(ctx, cutoff)
	require.NoError(t, err)
	assert.Len(t, seen, 1)

	futureCutoff := time.Now().Add(time.Minute)
	notSeen, err := store.GetStewardsSeen(ctx, futureCutoff)
	require.NoError(t, err)
	assert.Empty(t, notSeen)
}

// TestFlatFileStewardStore_RestartPersistence verifies that records survive a store restart.
// This simulates a controller restart: create a new store instance against the same directory.
func TestFlatFileStewardStore_RestartPersistence(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	// First store instance — populate data
	store1, err := NewFlatFileStewardStore(root)
	require.NoError(t, err)

	require.NoError(t, store1.RegisterSteward(ctx, testStewardRecord("s-persist")))
	require.NoError(t, store1.UpdateHeartbeat(ctx, "s-persist"))
	require.NoError(t, store1.UpdateStewardStatus(ctx, "s-persist", business.StewardStatusActive))
	require.NoError(t, store1.Close())

	// Second store instance — same root, simulates controller restart
	store2, err := NewFlatFileStewardStore(root)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	got, err := store2.GetSteward(ctx, "s-persist")
	require.NoError(t, err)
	assert.Equal(t, "s-persist", got.ID)
	assert.Equal(t, business.StewardStatusActive, got.Status)
	assert.False(t, got.LastHeartbeatAt.IsZero())

	all, err := store2.ListStewards(ctx)
	require.NoError(t, err)
	assert.Len(t, all, 1)
}

func TestFlatFileStewardStore_HealthCheck(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	assert.NoError(t, store.HealthCheck(context.Background()))
}

func TestFlatFileStewardStore_Initialize(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	// Safe to call multiple times
	assert.NoError(t, store.Initialize(context.Background()))
	assert.NoError(t, store.Initialize(context.Background()))
}

func TestFlatFileStewardStore_RegisterNilRecord(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	err = store.RegisterSteward(context.Background(), nil)
	assert.Error(t, err)
}

func TestFlatFileStewardStore_RegisterEmptyID(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	err = store.RegisterSteward(context.Background(), &business.StewardRecord{})
	assert.Error(t, err)
}

func TestFlatFileStewardStore_UpdateStatusNotFound(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	err = store.UpdateStewardStatus(context.Background(), "ghost", business.StewardStatusLost)
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestFlatFileStewardStore_DeregisterNotFound(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	err = store.DeregisterSteward(context.Background(), "ghost")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestFlatFileStewardStore_GetStewardByDeviceID(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	const deviceID = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
	rec := testStewardRecord("s-dvc")
	rec.DeviceID = deviceID
	rec.IdentityKeyPub = []byte{0xde, 0xad}
	rec.KeyProtectionLevel = "file"
	rec.LastProvenanceJSON = `{"hostname":"host-s-dvc"}`
	require.NoError(t, store.RegisterSteward(ctx, rec))

	got, err := store.GetStewardByDeviceID(ctx, deviceID)
	require.NoError(t, err)
	assert.Equal(t, "s-dvc", got.ID)
	assert.Equal(t, deviceID, got.DeviceID)
	assert.Equal(t, []byte{0xde, 0xad}, got.IdentityKeyPub)
	assert.Equal(t, "file", got.KeyProtectionLevel)
	assert.Equal(t, `{"hostname":"host-s-dvc"}`, got.LastProvenanceJSON)

	_, err = store.GetStewardByDeviceID(ctx, "0000000000000000000000000000000000000000000000000000000000000000")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestFlatFileStewardStore_GetStewardByDeviceID_EmptyID(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	_, err = store.GetStewardByDeviceID(context.Background(), "")
	require.Error(t, err, "empty device ID must return an error")
}

func TestFlatFileStewardStore_UpdateStewardTenant(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	rec := testStewardRecord("s-move")
	rec.TenantID = "tenant-src"
	require.NoError(t, store.RegisterSteward(ctx, rec))

	// Move to a new tenant.
	require.NoError(t, store.UpdateStewardTenant(ctx, "s-move", "tenant-dst"))

	got, err := store.GetSteward(ctx, "s-move")
	require.NoError(t, err)
	assert.Equal(t, "tenant-dst", got.TenantID)
	// Status must not change.
	assert.Equal(t, business.StewardStatusRegistered, got.Status)
}

func TestFlatFileStewardStore_UpdateStewardTenant_NotFound(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	err = store.UpdateStewardTenant(context.Background(), "nonexistent", "tenant-dst")
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

func TestFlatFileStewardStore_SetStewardHidden(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	require.NoError(t, store.RegisterSteward(ctx, testStewardRecord("s-hide")))

	// Default: not hidden.
	got, err := store.GetSteward(ctx, "s-hide")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "freshly registered steward must not be hidden")

	// Hide it.
	require.NoError(t, store.SetStewardHidden(ctx, "s-hide", true))
	got, err = store.GetSteward(ctx, "s-hide")
	require.NoError(t, err)
	assert.True(t, got.Hidden, "GetSteward must reflect hidden=true after SetStewardHidden")

	// Un-hide it.
	require.NoError(t, store.SetStewardHidden(ctx, "s-hide", false))
	got, err = store.GetSteward(ctx, "s-hide")
	require.NoError(t, err)
	assert.False(t, got.Hidden, "GetSteward must reflect hidden=false after SetStewardHidden")
}

func TestFlatFileStewardStore_SetStewardHidden_NotFound(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	err = store.SetStewardHidden(context.Background(), "ghost", true)
	assert.ErrorIs(t, err, business.ErrStewardNotFound)
}

// TestFlatFileStewardStore_DeviceIDUniquePerTenant verifies that RegisterSteward
// enforces tenant-scoped device_id uniqueness, matching the sqlite and database providers.
// See Issue #3403 for the motivating CI failure and Issue #3506 for this fix.
//
// The check-then-act sequence in the registration handler means two concurrent claims can
// both pass the handler's GetStewardByDeviceID lookup; only the store-level guard decides
// the winner. This test exercises the guard directly.
func TestFlatFileStewardStore_DeviceIDUniquePerTenant(t *testing.T) {
	store, err := NewFlatFileStewardStore(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	const deviceID = "device-shared-1"

	first := testStewardRecord("steward-dup-a")
	first.TenantID = "tenant-1"
	first.DeviceID = deviceID
	require.NoError(t, store.RegisterSteward(ctx, first))

	// A different steward asserting the same device_id in the same tenant must be rejected.
	second := testStewardRecord("steward-dup-b")
	second.TenantID = "tenant-1"
	second.DeviceID = deviceID
	err = store.RegisterSteward(ctx, second)
	require.Error(t, err, "a second steward must not take a device_id already held in the tenant")
	assert.ErrorIs(t, err, business.ErrStewardDeviceIDConflict,
		"the conflict must be reported as ErrStewardDeviceIDConflict, not the benign ErrStewardAlreadyExists")

	// Cross-tenant is a separate namespace and must still be allowed.
	other := testStewardRecord("steward-dup-c")
	other.TenantID = "tenant-2"
	other.DeviceID = deviceID
	assert.NoError(t, store.RegisterSteward(ctx, other),
		"the same device_id under a different tenant is a distinct namespace")

	// Empty device_id means "not asserted" and must not collide with itself.
	blankA := testStewardRecord("steward-blank-a")
	blankA.TenantID = "tenant-1"
	blankA.DeviceID = ""
	blankB := testStewardRecord("steward-blank-b")
	blankB.TenantID = "tenant-1"
	blankB.DeviceID = ""
	require.NoError(t, store.RegisterSteward(ctx, blankA))
	assert.NoError(t, store.RegisterSteward(ctx, blankB),
		"rows with no device_id must be excluded from the uniqueness check")

	// Re-registering the SAME steward is still the benign duplicate, not a device conflict.
	dupSelf := testStewardRecord("steward-dup-a")
	dupSelf.TenantID = "tenant-1"
	dupSelf.DeviceID = deviceID
	selfErr := store.RegisterSteward(ctx, dupSelf)
	require.Error(t, selfErr)
	assert.ErrorIs(t, selfErr, business.ErrStewardAlreadyExists,
		"the same steward written twice stays ErrStewardAlreadyExists so idempotent retries remain benign")

	// GetStewardByDeviceID stays unambiguous within the tenant — the property
	// the revocation gate in handlers_registration_refresh.go depends on.
	got, getErr := store.GetStewardByDeviceID(ctx, deviceID)
	require.NoError(t, getErr)
	require.NotNil(t, got)
}

func TestFlatFileStewardStore_UpdateStewardTenant_TenantPersistedInFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFlatFileStewardStore(dir)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	rec := testStewardRecord("s-persist")
	rec.TenantID = "original-tenant"
	require.NoError(t, store.RegisterSteward(ctx, rec))
	require.NoError(t, store.UpdateStewardTenant(ctx, "s-persist", "new-tenant"))

	// Re-open the store — the new tenant ID must survive a reload from disk.
	store2, err := NewFlatFileStewardStore(dir)
	require.NoError(t, err)
	defer func() { _ = store2.Close() }()

	got, err := store2.GetSteward(ctx, "s-persist")
	require.NoError(t, err)
	assert.Equal(t, "new-tenant", got.TenantID)
}
