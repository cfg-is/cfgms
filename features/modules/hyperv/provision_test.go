// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── ProvisionStore CRUD tests ────────────────────────────────────────────────

// TestProvisionStore_CRUD exercises Get/Set/Delete/ErrProvisionNotFound
// round-trips on memProvisionStore.
func TestProvisionStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := newMemProvisionStore()

	// Get on empty store returns ErrProvisionNotFound.
	_, err := store.GetProvision(ctx, "vm-01")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisionNotFound, "Get on absent record must return ErrProvisionNotFound")

	// Delete on empty store returns ErrProvisionNotFound.
	err = store.DeleteProvision(ctx, "vm-01")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisionNotFound, "Delete on absent record must return ErrProvisionNotFound")

	// Set creates a record.
	now := time.Now().Truncate(time.Second)
	record := &ProvisionRecord{
		VMName:        "vm-01",
		State:         ProvisionStateCreating,
		CorrelationID: "corr-abc-123",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, store.SetProvision(ctx, record))

	// Get returns the stored record.
	got, err := store.GetProvision(ctx, "vm-01")
	require.NoError(t, err)
	assert.Equal(t, "vm-01", got.VMName)
	assert.Equal(t, ProvisionStateCreating, got.State)
	assert.Equal(t, "corr-abc-123", got.CorrelationID)
	assert.Equal(t, now, got.StartedAt)
	assert.Equal(t, now, got.UpdatedAt)

	// Set overwrites with a new state.
	record.State = ProvisionStateInstalling
	record.UpdatedAt = now.Add(time.Minute)
	require.NoError(t, store.SetProvision(ctx, record))

	got, err = store.GetProvision(ctx, "vm-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, got.State, "Set must overwrite existing record")

	// Mutating the returned pointer does not corrupt the store.
	got.State = ProvisionStateFailed
	reFetch, err := store.GetProvision(ctx, "vm-01")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, reFetch.State,
		"Get must return a copy; mutating it must not affect the store")

	// Delete removes the record.
	require.NoError(t, store.DeleteProvision(ctx, "vm-01"))
	_, err = store.GetProvision(ctx, "vm-01")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisionNotFound, "Get after Delete must return ErrProvisionNotFound")

	// Second Delete returns ErrProvisionNotFound.
	err = store.DeleteProvision(ctx, "vm-01")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisionNotFound, "Delete on already-deleted record must return ErrProvisionNotFound")
}

// TestProvisionStore_MultipleVMs verifies independent records for different VMs.
func TestProvisionStore_MultipleVMs(t *testing.T) {
	ctx := context.Background()
	store := newMemProvisionStore()
	now := time.Now().Truncate(time.Second)

	recordA := &ProvisionRecord{VMName: "vm-a", State: ProvisionStateCreating, CorrelationID: "corr-a", StartedAt: now, UpdatedAt: now}
	recordB := &ProvisionRecord{VMName: "vm-b", State: ProvisionStateReady, CorrelationID: "corr-b", StartedAt: now, UpdatedAt: now}

	require.NoError(t, store.SetProvision(ctx, recordA))
	require.NoError(t, store.SetProvision(ctx, recordB))

	gotA, err := store.GetProvision(ctx, "vm-a")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateCreating, gotA.State)

	gotB, err := store.GetProvision(ctx, "vm-b")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateReady, gotB.State)

	// Deleting A does not affect B.
	require.NoError(t, store.DeleteProvision(ctx, "vm-a"))
	_, err = store.GetProvision(ctx, "vm-a")
	assert.ErrorIs(t, err, ErrProvisionNotFound)
	_, err = store.GetProvision(ctx, "vm-b")
	require.NoError(t, err, "vm-b must survive deletion of vm-a")
}

// TestProvisionRecord_LastError verifies that LastError is carried through Set/Get.
func TestProvisionRecord_LastError(t *testing.T) {
	ctx := context.Background()
	store := newMemProvisionStore()
	now := time.Now().Truncate(time.Second)

	record := &ProvisionRecord{
		VMName:        "vm-err",
		State:         ProvisionStateFailed,
		CorrelationID: "corr-x",
		StartedAt:     now,
		UpdatedAt:     now,
		LastError:     "timeout waiting for steward registration",
	}
	require.NoError(t, store.SetProvision(ctx, record))

	got, err := store.GetProvision(ctx, "vm-err")
	require.NoError(t, err)
	assert.Equal(t, "timeout waiting for steward registration", got.LastError)
}

// TestProvisionState_Values verifies the ProvisionState string enum values are
// stable and serialise to the expected strings.
func TestProvisionState_Values(t *testing.T) {
	cases := []struct {
		state ProvisionState
		want  string
	}{
		{ProvisionStateAbsent, "absent"},
		{ProvisionStateCreating, "creating"},
		{ProvisionStateInstalling, "installing"},
		{ProvisionStateFinalizing, "finalizing"},
		{ProvisionStateReady, "ready"},
		{ProvisionStateFailed, "failed"},
		{ProvisionStateDegraded, "degraded"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, string(tc.state),
			"ProvisionState(%q) must serialise to %q", tc.state, tc.want)
	}
}

// TestProvisionNotFound_IsSentinel verifies that ErrProvisionNotFound is a
// standalone sentinel, not wrapping another error.
func TestProvisionNotFound_IsSentinel(t *testing.T) {
	assert.False(t, errors.Is(ErrProvisionNotFound, ErrVMNotFound),
		"ErrProvisionNotFound must be a distinct sentinel from ErrVMNotFound")
}
