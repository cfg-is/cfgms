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

// TestProvisionStore_SurvivesReopen is the REQUIRED TEST from AC: a record
// written to the durable store is readable after the store is re-opened at the
// same root (simulating a steward restart). This proves the in-memory-only
// default is replaced by a real durable implementation in the default wiring
// path (NewFlatFileProvisionStore → ConfigBackedProvisionStore).
func TestProvisionStore_SurvivesReopen(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()

	store1, err := NewFlatFileProvisionStore(root)
	require.NoError(t, err, "NewFlatFileProvisionStore must succeed on a writable root")

	now := time.Now().Truncate(time.Second).UTC()
	record := &ProvisionRecord{
		VMName:        "vm-01",
		State:         ProvisionStateInstalling,
		CorrelationID: "corr-restart-test",
		StartedAt:     now,
		UpdatedAt:     now,
	}
	require.NoError(t, store1.SetProvision(ctx, record))

	// Simulate a steward restart: open a second store instance at the same root.
	store2, err := NewFlatFileProvisionStore(root)
	require.NoError(t, err)

	got, err := store2.GetProvision(ctx, "vm-01")
	require.NoError(t, err, "record written before re-open must be readable after (durable store)")
	assert.Equal(t, "vm-01", got.VMName)
	assert.Equal(t, ProvisionStateInstalling, got.State)
	assert.Equal(t, "corr-restart-test", got.CorrelationID)
	assert.Equal(t, now, got.StartedAt)
}

// TestProvisionStore_ConfigBacked_CRUD exercises full Get/Set/Delete/List
// round-trips on ConfigBackedProvisionStore via NewFlatFileProvisionStore.
func TestProvisionStore_ConfigBacked_CRUD(t *testing.T) {
	root := t.TempDir()
	ctx := context.Background()
	store, err := NewFlatFileProvisionStore(root)
	require.NoError(t, err)

	// Get on empty store returns ErrProvisionNotFound.
	_, err = store.GetProvision(ctx, "vm-a")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisionNotFound)

	// Delete on empty store returns ErrProvisionNotFound.
	err = store.DeleteProvision(ctx, "vm-a")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProvisionNotFound)

	// List on empty store returns empty non-nil slice.
	list, err := store.ListProvisions(ctx)
	require.NoError(t, err)
	assert.NotNil(t, list)
	assert.Empty(t, list)

	now := time.Now().Truncate(time.Second).UTC()
	recA := &ProvisionRecord{VMName: "vm-a", State: ProvisionStateCreating, CorrelationID: "c-a", StartedAt: now, UpdatedAt: now}
	recB := &ProvisionRecord{VMName: "vm-b", State: ProvisionStateReady, CorrelationID: "c-b", StartedAt: now, UpdatedAt: now, LastError: "prior-err"}
	require.NoError(t, store.SetProvision(ctx, recA))
	require.NoError(t, store.SetProvision(ctx, recB))

	// Get returns the stored record.
	gotA, err := store.GetProvision(ctx, "vm-a")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateCreating, gotA.State)
	assert.Equal(t, "c-a", gotA.CorrelationID)

	// List returns all records.
	list, err = store.ListProvisions(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2)

	// Set overwrites existing record.
	recA.State = ProvisionStateFailed
	require.NoError(t, store.SetProvision(ctx, recA))
	got, err := store.GetProvision(ctx, "vm-a")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateFailed, got.State)

	// Delete removes the record; Get afterwards returns ErrProvisionNotFound.
	require.NoError(t, store.DeleteProvision(ctx, "vm-b"))
	_, err = store.GetProvision(ctx, "vm-b")
	assert.ErrorIs(t, err, ErrProvisionNotFound)

	// vm-a still present.
	_, err = store.GetProvision(ctx, "vm-a")
	require.NoError(t, err)
}

// ─── ProvisionStore CRUD tests ────────────────────────────────────────────────

// TestProvisionStore_CRUD exercises Get/Set/Delete/ErrProvisionNotFound
// round-trips on memProvisionStore.
func TestProvisionStore_CRUD(t *testing.T) {
	ctx := context.Background()
	store := NewMemProvisionStore()

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
	store := NewMemProvisionStore()
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

// TestProvisionStore_ListProvisions verifies that ListProvisions returns
// independent copies of all stored records and that the empty-store case
// returns a non-nil empty slice.
func TestProvisionStore_ListProvisions(t *testing.T) {
	ctx := context.Background()
	store := NewMemProvisionStore()

	// Empty store returns empty slice, not nil.
	list, err := store.ListProvisions(ctx)
	require.NoError(t, err)
	assert.NotNil(t, list)
	assert.Empty(t, list)

	now := time.Now().Truncate(time.Second)
	recA := &ProvisionRecord{VMName: "vm-a", State: ProvisionStateCreating, CorrelationID: "corr-a", StartedAt: now, UpdatedAt: now}
	recB := &ProvisionRecord{VMName: "vm-b", State: ProvisionStateReady, CorrelationID: "corr-b", StartedAt: now, UpdatedAt: now}
	require.NoError(t, store.SetProvision(ctx, recA))
	require.NoError(t, store.SetProvision(ctx, recB))

	list, err = store.ListProvisions(ctx)
	require.NoError(t, err)
	assert.Len(t, list, 2, "ListProvisions must return all stored records")

	// Mutating a returned pointer must not corrupt the store.
	for _, r := range list {
		r.State = ProvisionStateFailed
	}
	list2, err := store.ListProvisions(ctx)
	require.NoError(t, err)
	for _, r := range list2 {
		assert.NotEqual(t, ProvisionStateFailed, r.State,
			"ListProvisions must return copies; mutating them must not affect the store")
	}
}

// TestProvisionRecord_LastError verifies that LastError is carried through Set/Get.
func TestProvisionRecord_LastError(t *testing.T) {
	ctx := context.Background()
	store := NewMemProvisionStore()
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

// TestIsOwnIncompleteAttempt verifies the existence-gating helper: a record in a
// host-side in-progress state (creating/installing/finalizing) reports true;
// missing or terminal-state records report false. This is the discriminator that
// separates "our own incomplete attempt" (safe to surface-and-wait) from "a real
// existing VM" (never destroyed) in the ADR-009 §2 decision tree.
func TestIsOwnIncompleteAttempt(t *testing.T) {
	ctx := context.Background()
	m := &hypervModule{provisionStore: NewMemProvisionStore()}

	// No record → false.
	assert.False(t, m.isOwnIncompleteAttempt(ctx, "vm-x"),
		"no provisioning record must report not-in-progress")

	cases := []struct {
		state ProvisionState
		want  bool
	}{
		{ProvisionStateAbsent, false},
		{ProvisionStateCreating, true},
		{ProvisionStateInstalling, true},
		{ProvisionStateFinalizing, true},
		{ProvisionStateReady, false},
		{ProvisionStateFailed, false},
		{ProvisionStateDegraded, false},
	}
	for _, tc := range cases {
		require.NoError(t, m.provisionStore.SetProvision(ctx, &ProvisionRecord{
			VMName: "vm-x", State: tc.state, CorrelationID: "vm-x",
		}))
		assert.Equal(t, tc.want, m.isOwnIncompleteAttempt(ctx, "vm-x"),
			"isOwnIncompleteAttempt for state %q", tc.state)
	}
}

// TestIsHealthyVMState verifies the broken-state classifier used by the degraded
// surface: running/stopped/off/paused/saved/absent are healthy; any other state
// (critical, off-critical, paused-critical, unknown) is broken (ADR-009 §2).
func TestIsHealthyVMState(t *testing.T) {
	for _, s := range []string{"running", "stopped", "off", "paused", "saved", "absent", "Running", "Off"} {
		assert.True(t, isHealthyVMState(s), "%q must be classified healthy", s)
	}
	for _, s := range []string{"critical", "off-critical", "paused-critical", "Critical", "starting-critical", "weird"} {
		assert.False(t, isHealthyVMState(s), "%q must be classified broken", s)
	}
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
