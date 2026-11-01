// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package hyperv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The CSV ProvisionStore is exercised against a real local temp dir (standing in
// for a VM's CSV home directory) — real file IO, no mocks, per the ProvisionStore
// contract memProvisionStore also satisfies.

func ccsRecord(name string, state ProvisionState) *ProvisionRecord {
	now := time.Now().UTC().Truncate(time.Second)
	return &ProvisionRecord{
		VMName:        name,
		State:         state,
		CorrelationID: name,
		StartedAt:     now,
		UpdatedAt:     now,
	}
}

// TestCSVProvisionStore_SetGetRoundTrip: a written record reads back byte-equal
// and lands at <home>/.cfgms-provision/<name>.json.
func TestCSVProvisionStore_SetGetRoundTrip(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	s := newCSVProvisionStore(home)

	rec := ccsRecord("vm-a", ProvisionStateInstalling)
	rec.LastError = "mid-flight"
	require.NoError(t, s.SetProvision(ctx, rec))

	got, err := s.GetProvision(ctx, "vm-a")
	require.NoError(t, err)
	assert.Equal(t, rec.VMName, got.VMName)
	assert.Equal(t, rec.State, got.State)
	assert.Equal(t, rec.CorrelationID, got.CorrelationID)
	assert.Equal(t, "mid-flight", got.LastError)
	assert.True(t, rec.StartedAt.Equal(got.StartedAt), "StartedAt round-trips")

	// The record file lives beside the VHD, under the dotfile subdir.
	assert.FileExists(t, filepath.Join(home, csvProvisionSubdir, "vm-a.json"))
}

// TestCSVProvisionStore_CopyOnRead: a returned record is an independent copy —
// mutating it must not change the stored record (memProvisionStore contract).
func TestCSVProvisionStore_CopyOnRead(t *testing.T) {
	ctx := context.Background()
	s := newCSVProvisionStore(t.TempDir())
	require.NoError(t, s.SetProvision(ctx, ccsRecord("vm-b", ProvisionStateInstalling)))

	got, err := s.GetProvision(ctx, "vm-b")
	require.NoError(t, err)
	got.State = ProvisionStateFailed // mutate the caller's copy

	again, err := s.GetProvision(ctx, "vm-b")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, again.State,
		"mutating a read copy must not affect the store")
}

// TestCSVProvisionStore_GetMissing_NotFound: a missing record is ErrProvisionNotFound
// (distinct from an IO error — this is what lets isOwnIncompleteAttempt treat a
// clean absence as "no attempt, proceed" while a real IO error fails loud).
func TestCSVProvisionStore_GetMissing_NotFound(t *testing.T) {
	_, err := newCSVProvisionStore(t.TempDir()).GetProvision(context.Background(), "nope")
	assert.ErrorIs(t, err, ErrProvisionNotFound)
}

// TestCSVProvisionStore_Delete: delete removes the record; deleting a missing one
// is ErrProvisionNotFound.
func TestCSVProvisionStore_Delete(t *testing.T) {
	ctx := context.Background()
	s := newCSVProvisionStore(t.TempDir())
	require.NoError(t, s.SetProvision(ctx, ccsRecord("vm-c", ProvisionStateReady)))

	require.NoError(t, s.DeleteProvision(ctx, "vm-c"))
	_, err := s.GetProvision(ctx, "vm-c")
	assert.ErrorIs(t, err, ErrProvisionNotFound)
	assert.ErrorIs(t, s.DeleteProvision(ctx, "vm-c"), ErrProvisionNotFound)
}

// TestCSVProvisionStore_ListSnapshot: List returns independent copies of every
// record; a missing directory is an empty list (not an error).
func TestCSVProvisionStore_ListSnapshot(t *testing.T) {
	ctx := context.Background()
	s := newCSVProvisionStore(t.TempDir())

	empty, err := s.ListProvisions(ctx)
	require.NoError(t, err)
	assert.Empty(t, empty, "no directory yet → empty list, not an error")

	require.NoError(t, s.SetProvision(ctx, ccsRecord("vm-d1", ProvisionStateInstalling)))
	require.NoError(t, s.SetProvision(ctx, ccsRecord("vm-d2", ProvisionStateFinalizing)))

	list, err := s.ListProvisions(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	for _, r := range list {
		r.State = ProvisionStateFailed // mutate the snapshot
	}
	again, err := s.ListProvisions(ctx)
	require.NoError(t, err)
	for _, r := range again {
		assert.NotEqual(t, ProvisionStateFailed, r.State,
			"ListProvisions must return copies; mutating them must not affect the store")
	}
}

// TestCSVProvisionStore_AtomicWrite: overwriting a record leaves exactly one valid
// JSON file and no leftover temp files — the write is commit-by-rename, so a
// concurrent reader never sees a partial record (the window Option A closes).
func TestCSVProvisionStore_AtomicWrite(t *testing.T) {
	ctx := context.Background()
	home := t.TempDir()
	s := newCSVProvisionStore(home)

	require.NoError(t, s.SetProvision(ctx, ccsRecord("vm-e", ProvisionStateCreating)))
	require.NoError(t, s.SetProvision(ctx, ccsRecord("vm-e", ProvisionStateInstalling)))

	entries, err := os.ReadDir(filepath.Join(home, csvProvisionSubdir))
	require.NoError(t, err)
	require.Len(t, entries, 1, "only the committed record file must remain — no leftover temp files")
	assert.Equal(t, "vm-e.json", entries[0].Name())

	got, err := s.GetProvision(ctx, "vm-e")
	require.NoError(t, err)
	assert.Equal(t, ProvisionStateInstalling, got.State)
}

// TestCSVProvisionStore_InvalidHomeDir: an empty or UNC home dir is rejected at
// every operation with ErrInvalidSeedPath (the record must live on a local/CSV
// drive, never a network share — the ErrInvalidSeedPath precedent).
func TestCSVProvisionStore_InvalidHomeDir(t *testing.T) {
	ctx := context.Background()
	for _, home := range []string{
		"",
		`\\server\share\vm`,                    // UNC (backslash)
		`//server/share/vm`,                    // UNC (forward slash)
		`C:\ClusterStorage\Vol1\..\..\Windows`, // .. traversal escaping the CSV
		`C:\ClusterStorage\Vol1\..`,            // .. segment
	} {
		s := newCSVProvisionStore(home)
		_, gErr := s.GetProvision(ctx, "vm")
		assert.ErrorIs(t, gErr, ErrInvalidSeedPath, "home=%q Get", home)
		assert.ErrorIs(t, s.SetProvision(ctx, ccsRecord("vm", ProvisionStateCreating)), ErrInvalidSeedPath, "home=%q Set", home)
		assert.ErrorIs(t, s.DeleteProvision(ctx, "vm"), ErrInvalidSeedPath, "home=%q Delete", home)
		_, lErr := s.ListProvisions(ctx)
		assert.ErrorIs(t, lErr, ErrInvalidSeedPath, "home=%q List", home)
	}
}

// TestCSVProvisionStore_VMNameTraversalRejected: a vmName that would escape the
// record dir (separators or ..) is rejected — vmName becomes a filename.
func TestCSVProvisionStore_VMNameTraversalRejected(t *testing.T) {
	ctx := context.Background()
	s := newCSVProvisionStore(t.TempDir())
	for _, bad := range []string{`..\evil`, `sub/evil`, "..", ""} {
		_, err := s.GetProvision(ctx, bad)
		assert.ErrorIs(t, err, ErrInvalidSeedPath, "vmName=%q", bad)
	}
}

// TestCSVProvisionStore_SatisfiesInterface: compile-time + runtime confirmation
// the CSV store is a ProvisionStore (the interface storeFor returns).
func TestCSVProvisionStore_SatisfiesInterface(t *testing.T) {
	var _ ProvisionStore = newCSVProvisionStore(t.TempDir())
	_, err := newCSVProvisionStore(t.TempDir()).GetProvision(context.Background(), "x")
	assert.True(t, errors.Is(err, ErrProvisionNotFound))
}
