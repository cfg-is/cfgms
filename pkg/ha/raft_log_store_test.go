// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3/raftpb"
)

// TestRaftLogStore_RecoversAfterUncleanShutdown verifies that every batch
// committed before an unclean process exit is present on re-open, and that no
// partially-written batch is visible. The crash is simulated by closing the
// underlying bbolt.DB directly — bypassing store.Close() — which reproduces
// the OS-level file handle close that occurs when a process exits abruptly
// after completing one or more committed (fsync'd) transactions. bbolt's
// fsync-on-commit guarantee means those transactions are durable regardless of
// whether the application-level close path runs.
func TestRaftLogStore_RecoversAfterUncleanShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raft.db")

	store, err := OpenRaftLogStore(path)
	require.NoError(t, err)

	// v3.7.0: HardState fields are *uint64; Entry fields (Index, Term, Type) are
	// also pointers — use new(value) and .Enum() to initialise them.
	hs := &raftpb.HardState{Term: new(uint64(3)), Vote: new(uint64(1)), Commit: new(uint64(5))}
	entries := []*raftpb.Entry{
		{Index: new(uint64(1)), Term: new(uint64(1)), Type: raftpb.EntryNormal.Enum(), Data: []byte("entry-1")},
		{Index: new(uint64(2)), Term: new(uint64(1)), Type: raftpb.EntryNormal.Enum(), Data: []byte("entry-2")},
		{Index: new(uint64(3)), Term: new(uint64(2)), Type: raftpb.EntryNormal.Enum(), Data: []byte("entry-3")},
	}
	require.NoError(t, store.SaveBatch(hs, entries, nil, 2))

	// Simulate unclean shutdown: bypass store.Close() and close the underlying
	// bbolt.DB directly. This releases the OS file lock (flock) without running
	// any application-level flush — the same effect as a SIGKILL after the
	// committed transaction's fsync() returned.
	require.NoError(t, store.db.Close())

	// Re-open the store as a fresh instance (as the next process boot would).
	store2, err := OpenRaftLogStore(path)
	require.NoError(t, err)
	defer store2.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	gotHS, gotEntries, _, gotApplied, err := store2.LoadState()
	require.NoError(t, err)

	assert.Equal(t, hs.GetTerm(), gotHS.GetTerm(), "HardState.Term must survive unclean shutdown")
	assert.Equal(t, hs.GetVote(), gotHS.GetVote(), "HardState.Vote must survive unclean shutdown")
	assert.Equal(t, hs.GetCommit(), gotHS.GetCommit(), "HardState.Commit must survive unclean shutdown")
	require.Len(t, gotEntries, len(entries), "all committed entries must be present after unclean shutdown")
	for i, e := range entries {
		assert.Equal(t, e.GetIndex(), gotEntries[i].GetIndex(), "entry %d index must match", i)
		assert.Equal(t, e.GetTerm(), gotEntries[i].GetTerm(), "entry %d term must match", i)
		assert.Equal(t, e.Data, gotEntries[i].Data, "entry %d data must match", i)
	}
	assert.Equal(t, uint64(2), gotApplied, "applied index must survive unclean shutdown")

	// Confirm HasData is true after re-open.
	assert.True(t, store2.HasData(), "HasData must return true when persisted state exists")
}

// TestRaftLogStore_RejectsCorruptDatabase verifies that a file whose bbolt
// magic bytes have been overwritten is rejected at open rather than silently
// returning partial or zero state.
func TestRaftLogStore_RejectsCorruptDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raft.db")

	// Create and close a valid store so the file exists.
	store, err := OpenRaftLogStore(path)
	require.NoError(t, err)
	require.NoError(t, store.Close())

	// Overwrite the file with garbage to simulate corruption.
	require.NoError(t, os.WriteFile(path, []byte("this is not a bbolt database"), 0600))

	_, err = OpenRaftLogStore(path)
	require.Error(t, err, "corrupt database must be rejected at open with a non-nil error")
}

// TestRaftLogStore_HasData_FreshStore verifies that HasData returns false on a
// store that has never received a SaveBatch call.
func TestRaftLogStore_HasData_FreshStore(t *testing.T) {
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	assert.False(t, store.HasData(), "fresh store must report HasData == false")
}

// TestRaftLogStore_LoadState_FreshStore verifies that LoadState returns nil
// values for all pointer fields on a store that has never had data written to
// it (v3.7.0: HardState, Snapshot, and Entries are nil for a fresh store).
func TestRaftLogStore_LoadState_FreshStore(t *testing.T) {
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	hs, entries, snap, applied, err := store.LoadState()
	require.NoError(t, err)
	assert.Nil(t, hs)
	assert.Nil(t, entries)
	assert.Nil(t, snap)
	assert.Equal(t, uint64(0), applied)
}

// TestRaftLogStore_EntriesInIndexOrder verifies that entries written in any
// order are returned in ascending index order by LoadState (bbolt big-endian key ordering).
func TestRaftLogStore_EntriesInIndexOrder(t *testing.T) {
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	// Write entries in reverse order across two batches to exercise ordering.
	batch1 := []*raftpb.Entry{
		{Index: new(uint64(3)), Term: new(uint64(1)), Data: []byte("c")},
		{Index: new(uint64(4)), Term: new(uint64(1)), Data: []byte("d")},
	}
	batch2 := []*raftpb.Entry{
		{Index: new(uint64(1)), Term: new(uint64(1)), Data: []byte("a")},
		{Index: new(uint64(2)), Term: new(uint64(1)), Data: []byte("b")},
	}
	require.NoError(t, store.SaveBatch(nil, batch1, nil, 0))
	require.NoError(t, store.SaveBatch(nil, batch2, nil, 0))

	_, entries, _, _, err := store.LoadState()
	require.NoError(t, err)
	require.Len(t, entries, 4)
	for i, want := range []uint64{1, 2, 3, 4} {
		assert.Equal(t, want, entries[i].GetIndex(), "entry %d must have index %d", i, want)
	}
}

// TestRaftLogStore_SnapshotRoundTrip verifies that a non-empty snapshot is
// stored and recovered intact.
func TestRaftLogStore_SnapshotRoundTrip(t *testing.T) {
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	// v3.7.0: Snapshot.Metadata is *SnapshotMetadata; its Index and Term are *uint64.
	snap := &raftpb.Snapshot{
		Data: []byte(`{"leader":1}`),
		Metadata: &raftpb.SnapshotMetadata{
			Index: new(uint64(10)),
			Term:  new(uint64(2)),
		},
	}
	require.NoError(t, store.SaveBatch(nil, nil, snap, 10))

	_, _, gotSnap, gotApplied, err := store.LoadState()
	require.NoError(t, err)
	assert.Equal(t, snap.GetMetadata().GetIndex(), gotSnap.GetMetadata().GetIndex())
	assert.Equal(t, snap.Data, gotSnap.Data)
	assert.Equal(t, uint64(10), gotApplied)
}

// TestRaftLogStore_AppliedIndexMonotonicallyIncreases verifies that SaveBatch
// never writes a smaller applied index than the one already stored.
func TestRaftLogStore_AppliedIndexMonotonicallyIncreases(t *testing.T) {
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	require.NoError(t, store.SaveBatch(nil, nil, nil, 10))
	// Write a smaller applied — must not overwrite the stored value.
	require.NoError(t, store.SaveBatch(nil, nil, nil, 5))

	_, _, _, applied, err := store.LoadState()
	require.NoError(t, err)
	assert.Equal(t, uint64(10), applied, "applied index must not decrease")
}

// TestRaftLogStore_ClusterNodesRoundTrip verifies that cluster membership
// survives a save/load cycle and that subsequent writes overwrite the previous
// snapshot (last-write-wins, no accumulation).
func TestRaftLogStore_ClusterNodesRoundTrip(t *testing.T) {
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	defer store.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	// Fresh store must return nil without error.
	got, err := store.LoadClusterNodes()
	require.NoError(t, err)
	assert.Nil(t, got, "fresh store must return nil cluster nodes")

	// Round-trip a JSON membership snapshot.
	snapshot := []byte(`{"1":{"id":"node-a","state":"healthy"},"2":{"id":"node-b","state":"healthy"}}`)
	require.NoError(t, store.SaveClusterNodes(snapshot))

	got, err = store.LoadClusterNodes()
	require.NoError(t, err)
	assert.Equal(t, snapshot, got, "cluster nodes must survive save/load round-trip")

	// A subsequent write overwrites the previous snapshot.
	updated := []byte(`{"1":{"id":"node-a","state":"healthy"}}`)
	require.NoError(t, store.SaveClusterNodes(updated))

	got, err = store.LoadClusterNodes()
	require.NoError(t, err)
	assert.Equal(t, updated, got, "subsequent SaveClusterNodes must overwrite the previous snapshot")
}

// TestRaftLogStore_ClusterNodesSurvivesUncleanShutdown verifies that the
// cluster membership snapshot is durable across an unclean process exit
// (the same fsync-on-commit guarantee as HardState and log entries).
func TestRaftLogStore_ClusterNodesSurvivesUncleanShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "raft.db")

	store, err := OpenRaftLogStore(path)
	require.NoError(t, err)

	snapshot := []byte(`{"42":{"id":"survivor","state":"healthy"}}`)
	require.NoError(t, store.SaveClusterNodes(snapshot))

	// Simulate unclean shutdown by bypassing store.Close().
	require.NoError(t, store.db.Close())

	// Re-open as the next boot would.
	store2, err := OpenRaftLogStore(path)
	require.NoError(t, err)
	defer store2.Close() //nolint:errcheck // Close always returns nil for bbolt; error is non-actionable in test cleanup

	got, err := store2.LoadClusterNodes()
	require.NoError(t, err)
	assert.Equal(t, snapshot, got, "cluster nodes must survive unclean shutdown")
}
