// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
	"google.golang.org/protobuf/proto"
)

// Regression coverage for Issue #3479.
//
// Since Issue #3284 the Raft log is persisted, and NewRaftConsensus takes
// raft.RestartNode whenever the WAL has data. raft.RestartNode reads its voter
// set from Storage.InitialState(), which serves the snapshot's ConfState — but
// nothing persisted a ConfState, and config.Applied (set to the recovered
// applied index) suppresses re-delivery of the ConfChange entries that would
// otherwise rebuild membership. Every node therefore came back with an empty
// voter set and no way to acquire one, so no election ever happened:
//
//	newRaft <id> [peers: [], term: 3, commit: 8, applied: 8, ...]
//
// and GET /api/v1/raft/status reported "leader":0 indefinitely. Reproduced
// deterministically on the real 3-node cfg-lab cluster across two full
// stop-all/start-all cycles, with terms diverging between nodes. Recovery
// required deleting every node's raft.db by hand.
//
// These tests exercise the storage-seeding path directly rather than standing up
// a cluster, because the defect is entirely in what Storage.InitialState()
// returns at construction time.

// seedTestLogStore writes a small persisted log — entries, hard state and
// applied index — mimicking a node that has been running in a cluster.
func seedTestLogStore(t *testing.T, dir string, voters []uint64, withConfState bool) *RaftLogStore {
	t.Helper()
	store, err := OpenRaftLogStore(filepath.Join(dir, "raft.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	const term, lastIndex = uint64(3), uint64(4)
	entries := make([]*raftpb.Entry, 0, lastIndex)
	for i := uint64(1); i <= lastIndex; i++ {
		entries = append(entries, &raftpb.Entry{
			Index: proto.Uint64(i),
			Term:  proto.Uint64(term),
			Type:  raftpb.EntryNormal.Enum(),
		})
	}
	hs := &raftpb.HardState{
		Term:   proto.Uint64(term),
		Vote:   proto.Uint64(voters[0]),
		Commit: proto.Uint64(lastIndex),
	}
	require.NoError(t, store.SaveBatch(hs, entries, nil, lastIndex))

	if withConfState {
		require.NoError(t, store.SaveConfState(&raftpb.ConfState{Voters: voters}))
	}
	return store
}

// loadStateFor is the recovery half of NewRaftConsensus, isolated so the tests
// can inspect exactly what raft.RestartNode would be handed.
func loadStateFor(t *testing.T, store *RaftLogStore, peers []raft.Peer) (*raft.MemoryStorage, *raftpb.ConfState) {
	t.Helper()
	hs, entries, snap, applied, err := store.LoadState()
	require.NoError(t, err)

	storage := raft.NewMemoryStorage()
	if snap == nil || raft.IsEmptySnap(snap) {
		_, seedErr := seedConfStateSnapshot(storage, store, peers, entries, hs, applied)
		require.NoError(t, seedErr)
	}
	if len(entries) > 0 {
		toAppend := entries[:0:0]
		first, ferr := storage.FirstIndex()
		require.NoError(t, ferr)
		for _, e := range entries {
			if e.GetIndex() >= first {
				toAppend = append(toAppend, e)
			}
		}
		if len(toAppend) > 0 {
			require.NoError(t, storage.Append(toAppend))
		}
	}
	if hs != nil && !raft.IsEmptyHardState(hs) {
		require.NoError(t, storage.SetHardState(hs))
	}

	_, confState, err := storage.InitialState()
	require.NoError(t, err)
	return storage, confState
}

// TestRaftRestart_RestoresVoterSetFromPersistedConfState is the core guard: a
// node restarting from a persisted log must hand raft a populated voter set.
// Against the pre-fix code this returns no voters, which is precisely the
// "peers: []" that left the lab cluster permanently leaderless.
func TestRaftRestart_RestoresVoterSetFromPersistedConfState(t *testing.T) {
	t.Parallel()
	voters := []uint64{11, 22, 33}
	store := seedTestLogStore(t, t.TempDir(), voters, true)

	_, confState := loadStateFor(t, store, nil)

	require.NotEmpty(t, confState.GetVoters(),
		"a restarted node must recover its voter set; empty means raft starts with "+
			"peers: [] and no election can ever happen (Issue #3479)")
	assert.ElementsMatch(t, voters, confState.GetVoters(),
		"the recovered voter set must match what was persisted")
}

// TestRaftRestart_PreservesCommittedEntries guards the fix's main risk. The
// ConfState is injected via a synthetic snapshot, and MemoryStorage.ApplySnapshot
// discards entries up to the snapshot index — so the seed is placed at the
// applied index and everything above it must survive. Losing committed entries
// here would be a far worse bug than the one being fixed.
func TestRaftRestart_PreservesCommittedEntries(t *testing.T) {
	t.Parallel()
	store := seedTestLogStore(t, t.TempDir(), []uint64{11, 22, 33}, true)

	storage, _ := loadStateFor(t, store, nil)

	last, err := storage.LastIndex()
	require.NoError(t, err)
	assert.Equal(t, uint64(4), last,
		"the log must still reach its last committed index after the conf-state seed")

	hs, _, err := storage.InitialState()
	require.NoError(t, err)
	assert.Equal(t, uint64(4), hs.GetCommit(),
		"the recovered commit index must be preserved")
}

// TestRaftRestart_NoPersistedConfStateSeedsNothing covers the fresh-cluster and
// pre-#3479-store cases: with nothing persisted there is nothing to restore, and
// the node must fall through to the normal bootstrap path rather than being
// handed a fabricated membership.
func TestRaftRestart_NoPersistedConfStateSeedsNothing(t *testing.T) {
	t.Parallel()
	store := seedTestLogStore(t, t.TempDir(), []uint64{11, 22, 33}, false)

	_, confState := loadStateFor(t, store, nil)

	assert.Empty(t, confState.GetVoters(),
		"with no persisted ConfState the node must not invent one")
}

// TestRaftLogStore_ConfStateRoundTrip pins the persistence itself, including the
// "never written" case that a store created before this change will present.
func TestRaftLogStore_ConfStateRoundTrip(t *testing.T) {
	t.Parallel()
	store, err := OpenRaftLogStore(filepath.Join(t.TempDir(), "raft.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	got, err := store.LoadConfState()
	require.NoError(t, err)
	assert.Nil(t, got, "a store with no recorded ConfState must report nil, not an empty value")

	want := []uint64{7, 8, 9}
	require.NoError(t, store.SaveConfState(&raftpb.ConfState{Voters: want}))

	got, err = store.LoadConfState()
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.ElementsMatch(t, want, got.GetVoters())
}

// TestRaftRestart_LegacyStoreHealsFromConfiguredPeers covers the upgrade path.
// A store written before this change has a full log and no ConfState — exactly
// the wedged state found on the lab cluster. The configured peer list must heal
// it in place, so operators are not required to delete raft.db by hand.
func TestRaftRestart_LegacyStoreHealsFromConfiguredPeers(t *testing.T) {
	t.Parallel()
	store := seedTestLogStore(t, t.TempDir(), []uint64{11, 22, 33}, false)

	peers := []raft.Peer{{ID: 11}, {ID: 22}, {ID: 33}}
	_, confState := loadStateFor(t, store, peers)

	require.NotEmpty(t, confState.GetVoters(),
		"a pre-#3479 store must recover membership from the configured peers rather "+
			"than needing a manual raft.db wipe")
	assert.ElementsMatch(t, []uint64{11, 22, 33}, confState.GetVoters())
}
