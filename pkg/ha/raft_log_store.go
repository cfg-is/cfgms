// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package ha

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
	"go.etcd.io/raft/v3"
	"go.etcd.io/raft/v3/raftpb"
)

var (
	bucketHardState = []byte("hardstate")
	bucketEntries   = []byte("entries")
	bucketSnapshot  = []byte("snapshot")
	bucketApplied   = []byte("applied")

	keyHardState = []byte("hs")
	keySnapshot  = []byte("snap")
	keyApplied   = []byte("idx")
)

// RaftLogStore persists Raft log entries, HardState, and snapshots to a bbolt
// database so a restarting controller node can rejoin its live cluster instead
// of re-bootstrapping from the configured peer list. See ADR-028.
//
// Layout:
//
//	hardstate/hs  — serialised raftpb.HardState (term, vote, commit)
//	entries/<idx> — serialised raftpb.Entry keyed by big-endian uint64 index
//	snapshot/snap — serialised raftpb.Snapshot
//	applied/idx   — last applied index (big-endian uint64)
//
// One bbolt.Update transaction per Ready batch gives a single fsync and is
// atomic: a crash leaves the previous committed state intact, not a torn write.
type RaftLogStore struct {
	db *bbolt.DB
}

// OpenRaftLogStore opens (or creates) the bbolt database at path. Parent
// directories are created with mode 0700; the database file uses mode 0600.
// Returns an error if the file exists but is not a valid bbolt database.
func OpenRaftLogStore(path string) (*RaftLogStore, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create raft log dir: %w", err)
	}
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("open raft log store at %s: %w", path, err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		for _, name := range [][]byte{bucketHardState, bucketEntries, bucketSnapshot, bucketApplied} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialise raft log store buckets: %w", err)
	}
	return &RaftLogStore{db: db}, nil
}

// Close closes the underlying bbolt database. Safe to call on a nil receiver.
func (s *RaftLogStore) Close() error {
	if s == nil {
		return nil
	}
	return s.db.Close()
}

// HasData reports whether any HardState or log entries have been persisted.
// Used at startup to choose between StartNode (fresh cluster) and RestartNode
// (recovering existing state).
func (s *RaftLogStore) HasData() bool {
	var has bool
	_ = s.db.View(func(tx *bbolt.Tx) error {
		if b := tx.Bucket(bucketHardState); b != nil && b.Get(keyHardState) != nil {
			has = true
			return nil
		}
		if e := tx.Bucket(bucketEntries); e != nil && e.Stats().KeyN > 0 {
			has = true
		}
		return nil
	})
	return has
}

// SaveBatch durably persists HardState, new log entries, and an optional
// snapshot in a single fsync-on-commit bbolt transaction. applied is the
// state machine's last applied index at the point the batch is built; it is
// stored so the next boot can set raft.Config.Applied correctly.
//
// Zero-value HardState and empty entries slices are skipped. A snapshot
// is skipped when raft.IsEmptySnap returns true. A zero applied value is
// stored only when the previous value would be overwritten by a larger one.
func (s *RaftLogStore) SaveBatch(hs raftpb.HardState, entries []raftpb.Entry, snap raftpb.Snapshot, applied uint64) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		if !raft.IsEmptyHardState(hs) {
			data, err := hs.Marshal()
			if err != nil {
				return fmt.Errorf("marshal HardState: %w", err)
			}
			if err := tx.Bucket(bucketHardState).Put(keyHardState, data); err != nil {
				return fmt.Errorf("put HardState: %w", err)
			}
		}

		if len(entries) > 0 {
			b := tx.Bucket(bucketEntries)
			for i := range entries {
				data, err := entries[i].Marshal()
				if err != nil {
					return fmt.Errorf("marshal entry index %d: %w", entries[i].Index, err)
				}
				if err := b.Put(encodeIndex(entries[i].Index), data); err != nil {
					return fmt.Errorf("put entry index %d: %w", entries[i].Index, err)
				}
			}
		}

		if !raft.IsEmptySnap(snap) {
			data, err := snap.Marshal()
			if err != nil {
				return fmt.Errorf("marshal snapshot: %w", err)
			}
			if err := tx.Bucket(bucketSnapshot).Put(keySnapshot, data); err != nil {
				return fmt.Errorf("put snapshot: %w", err)
			}
		}

		if applied > 0 {
			b := tx.Bucket(bucketApplied)
			existing := b.Get(keyApplied)
			if existing == nil || decodeIndex(existing) < applied {
				if err := b.Put(keyApplied, encodeIndex(applied)); err != nil {
					return fmt.Errorf("put applied index: %w", err)
				}
			}
		}

		return nil
	})
}

// LoadState reads all persisted state from the database and returns the
// HardState, log entries (in ascending index order), latest snapshot, and the
// last saved applied index. Returns zero-value outputs (not an error) when no
// state has been saved yet; that is the normal first-boot condition.
func (s *RaftLogStore) LoadState() (raftpb.HardState, []raftpb.Entry, raftpb.Snapshot, uint64, error) {
	var (
		hs      raftpb.HardState
		entries []raftpb.Entry
		snap    raftpb.Snapshot
		applied uint64
	)

	if err := s.db.View(func(tx *bbolt.Tx) error {
		if b := tx.Bucket(bucketHardState); b != nil {
			if data := b.Get(keyHardState); data != nil {
				if err := hs.Unmarshal(data); err != nil {
					return fmt.Errorf("unmarshal HardState: %w", err)
				}
			}
		}

		if b := tx.Bucket(bucketEntries); b != nil {
			if err := b.ForEach(func(_, v []byte) error {
				var e raftpb.Entry
				if err := e.Unmarshal(v); err != nil {
					return fmt.Errorf("unmarshal log entry: %w", err)
				}
				entries = append(entries, e)
				return nil
			}); err != nil {
				return err
			}
		}

		if b := tx.Bucket(bucketSnapshot); b != nil {
			if data := b.Get(keySnapshot); data != nil {
				if err := snap.Unmarshal(data); err != nil {
					return fmt.Errorf("unmarshal snapshot: %w", err)
				}
			}
		}

		if b := tx.Bucket(bucketApplied); b != nil {
			if data := b.Get(keyApplied); data != nil {
				applied = decodeIndex(data)
			}
		}

		return nil
	}); err != nil {
		return raftpb.HardState{}, nil, raftpb.Snapshot{}, 0, err
	}

	return hs, entries, snap, applied, nil
}

// encodeIndex returns idx as a big-endian 8-byte slice so bbolt cursor
// iteration over the entries bucket is in ascending log-index order.
func encodeIndex(idx uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, idx)
	return b
}

func decodeIndex(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}
