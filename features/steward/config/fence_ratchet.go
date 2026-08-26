// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const fenceRatchetFileName = "fence_ratchet.json"

// FenceRatchet persists the Raft-term fence ratchet state across steward
// process restarts (Story #3437, ADR-029 Decision 6). Two fields survive:
// the ratchet-set flag and the highest Raft term observed from the controller.
//
// The zero value (dir = "") is valid: Load returns zero values and Save/ClearRatchet
// are no-ops — the ratchet operates in-memory only, matching pre-#3437 behaviour.
//
// FenceRatchet is safe for concurrent use, and this is load-bearing rather than
// incidental: inbound commands are dispatched one goroutine per command
// (pkg/controlplane/providers/grpc/provider.go), so several accepted commands can
// reach Save at once. Every method serializes on mu, which gives two guarantees
// the fence depends on:
//
//  1. No interleaved writes. Each save creates its own temp file (os.CreateTemp)
//     and renames it over the target under mu, so a concurrent saver can never
//     publish a truncated file that would make the next boot's Load fail — a
//     failed Load leaves the fence fully open.
//  2. Monotonicity. The persisted high-water term never decreases (see Save).
//     Without this, two concurrent saves for terms 10 and 11 could land on disk
//     in either order and leave 10 behind, re-opening the restart-downgrade this
//     story exists to close.
type FenceRatchet struct {
	dir string

	mu sync.Mutex
	// savedSet / savedTerm mirror the state believed to be on disk, and are the
	// reference for Save's monotonic guard. They are seeded lazily from disk by
	// loadStateLocked so the guard holds even when Save is the first call made on
	// a freshly constructed FenceRatchet (e.g. after a Load error at startup).
	savedSet  bool
	savedTerm uint64
	// seeded records that savedSet/savedTerm reflect disk, so the seeding read
	// happens at most once per process.
	seeded bool
}

// fenceRatchetState is the on-disk JSON format.
type fenceRatchetState struct {
	RatchetSet      bool   `json:"ratchet_set"`
	HighestTermSeen uint64 `json:"highest_term_seen"`
}

// NewFenceRatchet returns a FenceRatchet backed by a file in dir.
// Pass an empty dir for in-memory-only operation (no I/O on any method).
func NewFenceRatchet(dir string) *FenceRatchet {
	return &FenceRatchet{dir: dir}
}

func (r *FenceRatchet) filePath() string {
	return filepath.Join(r.dir, fenceRatchetFileName)
}

// Load reads persisted ratchet state from disk. Returns (false, 0, nil) when
// no state file exists (first boot after upgrade, or after ClearRatchet).
func (r *FenceRatchet) Load() (ratchetSet bool, highestTermSeen uint64, err error) {
	if r == nil || r.dir == "" {
		return false, 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	state, err := r.loadStateLocked()
	if err != nil {
		return false, 0, err
	}
	return state.RatchetSet, state.HighestTermSeen, nil
}

// loadStateLocked reads the on-disk state and seeds the monotonic guard from it.
// A missing file yields the zero state. Callers must hold mu.
func (r *FenceRatchet) loadStateLocked() (fenceRatchetState, error) {
	var state fenceRatchetState

	data, readErr := os.ReadFile(r.filePath())
	if os.IsNotExist(readErr) {
		r.savedSet, r.savedTerm, r.seeded = false, 0, true
		return state, nil
	}
	if readErr != nil {
		return fenceRatchetState{}, fmt.Errorf("read fence ratchet: %w", readErr)
	}

	if unmarshalErr := json.Unmarshal(data, &state); unmarshalErr != nil {
		return fenceRatchetState{}, fmt.Errorf("parse fence ratchet: %w", unmarshalErr)
	}

	r.savedSet, r.savedTerm, r.seeded = state.RatchetSet, state.HighestTermSeen, true
	return state, nil
}

// Save persists the ratchet state atomically and monotonically.
//
// Atomically: the payload goes to a uniquely named temp file in the same
// directory (os.CreateTemp — never a fixed ".tmp" path, which two concurrent
// savers would truncate under each other) and is renamed over the target, so a
// reader never observes a partial write.
//
// Monotonically: Save never lowers the persisted state. A call carrying a term
// below the stored high-water mark, or ratchetSet=false once the ratchet is set,
// is a no-op returning nil. This is what makes Save safe to call from the
// per-command goroutines: two accepted commands for terms 10 and 11 may reach
// Save in either order, and the file still ends at 11. Resetting the ratchet is
// ClearRatchet's job, not a low Save's.
//
// Save is a no-op when dir is empty.
func (r *FenceRatchet) Save(ratchetSet bool, highestTermSeen uint64) error {
	if r == nil || r.dir == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.seeded {
		// Seed the guard from disk so a Save issued before any Load (or after a
		// Load that failed) cannot overwrite a higher persisted term.
		if _, err := r.loadStateLocked(); err != nil {
			// Unreadable or corrupt on-disk state carries no high-water mark worth
			// preserving; overwriting it with the current state is a repair, and
			// treating this instance as seeded keeps the guard active from here on.
			r.savedSet, r.savedTerm, r.seeded = false, 0, true
		}
	}

	if r.savedSet && (!ratchetSet || highestTermSeen < r.savedTerm) {
		return nil
	}

	data, err := json.Marshal(fenceRatchetState{
		RatchetSet:      ratchetSet,
		HighestTermSeen: highestTermSeen,
	})
	if err != nil {
		return fmt.Errorf("marshal fence ratchet: %w", err)
	}

	tmpFile, err := os.CreateTemp(r.dir, fenceRatchetFileName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create fence ratchet tmp: %w", err)
	}
	tmpPath := tmpFile.Name()

	// discardTmp removes an abandoned temp file and folds a removal failure into
	// the returned error, so leaked temp files are reported rather than quietly
	// accumulating in the cert-store directory.
	discardTmp := func(cause error) error {
		if rmErr := os.Remove(tmpPath); rmErr != nil && !os.IsNotExist(rmErr) {
			return errors.Join(cause, fmt.Errorf("remove fence ratchet tmp: %w", rmErr))
		}
		return cause
	}

	if _, writeErr := tmpFile.Write(data); writeErr != nil {
		return discardTmp(errors.Join(
			fmt.Errorf("write fence ratchet tmp: %w", writeErr),
			tmpFile.Close(),
		))
	}
	// Close before rename so the bytes are handed to the filesystem, and so the
	// rename does not publish a file with a write error still pending.
	if closeErr := tmpFile.Close(); closeErr != nil {
		return discardTmp(fmt.Errorf("close fence ratchet tmp: %w", closeErr))
	}
	// os.CreateTemp already creates the file with mode 0600, so no chmod is needed.
	if renameErr := os.Rename(tmpPath, r.filePath()); renameErr != nil {
		return discardTmp(fmt.Errorf("rename fence ratchet: %w", renameErr))
	}

	r.savedSet, r.savedTerm = ratchetSet, highestTermSeen
	return nil
}

// ClearRatchet removes the persisted ratchet state so the fence starts fresh
// on the next steward startup. Its only production caller is the enrollment
// completion path in features/steward/registration (Story #3437), which clears
// the ratchet only after verifying the certificate set the enrollment exchange
// returned. This isolation is enforced by the AST-walk test in
// features/steward/registration/architecture_test.go.
//
// Safety contingency: the reset's effectiveness against a network-positioned
// adversary depends on a forthcoming story that closes the registration-gating
// gap — see docs/architecture/steward-operating-model.md §Raft-Term Command
// Fence for the contingency statement. The reset is safe against the failure
// modes this story exists for: a routine steward restart and a legitimate
// controller-cluster rebuild.
func (r *FenceRatchet) ClearRatchet() error {
	if r == nil || r.dir == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	err := os.Remove(r.filePath())
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// The reset is the one sanctioned way past Save's monotonic guard: drop the
	// remembered high-water mark so the next Save starts the ratchet fresh.
	r.savedSet, r.savedTerm, r.seeded = false, 0, true
	return nil
}
