// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PersistedState records the orchestrator's last-known canonical and
// quarantined binaries on disk so the cfg CLI can read them between
// invocations. Without this file, `cfg controller status` would have
// no way to report which version is serving and `cfg controller
// rollback` would have no rollback target.
//
// Schema is intentionally tiny — just the binary paths and timestamps.
// The orchestrator's runtime state (current State, ProcessHandle
// pointers, etc.) is reconstructed by the caller from this snapshot.
type PersistedState struct {
	CanonicalBinary      string    `json:"canonical_binary"`
	CanonicalStartedAt   time.Time `json:"canonical_started_at"`
	QuarantinedBinary    string    `json:"quarantined_binary,omitempty"`
	QuarantinedStartedAt time.Time `json:"quarantined_started_at,omitempty"`
	QuarantineExpiresAt  time.Time `json:"quarantine_expires_at,omitempty"`
}

// LoadPersistedState reads the file at path. Returns (zero-value, nil)
// if the file does not exist — callers treat that as "fresh install,
// no upgrade has run yet."
func LoadPersistedState(path string) (PersistedState, error) {
	raw, err := os.ReadFile(path) //#nosec G304 -- caller owns path
	if err != nil {
		if os.IsNotExist(err) {
			return PersistedState{}, nil
		}
		return PersistedState{}, err
	}
	var ps PersistedState
	if err := json.Unmarshal(raw, &ps); err != nil {
		return PersistedState{}, fmt.Errorf("cutover: parse state file %s: %w", path, err)
	}
	return ps, nil
}

// SavePersistedState writes the snapshot atomically via temp + rename.
// Crash-safe on every supported OS.
func SavePersistedState(path string, ps PersistedState) error {
	if path == "" {
		return errors.New("cutover: state path must not be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(ps, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	success := false
	defer func() {
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	success = true
	return nil
}

// SnapshotToPersisted converts a Snapshot (orchestrator's in-memory
// view) into a PersistedState (on-disk shape). Used after a successful
// Upgrade / Rollback / FinalizeQuarantine to flush state to disk.
func SnapshotToPersisted(s Snapshot) PersistedState {
	return PersistedState{
		CanonicalBinary:      s.CanonicalBinary,
		CanonicalStartedAt:   s.CanonicalStartedAt,
		QuarantinedBinary:    s.QuarantinedBinary,
		QuarantinedStartedAt: s.QuarantinedStartedAt,
		QuarantineExpiresAt:  s.QuarantineExpiresAt,
	}
}

// SetQuarantinedForRollback seeds the orchestrator's quarantined slot
// from persisted state. Used by `cfg controller rollback`: the CLI
// process is fresh and has no in-memory knowledge of the previous
// upgrade, so it loads the quarantined binary path from disk and uses
// this helper to put the orchestrator into StateQuarantined before
// calling Rollback().
//
// ONLY safe to call when the orchestrator is freshly-constructed (still
// in StateIdle and with no in-flight upgrade). The helper transitions
// the orchestrator to StateQuarantined under the lock and is a no-op
// if the state machine is anywhere else, since interrupting an
// in-flight upgrade with a quarantine reseed would corrupt the state
// machine's invariants.
func SetQuarantinedForRollback(o *Orchestrator, quarantined ProcessHandle, startedAt, expiresAt time.Time) {
	if o == nil || quarantined == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.state != StateIdle {
		return
	}
	o.quarantined = quarantined
	o.quarantinedStartedAt = startedAt
	o.quarantineExpiresAt = expiresAt
	o.state = StateQuarantined
}
