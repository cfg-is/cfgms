// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// UpgradeEvent is one record in the upgrade-history log. Emitted at
// each transition the orchestrator makes during a cutover, plus the
// retention pruner. Structured to match the existing CFGMS log
// pipeline so alerting can match on event_type.
//
// Field names use snake_case for JSON to match the controller's
// existing log marshalling conventions.
type UpgradeEvent struct {
	// EventType is the machine-readable event identifier. Defined
	// constants below cover the full set; new types should be added
	// here so consumers can match on a fixed enum.
	EventType string `json:"event_type"`

	// Timestamp is when the event was emitted (UTC).
	Timestamp time.Time `json:"timestamp"`

	// Component is "controller" or "steward".
	Component string `json:"component"`

	// BinaryPath is the path of the binary the event concerns. May be
	// empty for non-binary-specific events.
	BinaryPath string `json:"binary_path,omitempty"`

	// CanonicalBinary is the binary that was canonical at the moment
	// the event was emitted (may differ from BinaryPath for events
	// about candidates / quarantined targets).
	CanonicalBinary string `json:"canonical_binary,omitempty"`

	// PreviousBinary is the binary that WAS canonical before this
	// event (only meaningful for upgrade.committed / upgrade.rolled_back).
	PreviousBinary string `json:"previous_binary,omitempty"`

	// Reason is a human-readable explanation. For failure events,
	// this is the operator-actionable message.
	Reason string `json:"reason,omitempty"`

	// DurationMS is the duration of the operation in milliseconds,
	// where meaningful (e.g. smoketest_passed includes how long the
	// probe took).
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// Event types — exhaustive list. Maintain alphabetical order in the
// const block so it's easy to scan + grep.
const (
	EventStaged            = "upgrade.staged"             // Candidate binary validated, about to spawn.
	EventSmoketestPassed   = "upgrade.smoketest_passed"   // Smoketest probe returned healthy.
	EventSmoketestFailed   = "upgrade.smoketest_failed"   // Smoketest probe returned error.
	EventCommitted         = "upgrade.committed"          // Swap completed; new canonical serving.
	EventRolledBack        = "upgrade.rolled_back"        // Operator rollback restored previous binary.
	EventQuarantineExpired = "upgrade.quarantine_expired" // FinalizeQuarantine stopped parked backend.
	EventPruned            = "upgrade.pruned"             // Retention pruner deleted a binary.
	EventValidationFailed  = "upgrade.validation_failed"  // Validator rejected the binary.
	EventAborted           = "upgrade.aborted"            // ctx cancel during upgrade.
)

// History is a thread-safe append-only event log persisted to disk.
// Reads return events newest-first because that's the operator's most
// common access pattern ("what just happened?").
//
// Persisted as a JSON-lines file: one UpgradeEvent per line. Atomic
// append via O_APPEND so concurrent writers don't tear records.
type History struct {
	path string
	mu   sync.Mutex
}

// NewHistory binds a History to a file path. The file is created on
// first append. Caller is responsible for placing the path inside the
// controller's data directory so existing backup tooling captures it.
func NewHistory(path string) *History {
	return &History{path: path}
}

// Append writes the event to the history file. Returns nil on success;
// an error only when the file open / write fails (which the caller
// usually logs but doesn't fail the upgrade for — losing history is
// strictly worse than the operator losing a record, not worse than
// failing an upgrade).
func (h *History) Append(ev UpgradeEvent) (retErr error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if err := os.MkdirAll(filepath.Dir(h.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(h.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //#nosec G304 -- caller owns path
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && retErr == nil {
			retErr = cerr
		}
	}()
	raw, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return err
	}
	return nil
}

// Recent reads the last `limit` events from the history, newest first.
// Returns an empty slice if the file does not exist (caller treats
// this as "fresh install, no upgrades yet"). limit <= 0 returns all
// events.
func (h *History) Recent(limit int) ([]UpgradeEvent, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	raw, err := os.ReadFile(h.path) //#nosec G304 -- caller owns path
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	// Split on newlines, parse each non-empty line.
	var events []UpgradeEvent
	lineStart := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '\n' {
			if i > lineStart {
				line := raw[lineStart:i]
				if len(line) > 0 {
					var ev UpgradeEvent
					if jerr := json.Unmarshal(line, &ev); jerr != nil {
						return events, fmt.Errorf("history: parse line: %w", jerr)
					}
					events = append(events, ev)
				}
			}
			lineStart = i + 1
		}
	}
	// Newest first.
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.After(events[j].Timestamp) })
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}
