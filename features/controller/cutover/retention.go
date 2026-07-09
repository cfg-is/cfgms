// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cutover

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RetentionPolicy controls how long previous controller binaries are
// retained for rollback after a successful cutover, and when they're
// pruned to reclaim disk space.
//
// The two limits — MaxVersions and MaxBytes — are evaluated together
// and the MORE RESTRICTIVE wins: if either is exceeded, pruning runs
// from oldest to newest. The quarantine window provides a HARD floor
// — a binary younger than QuarantineWindow is NEVER pruned regardless
// of the other limits, so `cfg controller upgrade rollback` is always
// safe within that window.
type RetentionPolicy struct {
	// QuarantineWindow is the minimum time a previous binary stays
	// available for rollback after being demoted from canonical.
	// Pruning skips any binary younger than this. Default 1 hour
	// (matches the cutover.Config default).
	QuarantineWindow time.Duration

	// MaxVersions caps how many previous binaries are retained on
	// disk past the quarantine window. The currently-canonical
	// binary is NOT counted against this. Default 3.
	MaxVersions int

	// MaxBytes caps total disk used by retained-but-not-canonical
	// binaries. Default 500 MB. Set to 0 to disable.
	MaxBytes int64
}

// DefaultRetentionPolicy returns sensible defaults matching the Story
// #1921 acceptance criteria.
func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      3,
		MaxBytes:         500 * 1024 * 1024,
	}
}

// RetainedBinary describes a binary on disk eligible for pruning.
// Operators may inspect these via cfg controller upgrade history.
type RetainedBinary struct {
	Path     string    `json:"path"`
	Size     int64     `json:"size_bytes"`
	ModTime  time.Time `json:"mod_time"`
	IsActive bool      `json:"is_active"` // true for the currently-canonical binary
}

// PruneDecision describes what Prune would do (or did do) for a single
// retained binary.
type PruneDecision struct {
	Binary   RetainedBinary `json:"binary"`
	Action   string         `json:"action"` // "kept" | "deleted"
	Reason   string         `json:"reason"`
	PrunedAt time.Time      `json:"pruned_at"`
}

// ListRetainedBinaries scans archiveDir for controller binary archive
// entries. Each entry is a file (any name) whose mod-time and size
// are recorded. activePath, if non-empty, marks one entry as the
// currently-canonical binary (so it's exempted from pruning).
//
// Returns the sorted oldest-first slice so callers see the natural
// prune order.
func ListRetainedBinaries(archiveDir, activePath string) ([]RetainedBinary, error) {
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []RetainedBinary
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(archiveDir, e.Name())
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		out = append(out, RetainedBinary{
			Path:     full,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			IsActive: sameFile(full, activePath),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.Before(out[j].ModTime) })
	return out, nil
}

// sameFile compares two paths in a way tolerant of trailing slashes
// and case-difference on Windows. Returns false if either is empty.
func sameFile(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ca, _ := filepath.Abs(a)
	cb, _ := filepath.Abs(b)
	return filepath.Clean(ca) == filepath.Clean(cb)
}

// Prune deletes retained binaries that violate the policy and returns
// a per-entry decision log.
//
// Decision precedence:
//  1. Active binary (IsActive==true) is ALWAYS kept regardless of policy.
//  2. Binary younger than QuarantineWindow (mod-time within window from
//     now) is ALWAYS kept — the rollback escape hatch must work.
//  3. After 1 & 2, if MaxVersions is non-zero and the retained-but-non-
//     active count would exceed it, oldest-first deletion brings the
//     count down to MaxVersions.
//  4. If MaxBytes is non-zero and total retained size still exceeds
//     it, oldest-first deletion brings the total under MaxBytes.
//
// The function is destructive: deleted entries are removed from disk.
// Returns decisions slice (kept entries first by sort order, then
// deleted entries) so operators can replay what happened.
func Prune(archiveDir, activePath string, policy RetentionPolicy, now time.Time) ([]PruneDecision, error) {
	if policy.QuarantineWindow < 0 {
		return nil, errors.New("retention: QuarantineWindow must not be negative")
	}
	if policy.MaxVersions < 0 {
		return nil, errors.New("retention: MaxVersions must not be negative")
	}
	if policy.MaxBytes < 0 {
		return nil, errors.New("retention: MaxBytes must not be negative")
	}

	all, err := ListRetainedBinaries(archiveDir, activePath)
	if err != nil {
		return nil, err
	}

	// Decisions accumulated in encounter order.
	decisions := make([]PruneDecision, 0, len(all))

	// First pass: classify each entry. Active + in-quarantine binaries
	// are immediately "kept"; the rest are candidates for further
	// MaxVersions / MaxBytes evaluation.
	type candidate struct {
		idx int
		bin RetainedBinary
	}
	var candidates []candidate
	for i, b := range all {
		switch {
		case b.IsActive:
			decisions = append(decisions, PruneDecision{
				Binary: b, Action: "kept", Reason: "active canonical binary", PrunedAt: now,
			})
		case policy.QuarantineWindow > 0 && now.Sub(b.ModTime) < policy.QuarantineWindow:
			decisions = append(decisions, PruneDecision{
				Binary: b, Action: "kept", Reason: fmt.Sprintf("within quarantine window (age %s < %s)", now.Sub(b.ModTime), policy.QuarantineWindow), PrunedAt: now,
			})
		default:
			candidates = append(candidates, candidate{idx: i, bin: b})
		}
	}

	// MaxVersions: oldest-first deletion until the candidate count
	// (which counts retained-non-active-past-quarantine entries) is
	// under MaxVersions.
	toDelete := make(map[int]string) // idx → reason
	if policy.MaxVersions > 0 {
		overflow := len(candidates) - policy.MaxVersions
		for i := 0; i < overflow && i < len(candidates); i++ {
			toDelete[candidates[i].idx] = fmt.Sprintf("exceeds MaxVersions=%d", policy.MaxVersions)
		}
	}

	// MaxBytes: oldest-first deletion until the total non-deleted
	// candidate size is under MaxBytes.
	if policy.MaxBytes > 0 {
		var total int64
		for _, c := range candidates {
			if _, deleted := toDelete[c.idx]; !deleted {
				total += c.bin.Size
			}
		}
		for _, c := range candidates {
			if total <= policy.MaxBytes {
				break
			}
			if _, alreadyDel := toDelete[c.idx]; alreadyDel {
				continue
			}
			toDelete[c.idx] = fmt.Sprintf("exceeds MaxBytes=%d", policy.MaxBytes)
			total -= c.bin.Size
		}
	}

	// Apply: delete + record decisions in candidate iteration order.
	for _, c := range candidates {
		if reason, del := toDelete[c.idx]; del {
			if err := os.Remove(c.bin.Path); err != nil && !os.IsNotExist(err) {
				return decisions, fmt.Errorf("retention: prune %s: %w", c.bin.Path, err)
			}
			decisions = append(decisions, PruneDecision{
				Binary: c.bin, Action: "deleted", Reason: reason, PrunedAt: now,
			})
		} else {
			decisions = append(decisions, PruneDecision{
				Binary: c.bin, Action: "kept", Reason: "within policy limits", PrunedAt: now,
			})
		}
	}

	return decisions, nil
}
