// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// RetentionPolicy controls how long previous steward version directories are
// retained for rollback after a successful startup, and when they are pruned
// to reclaim disk space.
//
// The two limits — MaxVersions and MaxBytes — are evaluated together and the
// MORE RESTRICTIVE wins. The quarantine window provides a HARD floor — a
// version directory younger than QuarantineWindow is NEVER pruned regardless
// of the other limits, so rollback is always safe within that window.
type RetentionPolicy struct {
	// QuarantineWindow is the minimum time a previous version directory stays
	// available for rollback after being superseded. Default 1 hour.
	QuarantineWindow time.Duration

	// MaxVersions caps how many previous version directories are retained on
	// disk past the quarantine window. The currently-active version is NOT
	// counted. Default 3.
	MaxVersions int

	// MaxBytes caps total disk used by retained-but-not-active version
	// directories. Default 500 MB. Set to 0 to disable.
	MaxBytes int64
}

func defaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		QuarantineWindow: time.Hour,
		MaxVersions:      3,
		MaxBytes:         500 * 1024 * 1024,
	}
}

// retainedVersion describes a version directory on disk eligible for pruning.
type retainedVersion struct {
	Name     string
	Path     string
	Size     int64
	ModTime  time.Time
	IsActive bool
}

// pruneDecision records what pruneVersions did (or decided to do) for a
// single version directory.
type pruneDecision struct {
	Version retainedVersion
	Action  string // "kept" | "deleted"
	Reason  string
}

// pruneVersions deletes version directories that violate the policy and
// returns a per-entry decision log.
//
// The launcher's versions/ dir holds one SUBDIRECTORY per version
// (<Root>/versions/<name>/…). The active version is identified by comparing
// the directory name to activeVersion (from Layout.ReadCurrent()), NOT by
// file-path/sameFile comparison.
//
// Decision precedence mirrors features/controller/cutover/retention.go:
//  1. Active version is ALWAYS kept regardless of policy.
//  2. Version younger than QuarantineWindow is ALWAYS kept.
//  3. If MaxVersions is non-zero and the count of retained-non-active
//     candidates exceeds it, oldest-first deletion brings the count down.
//  4. If MaxBytes is non-zero and total retained size exceeds it,
//     oldest-first deletion brings the total under MaxBytes.
//
// Prune is best-effort: callers log errors from this function but must not
// abort the supervision loop.
func pruneVersions(versionsDir, activeVersion string, policy RetentionPolicy, now time.Time) ([]pruneDecision, error) {
	if policy.QuarantineWindow < 0 {
		return nil, errors.New("retention: QuarantineWindow must not be negative")
	}
	if policy.MaxVersions < 0 {
		return nil, errors.New("retention: MaxVersions must not be negative")
	}
	if policy.MaxBytes < 0 {
		return nil, errors.New("retention: MaxBytes must not be negative")
	}

	entries, err := os.ReadDir(versionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var all []retainedVersion
	for _, e := range entries {
		if !e.IsDir() {
			continue // flat files in versions/ are not version units
		}
		full := filepath.Join(versionsDir, e.Name())
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		sz, _ := dirTotalSize(full) // best-effort; zero counts for nothing under MaxBytes
		all = append(all, retainedVersion{
			Name:     e.Name(),
			Path:     full,
			Size:     sz,
			ModTime:  info.ModTime(),
			IsActive: e.Name() == activeVersion,
		})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ModTime.Before(all[j].ModTime) })

	decisions := make([]pruneDecision, 0, len(all))

	type candidate struct {
		idx int
		ver retainedVersion
	}
	var candidates []candidate
	for i, v := range all {
		switch {
		case v.IsActive:
			decisions = append(decisions, pruneDecision{Version: v, Action: "kept", Reason: "active version"})
		case policy.QuarantineWindow > 0 && now.Sub(v.ModTime) < policy.QuarantineWindow:
			decisions = append(decisions, pruneDecision{
				Version: v, Action: "kept",
				Reason: fmt.Sprintf("within quarantine window (age %s < %s)", now.Sub(v.ModTime), policy.QuarantineWindow),
			})
		default:
			candidates = append(candidates, candidate{idx: i, ver: v})
		}
	}

	toDelete := make(map[int]string) // idx → reason

	if policy.MaxVersions > 0 {
		overflow := len(candidates) - policy.MaxVersions
		for i := 0; i < overflow && i < len(candidates); i++ {
			toDelete[candidates[i].idx] = fmt.Sprintf("exceeds MaxVersions=%d", policy.MaxVersions)
		}
	}

	if policy.MaxBytes > 0 {
		var total int64
		for _, c := range candidates {
			if _, deleted := toDelete[c.idx]; !deleted {
				total += c.ver.Size
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
			total -= c.ver.Size
		}
	}

	for _, c := range candidates {
		if reason, del := toDelete[c.idx]; del {
			if rmErr := os.RemoveAll(c.ver.Path); rmErr != nil && !os.IsNotExist(rmErr) {
				return decisions, fmt.Errorf("retention: prune %s: %w", c.ver.Path, rmErr)
			}
			decisions = append(decisions, pruneDecision{Version: c.ver, Action: "deleted", Reason: reason})
		} else {
			decisions = append(decisions, pruneDecision{Version: c.ver, Action: "kept", Reason: "within policy limits"})
		}
	}

	return decisions, nil
}

// dirTotalSize sums the sizes of all regular files directly under dir.
// One level deep is sufficient — each version dir contains exactly one binary.
func dirTotalSize(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		total += info.Size()
	}
	return total, nil
}
