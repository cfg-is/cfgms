//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ha

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoRawLeaderPrimitiveOutsidePkgHA enforces that IsRaftLeader() and the
// deprecated IsLeader() are never called outside pkg/ha without an explicit
// //architecture:allow-raw-leader annotation that states the reason.
//
// Outside pkg/ha, use HasLeadership() for all authority (admission) decisions.
// For status and observability handlers that genuinely need raw protocol state,
// annotate the call on the same line:
//
//	raftIsLeader := haManager.IsRaftLeader() //architecture:allow-raw-leader -- <reason>
//
// Known evasion limits: the rule detects method calls by name. It does not detect
// the raw primitive accessed through an interface that re-exposes it (IsRaftLeader
// is intentionally absent from ClusterManager, so this requires holding the
// concrete *Manager or *RaftConsensus type), nor through a local wrapper function
// that re-exposes IsRaftLeader under a different name. These limits are
// intentional — the rule catches the obvious direct call. Wrappers that smuggle the
// primitive should be treated as violations of the same intent.
func TestNoRawLeaderPrimitiveOutsidePkgHA(t *testing.T) {
	repoRoot := findHARepoRoot(t)
	haPkgPath := filepath.Join(repoRoot, "pkg", "ha")

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		// pkg/ha is the owning package; internal uses of IsRaftLeader/IsLeader are expected.
		if rel, relErr := filepath.Rel(haPkgPath, path); relErr == nil && !strings.HasPrefix(rel, "..") {
			return nil
		}

		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		fileViolations := checkForRawLeaderCalls(path, src)
		// Make paths relative to repo root for readable output.
		for _, v := range fileViolations {
			rel, relErr := filepath.Rel(repoRoot, strings.SplitN(v, ":", 2)[0])
			if relErr == nil {
				parts := strings.SplitN(v, ":", 2)
				if len(parts) == 2 {
					v = filepath.ToSlash(rel) + ":" + parts[1]
				}
			}
			violations = append(violations, v)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Empty(t, violations,
		"raw leader primitive (IsRaftLeader/IsLeader) called outside pkg/ha without "+
			"//architecture:allow-raw-leader annotation; use HasLeadership() for authority "+
			"decisions, or annotate observational call sites with the reason: %v", violations)
}

// findHARepoRoot walks up from the working directory to find the repository root.
func findHARepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (go.mod not found)")
		}
		dir = parent
	}
}
