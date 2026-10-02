//go:build linux

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package ctxkeys_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRootScope_RestrictedCaller enforces the restricted-caller rule for
// ctxkeys.NewRootScope (Issue #4316). Any production file outside the allow-list that
// calls ctxkeys.NewRootScope fails this test. Test files (_test.go) are excluded —
// they are test infrastructure, not production code paths.
//
// The risk this guards is the same shape as pkg/cert's TestSetRootScopeMarker_Architecture:
// NewRootScope grants unrestricted, cross-tenant access, so an unauthorized caller is a
// privilege-escalation risk exactly of the kind this story exists to close — a context
// value that means "root, allow everything" must only ever be produced from a verified
// admin certificate marker, in one auditable place, not constructed ad hoc wherever a
// caller happens to want unrestricted access.
func TestNewRootScope_RestrictedCaller(t *testing.T) {
	allowList := map[string]bool{
		// Issue #4316: the authentication middleware constructs root scope only after
		// extractAdminPrincipal has independently verified the caller's mTLS certificate
		// carries the CFGMS admin marker (cert.HasAdminMarker) and is not revoked.
		"features/controller/api/middleware.go": true,
	}

	repoRoot := findRepoRoot(t)

	var violations []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip agent dispatch worktrees — they contain nested repo copies from
			// /dispatch agents and are not part of this checkout's source. Skip the
			// in-tree module cache — GOMODCACHE is set to .cache/go-mod inside the
			// working tree, and third-party code there is not first-party.
			if d.Name() == "worktrees" || d.Name() == ".cache" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		content, readErr := os.ReadFile(path) // #nosec G304 -- repo scan reads controlled source files
		if readErr != nil {
			return nil
		}
		if bytes.Contains(content, []byte("ctxkeys.NewRootScope")) {
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				rel = path
			}
			rel = filepath.ToSlash(rel)
			if !allowList[rel] {
				violations = append(violations, rel)
			}
		}
		return nil
	})
	require.NoError(t, err)

	assert.Empty(t, violations,
		"unauthorized production callers of ctxkeys.NewRootScope; "+
			"add to allow-list only alongside an equivalent verified-certificate check, "+
			"or move the call to an allowed file: %v", violations)
}

// findRepoRoot walks up from the working directory to find the repository root (go.mod presence).
func findRepoRoot(t *testing.T) string {
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
