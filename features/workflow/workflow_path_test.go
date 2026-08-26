// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolveWorkflowFilePath_POSIXAbsoluteHonoredOnEveryPlatform is the Issue #3460
// regression: a WorkflowExecutionConfig.WorkflowFile authored as a POSIX path must be
// honored verbatim, not silently re-routed into the search-path branch, where
// filepath.IsAbs disagrees with filepath.IsAbs's own platform-specific answer on
// Windows (a rooted path with no volume name is not "absolute" there).
func TestResolveWorkflowFilePath_POSIXAbsoluteHonoredOnEveryPlatform(t *testing.T) {
	const posix = "/etc/cfgms/workflows/deploy.yaml"

	got, found := resolveWorkflowFilePath(posix, []string{"./workflows", "/usr/local/etc/cfgms/workflows"})

	require.True(t, found, "a rooted workflow file must be found without searching")
	assert.Equal(t, posix, got, "a rooted workflow file must be honored verbatim on %s", runtime.GOOS)
}

// TestResolveWorkflowFilePath_WindowsSpellingsHonored covers the separator and volume
// forms that only exist on Windows.
func TestResolveWorkflowFilePath_WindowsSpellingsHonored(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("volume-qualified and backslash-rooted paths are only meaningful on Windows")
	}
	for _, p := range []string{`C:\ProgramData\cfgms\workflows\deploy.yaml`, `\cfgms\workflows\deploy.yaml`} {
		got, found := resolveWorkflowFilePath(p, []string{"./workflows"})
		require.True(t, found, "%q must be found without searching", p)
		assert.Equal(t, p, got)
	}
}

// TestResolveWorkflowFilePath_RelativeSearchesPaths keeps the original behaviour intact:
// a bare/relative workflow file name is still resolved by joining it onto workflowPaths,
// not honored verbatim like a rooted path is.
//
// Note: fileExists (integration.go) does not actually probe the filesystem — a
// pre-existing, unrelated defect (it round-trips filepath.Abs twice and never returns
// false for a syntactically valid path) — so every candidate "exists." That defect is
// out of scope for #3460 (no filepath.IsAbs re-anchor decision involved); this test
// only asserts the search-vs-verbatim branch, using the always-true fileExists as a
// given rather than asserting real existence-checking.
func TestResolveWorkflowFilePath_RelativeSearchesPaths(t *testing.T) {
	dir := t.TempDir()

	got, found := resolveWorkflowFilePath("deploy.yaml", []string{dir})

	require.True(t, found)
	assert.Equal(t, filepath.Join(dir, "deploy.yaml"), got, "a relative workflow file must be joined onto a search path, not honored verbatim")
}

// TestResolveWorkflowFilePath_RelativeNotFoundWithNoSearchPaths is the paired negative
// case: with no search paths configured, a relative name cannot be resolved.
func TestResolveWorkflowFilePath_RelativeNotFoundWithNoSearchPaths(t *testing.T) {
	_, found := resolveWorkflowFilePath("missing.yaml", nil)
	assert.False(t, found)
}
