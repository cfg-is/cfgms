// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"os"
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
// fileExists (integration.go) now genuinely probes the filesystem (Issue #3650), so the
// candidate file must actually exist under dir for this to find it.
func TestResolveWorkflowFilePath_RelativeSearchesPaths(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte("x"), 0o600))

	got, found := resolveWorkflowFilePath("deploy.yaml", []string{dir})

	require.True(t, found)
	assert.Equal(t, filepath.Join(dir, "deploy.yaml"), got, "a relative workflow file must be joined onto a search path, not honored verbatim")
}

// TestResolveWorkflowFilePath_RelativeSkipsMissingSearchPath is the Issue #3650
// regression: before the fix, fileExists always returned true, so the FIRST search path
// was always reported as a match even when the file only existed under a later one — a
// real correctness bug for any config with more than one workflowPaths entry, not just
// dead code.
func TestResolveWorkflowFilePath_RelativeSkipsMissingSearchPath(t *testing.T) {
	empty := t.TempDir()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "deploy.yaml"), []byte("x"), 0o600))

	got, found := resolveWorkflowFilePath("deploy.yaml", []string{empty, dir})

	require.True(t, found, "must fall through to the search path where the file actually exists")
	assert.Equal(t, filepath.Join(dir, "deploy.yaml"), got)
}

// TestResolveWorkflowFilePath_RelativeNotFoundWithNoSearchPaths is the paired negative
// case: with no search paths configured, a relative name cannot be resolved.
func TestResolveWorkflowFilePath_RelativeNotFoundWithNoSearchPaths(t *testing.T) {
	_, found := resolveWorkflowFilePath("missing.yaml", nil)
	assert.False(t, found)
}
