// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNoIsAdminInGoSource verifies that Principal.IsAdmin has been fully deleted
// from all non-test Go source files. Any hit means a site was missed during the
// migration to principal.Assurance >= session.AssuranceBasic (Issue #2781).
//
// This runs as a CI-runnable check rather than a manual grep step.
func TestNoIsAdminInGoSource(t *testing.T) {
	repoRoot := findRepoRoot(t)

	// grep -rn '\.IsAdmin\b' --include=*.go, then filter out _test.go and docs/.
	cmd := exec.Command("grep", "-rn", `\.IsAdmin\b`, "--include=*.go", repoRoot)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		// grep exits 1 when no matches found — that is the success case.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return // zero hits — correct
		}
		require.NoError(t, err, "grep failed unexpectedly: %s", out.String())
	}

	// grep exited 0 → matches found. Filter out test files and docs/.
	lines := bytes.Split(bytes.TrimSpace(out.Bytes()), []byte("\n"))
	var violations []string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		s := string(line)
		if isTestFile(s) || isDocsPath(s) {
			continue
		}
		violations = append(violations, s)
	}

	assert.Empty(t, violations,
		"Principal.IsAdmin must be fully deleted from non-test Go source files (Issue #2781).\n"+
			"Found %d remaining site(s):\n%s",
		len(violations), bytes.Join(func() [][]byte {
			var bs [][]byte
			for _, v := range violations {
				bs = append(bs, []byte("  "+v))
			}
			return bs
		}(), []byte("\n")))
}

// findRepoRoot walks up from the current source file until it finds go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller must succeed")

	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found walking up from test file)")
		}
		dir = parent
	}
}

// extractGrepPath returns the file path portion of a grep output line.
//
// grep output format: path:linenum:match
//
// On Windows, the path may begin with a drive-letter prefix such as "D:\",
// so the first ':' in the line is the drive colon, not the path/linenum separator.
// We detect this case (single ASCII letter followed by ':') and skip over the
// volume prefix before scanning for the real separator colon.
func extractGrepPath(line string) string {
	start := 0
	// Windows volume prefix: single ASCII letter + ':' (e.g. "D:").
	if len(line) >= 2 && line[1] == ':' && isASCIILetter(line[0]) {
		start = 2
	}
	for i := start; i < len(line); i++ {
		if line[i] == ':' {
			return line[:i]
		}
	}
	return line
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// isTestFile reports whether the grep output line references a _test.go file.
func isTestFile(line string) bool {
	return containsTestSuffix(extractGrepPath(line))
}

func containsTestSuffix(path string) bool {
	base := filepath.Base(path)
	return len(base) > 8 && base[len(base)-8:] == "_test.go"
}

// isDocsPath reports whether the grep output line refers to a file under docs/.
func isDocsPath(line string) bool {
	path := extractGrepPath(line)
	rel := filepath.ToSlash(path)
	// Require the full directory boundary: "/docs/" or a relative path starting "docs/".
	// Checking "/docs/" (6 chars) avoids false positives from filenames like
	// "features/config/docstore.go" which contain "/docs" without being in docs/.
	for j := 0; j < len(rel)-6; j++ {
		if rel[j:j+6] == "/docs/" {
			return true
		}
	}
	return len(rel) >= 5 && rel[:5] == "docs/"
}

// TestExtractGrepPath_WindowsDriveLetter verifies that extractGrepPath correctly
// skips the Windows drive-letter colon so _test.go and docs/ filtering works
// on merge-group Windows runners. Regression test for the eviction bug where
// D:\...\foo_test.go:17:match was split at 'D' instead of the actual path.
func TestExtractGrepPath_WindowsDriveLetter(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "unix_path",
			line: "/home/runner/work/cfgms/features/controller/api/handlers.go:42:match",
			want: "/home/runner/work/cfgms/features/controller/api/handlers.go",
		},
		{
			name: "unix_test_path",
			line: "/home/runner/work/cfgms/features/controller/api/no_isadmin_test.go:17:// TestNoIsAdminInGoSource",
			want: "/home/runner/work/cfgms/features/controller/api/no_isadmin_test.go",
		},
		{
			name: "windows_uppercase_drive",
			line: `D:\a\cfgms\cfgms/features/controller/api/handlers.go:42:match`,
			want: `D:\a\cfgms\cfgms/features/controller/api/handlers.go`,
		},
		{
			name: "windows_test_file",
			line: `D:\a\cfgms\cfgms/features/controller/api/no_isadmin_test.go:17:// TestNoIsAdminInGoSource`,
			want: `D:\a\cfgms\cfgms/features/controller/api/no_isadmin_test.go`,
		},
		{
			name: "windows_lowercase_drive",
			line: `c:\workspace\cfgms\features\controller\api\handlers.go:100:match`,
			want: `c:\workspace\cfgms\features\controller\api\handlers.go`,
		},
		{
			name: "relative_path_no_drive",
			line: "features/controller/api/handlers.go:42:match",
			want: "features/controller/api/handlers.go",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractGrepPath(tc.line)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestIsTestFile_WindowsDriveLetter verifies that _test.go files are correctly
// identified when the grep line contains a Windows drive-letter prefix.
func TestIsTestFile_WindowsDriveLetter(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "windows_test_file_is_test",
			line: `D:\a\cfgms\cfgms/features/controller/api/no_isadmin_test.go:17:// TestNoIsAdminInGoSource`,
			want: true,
		},
		{
			name: "windows_prod_file_not_test",
			line: `D:\a\cfgms\cfgms/features/controller/api/handlers.go:42:.IsAdmin`,
			want: false,
		},
		{
			name: "unix_test_file_is_test",
			line: "/workspace/features/controller/api/no_isadmin_test.go:25:s := string(line)",
			want: true,
		},
		{
			name: "unix_prod_file_not_test",
			line: "/workspace/features/controller/api/handlers.go:42:.IsAdmin",
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTestFile(tc.line)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestIsDocsPath_WindowsDriveLetter verifies that docs/ paths are correctly
// identified when the grep line contains a Windows drive-letter prefix.
func TestIsDocsPath_WindowsDriveLetter(t *testing.T) {
	cases := []struct {
		name string
		line string
		want bool
	}{
		{
			name: "windows_docs_path",
			line: `D:\a\cfgms\cfgms/docs/architecture/operating-model.md:5:IsAdmin`,
			want: true,
		},
		{
			name: "windows_non_docs_path",
			line: `D:\a\cfgms\cfgms/features/controller/api/handlers.go:42:.IsAdmin`,
			want: false,
		},
		{
			name: "unix_docs_path",
			line: "/workspace/docs/architecture/operating-model.md:5:IsAdmin",
			want: true,
		},
		{
			name: "windows_docstore_not_docs_dir",
			line: `D:\a\cfgms\cfgms/features/config/docstore.go:10:.IsAdmin`,
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isDocsPath(tc.line)
			assert.Equal(t, tc.want, got)
		})
	}
}
