// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileExists is the [REQUIRED TEST] regression guard for Issue #3650: fileExists
// used to round-trip filepath.Abs() twice and never touch the filesystem, so it always
// returned true for any syntactically valid path (fixed with os.Stat).
func TestFileExists(t *testing.T) {
	dir := t.TempDir()

	existing := filepath.Join(dir, "present.yaml")
	require.NoError(t, os.WriteFile(existing, []byte("x"), 0o600))

	nonexistent := filepath.Join(dir, "absent.yaml")
	nonexistentDeepPath := filepath.Join(dir, "no", "such", "dir", "absent.yaml")

	tests := []struct {
		name string
		path string
		want bool
	}{
		{"existing file", existing, true},
		{"nonexistent file, syntactically valid path", nonexistent, false},
		{"nonexistent-but-syntactically-valid deep path", nonexistentDeepPath, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fileExists(tt.path))
		})
	}
}
