// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunInstallReadsTokenFileBeforeElevation proves the token file is read
// (and refused when unsafe) before the elevation check, so a bad file fails
// before any privileged step and the read is testable without root.
func TestRunInstallReadsTokenFileBeforeElevation(t *testing.T) {
	const token = "tok_file_secret_0123456789abcdef"

	t.Run("group-readable file is refused before elevation check", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte(token), 0o600))
		require.NoError(t, os.Chmod(path, 0o644))

		err := runInstall("", path, "", "", "")
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "elevated privileges")
		assert.NotContains(t, err.Error(), token)
	})

	t.Run("valid file gets past the read to the elevation check", func(t *testing.T) {
		if isElevated() {
			t.Skip("test requires non-elevated process — an elevated run would proceed to Install")
		}
		path := filepath.Join(t.TempDir(), "token")
		require.NoError(t, os.WriteFile(path, []byte(token), 0o600))

		err := runInstall("", path, "", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "elevated privileges")
		assert.NotContains(t, err.Error(), token)
	})
}
