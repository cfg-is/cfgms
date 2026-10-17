// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package security

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsProtectedBootConfigPath(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	assert.True(t, IsProtectedBootConfigPath(filepath.Join(cwd, BootConfigFileName)))
	assert.True(t, IsProtectedBootConfigPath(cwd))
	assert.False(t, IsProtectedBootConfigPath(filepath.Join(cwd, "other.txt")))

	host, err := os.Hostname()
	require.NoError(t, err)
	assert.True(t, IsProtectedBootConfigPath(filepath.Join(cwd, host+".cfg")))

	if runtime.GOOS != "windows" {
		link := filepath.Join(t.TempDir(), "alias")
		require.NoError(t, os.Symlink(cwd, link))
		assert.True(t, IsProtectedBootConfigPath(filepath.Join(link, BootConfigFileName)))
	}
}
