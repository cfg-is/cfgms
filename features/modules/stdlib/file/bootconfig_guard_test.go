// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A delivered file resource must not rewrite, delete or re-mode the local
// steward.cfg (Issue #5146). Fails if the guard in Set is reverted.
func TestFileModule_Set_RefusesBootConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("boot-config search dirs on Windows come from PROGRAMDATA; covered by pkg/security tests")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "cfgms")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	cfgPath := filepath.Join(dir, "steward.cfg")
	original := []byte("steward:\n  remote_terminal:\n    enabled: false\n")
	require.NoError(t, os.WriteFile(cfgPath, original, 0o600))

	cases := map[string]map[string]interface{}{
		"overwrite": {"state": "present", "content": "steward:\n  remote_terminal:\n    enabled: true\n"},
		"delete":    {"state": "absent"},
		"chmod":     {"state": "present", "content": string(original), "permissions": 0o666},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			m := New()
			err := m.Set(context.Background(), cfgPath, &FileConfig{
				State:           extra["state"].(string),
				Content:         strOr(extra["content"]),
				AllowedBasePath: home,
				Permissions:     permOr(extra["permissions"]),
			})
			assert.ErrorIs(t, err, ErrProtectedBootConfig)

			got, rerr := os.ReadFile(cfgPath)
			require.NoError(t, rerr)
			assert.Equal(t, original, got)
			info, serr := os.Stat(cfgPath)
			require.NoError(t, serr)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}

	t.Run("directory", func(t *testing.T) {
		err := New().Set(context.Background(), dir, &FileConfig{State: "present", Type: "directory", AllowedBasePath: home, Permissions: 0o777})
		assert.ErrorIs(t, err, ErrProtectedBootConfig)
	})

	t.Run("unrelated file still works", func(t *testing.T) {
		other := filepath.Join(dir, "other.txt")
		require.NoError(t, New().Set(context.Background(), other, &FileConfig{State: "present", Content: "x", AllowedBasePath: home, Permissions: 0o600}))
	})
}

func strOr(v interface{}) string {
	s, _ := v.(string)
	return s
}

func permOr(v interface{}) int {
	i, _ := v.(int)
	return i
}
