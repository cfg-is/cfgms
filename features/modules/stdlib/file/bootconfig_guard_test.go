// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package file

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/security"
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
	// Use the loader's own search dirs: they differ per OS (darwin has no ~/.config/cfgms).
	var dir string
	for _, d := range security.BootConfigDirs() {
		if strings.HasPrefix(d, home) {
			dir = d
			break
		}
	}
	require.NotEmpty(t, dir, "no boot-config dir under HOME")
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

	// Creating a boot config that does not exist yet must also be refused,
	// and must leave nothing behind.
	for _, name := range security.BootConfigFileNames() {
		t.Run("create "+name, func(t *testing.T) {
			fresh := t.TempDir()
			t.Setenv("HOME", fresh)
			var freshDir string
			for _, d := range security.BootConfigDirs() {
				if strings.HasPrefix(d, fresh) {
					freshDir = d
					break
				}
			}
			require.NotEmpty(t, freshDir, "no boot-config dir under HOME")
			require.NoError(t, os.MkdirAll(freshDir, 0o700))
			target := filepath.Join(freshDir, name)
			err := New().Set(context.Background(), target, &FileConfig{
				State: "present", Content: "steward:\n  remote_terminal:\n    enabled: true\n",
				AllowedBasePath: fresh, Permissions: 0o600,
			})
			assert.ErrorIs(t, err, ErrProtectedBootConfig)
			_, serr := os.Stat(target)
			assert.True(t, os.IsNotExist(serr), "%s must not be created", name)
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

// After the hostname changes, the file the steward loaded and the file for the
// new hostname both stay protected (Issue #5490).
func TestFileModule_Set_RefusesLoadedBootConfigAfterHostnameChange(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("boot-config search dirs on Windows come from PROGRAMDATA; covered by pkg/security tests")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	var dir string
	for _, d := range security.BootConfigDirs() {
		if strings.HasPrefix(d, home) {
			dir = d
			break
		}
	}
	require.NotEmpty(t, dir)
	require.NoError(t, os.MkdirAll(dir, 0o700))

	realHost, err := os.Hostname()
	require.NoError(t, err)
	oldHost := "oldhost-" + realHost

	oldPath := filepath.Join(dir, oldHost+".cfg")
	newPath := filepath.Join(dir, realHost+".cfg")
	original := []byte("steward:\n  remote_terminal:\n    enabled: false\n")
	require.NoError(t, os.WriteFile(oldPath, original, 0o600))
	require.NoError(t, os.WriteFile(newPath, original, 0o600))
	security.SetLoadedBootConfigPath(oldPath)

	for _, target := range []string{oldPath, newPath} {
		err := New().Set(context.Background(), target, &FileConfig{
			State: "present", Content: "steward:\n  remote_terminal:\n    enabled: true\n",
			AllowedBasePath: home, Permissions: 0o600,
		})
		assert.ErrorIs(t, err, ErrProtectedBootConfig, target)
		got, rerr := os.ReadFile(target)
		require.NoError(t, rerr)
		assert.Equal(t, original, got)
	}

	other := filepath.Join(dir, "other.cfg")
	require.NoError(t, New().Set(context.Background(), other, &FileConfig{
		State: "present", Content: "x", AllowedBasePath: home, Permissions: 0o600,
	}))
}
