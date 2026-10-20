// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

//go:build windows

package file

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cfgis/cfgms/pkg/security"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A delivered file resource must not reach steward.cfg through any Windows
// alias of its name (Issue #5204). Fails if the guard is string-based.
func TestFileModule_Set_RefusesBootConfigAliases_Windows(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	cfg := filepath.Join(cwd, security.BootConfigFileName)
	original := []byte("steward:\n  remote_terminal:\n    enabled: false\n")
	require.NoError(t, os.WriteFile(cfg, original, 0o600))

	junction := filepath.Join(t.TempDir(), "junction")
	out, err := exec.Command("cmd", "/c", "mklink", "/J", junction, cwd).CombinedOutput()
	require.NoError(t, err, string(out))
	// The hard link lives inside the allowed base but outside the search dirs.
	base := t.TempDir()
	hardlink := filepath.Join(base, "innocent.txt")
	require.NoError(t, os.Link(cfg, hardlink))

	aliases := map[string]string{
		"case":         filepath.Join(strings.ToUpper(cwd), "STEWARD.CFG"),
		"trailing dot": cfg + ".",
		"stream":       cfg + "::$DATA",
		"junction":     filepath.Join(junction, security.BootConfigFileName),
		"hard link":    hardlink,
	}
	for name, alias := range aliases {
		t.Run(name, func(t *testing.T) {
			base := filepath.Dir(alias)
			if name != "hard link" {
				base = filepath.VolumeName(alias) + `\`
			}
			err := New().Set(context.Background(), alias, &FileConfig{
				State: "present", Content: "steward:\n  remote_terminal:\n    enabled: true\n",
				AllowedBasePath: base, Permissions: 0o600,
			})
			assert.Error(t, err)
			got, rerr := os.ReadFile(cfg)
			require.NoError(t, rerr)
			assert.Equal(t, original, got)
		})
	}
}

// Creating a not-yet-existing boot config in a search directory is refused.
func TestFileModule_Set_RefusesNewBootConfig_Windows(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	host, err := os.Hostname()
	require.NoError(t, err)
	for _, name := range []string{security.BootConfigFileName, host + ".cfg"} {
		target := filepath.Join(cwd, name)
		err := New().Set(context.Background(), target, &FileConfig{
			State: "present", Content: "x", AllowedBasePath: cwd, Permissions: 0o600,
		})
		assert.ErrorIs(t, err, ErrProtectedBootConfig, name)
		_, serr := os.Stat(target)
		assert.True(t, os.IsNotExist(serr), name)
	}
}
