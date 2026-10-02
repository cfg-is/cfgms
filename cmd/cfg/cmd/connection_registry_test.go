// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package cmd

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withTempConfigDir overrides userConfigDirFn to use t.TempDir() and restores it via t.Cleanup.
// Returns the temp directory path for use in per-test assertions.
func withTempConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	orig := userConfigDirFn
	t.Cleanup(func() { userConfigDirFn = orig })
	userConfigDirFn = func() (string, error) { return dir, nil }
	return dir
}

// TestConnectionRegistry_RoundTrip exercises the full register → list → update-last-used → delete
// lifecycle and asserts the written JSON contains no credential, key, cert, or token field name.
func TestConnectionRegistry_RoundTrip(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	entry := ConnectionEntry{
		Name:          "prod",
		ControllerURL: "https://ctrl.example.com:9090",
		AdminIdentity: "admin@example.com",
	}

	// Register — writes new entry
	require.NoError(t, reg.Register(entry))

	// List returns the registered entry
	list, err := reg.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "prod", list[0].Name)
	assert.Equal(t, "https://ctrl.example.com:9090", list[0].ControllerURL)
	assert.Equal(t, "admin@example.com", list[0].AdminIdentity)

	// Assert written JSON contains no sensitive field names
	raw, err := os.ReadFile(reg.path)
	require.NoError(t, err)
	var parsed []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &parsed))
	sensitivePatterns := []string{"credential", "key", "cert", "token", "secret", "password"}
	for _, e := range parsed {
		for fieldName := range e {
			lower := strings.ToLower(fieldName)
			for _, pattern := range sensitivePatterns {
				assert.NotContainsf(t, lower, pattern,
					"JSON field %q matches sensitive pattern %q — no credentials may appear in connections.json",
					fieldName, pattern)
			}
		}
	}

	// UpdateLastUsed
	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, reg.UpdateLastUsed("prod", now))

	list, err = reg.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, now, list[0].LastUsed.UTC().Truncate(time.Second))

	// Delete
	require.NoError(t, reg.Delete("prod"))

	list, err = reg.List()
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestConnectionRegistry_FilePermissions(t *testing.T) {
	dir := withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	// Write at least one entry so the file is created
	require.NoError(t, reg.Register(ConnectionEntry{
		Name:          "perm-test",
		ControllerURL: "https://ctrl.example.com:9090",
		AdminIdentity: "admin@example.com",
	}))

	// POSIX permission bits are not meaningful on Windows (ACL-based); only
	// assert the modes where the underlying filesystem honors 0700/0600.
	if runtime.GOOS == "windows" {
		return
	}

	// Config directory must be 0700
	cfgmsDir := dir + "/cfgms"
	dirInfo, err := os.Stat(cfgmsDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), dirInfo.Mode().Perm(),
		"cfgms config directory must have mode 0700")

	// connections.json must be 0600
	fileInfo, err := os.Stat(reg.path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), fileInfo.Mode().Perm(),
		"connections.json must have mode 0600")
}

func TestConnectionRegistry_EmptyListWhenNoFile(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	list, err := reg.List()
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestConnectionRegistry_RegisterOverwritesSameName(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	first := ConnectionEntry{Name: "staging", ControllerURL: "https://old.example.com:9090", AdminIdentity: "old-admin"}
	require.NoError(t, reg.Register(first))

	updated := ConnectionEntry{Name: "staging", ControllerURL: "https://new.example.com:9090", AdminIdentity: "new-admin"}
	require.NoError(t, reg.Register(updated))

	list, err := reg.List()
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "https://new.example.com:9090", list[0].ControllerURL)
	assert.Equal(t, "new-admin", list[0].AdminIdentity)
}

func TestConnectionRegistry_MultipleEntries(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	names := []string{"prod", "staging", "dev"}
	for _, name := range names {
		require.NoError(t, reg.Register(ConnectionEntry{
			Name:          name,
			ControllerURL: "https://" + name + ".example.com:9090",
			AdminIdentity: name + "-admin",
		}))
	}

	list, err := reg.List()
	require.NoError(t, err)
	require.Len(t, list, 3)

	got := make(map[string]bool)
	for _, e := range list {
		got[e.Name] = true
	}
	for _, name := range names {
		assert.True(t, got[name], "expected entry %q in list", name)
	}
}

func TestConnectionRegistry_Get(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	require.NoError(t, reg.Register(ConnectionEntry{
		Name:          "prod",
		ControllerURL: "https://ctrl.example.com:9090",
		AdminIdentity: "admin@example.com",
	}))

	got, err := reg.Get("prod")
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "prod", got.Name)
	assert.Equal(t, "https://ctrl.example.com:9090", got.ControllerURL)
}

func TestConnectionRegistry_GetNonExistent(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	got, err := reg.Get("nonexistent")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestConnectionRegistry_DeleteNonExistent(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	err = reg.Delete("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestConnectionRegistry_UpdateLastUsedNonExistent(t *testing.T) {
	withTempConfigDir(t)

	reg, err := newConnectionRegistry()
	require.NoError(t, err)

	err = reg.UpdateLastUsed("nonexistent", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}
