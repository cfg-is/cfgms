// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// manifestPath is the repository manifest, relative to this package.
const manifestPath = "../../compat/steward-support.yaml"

// TestRepositoryManifest validates the real manifest: syntax valid, floor
// listed, no entry sorting below it. It needs no git and no Docker.
func TestRepositoryManifest(t *testing.T) {
	m, err := LoadManifest(manifestPath)
	require.NoError(t, err)
	require.NotEmpty(t, m.Floor)

	listed := false
	for _, e := range m.Stewards {
		c, err := CompareSemver(e.Tag, m.Floor)
		require.NoError(t, err)
		assert.GreaterOrEqual(t, c, 0, "%s sorts below the floor %s", e.Tag, m.Floor)
		listed = listed || e.Tag == m.Floor
	}
	assert.True(t, listed, "floor %s must be listed under stewards", m.Floor)
}

func TestParseManifest(t *testing.T) {
	const valid = `
floor: v0.10.5
stewards:
  - tag: v0.10.5
    profile: floor
  - tag: v0.11.0
    profile: declared
`
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "valid", yaml: valid},
		{
			name: "prerelease above floor is accepted",
			yaml: "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: floor}\n  - {tag: v0.11.0-rc.1, profile: declared}\n",
		},
		{name: "invalid yaml syntax", yaml: "floor: [v0.10.5\n", wantErr: "decode"},
		{name: "unknown key", yaml: "floor: v0.10.5\nlatest: v1.0.0\nstewards:\n  - {tag: v0.10.5, profile: floor}\n", wantErr: "decode"},
		{name: "empty document", yaml: "", wantErr: "decode"},
		{name: "missing floor", yaml: "stewards:\n  - {tag: v0.10.5, profile: floor}\n", wantErr: "floor is required"},
		{name: "floor not a release tag", yaml: "floor: latest\nstewards:\n  - {tag: v0.10.5, profile: floor}\n", wantErr: "not a vMAJOR"},
		{name: "no entries", yaml: "floor: v0.10.5\nstewards: []\n", wantErr: "at least one entry"},
		{name: "floor not listed", yaml: "floor: v0.10.5\nstewards:\n  - {tag: v0.11.0, profile: declared}\n", wantErr: "is not listed"},
		{
			name:    "entry below the floor",
			yaml:    "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: floor}\n  - {tag: v0.9.6, profile: declared}\n",
			wantErr: "sorts below the floor",
		},
		{
			name:    "numeric not lexical ordering: v0.9.6 is below v0.10.5",
			yaml:    "floor: v0.10.5\nstewards:\n  - {tag: v0.9.6, profile: declared}\n  - {tag: v0.10.5, profile: floor}\n",
			wantErr: "sorts below the floor",
		},
		{
			name:    "prerelease of the floor sorts below it",
			yaml:    "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: floor}\n  - {tag: v0.10.5-rc.1, profile: declared}\n",
			wantErr: "sorts below the floor",
		},
		{
			name:    "duplicate tag",
			yaml:    "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: floor}\n  - {tag: v0.10.5, profile: floor}\n",
			wantErr: "listed twice",
		},
		{name: "unknown profile", yaml: "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: legacy}\n", wantErr: "must be"},
		{
			name:    "floor tag with declared profile",
			yaml:    "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: declared}\n",
			wantErr: "only valid for the floor tag",
		},
		{
			name:    "non-floor tag with floor profile",
			yaml:    "floor: v0.10.5\nstewards:\n  - {tag: v0.10.5, profile: floor}\n  - {tag: v0.11.0, profile: floor}\n",
			wantErr: "only valid for the floor tag",
		},
		{name: "entry tag not a release tag", yaml: "floor: v0.10.5\nstewards:\n  - {tag: main, profile: floor}\n", wantErr: "not a vMAJOR"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := ParseManifest([]byte(tc.yaml))
			if tc.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantErr)
				assert.Nil(t, m)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, m)
			assert.Equal(t, "v0.10.5", m.Floor)
		})
	}
}

func TestLoadManifestMissingFile(t *testing.T) {
	_, err := LoadManifest(filepath.Join(t.TempDir(), "absent.yaml"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read steward support manifest")
}

func TestLoadManifestRejectsBadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "steward-support.yaml")
	require.NoError(t, os.WriteFile(path, []byte("floor: v0.10.5\nstewards: []\n"), 0o600))
	_, err := LoadManifest(path)
	require.Error(t, err)
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"v0.10.5", "v0.10.5", 0},
		{"v0.9.6", "v0.10.5", -1},
		{"v0.10.5", "v0.9.6", 1},
		{"v1.0.0", "v0.99.99", 1},
		{"v0.10.4", "v0.10.5", -1},
		{"v0.10.5-rc.1", "v0.10.5", -1},
		{"v0.10.5", "v0.10.5-rc.1", 1},
		{"v0.10.5-rc.2", "v0.10.5-rc.10", -1},
		{"v0.10.5-alpha", "v0.10.5-beta", -1},
		{"v0.10.5-1", "v0.10.5-alpha", -1},
		{"v0.10.5-rc", "v0.10.5-rc.1", -1},
	}
	for _, tc := range tests {
		got, err := CompareSemver(tc.a, tc.b)
		require.NoError(t, err, "%s vs %s", tc.a, tc.b)
		assert.Equal(t, tc.want, got, "%s vs %s", tc.a, tc.b)
	}
}

func TestCompareSemverRejectsNonReleaseTags(t *testing.T) {
	for _, bad := range []string{"", "0.10.5", "v0.10", "v0.10.5.1", "latest", "v0.10.x", "v99999999999999999999.0.0"} {
		_, err := CompareSemver(bad, "v0.10.5")
		require.Error(t, err, "%q", bad)
		_, err = CompareSemver("v0.10.5", bad)
		require.Error(t, err, "%q", bad)
		assert.True(t, strings.Contains(err.Error(), "tag"), "error should name the tag: %v", err)
	}
}
