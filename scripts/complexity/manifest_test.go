// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seg(name, covers, cannot string, paths ...string) string {
	b, _ := json.Marshal(Segment{Name: name, Paths: paths, Covers: covers, CannotSee: cannot})
	return string(b)
}

func manifestOf(segs ...string) []byte {
	out := `{"version":1,"segments":[`
	for i, s := range segs {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return []byte(out + `]}`)
}

func TestLoadManifestRejects(t *testing.T) {
	cases := map[string][]byte{
		"overlap":       manifestOf(seg("pkg", "c", "x", "pkg/"), seg("cmd", "c", "x", "pkg/storage/")),
		"bare features": manifestOf(seg("pkg", "c", "x", "features/")),
		"empty covers":  manifestOf(seg("pkg", "", "x", "pkg/")),
		"empty cannot":  manifestOf(seg("pkg", "c", " ", "pkg/")),
		"empty paths":   manifestOf(seg("pkg", "c", "x")),
		"unknown name":  manifestOf(seg("bogus", "c", "x", "pkg/")),
		"duplicate":     manifestOf(seg("pkg", "c", "x", "pkg/"), seg("pkg", "c", "x", "cmd/")),
		"glob":          manifestOf(seg("pkg", "c", "x", "pkg/*/")),
		"no slash":      manifestOf(seg("pkg", "c", "x", "pkg")),
		"traversal":     manifestOf(seg("pkg", "c", "x", "../pkg/")),
		"bad version":   []byte(`{"version":2,"segments":[]}`),
		"not json":      []byte(`{`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadManifest(data)
			assert.Error(t, err)
		})
	}
	_, err := LoadManifest(cases["overlap"])
	assert.ErrorContains(t, err, "claimed twice")
}

func TestCommittedManifestHasSevenSegments(t *testing.T) {
	data, err := os.ReadFile("manifest.json")
	require.NoError(t, err)
	m, err := LoadManifest(data)
	require.NoError(t, err)
	var names []string
	for _, s := range m.Segments {
		names = append(names, s.Name)
		assert.NotEmpty(t, s.Covers)
		assert.NotEmpty(t, s.CannotSee)
	}
	assert.ElementsMatch(t, []string{"controller", "steward", "workflow", "modules", "pkg", "cmd", "features-shared"}, names)
	for _, s := range m.Segments {
		if s.Name == "features-shared" {
			assert.Equal(t, []string{"features/config/", "features/monitoring/", "features/rbac/",
				"features/reports/", "features/tenant/", "features/terminal/"}, s.Paths)
		}
	}
}

func TestAssign(t *testing.T) {
	m, err := LoadManifest(manifestOf(seg("pkg", "c", "x", "pkg/", "api/"), seg("cmd", "c", "x", "cmd/")))
	require.NoError(t, err)
	assert.Equal(t, []string{"pkg"}, m.Assign("api/x/y.go"))
	assert.Equal(t, []string{"cmd"}, m.Assign("cmd/a.go"))
	assert.Empty(t, m.Assign("features/new/a.go"))
	assert.Empty(t, m.Assign("pkgx/a.go"))
}
