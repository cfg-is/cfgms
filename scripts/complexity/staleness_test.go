// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// writeMeasurement writes m to a new file in a temp dir.
func writeMeasurement(t *testing.T, m metrics.Measurement) string {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, metrics.Write(&buf, m))
	p := filepath.Join(t.TempDir(), "m.json")
	require.NoError(t, os.WriteFile(p, buf.Bytes(), 0o600))
	return p
}

func TestStalenessFourConditions(t *testing.T) {
	root, baseline := checkRepo(t)
	manifest := filepath.Join(root, "manifest.json")

	fresh := readMetrics(t, baseline)
	reasons, err := Staleness(fresh, manifest)
	require.NoError(t, err)
	assert.Empty(t, reasons, "fresh baseline passes")

	cases := map[string]func(*metrics.Measurement){
		"schema_version":    func(m *metrics.Measurement) { m.SchemaVersion = 99 },
		"analyzer_version":  func(m *metrics.Measurement) { m.AnalyzerVersion = "0" },
		"hotspot_threshold": func(m *metrics.Measurement) { m.HotspotThreshold = 7 },
		"manifest_sha256":   func(m *metrics.Measurement) { m.ManifestSHA256 = "deadbeef" },
	}
	for field, mutate := range cases {
		t.Run(field, func(t *testing.T) {
			m := fresh
			mutate(&m)
			reasons, err := Staleness(m, manifest)
			require.NoError(t, err)
			require.Len(t, reasons, 1)
			assert.Contains(t, reasons[0], field)
		})
	}
}

func TestStalenessIgnoresIdentitySet(t *testing.T) {
	root, baseline := checkRepo(t)
	m := readMetrics(t, baseline)
	m.Functions = nil // every hotspot deleted is legitimate
	reasons, err := Staleness(m, filepath.Join(root, "manifest.json"))
	require.NoError(t, err)
	assert.Empty(t, reasons)
}

func TestStalenessCmdAndCheckFail(t *testing.T) {
	root, baseline := checkRepo(t)
	manifest := filepath.Join(root, "manifest.json")

	var so, se bytes.Buffer
	assert.Equal(t, 0, stalenessCmd([]string{"-baseline", baseline, "-manifest", manifest}, &so, &se), se.String())

	stale := readMetrics(t, baseline)
	stale.ManifestSHA256 = "deadbeef"
	stalePath := writeMeasurement(t, stale)
	so.Reset()
	se.Reset()
	assert.Equal(t, 1, stalenessCmd([]string{"-baseline", stalePath, "-manifest", manifest}, &so, &se))
	assert.Contains(t, se.String(), "manifest_sha256")

	code, _, stderr := runCheck(t, root, stalePath)
	assert.Equal(t, 1, code, "check refuses a stale baseline before the gate")
	assert.Contains(t, stderr, "stale baseline")

	assert.Equal(t, 2, stalenessCmd([]string{}, &so, &se), "-baseline is required")
	assert.Equal(t, 2, stalenessCmd([]string{"-baseline", baseline, "-manifest", filepath.Join(root, "nope.json")}, &so, &se))
}
