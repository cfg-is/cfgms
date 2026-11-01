// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

func sha256File(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func runRatchet(t *testing.T, root, baseline string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	args := append([]string{"-root", root, "-manifest", filepath.Join(root, "manifest.json"), "-baseline", baseline}, extra...)
	code = ratchetCmd(args, &so, &se)
	return code, so.String(), se.String()
}

// ratchetFixture returns a repo, a ratchet.json copy in its own temp dir and
// a frozen.json beside it.
func ratchetFixture(t *testing.T) (root, ratchet, frozen string) {
	t.Helper()
	root, baseline := checkRepo(t)
	dir := t.TempDir()
	ratchet = filepath.Join(dir, "ratchet.json")
	frozen = filepath.Join(dir, "frozen.json")
	b, err := os.ReadFile(baseline)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(ratchet, b, 0o600))
	require.NoError(t, os.WriteFile(frozen, b, 0o600))
	return root, ratchet, frozen
}

func TestRatchetRefusesFailingRules(t *testing.T) {
	cases := map[string]func(m *metrics.Measurement){
		"rule1": func(m *metrics.Measurement) { m.Aggregate.Hotspots++ },
		"rule2": func(m *metrics.Measurement) { m.Functions[0].CC++ },
		"rule3": func(m *metrics.Measurement) { m.Functions[0].Effort += 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root, ratchet, frozen := ratchetFixture(t)
			if name == "rule3" {
				// Rule 3 needs a touched file whose function differs from Previous.
				writeFile(t, root, "pkg/a/a.go", hotFn+"\n// touched\n")
			}
			cur := readMetrics(t, ratchet)
			mutate(&cur)
			curFile := writeMeasurement(t, cur)
			before, frozenBefore := sha256File(t, ratchet), sha256File(t, frozen)

			code, stdout, stderr := runRatchet(t, root, ratchet, "-current", curFile)
			assert.Equal(t, 1, code, stdout+stderr)
			assert.Contains(t, stdout, "rule "+name[len(name)-1:])
			assert.Equal(t, before, sha256File(t, ratchet), "ratchet.json byte-identical")
			assert.Equal(t, frozenBefore, sha256File(t, frozen))
		})
	}
}

func TestRatchetWritesImprovedBaselineAndLeavesFrozen(t *testing.T) {
	root, ratchet, frozen := ratchetFixture(t)
	cur := readMetrics(t, ratchet)
	cur.Functions[0].CC = 11
	cur.Aggregate.Hotspots = 1
	cur.Aggregate.AggregateExcess--
	cur.Aggregate.MeanCC += 1 // warn-only: must not block
	curFile := writeMeasurement(t, cur)
	frozenBefore := sha256File(t, frozen)

	code, stdout, stderr := runRatchet(t, root, ratchet, "-current", curFile)
	require.Equal(t, 0, code, stdout+stderr)
	assert.Contains(t, stdout, "WARN: mean_cc")
	got := readMetrics(t, ratchet)
	assert.Equal(t, 11, got.Functions[0].CC)
	assert.Equal(t, cur.Aggregate.MeanCC, got.Aggregate.MeanCC)
	assert.Equal(t, AnalyzerVersion, got.AnalyzerVersion)
	assert.NotEmpty(t, got.ManifestSHA256)
	assert.Equal(t, frozenBefore, sha256File(t, frozen), "frozen.json untouched")
}

func TestRatchetCountingRulesChanged(t *testing.T) {
	cases := map[string]func(m *metrics.Measurement){
		"schema_version":    func(m *metrics.Measurement) { m.SchemaVersion = 2 },
		"analyzer_version":  func(m *metrics.Measurement) { m.AnalyzerVersion = "0" },
		"hotspot_threshold": func(m *metrics.Measurement) { m.HotspotThreshold = 7 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root, ratchet, _ := ratchetFixture(t)
			b := readMetrics(t, ratchet)
			mutate(&b)
			writeBaselineFile(t, ratchet, b)
			before := sha256File(t, ratchet)
			code, _, stderr := runRatchet(t, root, ratchet)
			assert.Equal(t, 1, code)
			assert.Contains(t, stderr, "counting rules changed: delete baselines/ratchet.json in a reviewed diff and run `make complexity-ratchet COMPLEXITY_INIT=1`")
			assert.Equal(t, before, sha256File(t, ratchet))
		})
	}
}

// writeBaselineFile writes b to path.
func writeBaselineFile(t *testing.T, path string, b metrics.Measurement) {
	t.Helper()
	var buf bytes.Buffer
	require.NoError(t, metrics.Write(&buf, b))
	require.NoError(t, os.WriteFile(path, buf.Bytes(), 0o600))
}

func TestRatchetManifestDriftProceedsToGate(t *testing.T) {
	root, ratchet, _ := ratchetFixture(t)
	b := readMetrics(t, ratchet)
	b.ManifestSHA256 = "deadbeef"
	writeBaselineFile(t, ratchet, b)
	code, stdout, stderr := runRatchet(t, root, ratchet)
	require.Equal(t, 0, code, stdout+stderr)
	assert.NotEqual(t, "deadbeef", readMetrics(t, ratchet).ManifestSHA256, "ratchet refreshes the manifest hash")
}

func TestRatchetInit(t *testing.T) {
	root, existing, _ := ratchetFixture(t)
	before := sha256File(t, existing)
	code, _, stderr := runRatchet(t, root, existing, "-init")
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "already exists")
	assert.Equal(t, before, sha256File(t, existing))

	fresh := filepath.Join(t.TempDir(), "baselines", "ratchet.json")
	code, stdout, stderr := runRatchet(t, root, fresh, "-init")
	require.Equal(t, 0, code, stdout+stderr)
	m := readMetrics(t, fresh)
	assert.Equal(t, metrics.FormHotspots, m.Form)
	assert.Equal(t, AnalyzerVersion, m.AnalyzerVersion)
	reasons, err := Staleness(m, filepath.Join(root, "manifest.json"))
	require.NoError(t, err)
	assert.Empty(t, reasons)
}

func TestRatchetErrors(t *testing.T) {
	root, _, _ := ratchetFixture(t)
	missing := filepath.Join(t.TempDir(), "ratchet.json")
	code, _, stderr := runRatchet(t, root, missing)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "-init")
	assert.Equal(t, 2, ratchetCmd([]string{}, &bytes.Buffer{}, &bytes.Buffer{}), "-baseline is required")
	assert.Equal(t, 2, ratchetCmd([]string{"-nope"}, &bytes.Buffer{}, &bytes.Buffer{}))
}
