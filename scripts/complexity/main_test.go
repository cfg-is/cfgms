// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

func TestRunPrintsCountAndJSONLines(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "pkg"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "pkg", "a.go"),
		[]byte("package pkg\n\nfunc F(a bool) {\n\tif a {\n\t}\n}\n"), 0o644))

	var out bytes.Buffer
	require.NoError(t, run(root, &out))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Len(t, lines, 2)
	assert.Equal(t, "1", lines[0])
	var rec map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &rec))
	assert.Equal(t, "F", rec["name"])
	assert.EqualValues(t, 2, rec["cc"])
}

func TestRunReportsParseError(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "bad.go"), []byte("package"), 0o644))
	assert.Error(t, run(root, &bytes.Buffer{}))
}

// synthTree builds a small repo with one function per manifest segment dir and
// returns the root and a manifest path.
func synthTree(t *testing.T, files map[string]string) (root, manifest string) {
	t.Helper()
	root = t.TempDir()
	for name, body := range files {
		p := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	}
	manifest = filepath.Join(root, "manifest.json")
	require.NoError(t, os.WriteFile(manifest, manifestOf(
		seg("pkg", "c", "x", "pkg/"),
		seg("cmd", "c", "x", "cmd/"),
		seg("features-shared", "c", "x", "features/config/"),
	), 0o644))
	return root, manifest
}

const hotFn = "package p\n\nfunc F(a, b, c, d, e, f, g, h, i, j, k bool) {\n\tif a {}\n\tif b {}\n\tif c {}\n\tif d {}\n\tif e {}\n\tif f {}\n\tif g {}\n\tif h {}\n\tif i {}\n\tif j {}\n\tif k {}\n}\n"

func runReport(t *testing.T, root, manifest, out string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	args := append([]string{"-root", root, "-manifest", manifest, "-out", out, "-base-commit", "base123"}, extra...)
	code = reportCmd(args, &so, &se)
	return code, so.String(), se.String()
}

func readMetrics(t *testing.T, out string) metrics.Measurement {
	t.Helper()
	f, err := os.Open(out)
	require.NoError(t, err)
	defer f.Close()
	m, err := metrics.Read(f)
	require.NoError(t, err)
	return m
}

func TestReportSyntheticTreePasses(t *testing.T) {
	root, manifest := synthTree(t, map[string]string{
		"pkg/a/a.go": hotFn, "cmd/c/c.go": "package c\n\nfunc G() {}\n", "features/config/x.go": "package x\n\nfunc H() {}\n",
	})
	out := filepath.Join(t.TempDir(), "sub", "metrics.json")
	code, stdout, stderr := runReport(t, root, manifest, out)
	require.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "aggregate")
	m := readMetrics(t, out)
	assert.Equal(t, metrics.StatusPass, m.Status)
	assert.Equal(t, "base123", m.BaseCommit)
	assert.Equal(t, 3, m.Aggregate.Functions)
	assert.Equal(t, 1, m.Segments["pkg"].Hotspots)
	assert.Equal(t, 2, m.Segments["pkg"].AggregateExcess)
	assert.Len(t, m.Functions, 3)
}

func TestReportNewFeaturesDirIsUnclassified(t *testing.T) {
	root, manifest := synthTree(t, map[string]string{
		"pkg/a/a.go": "package a\n\nfunc F() {}\n", "features/newdir/n.go": "package n\n\nfunc N() {}\n",
	})
	out := filepath.Join(t.TempDir(), "m.json")
	code, _, stderr := runReport(t, root, manifest, out)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "unclassified")
	assert.Contains(t, stderr, "features/newdir")
	m := readMetrics(t, out)
	assert.Equal(t, metrics.StatusFail, m.Status)
	require.NotEmpty(t, m.Violations)
	assert.Contains(t, m.Violations[0], "features/newdir")
	assert.NotEmpty(t, m.ManifestSHA256)
	assert.NotEmpty(t, m.AnalyzerVersion)
	assert.Equal(t, metrics.SchemaVersion, m.SchemaVersion)
	assert.Equal(t, metrics.HotspotThreshold, m.HotspotThreshold)
}

func TestReportUnusedPrefixWarnsAndPasses(t *testing.T) {
	root, manifest := synthTree(t, map[string]string{"pkg/a/a.go": "package a\n\nfunc F() {}\n"})
	code, stdout, stderr := runReport(t, root, manifest, filepath.Join(t.TempDir(), "m.json"))
	assert.Equal(t, 0, code, stderr)
	assert.Contains(t, stdout, "WARN")
	assert.Contains(t, stdout, "cmd/")
}

func TestReportParseErrorWritesErrorStatus(t *testing.T) {
	root, manifest := synthTree(t, map[string]string{"pkg/a/a.go": "package"})
	out := filepath.Join(t.TempDir(), "m.json")
	code, _, _ := runReport(t, root, manifest, out)
	assert.Equal(t, 2, code)
	assert.Equal(t, metrics.StatusError, readMetrics(t, out).Status)
}

func TestReportBadManifestAndMissingManifest(t *testing.T) {
	root, manifest := synthTree(t, map[string]string{"pkg/a/a.go": "package a\n"})
	require.NoError(t, os.WriteFile(manifest, []byte(`{"version":1,"segments":[{"name":"pkg","paths":["features/"],"covers":"c","cannot_see":"x"}]}`), 0o644))
	out := filepath.Join(t.TempDir(), "m.json")
	code, _, _ := runReport(t, root, manifest, out)
	assert.Equal(t, 2, code)
	assert.Equal(t, metrics.StatusError, readMetrics(t, out).Status)

	code, _, stderr := runReport(t, root, filepath.Join(root, "absent.json"), out)
	assert.Equal(t, 2, code)
	assert.NotContains(t, stderr, "open ", "OS error must not repeat the path")
}

func TestReportCompactBaselineHoldsHotspotsOnly(t *testing.T) {
	root, manifest := synthTree(t, map[string]string{
		"pkg/a/a.go": hotFn, "cmd/c/c.go": "package c\n\nfunc G() {}\n",
	})
	out := filepath.Join(t.TempDir(), "inv.json")
	code, _, stderr := runReport(t, root, manifest, out, "-compact-baseline")
	require.Equal(t, 0, code, stderr)
	m := readMetrics(t, out)
	assert.Equal(t, metrics.FormHotspots, m.Form)
	assert.Equal(t, 2, m.Aggregate.Functions)
	require.Len(t, m.Functions, 1)
	assert.Equal(t, "pkg", m.Functions[0].Segment)
}

func TestReportBadFlagIsUsageError(t *testing.T) {
	assert.Equal(t, 2, reportCmd([]string{"-nope"}, &bytes.Buffer{}, &bytes.Buffer{}))
}

func TestReportRealTreeSumsMatchAggregate(t *testing.T) {
	out := filepath.Join(t.TempDir(), "metrics.json")
	code, _, stderr := runReport(t, "../..", "manifest.json", out)
	require.Equal(t, 0, code, stderr)
	m := readMetrics(t, out)
	assert.Equal(t, metrics.StatusPass, m.Status)
	sumFns, sumExcess := 0, 0
	require.Len(t, m.Segments, 7)
	for _, s := range m.Segments {
		sumFns += s.Functions
		sumExcess += s.AggregateExcess
	}
	assert.Equal(t, m.Aggregate.Functions, sumFns)
	assert.Equal(t, m.Aggregate.AggregateExcess, sumExcess)
	assert.Len(t, m.Functions, m.Aggregate.Functions)
	for _, f := range m.Functions {
		assert.NotEmpty(t, f.Segment, f.Identity)
	}
}

func TestCommittedInventoryIsValidHotspotForm(t *testing.T) {
	f, err := os.Open("baselines/inventory.json")
	require.NoError(t, err)
	defer f.Close()
	m, err := metrics.Read(f)
	require.NoError(t, err)
	assert.Equal(t, metrics.FormHotspots, m.Form)
	assert.Equal(t, metrics.StatusPass, m.Status)
	assert.Len(t, m.BaseCommit, 40)
	assert.Equal(t, m.Aggregate.Hotspots, len(m.Functions))
	for _, fn := range m.Functions {
		assert.Greater(t, fn.CC, metrics.HotspotThreshold)
	}
}
