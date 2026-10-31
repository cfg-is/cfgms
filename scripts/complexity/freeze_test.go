// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

func runFreeze(root, out string, extra ...string) (code int, stdout, stderr string) {
	var so, se bytes.Buffer
	args := append([]string{"-root", root, "-manifest", filepath.Join(root, "manifest.json"), "-out", out, "-base-commit", "abc123"}, extra...)
	code = freezeCmd(args, &so, &se)
	return code, so.String(), se.String()
}

func TestFreezeWritesAndRefusesOverwrite(t *testing.T) {
	root, _ := checkRepo(t)
	out := filepath.Join(t.TempDir(), "baselines", "frozen.json")

	code, _, stderr := runFreeze(root, out)
	require.Equal(t, 0, code, stderr)
	m := readMetrics(t, out)
	assert.Equal(t, metrics.SchemaVersion, m.SchemaVersion)
	assert.Equal(t, "abc123", m.BaseCommit)
	assert.Equal(t, metrics.FormHotspots, m.Form)
	require.Len(t, m.Functions, 1, "hotspots only")
	assert.Greater(t, m.Functions[0].CC, metrics.HotspotThreshold)

	before := sha256File(t, out)
	code, _, stderr = runFreeze(root, out)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "already exists")
	assert.Equal(t, before, sha256File(t, out), "existing frozen.json untouched")
}

func TestFreezeNeedsBaseCommit(t *testing.T) {
	root, _ := checkRepo(t)
	out := filepath.Join(t.TempDir(), "frozen.json")
	// No origin/develop in the synthetic repo: the base commit is unknown.
	var so, se bytes.Buffer
	code := freezeCmd([]string{"-root", root, "-manifest", filepath.Join(root, "manifest.json"), "-out", out}, &so, &se)
	assert.Equal(t, 2, code)
	assert.NoFileExists(t, out)
}

func TestFreezeBadFlag(t *testing.T) {
	assert.Equal(t, 2, freezeCmd([]string{"-nope"}, &bytes.Buffer{}, &bytes.Buffer{}))
}
