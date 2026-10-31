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

// checkRepo is a synthetic repo with the report manifest, a develop base
// holding a CC 12 hotspot and a ratchet baseline measured from it.
func checkRepo(t *testing.T) (root, baseline string) {
	t.Helper()
	root = synthRepo(t, map[string]string{
		"pkg/a/a.go": hotFn, "cmd/c/c.go": "package c\n\nfunc G() {}\n",
	})
	writeFile(t, root, "manifest.json", string(manifestOf(
		seg("pkg", "c", "x", "pkg/"), seg("cmd", "c", "x", "cmd/"), seg("features-shared", "c", "x", "features/config/"))))
	runGit(t, root, "add", "manifest.json")
	runGit(t, root, "commit", "-q", "-m", "manifest")
	runGit(t, root, "branch", "-f", "develop", "HEAD")
	baseline = filepath.Join(t.TempDir(), "baseline.json")
	code, _, stderr := runReport(t, root, filepath.Join(root, "manifest.json"), baseline, "-compact-baseline")
	require.Equal(t, 0, code, stderr)
	return root, baseline
}

func runCheck(t *testing.T, root, baseline string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	args := append([]string{"-root", root, "-manifest", filepath.Join(root, "manifest.json"), "-baseline", baseline}, extra...)
	code = checkCmd(args, &so, &se)
	return code, so.String(), se.String()
}

func TestCheckExitPass(t *testing.T) {
	root, baseline := checkRepo(t)
	writeFile(t, root, "cmd/c/new.go", "package c\n\nfunc Small() {}\n")
	code, stdout, stderr := runCheck(t, root, baseline)
	assert.Equal(t, 0, code, stdout+stderr)
	assert.Contains(t, stdout, "pass")
}

func TestCheckExitFinding(t *testing.T) {
	root, baseline := checkRepo(t)
	// Grow the hotspot from 12 to 13: rules 1, 2 and 3 all fire.
	writeFile(t, root, "pkg/a/a.go", hotFn[:len(hotFn)-2]+"\tif a && b {}\n}\n")
	code, stdout, _ := runCheck(t, root, baseline)
	assert.Equal(t, 1, code, stdout)
	assert.Contains(t, stdout, "pkg/a/a.go:3: rule 2: ")
	assert.Contains(t, stdout, "rule 3: ")
	assert.Contains(t, stdout, "rule 1: aggregate_excess")
	assert.Contains(t, stdout, "CC 12 -> 14")
}

func TestCheckExitError(t *testing.T) {
	root, baseline := checkRepo(t)
	code, _, stderr := runCheck(t, root, filepath.Join(root, "missing.json"))
	assert.Equal(t, 2, code)
	assert.NotEmpty(t, stderr)

	code, _, _ = runCheck(t, root, "")
	assert.Equal(t, 2, code, "-baseline is required")

	runGit(t, root, "branch", "-m", "develop", "trunk")
	code, _, stderr = runCheck(t, root, baseline)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "origin/develop")
}

func TestCheckExitsTwoOnShallowClone(t *testing.T) {
	root, baseline := checkRepo(t)
	clone := filepath.Join(t.TempDir(), "clone")
	runGit(t, root, "clone", "-q", "--depth", "1", "--branch", "develop", "file://"+root, clone)
	code, _, stderr := runCheck(t, clone, baseline)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "history too shallow to compute merge-base")
}

func TestCheckPartitionViolationIsFinding(t *testing.T) {
	root, baseline := checkRepo(t)
	writeFile(t, root, "features/newdir/n.go", "package n\n\nfunc N() {}\n")
	code, stdout, _ := runCheck(t, root, baseline)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "partition: unclassified")
	assert.Contains(t, stdout, "features/newdir")
}

func TestCheckWarningsDoNotFail(t *testing.T) {
	root, baseline := checkRepo(t)
	base := readMetrics(t, baseline)
	cur := base
	cur.Aggregate.MeanCC += 1
	cur.Aggregate.P95Volume += 1
	cur.Aggregate.Functions += 5
	curFile := filepath.Join(t.TempDir(), "cur.json")
	f, err := os.Create(curFile)
	require.NoError(t, err)
	require.NoError(t, metrics.Write(f, cur))
	require.NoError(t, f.Close())

	code, stdout, stderr := runCheck(t, root, baseline, "-current", curFile)
	assert.Equal(t, 0, code, stdout+stderr)
	assert.Contains(t, stdout, "WARN: mean_cc")
	assert.Contains(t, stdout, "WARN: p95_volume")
}

func TestCheckBadFlag(t *testing.T) {
	assert.Equal(t, 2, checkCmd([]string{"-nope"}, &bytes.Buffer{}, &bytes.Buffer{}))
}
