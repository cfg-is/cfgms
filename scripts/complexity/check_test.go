// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/scripts/complexity/metrics"
)

// checkRepo is a synthetic repo with the report manifest and a develop base
// holding a CC 12 hotspot; the working tree starts identical to its merge-base.
func checkRepo(t *testing.T) string {
	t.Helper()
	root := synthRepo(t, map[string]string{
		"pkg/a/a.go": hotFn, "cmd/c/c.go": "package c\n\nfunc G() {}\n",
	})
	writeFile(t, root, "manifest.json", string(manifestOf(
		seg("pkg", "c", "x", "pkg/"), seg("cmd", "c", "x", "cmd/"), seg("features-shared", "c", "x", "features/config/"))))
	runGit(t, root, "add", "manifest.json")
	runGit(t, root, "commit", "-q", "-m", "manifest")
	runGit(t, root, "branch", "-f", "develop", "HEAD")
	return root
}

func runCheck(t *testing.T, root string, extra ...string) (code int, stdout, stderr string) {
	t.Helper()
	var so, se bytes.Buffer
	args := append([]string{"-root", root, "-manifest", filepath.Join(root, "manifest.json")}, extra...)
	code = checkCmd(args, &so, &se)
	return code, so.String(), se.String()
}

// Population parity: a tree identical to its merge-base yields no findings,
// so Current (via report) and Previous (via analyzer) cover the same functions.
func TestCheckIdenticalToMergeBaseHasNoFindings(t *testing.T) {
	root := checkRepo(t)
	code, stdout, stderr := runCheck(t, root)
	assert.Equal(t, 0, code, stdout+stderr)
	assert.Equal(t, "complexity gate: pass\n", stdout)
}

func TestCheckExitPass(t *testing.T) {
	root := checkRepo(t)
	writeFile(t, root, "cmd/c/new.go", "package c\n\nfunc Small() {}\n")
	code, stdout, stderr := runCheck(t, root)
	assert.Equal(t, 0, code, stdout+stderr)
	assert.Contains(t, stdout, "pass")
}

func TestCheckExitFinding(t *testing.T) {
	root := checkRepo(t)
	// Grow the hotspot from 12 to 14 in a commit: rules 1, 2 and 3 all fire.
	writeFile(t, root, "pkg/a/a.go", hotFn[:len(hotFn)-2]+"\tif a && b {}\n}\n")
	runGit(t, root, "commit", "-q", "-a", "-m", "grow")
	code, stdout, _ := runCheck(t, root)
	assert.Equal(t, 1, code, stdout)
	assert.Contains(t, stdout, "pkg/a/a.go:3: rule 2: pkg/a/a.go::.F#0 CC 12 -> 14")
	assert.Contains(t, stdout, "rule 3: ")
	assert.Contains(t, stdout, "rule 1: aggregate_excess")
}

func TestCheckExitError(t *testing.T) {
	root := checkRepo(t)
	runGit(t, root, "branch", "-m", "develop", "trunk")
	code, _, stderr := runCheck(t, root)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "origin/develop")
}

func TestCheckRejectsRemovedBaselineFlag(t *testing.T) {
	root := checkRepo(t)
	code, _, _ := runCheck(t, root, "-baseline", "x.json")
	assert.Equal(t, 2, code)
}

func TestRemovedSubcommandsAreUnknown(t *testing.T) {
	for _, name := range []string{"ratchet", "freeze", "staleness"} {
		cmd := exec.Command("go", "run", ".", name)
		out, err := cmd.CombinedOutput()
		assert.Error(t, err, "%s: %s", name, out)
	}
}

func TestCheckExitsTwoOnShallowClone(t *testing.T) {
	root := checkRepo(t)
	clone := filepath.Join(t.TempDir(), "clone")
	runGit(t, root, "clone", "-q", "--depth", "1", "--branch", "develop", "file://"+root, clone)
	code, _, stderr := runCheck(t, clone)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr, "history too shallow to compute merge-base")
}

func TestCheckPartitionViolationIsFinding(t *testing.T) {
	root := checkRepo(t)
	writeFile(t, root, "features/newdir/n.go", "package n\n\nfunc N() {}\n")
	code, stdout, _ := runCheck(t, root)
	assert.Equal(t, 1, code)
	assert.Contains(t, stdout, "partition: unclassified")
	assert.Contains(t, stdout, "features/newdir")
}

func TestCheckWarningsDoNotFail(t *testing.T) {
	root := checkRepo(t)
	out := filepath.Join(t.TempDir(), "cur.json")
	code, _, stderr := runReport(t, root, filepath.Join(root, "manifest.json"), out)
	require.Equal(t, 0, code, stderr)
	cur := readMetrics(t, out)
	cur.Aggregate.MeanCC += 1
	cur.Aggregate.P95Volume += 1
	cur.Aggregate.Functions += 5
	f, err := os.Create(out)
	require.NoError(t, err)
	require.NoError(t, metrics.Write(f, cur))
	require.NoError(t, f.Close())

	code, stdout, stderr := runCheck(t, root, "-current", out)
	assert.Equal(t, 0, code, stdout+stderr)
	assert.Contains(t, stdout, "WARN: mean_cc")
	assert.Contains(t, stdout, "WARN: p95_volume")
}

func TestCheckBadFlag(t *testing.T) {
	assert.Equal(t, 2, checkCmd([]string{"-nope"}, &bytes.Buffer{}, &bytes.Buffer{}))
}
