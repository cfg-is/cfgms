// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package compat

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildScript is scripts/compat/build-tag-steward.sh, relative to this package.
const buildScript = "../../../scripts/compat/build-tag-steward.sh"

// runBuildScript runs the script with args inside dir (a git repository) and
// returns its combined output and exit code.
func runBuildScript(t *testing.T, dir string, args ...string) (string, int) {
	t.Helper()
	script, err := filepath.Abs(buildScript)
	require.NoError(t, err)
	// #nosec G204 -- bash and the script are fixed; the arguments are test-controlled
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	exitErr, ok := err.(*exec.ExitError)
	require.True(t, ok, "run script: %v", err)
	return string(out), exitErr.ExitCode()
}

// newRepo returns a throwaway git repository with one commit and no tags, whose
// Makefile records the arguments it was run with.
func newRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		// #nosec G204 -- git is a fixed binary; the arguments are test-controlled
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	run("init", "--quiet")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "test")
	run("config", "commit.gpgsign", "false")
	run("config", "tag.gpgsign", "false")
	makefile := "build-steward build-steward-launcher:\n" +
		"\t@mkdir -p bin\n" +
		"\t@printf '#!/bin/sh\\necho %s\\n' '$(VERSION) $(STEWARD_CONTROLLER_URL)' > bin/cfgms-steward\n" +
		"\t@cp bin/cfgms-steward bin/cfgms-steward-launcher\n" +
		"\t@chmod +x bin/cfgms-steward bin/cfgms-steward-launcher\n"
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Makefile"), []byte(makefile), 0o600))
	run("add", "Makefile")
	run("commit", "--quiet", "-m", "release")
	return dir
}

func TestBuildScriptUsageErrors(t *testing.T) {
	dir := newRepo(t)
	for _, args := range [][]string{
		{},
		{"v0.10.5"},
		{"v0.10.5", "out", "extra"},
	} {
		out, code := runBuildScript(t, dir, args...)
		assert.Equal(t, 2, code, "args %v: %s", args, out)
		assert.Contains(t, out, "usage")
	}
}

func TestBuildScriptRejectsUnsafeTagNames(t *testing.T) {
	dir := newRepo(t)
	for _, tag := range []string{"", "-v1", "v1;touch x", "v1 v2", "$(id)", "../x"} {
		out, code := runBuildScript(t, dir, tag, filepath.Join(t.TempDir(), "out"))
		assert.NotZero(t, code, "tag %q: %s", tag, out)
		_, statErr := os.Stat(filepath.Join(dir, "x"))
		assert.Error(t, statErr, "tag %q must not reach a shell", tag)
	}
}

func TestBuildScriptFailsWhenTagIsMissing(t *testing.T) {
	dir := newRepo(t)
	outdir := filepath.Join(t.TempDir(), "out")
	out, code := runBuildScript(t, dir, "v0.10.5", outdir)
	assert.Equal(t, 1, code, out)
	assert.Contains(t, out, "tag 'v0.10.5' not found")
	assert.NoFileExists(t, filepath.Join(outdir, "cfgms-steward"))
}

func TestBuildScriptRunsTheTagsOwnRecipe(t *testing.T) {
	dir := newRepo(t)
	// #nosec G204 -- git is a fixed binary; the arguments are test-controlled
	tagCmd := exec.Command("git", "tag", "v0.10.5")
	tagCmd.Dir = dir
	tagOut, err := tagCmd.CombinedOutput()
	require.NoError(t, err, string(tagOut))

	outdir := filepath.Join(t.TempDir(), "out")
	out, code := runBuildScript(t, dir, "v0.10.5", outdir)
	require.Equal(t, 0, code, out)

	for _, bin := range []string{"cfgms-steward", "cfgms-steward-launcher"} {
		info, err := os.Stat(filepath.Join(outdir, bin))
		require.NoError(t, err, bin)
		assert.NotZero(t, info.Mode()&0o111, "%s must be executable", bin)
	}

	// The binary reports what the tag's recipe stamped: VERSION=<tag>.
	// #nosec G204 -- the binary is the fake one this test just built
	run := exec.Command(filepath.Join(outdir, "cfgms-steward"))
	ran, err := run.CombinedOutput()
	require.NoError(t, err)
	assert.Equal(t, "v0.10.5", strings.TrimSpace(string(ran)))
}

func TestBuildScriptPassesControllerURLToTheRecipe(t *testing.T) {
	dir := newRepo(t)
	// #nosec G204 -- git is a fixed binary; the arguments are test-controlled
	tagCmd := exec.Command("git", "tag", "v0.10.5")
	tagCmd.Dir = dir
	tagOut, err := tagCmd.CombinedOutput()
	require.NoError(t, err, string(tagOut))

	t.Setenv("STEWARD_CONTROLLER_URL", "https://compat-controller:9080")
	outdir := filepath.Join(t.TempDir(), "out")
	out, code := runBuildScript(t, dir, "v0.10.5", outdir)
	require.Equal(t, 0, code, out)

	// #nosec G204 -- the binary is the fake one this test just built
	ran, err := exec.Command(filepath.Join(outdir, "cfgms-steward")).CombinedOutput()
	require.NoError(t, err)
	assert.Equal(t, "v0.10.5 https://compat-controller:9080", strings.TrimSpace(string(ran)))
}
