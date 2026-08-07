// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package build_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func binaryArtifactScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "check-binary-artifacts.sh")
}

// newTrackedFixture creates a git work tree in t.TempDir() containing the given
// files (name → contents) and stages them, so `git ls-files` reports them.
func newTrackedFixture(t *testing.T, files map[string][]byte) string {
	t.Helper()
	root := t.TempDir()

	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v failed: %s", args, out)
	}

	run("init", "--quiet")
	for name, contents := range files {
		path := filepath.Join(root, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, contents, 0o644))
	}
	run("add", "--all")

	return root
}

// runBinaryArtifactScript executes the gate against a fixture work tree. The
// PATH it runs with deliberately shadows file(1) with a stub that always fails,
// proving the gate classifies artifacts itself rather than depending on an
// optional external utility that slim container images do not ship.
func runBinaryArtifactScript(t *testing.T, fixtureRoot string) (int, string) {
	t.Helper()

	shimDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "file"),
		[]byte("#!/bin/sh\necho 'file: command unavailable' >&2\nexit 127\n"), 0o755))

	cmd := exec.Command("bash", binaryArtifactScriptPath(t))
	cmd.Dir = fixtureRoot
	cmd.Env = append(os.Environ(),
		"PATH="+shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	return exitErr.ExitCode(), string(out)
}

// TestBinaryArtifactGateRunsWithoutFileUtility is the regression test for the
// gate exiting 2 ("requires the 'file' utility") in environments without
// file(1), which took the whole `make security-scan` target down with it.
func TestBinaryArtifactGateRunsWithoutFileUtility(t *testing.T) {
	root := newTrackedFixture(t, map[string][]byte{
		"main.go":   []byte("package main\n\nfunc main() {}\n"),
		"README.md": []byte("# fixture\n"),
	})

	code, out := runBinaryArtifactScript(t, root)

	require.Equal(t, 0, code, "a source-only tree must pass even without file(1)\n%s", out)
	assert.Contains(t, out, "binary-artifact check passed")
	assert.NotContains(t, out, "requires the 'file' utility")
}

// TestBinaryArtifactGateDetectsCompiledArtifactsByMagic verifies that each
// compiled-artifact class the gate covers is still detected by content alone,
// with no help from file(1) and no giveaway file extension.
func TestBinaryArtifactGateDetectsCompiledArtifactsByMagic(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		magic    []byte
		expect   string
	}{
		{"elf", "build/steward", []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}, "ELF executable or shared object"},
		{"macho64le", "build/steward-darwin", []byte{0xcf, 0xfa, 0xed, 0xfe, 0x07, 0x00, 0x00, 0x01}, "Mach-O binary"},
		{"machoBE", "build/steward-ppc", []byte{0xfe, 0xed, 0xfa, 0xce, 0x00, 0x00, 0x00, 0x12}, "Mach-O binary"},
		{"machoFat", "build/steward-universal", []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x02}, "Mach-O universal binary"},
		{"pe", "build/steward-windows", []byte{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00}, "PE32/MS-DOS executable"},
		{"wasm", "build/module", []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}, "WebAssembly binary module"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := newTrackedFixture(t, map[string][]byte{
				"main.go":   []byte("package main\n"),
				tc.filename: tc.magic,
			})

			code, out := runBinaryArtifactScript(t, root)

			require.Equal(t, 1, code, "a tracked compiled artifact must block\n%s", out)
			assert.Contains(t, out, "tracked compiled artifact: "+tc.filename)
			assert.Contains(t, out, tc.expect)
			assert.Contains(t, out, "compiled artifacts must be produced by the release pipeline")
		})
	}
}

// TestBinaryArtifactGateDetectsCompiledExtensions verifies the extension arm
// still blocks artifacts whose contents are not magic-classifiable.
func TestBinaryArtifactGateDetectsCompiledExtensions(t *testing.T) {
	root := newTrackedFixture(t, map[string][]byte{
		"main.go":      []byte("package main\n"),
		"lib/thing.so": []byte("not really a shared object\n"),
	})

	code, out := runBinaryArtifactScript(t, root)

	require.Equal(t, 1, code, "a tracked .so must block regardless of contents\n%s", out)
	assert.Contains(t, out, "tracked compiled artifact extension: lib/thing.so")
}

// TestBinaryArtifactGateAllowsShortAndEmptyTextFiles guards the classifier
// against false positives on files shorter than a magic signature.
func TestBinaryArtifactGateAllowsShortAndEmptyTextFiles(t *testing.T) {
	root := newTrackedFixture(t, map[string][]byte{
		"empty.txt": {},
		"tiny.txt":  []byte("x"),
		"short.txt": []byte("ok\n"),
	})

	code, out := runBinaryArtifactScript(t, root)

	require.Equal(t, 0, code, "short text files must not be misclassified\n%s", out)
	assert.Contains(t, out, "binary-artifact check passed")
}

// TestBinaryArtifactGatePassesOnRealRepo verifies the working tree itself is
// clean under the gate, in this environment, without file(1).
func TestBinaryArtifactGatePassesOnRealRepo(t *testing.T) {
	code, out := runBinaryArtifactScript(t, repoRoot(t))

	assert.Equal(t, 0, code, "the repository must carry no tracked compiled artifacts\n%s", out)
}
