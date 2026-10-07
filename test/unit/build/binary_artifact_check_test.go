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

// newArtifactRepo creates a throwaway git repository whose index contains the
// supplied files, so the check script has a real `git ls-files` surface to walk.
func newArtifactRepo(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()

	for _, args := range [][]string{
		{"init", "--quiet"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}

	for name, content := range files {
		path := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, content, 0o644))
	}

	add := exec.Command("git", "add", "--all")
	add.Dir = dir
	out, err := add.CombinedOutput()
	require.NoError(t, err, "git add: %s", out)

	return dir
}

func runArtifactCheck(t *testing.T, repo string, extraEnv ...string) (int, string) {
	t.Helper()
	script := filepath.Join(repoRoot(t), "scripts", "check-binary-artifacts.sh")
	cmd := exec.Command("bash", script)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	return exitErr.ExitCode(), string(out)
}

func TestBinaryArtifactCheckPassesOnSourceOnlyTree(t *testing.T) {
	repo := newArtifactRepo(t, map[string][]byte{
		"main.go":   []byte("package main\n\nfunc main() {}\n"),
		"README.md": []byte("# docs\n"),
		"empty.txt": {},
		"short.txt": []byte("hi"),
	})

	code, output := runArtifactCheck(t, repo)

	require.Equal(t, 0, code, output)
	assert.Contains(t, output, "binary-artifact check passed")
}

func TestBinaryArtifactCheckDetectsCompiledArtifactsByMagicBytes(t *testing.T) {
	cases := map[string]struct {
		file   string
		header []byte
	}{
		"elf":      {"bin/controller", []byte{0x7f, 'E', 'L', 'F', 0x02, 0x01}},
		"machO64":  {"bin/steward-darwin", []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c}},
		"machOFat": {"bin/steward-universal", []byte{0xca, 0xfe, 0xba, 0xbe, 0x00}},
		"pe":       {"bin/cfg-windows", []byte{'M', 'Z', 0x90, 0x00, 0x03}},
		"wasm":     {"bin/module.bin", []byte{0x00, 'a', 's', 'm', 0x01}},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			repo := newArtifactRepo(t, map[string][]byte{
				"main.go": []byte("package main\n"),
				tc.file:   tc.header,
			})

			code, output := runArtifactCheck(t, repo)

			assert.Equal(t, 1, code, "a tracked compiled artifact must fail the gate\n%s", output)
			assert.Contains(t, output, "tracked compiled artifact: "+tc.file)
			assert.Contains(t, output, "compiled artifacts must be produced by the release pipeline")
		})
	}
}

func TestBinaryArtifactCheckDetectsCompiledArtifactsByExtension(t *testing.T) {
	repo := newArtifactRepo(t, map[string][]byte{
		"main.go":       []byte("package main\n"),
		"pkg/vendor.so": []byte("not actually a binary\n"),
	})

	code, output := runArtifactCheck(t, repo)

	assert.Equal(t, 1, code, "a compiled-artifact extension must fail the gate\n%s", output)
	assert.Contains(t, output, "tracked compiled artifact extension: pkg/vendor.so")
}

// The gate runs in CI, in dev containers, and on developer workstations. It must
// not depend on the optional file(1) package: a security gate that cannot run
// wherever it is invoked is a gate that gets bypassed. Shimming file(1) to
// misreport every input proves detection does not consult it.
func TestBinaryArtifactCheckDoesNotDependOnFileUtility(t *testing.T) {
	shimDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "file"),
		[]byte("#!/bin/sh\necho 'ASCII text'\n"), 0o755))

	repo := newArtifactRepo(t, map[string][]byte{
		"main.go":        []byte("package main\n"),
		"bin/controller": {0x7f, 'E', 'L', 'F', 0x02},
	})

	code, output := runArtifactCheck(t, repo,
		"PATH="+shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	assert.Equal(t, 1, code, "detection must not rely on file(1) output\n%s", output)
	assert.Contains(t, output, "tracked compiled artifact: bin/controller")
}
