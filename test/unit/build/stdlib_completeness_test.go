// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package build_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func completenessScriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "check-stdlib-completeness.sh")
}

// runCompletenessScript executes the completeness-check script with REPO_ROOT
// overridden to the given root directory.  Returns (exitCode, combined output).
func runCompletenessScript(t *testing.T, repoOverride string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", completenessScriptPath(t))
	cmd.Env = append(os.Environ(), "REPO_ROOT="+repoOverride)
	out, err := cmd.CombinedOutput()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("unexpected exec error: %v", err)
		}
	}
	return exitCode, string(out)
}

// completenessFixtureOpts describes a single stdlib module for a fixture tree.
type completenessFixtureOpts struct {
	// modules is the list of module specs to create under features/modules/stdlib/
	modules []completenessModuleSpec
}

type completenessModuleSpec struct {
	name string
	// manifestContent is written verbatim to module.yaml; "" means no manifest is created.
	manifestContent string
	// hasCmdMain controls whether cmd/main.go is created.
	hasCmdMain bool
	// goFiles maps bare filename → file content for extra .go files in the module dir.
	goFiles map[string]string
}

// buildCompletenessFixture creates a minimal fixture directory tree under
// t.TempDir() containing the given module specs plus a Makefile listing them.
func buildCompletenessFixture(t *testing.T, opts completenessFixtureOpts) string {
	t.Helper()
	root := t.TempDir()

	// Makefile with STDLIB_MODULES listing
	names := make([]string, 0, len(opts.modules))
	for _, m := range opts.modules {
		names = append(names, m.name)
	}
	makefileContent := "STDLIB_MODULES := \\\n"
	for i, name := range names {
		if i < len(names)-1 {
			makefileContent += fmt.Sprintf("\t%s \\\n", name)
		} else {
			makefileContent += fmt.Sprintf("\t%s\n", name)
		}
	}
	makefileContent += "\nbuild-stdlib-modules:\n\t@echo building\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "Makefile"), []byte(makefileContent), 0o644))

	stdlibBase := filepath.Join(root, "features", "modules", "stdlib")
	require.NoError(t, os.MkdirAll(stdlibBase, 0o755))

	for _, spec := range opts.modules {
		modDir := filepath.Join(stdlibBase, spec.name)
		require.NoError(t, os.MkdirAll(modDir, 0o755))

		if spec.manifestContent != "" {
			require.NoError(t, os.WriteFile(filepath.Join(modDir, "module.yaml"), []byte(spec.manifestContent), 0o644))
		}

		if spec.hasCmdMain {
			cmdDir := filepath.Join(modDir, "cmd")
			require.NoError(t, os.MkdirAll(cmdDir, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(cmdDir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644))
		}

		for filename, content := range spec.goFiles {
			require.NoError(t, os.WriteFile(filepath.Join(modDir, filename), []byte(content), 0o644))
		}
	}

	return root
}

// validManifest returns a complete, valid module.yaml content for the named module.
// It carries a check-6 (ADR-024 §3) deliberate-omission marker so fixtures
// exercising other checks aren't incidentally failed by check-6.
func validManifest(name string) string {
	return fmt.Sprintf(`name: %s
version: 0.1.0
publisher: cfgms
executors:
  - steward
interfaces:
  - Get
  - Set
  - Test
owns:
  - kind: %s
# observe_when: omitted — test fixture, not subject to ADR-024 tagging
`, name, name)
}

// cleanGoFile returns a simple Go file with no stub patterns.
const cleanGoFileContent = `package testmod

import "context"

type testModule struct{}

func (m *testModule) Get(_ context.Context, _ string) error { return nil }
func (m *testModule) Set(_ context.Context, _ string) error { return nil }
`

// TestCompletenessRealRepo verifies the script exits 0 against the actual
// repository tree with all six current stdlib modules.
func TestCompletenessRealRepo(t *testing.T) {
	root := repoRoot(t)
	code, out := runCompletenessScript(t, root)
	assert.Equal(t, 0, code, "check-stdlib-completeness should pass on the real repo tree\nOutput:\n%s", out)
}

// TestCompletenessFixtureBaseline verifies that a well-formed fixture passes.
func TestCompletenessFixtureBaseline(t *testing.T) {
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "good-module",
				manifestContent: validManifest("good-module"),
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.Equal(t, 0, code, "well-formed fixture should pass\nOutput:\n%s", out)
}

// TestCompletenessCheck2_MissingManifest verifies that a module directory with
// no module.yaml causes the gate to fail (check #2).
func TestCompletenessCheck2_MissingManifest(t *testing.T) {
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "no-manifest",
				manifestContent: "", // no module.yaml
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.NotEqual(t, 0, code, "missing module.yaml should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "check-2", "output should mention check-2")
	assert.Contains(t, out, "no-manifest", "output should mention the failing module")
}

// TestCompletenessCheck2_MissingRequiredField verifies that a module.yaml
// missing the `publisher` field fails check #2.
func TestCompletenessCheck2_MissingRequiredField(t *testing.T) {
	manifest := `name: incomplete-module
version: 0.1.0
executors:
  - steward
owns:
  - kind: incomplete-module
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "incomplete-module",
				manifestContent: manifest,
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.NotEqual(t, 0, code, "module.yaml missing publisher should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "check-2", "output should mention check-2")
	assert.Contains(t, out, "publisher", "output should mention the missing field")
}

// TestCompletenessCheck4_MissingOwns verifies that a module.yaml without an
// owns: entry causes the gate to fail (check #4).
func TestCompletenessCheck4_MissingOwns(t *testing.T) {
	manifest := `name: no-owns-module
version: 0.1.0
publisher: cfgms
executors:
  - steward
interfaces:
  - Get
  - Set
  - Test
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "no-owns-module",
				manifestContent: manifest,
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.NotEqual(t, 0, code, "missing owns: should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "check-4", "output should mention check-4")
	assert.Contains(t, out, "no-owns-module", "output should mention the failing module")
}

// TestCompletenessCheck5_StubFilename verifies that a module containing a file
// whose name starts with stub_ causes the gate to fail (check #5).
func TestCompletenessCheck5_StubFilename(t *testing.T) {
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "has-stub-file",
				manifestContent: validManifest("has-stub-file"),
				hasCmdMain:      true,
				goFiles: map[string]string{
					"module.go":     cleanGoFileContent,
					"stub_thing.go": "package testmod\n// stub_thing is an unresolved stub\n",
				},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.NotEqual(t, 0, code, "stub_*-prefixed file should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "check-5", "output should mention check-5")
	assert.Contains(t, out, "stub_thing.go", "output should mention the stub file")
}

// TestCompletenessCheck5_ErrNotImplemented verifies that a module containing
// ErrNotImplemented in a non-test Go file causes the gate to fail (check #5).
func TestCompletenessCheck5_ErrNotImplemented(t *testing.T) {
	stubGoContent := `package testmod

import "errors"

var ErrNotImplemented = errors.New("operation not implemented")

func doSomething() error {
	return ErrNotImplemented
}
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "has-err-not-implemented",
				manifestContent: validManifest("has-err-not-implemented"),
				hasCmdMain:      true,
				goFiles: map[string]string{
					"module.go": stubGoContent,
				},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.NotEqual(t, 0, code, "ErrNotImplemented in source should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "check-5", "output should mention check-5")
	assert.Contains(t, out, "ErrNotImplemented", "output should mention ErrNotImplemented")
}

// TestCompletenessCheck5_ErrUnsupportedPlatformDoesNotFail verifies that a
// module with ErrUnsupportedPlatform in a build-tag platform-fallback file does
// NOT cause the gate to fail (check #5, pass direction).
//
// This tests the critical distinction between:
//   - ErrUnsupportedPlatform — legitimate cross-platform boundary (not flagged)
//   - ErrNotImplemented      — unresolved work marker (flagged)
func TestCompletenessCheck5_ErrUnsupportedPlatformDoesNotFail(t *testing.T) {
	// A legitimate platform-fallback stub file (e.g. executor_stub.go for a
	// module that only supports linux): uses ErrUnsupportedPlatform, not ErrNotImplemented.
	platformStubContent := `//go:build !linux

package testmod

import "errors"

var ErrUnsupportedPlatform = errors.New("unsupported platform")

type stubExecutor struct{}

func newExecutor() *stubExecutor { return &stubExecutor{} }

func (e *stubExecutor) getState(_ string) error {
	return ErrUnsupportedPlatform
}

func (e *stubExecutor) setState(_ string, _ bool) error {
	return ErrUnsupportedPlatform
}
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "platform-stub",
				manifestContent: validManifest("platform-stub"),
				hasCmdMain:      true,
				goFiles: map[string]string{
					"module.go":        cleanGoFileContent,
					"executor_stub.go": platformStubContent,
				},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.Equal(t, 0, code, "ErrUnsupportedPlatform in build-tag stub should NOT cause failure\nOutput:\n%s", out)
}

// TestCompletenessCheck6_ObserveWhenPresent verifies that a module.yaml
// carrying an observe_when: key satisfies check #6 (ADR-024 §3).
func TestCompletenessCheck6_ObserveWhenPresent(t *testing.T) {
	manifest := `name: observe-when-present
version: 0.1.0
publisher: cfgms
executors:
  - steward
interfaces:
  - Get
  - Set
  - Test
owns:
  - kind: observe-when-present
observe_when:
  - fact: os
    equals: linux
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "observe-when-present",
				manifestContent: manifest,
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.Equal(t, 0, code, "observe_when: present should satisfy check-6\nOutput:\n%s", out)
}

// TestCompletenessCheck6_OmissionMarker verifies that a module.yaml carrying
// the deliberate-omission marker comment satisfies check #6 (ADR-024 §3)
// without declaring observe_when itself.
func TestCompletenessCheck6_OmissionMarker(t *testing.T) {
	manifest := `name: observe-when-omitted
version: 0.1.0
publisher: cfgms
executors:
  - steward
interfaces:
  - Get
  - Set
  - Test
owns:
  - kind: observe-when-omitted
# observe_when: omitted — unbounded domain; content-bearing module (ADR-024 §3)
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "observe-when-omitted",
				manifestContent: manifest,
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.Equal(t, 0, code, "omission marker should satisfy check-6\nOutput:\n%s", out)
}

// TestCompletenessCheck6_NeitherFails verifies that a module.yaml with
// neither observe_when: nor the omission marker fails check #6 (ADR-024 §3).
func TestCompletenessCheck6_NeitherFails(t *testing.T) {
	manifest := `name: observe-when-neither
version: 0.1.0
publisher: cfgms
executors:
  - steward
interfaces:
  - Get
  - Set
  - Test
owns:
  - kind: observe-when-neither
`
	root := buildCompletenessFixture(t, completenessFixtureOpts{
		modules: []completenessModuleSpec{
			{
				name:            "observe-when-neither",
				manifestContent: manifest,
				hasCmdMain:      true,
				goFiles:         map[string]string{"module.go": cleanGoFileContent},
			},
		},
	})
	code, out := runCompletenessScript(t, root)
	assert.NotEqual(t, 0, code, "missing observe_when and omission marker should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "check-6", "output should mention check-6")
	assert.Contains(t, out, "observe-when-neither", "output should mention the failing module")
}
