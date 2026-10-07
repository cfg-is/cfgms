// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package build_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoRoot locates the workspace root by walking up from this file's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok, "runtime.Caller failed")
	// test/unit/build/stdlib_payload_boundary_test.go → ../../.. = repo root
	root := filepath.Join(filepath.Dir(file), "..", "..", "..")
	abs, err := filepath.Abs(root)
	require.NoError(t, err)
	return abs
}

func scriptPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRoot(t), "scripts", "check-stdlib-payload-boundary.sh")
}

// runScript executes the boundary-check script with REPO_ROOT overridden to the
// given root directory.  It returns (exitCode, combined output).
func runScript(t *testing.T, repoOverride string) (int, string) {
	t.Helper()
	cmd := exec.Command("bash", scriptPath(t))
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

// TestRealRepo verifies that the script exits 0 against the actual repository tree.
// All four payload lists and the stdlib/ directory must agree on the six current
// stdlib modules.
func TestRealRepo(t *testing.T) {
	root := repoRoot(t)
	code, out := runScript(t, root)
	assert.Equal(t, 0, code, "check-stdlib-payload-boundary should pass on the real repo tree\nOutput:\n%s", out)
}

// fixtureTree builds a minimal but structurally correct repository fixture under
// t.TempDir(), with exactly the modules given in `modules`.
type fixtureOpts struct {
	// stdlibDirs names the directories to create under features/modules/stdlib/
	stdlibDirs []string
	// makefileModules is the space-separated STDLIB_MODULES value
	makefileModules []string
	// wxsModules are the module names (without cfgms-module- prefix or .exe suffix)
	// that appear as <File … Name="cfgms-module-X.exe" …/> inside MODULESDIR
	wxsModules []string
	// installShModules are the cfgms-module-X names in install.sh STDLIB_MODULES
	installShModules []string
	// buildPkgModules are the cfgms-module-X names in build-pkg.sh STDLIB_MODULES
	buildPkgModules []string
}

func buildFixture(t *testing.T, opts fixtureOpts) string {
	t.Helper()
	root := t.TempDir()

	// features/modules/stdlib/<name>/
	stdlibBase := filepath.Join(root, "features", "modules", "stdlib")
	require.NoError(t, os.MkdirAll(stdlibBase, 0o755))
	for _, name := range opts.stdlibDirs {
		require.NoError(t, os.MkdirAll(filepath.Join(stdlibBase, name), 0o755))
	}

	// Makefile — only the STDLIB_MODULES variable line matters to the script
	makefileContent := "STDLIB_MODULES := \\\n"
	for i, m := range opts.makefileModules {
		if i < len(opts.makefileModules)-1 {
			makefileContent += fmt.Sprintf("\t%s \\\n", m)
		} else {
			makefileContent += fmt.Sprintf("\t%s\n", m)
		}
	}
	makefileContent += "\nbuild-stdlib-modules:\n\t@echo building\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "Makefile"), []byte(makefileContent), 0o644))

	// build/windows/cfgms-steward.wxs — minimal structure
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build", "windows"), 0o755))
	wxsComponents := ""
	for _, m := range opts.wxsModules {
		capitalized := strings.ToUpper(m[:1]) + m[1:]
		wxsComponents += fmt.Sprintf(`          <Component Id="Module%s" Guid="*">
            <File Id="Module%sExe" Source="$(var.ModulesDir)\cfgms-module-%s.exe" Name="cfgms-module-%s.exe" KeyPath="yes" />
          </Component>
`, capitalized, capitalized, m, m)
	}
	wxsContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="CFGMS Steward">
    <StandardDirectory Id="ProgramFiles6432Folder">
      <Directory Id="INSTALLDIR" Name="CFGMS">
        <Directory Id="MODULESDIR" Name="modules">
%s        </Directory>
      </Directory>
    </StandardDirectory>
  </Package>
</Wix>
`, wxsComponents)
	require.NoError(t, os.WriteFile(filepath.Join(root, "build", "windows", "cfgms-steward.wxs"), []byte(wxsContent), 0o644))

	// build/linux/install.sh — minimal structure with STDLIB_MODULES array
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build", "linux"), 0o755))
	installShLines := "#!/bin/bash\n# Install stdlib module binaries\nSTDLIB_MODULES=(\n"
	for _, m := range opts.installShModules {
		installShLines += fmt.Sprintf("    %s\n", m)
	}
	installShLines += ")\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "build", "linux", "install.sh"), []byte(installShLines), 0o755))

	// build/darwin/build-pkg.sh — minimal structure with STDLIB_MODULES array
	require.NoError(t, os.MkdirAll(filepath.Join(root, "build", "darwin"), 0o755))
	buildPkgLines := "#!/bin/bash\n# Install stdlib module binaries into the payload tree.\nSTDLIB_MODULES=(\n"
	for _, m := range opts.buildPkgModules {
		buildPkgLines += fmt.Sprintf("    %s\n", m)
	}
	buildPkgLines += ")\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "build", "darwin", "build-pkg.sh"), []byte(buildPkgLines), 0o755))

	return root
}

var sixModules = []string{"file", "firewall", "package", "patch", "script", "service"}

func sixModulesWithPrefix() []string {
	result := make([]string, len(sixModules))
	for i, m := range sixModules {
		result[i] = "cfgms-module-" + m
	}
	return result
}

// TestFixtureBaseline verifies that the fixture builder itself produces a
// consistent tree that the script accepts (exit 0).
func TestFixtureBaseline(t *testing.T) {
	root := buildFixture(t, fixtureOpts{
		stdlibDirs:       sixModules,
		makefileModules:  sixModules,
		wxsModules:       sixModules,
		installShModules: sixModulesWithPrefix(),
		buildPkgModules:  sixModulesWithPrefix(),
	})
	code, out := runScript(t, root)
	assert.Equal(t, 0, code, "consistent fixture should pass\nOutput:\n%s", out)
}

// TestStrayStdlibDirectory verifies that a directory under features/modules/stdlib/
// not present in any of the four lists causes the script to fail with a diagnostic.
func TestStrayStdlibDirectory(t *testing.T) {
	dirs := append([]string{"stray"}, sixModules...)
	root := buildFixture(t, fixtureOpts{
		stdlibDirs:       dirs,
		makefileModules:  sixModules,
		wxsModules:       sixModules,
		installShModules: sixModulesWithPrefix(),
		buildPkgModules:  sixModulesWithPrefix(),
	})
	code, out := runScript(t, root)
	assert.NotEqual(t, 0, code, "stray stdlib dir should cause failure\nOutput:\n%s", out)
	assert.Contains(t, out, "stray", "diagnostic should mention the stray module name")
}

// TestMakefileEntryMissingFromWXS verifies that a module in the Makefile but
// absent from the WiX .wxs causes the script to fail.
func TestMakefileEntryMissingFromWXS(t *testing.T) {
	// extramodule appears in Makefile, stdlib dir, install.sh, build-pkg.sh but NOT wxs
	extraMods := append(sixModules, "extramodule")
	extraModsWithPrefix := append(sixModulesWithPrefix(), "cfgms-module-extramodule")
	root := buildFixture(t, fixtureOpts{
		stdlibDirs:       extraMods,
		makefileModules:  extraMods,
		wxsModules:       sixModules, // missing extramodule
		installShModules: extraModsWithPrefix,
		buildPkgModules:  extraModsWithPrefix,
	})
	code, out := runScript(t, root)
	assert.NotEqual(t, 0, code, "Makefile entry missing from wxs should fail\nOutput:\n%s", out)
	assert.Contains(t, out, "extramodule", "diagnostic should mention the missing module name")
}

// TestWXSEntryMissingFromInstallSh verifies that a module in the WiX .wxs but
// absent from install.sh causes the script to fail.
func TestWXSEntryMissingFromInstallSh(t *testing.T) {
	// extramodule appears in wxs (and Makefile, stdlib, build-pkg.sh) but NOT install.sh
	extraMods := append(sixModules, "extramodule")
	extraModsWithPrefix := append(sixModulesWithPrefix(), "cfgms-module-extramodule")
	root := buildFixture(t, fixtureOpts{
		stdlibDirs:       extraMods,
		makefileModules:  extraMods,
		wxsModules:       extraMods,
		installShModules: sixModulesWithPrefix(), // missing extramodule
		buildPkgModules:  extraModsWithPrefix,
	})
	code, out := runScript(t, root)
	assert.NotEqual(t, 0, code, "wxs entry missing from install.sh should fail\nOutput:\n%s", out)
	assert.Contains(t, out, "extramodule", "diagnostic should mention the missing module name")
}

// TestInstallShEntryMissingFromBuildPkg verifies that a module in install.sh but
// absent from build-pkg.sh causes the script to fail.
func TestInstallShEntryMissingFromBuildPkg(t *testing.T) {
	// extramodule appears in install.sh (and Makefile, stdlib, wxs) but NOT build-pkg.sh
	extraMods := append(sixModules, "extramodule")
	extraModsWithPrefix := append(sixModulesWithPrefix(), "cfgms-module-extramodule")
	root := buildFixture(t, fixtureOpts{
		stdlibDirs:       extraMods,
		makefileModules:  extraMods,
		wxsModules:       extraMods,
		installShModules: extraModsWithPrefix,
		buildPkgModules:  sixModulesWithPrefix(), // missing extramodule
	})
	code, out := runScript(t, root)
	assert.NotEqual(t, 0, code, "install.sh entry missing from build-pkg.sh should fail\nOutput:\n%s", out)
	assert.Contains(t, out, "extramodule", "diagnostic should mention the missing module name")
}

// TestEntryInListButNotStdlibDir verifies that a module listed in the Makefile
// but without a directory under features/modules/stdlib/ causes failure.
func TestEntryInListButNotStdlibDir(t *testing.T) {
	// "ghost" appears in all four lists but has no stdlib directory
	extraMods := append(sixModules, "ghost")
	extraModsWithPrefix := append(sixModulesWithPrefix(), "cfgms-module-ghost")
	root := buildFixture(t, fixtureOpts{
		stdlibDirs:       sixModules, // missing ghost directory
		makefileModules:  extraMods,
		wxsModules:       extraMods,
		installShModules: extraModsWithPrefix,
		buildPkgModules:  extraModsWithPrefix,
	})
	code, out := runScript(t, root)
	assert.NotEqual(t, 0, code, "list entry without stdlib dir should fail\nOutput:\n%s", out)
	assert.Contains(t, out, "ghost", "diagnostic should mention the missing module name")
}
