// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package build_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeMockTool(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755))
	return path
}

func runMakeSecurityTarget(t *testing.T, target string, extraEnv ...string) (int, string) {
	t.Helper()
	cmd := exec.Command("make", "--no-print-directory", target)
	cmd.Dir = repoRoot(t)
	cmd.Env = append(os.Environ(), extraEnv...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	var exitErr *exec.ExitError
	require.ErrorAs(t, err, &exitErr)
	return exitErr.ExitCode(), string(out)
}

func TestSecurityTrivyTargetFailsClosedOnInitializationError(t *testing.T) {
	binDir := t.TempDir()
	trivyPath := writeMockTool(t, binDir, "trivy", `
echo "FATAL run error: init error: DB error: failed to download vulnerability DB"
exit 1`)

	code, output := runMakeSecurityTarget(t, "security-trivy",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TRIVY_CMD="+trivyPath,
	)

	assert.NotEqual(t, 0, code, "an incomplete Trivy scan must fail the blocking target\n%s", output)
	assert.Contains(t, output, "Trivy scan incomplete")
	assert.Contains(t, output, "cannot pass until the scan completes cleanly")
}

func TestSecurityDepsTargetFailsClosedOnNancyFailure(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "go", `echo "{}"`)
	writeMockTool(t, binDir, "nancy", `
cat >/dev/null
echo "mock vulnerable dependency"
exit 1`)

	code, output := runMakeSecurityTarget(t, "security-deps",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GUIDE_TOKEN=test-only-token",
	)

	assert.NotEqual(t, 0, code, "Nancy findings or scanner failures must fail the blocking target\n%s", output)
	assert.Contains(t, output, "Nancy dependency scan failed or found vulnerable dependencies")
}

// Nancy v2 returns 401 Unauthorized without a Sonatype Guide token, so an
// unauthenticated run produces no evidence at all. CI must treat that as a
// failure rather than a clean scan.
func TestSecurityDepsTargetFailsClosedWithoutGuideTokenInCI(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "nancy", `exit 0`)

	code, output := runMakeSecurityTarget(t, "security-deps",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GUIDE_TOKEN=",
		"CI=true",
	)

	assert.NotEqual(t, 0, code, "Nancy v2 must not run anonymously in CI\n%s", output)
	assert.Contains(t, output, "GUIDE_TOKEN is required by Nancy v2")
}

// CFGMS_REQUIRE_GUIDE_TOKEN lets a developer opt into the CI contract on a
// workstation, so the fail-closed path can be exercised outside CI.
func TestSecurityDepsTargetFailsClosedWhenTokenExplicitlyRequired(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "nancy", `exit 0`)

	code, output := runMakeSecurityTarget(t, "security-deps",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GUIDE_TOKEN=",
		"CI=",
		"CFGMS_REQUIRE_GUIDE_TOKEN=1",
	)

	assert.NotEqual(t, 0, code, "an explicit token requirement must fail closed\n%s", output)
	assert.Contains(t, output, "GUIDE_TOKEN is required by Nancy v2")
}

// Outside CI the target skips rather than blocking local work — but it must say
// plainly that nothing was scanned, so a skip is never mistaken for a pass.
func TestSecurityDepsTargetSkipsLoudlyWithoutGuideTokenLocally(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "nancy", `exit 0`)

	code, output := runMakeSecurityTarget(t, "security-deps",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GUIDE_TOKEN=",
		"CI=",
		"CFGMS_REQUIRE_GUIDE_TOKEN=",
	)

	require.Equal(t, 0, code, "a local run without a token must not block development\n%s", output)
	assert.Contains(t, output, "SKIPPED: no GUIDE_TOKEN")
	assert.Contains(t, output, "dependency vulnerabilities were NOT checked")
	assert.NotContains(t, output, "no critical vulnerabilities found",
		"a skipped scan must never claim a clean result")
}

// A skipped dependency scan must be visible in the aggregate summary too, so
// local security-scan output cannot be read as complete evidence.
func TestSecurityScanReportsSkippedDependencyScan(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "go", `echo "{}"`)
	writeMockTool(t, binDir, "nancy", `cat >/dev/null`)
	writeMockTool(t, binDir, "gosec", `exit 0`)
	writeMockTool(t, binDir, "staticcheck", `exit 0`)
	trivyPath := writeMockTool(t, binDir, "trivy", `exit 0`)

	code, output := runMakeSecurityTarget(t, "security-scan",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TRIVY_CMD="+trivyPath,
		"GUIDE_TOKEN=",
		"CI=",
		"CFGMS_REQUIRE_GUIDE_TOKEN=",
	)

	require.Equal(t, 0, code, output)
	assert.Contains(t, output, "Nancy dependency scan: ⏭️  SKIPPED (no GUIDE_TOKEN)")
	assert.Contains(t, output, "not complete evidence")
}

func TestSecurityScanSuccessIsLocalEvidenceOnly(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "go", `echo "{}"`)
	writeMockTool(t, binDir, "nancy", `cat >/dev/null`)
	writeMockTool(t, binDir, "gosec", `exit 0`)
	writeMockTool(t, binDir, "staticcheck", `exit 0`)
	trivyPath := writeMockTool(t, binDir, "trivy", `exit 0`)

	code, output := runMakeSecurityTarget(t, "security-scan",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"TRIVY_CMD="+trivyPath,
		"GUIDE_TOKEN=test-only-token",
	)

	require.Equal(t, 0, code, output)
	assert.Contains(t, output, "ALL LOCAL SECURITY GATES PASSED")
	assert.False(t, strings.Contains(output, "DEPLOYMENT APPROVED"),
		"a local scanner run must not make a deployment-approval claim")
}

// stageFiles creates a throwaway git repository containing the given files and
// stages them, so the artifact check has a `git ls-files` inventory to walk.
func stageFiles(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), content, 0o644))
	}
	init := exec.Command("git", "init", "--quiet", ".")
	init.Dir = dir
	out, err := init.CombinedOutput()
	require.NoError(t, err, string(out))

	add := exec.Command("git", "add", "--all")
	add.Dir = dir
	out, err = add.CombinedOutput()
	require.NoError(t, err, string(out))
	return dir
}

// runBinaryArtifactCheck runs the gate against repoDir with a file(1) shim that
// always fails. The check is the first prerequisite of `make security-scan`, so
// depending on file(1) — a separate package missing from minimal build
// containers — aborted the whole security target with exit 2 before any scanner
// ran. Classification must come from the artifacts' own magic bytes.
func runBinaryArtifactCheck(t *testing.T, repoDir string) (int, string) {
	t.Helper()
	shimDir := t.TempDir()
	writeMockTool(t, shimDir, "file", `
echo "file utility is unavailable" >&2
exit 127`)

	cmd := exec.Command("bash", filepath.Join(repoRoot(t), "scripts", "check-binary-artifacts.sh"))
	cmd.Dir = repoDir
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

func TestBinaryArtifactCheckDetectsArtifactsWithoutFileUtility(t *testing.T) {
	repo := stageFiles(t, map[string][]byte{
		"linux-agent":   []byte("\x7fELF\x02\x01\x01\x00payload"),
		"darwin-agent":  []byte("\xcf\xfa\xed\xfe\x07\x00\x00\x01"),
		"windows-agent": []byte("MZ\x90\x00\x03\x00\x00\x00"),
		"module.wat":    []byte("\x00asm\x01\x00\x00\x00"),
		"main.go":       []byte("package main\n"),
	})

	code, output := runBinaryArtifactCheck(t, repo)

	require.Equal(t, 1, code, "committed compiled artifacts must fail the gate\n%s", output)
	assert.Contains(t, output, "linux-agent (ELF binary)")
	assert.Contains(t, output, "darwin-agent (Mach-O binary)")
	assert.Contains(t, output, "windows-agent (PE32/MS-DOS executable)")
	assert.Contains(t, output, "module.wat (WebAssembly binary module)")
	assert.NotContains(t, output, "main.go")
}

func TestBinaryArtifactCheckPassesOnSourceOnlyTreeWithoutFileUtility(t *testing.T) {
	repo := stageFiles(t, map[string][]byte{
		"main.go":   []byte("package main\n\nfunc main() {}\n"),
		"README.md": []byte("# cfgms\n"),
		"empty.txt": {},
	})

	code, output := runBinaryArtifactCheck(t, repo)

	require.Equal(t, 0, code, "a source-only tree must pass without file(1)\n%s", output)
	assert.Contains(t, output, "binary-artifact check passed")
}

func TestScriptSuiteRequiresOptInForLiveProjectMutations(t *testing.T) {
	scriptPath := filepath.Join(repoRoot(t), "scripts", "test-scripts.sh")
	content, err := os.ReadFile(scriptPath)
	require.NoError(t, err)

	const guard = `if [[ "${CFGMS_RUN_LIVE_PROJECT_TESTS:-}" != "1" ]]`
	assert.Equal(t, 2, strings.Count(string(content), guard),
		"both live GitHub project integration tests must require explicit opt-in")
}
