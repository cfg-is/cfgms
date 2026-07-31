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

func TestSecurityDepsTargetFailsClosedWithoutGuideToken(t *testing.T) {
	binDir := t.TempDir()
	writeMockTool(t, binDir, "nancy", `exit 0`)

	code, output := runMakeSecurityTarget(t, "security-deps",
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GUIDE_TOKEN=",
	)

	assert.NotEqual(t, 0, code, "Nancy v2 must not run anonymously\n%s", output)
	assert.Contains(t, output, "GUIDE_TOKEN is required by Nancy v2")
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

func TestScriptSuiteRequiresOptInForLiveProjectMutations(t *testing.T) {
	scriptPath := filepath.Join(repoRoot(t), "scripts", "test-scripts.sh")
	content, err := os.ReadFile(scriptPath)
	require.NoError(t, err)

	const guard = `if [[ "${CFGMS_RUN_LIVE_PROJECT_TESTS:-}" != "1" ]]`
	assert.Equal(t, 2, strings.Count(string(content), guard),
		"both live GitHub project integration tests must require explicit opt-in")
}
