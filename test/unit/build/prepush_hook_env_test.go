// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package build_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/testutil"
)

// TestInstalledPrePushHookClearsGitRepositoryEnvironment installs the pre-push
// hook into a scratch repository, runs it with the repository variables git
// exports to hooks, and asserts that the `make test` it launches sees none of
// the variables from `git rev-parse --local-env-vars`.
func TestInstalledPrePushHookClearsGitRepositoryEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pre-push hook is a bash script installed on POSIX shells")
	}

	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		out, err := testutil.GitCommand(t, repo, args...).CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, out)
	}
	run("init", "-q", "-b", "feature/story-1-hook")
	require.NoError(t, os.MkdirAll(filepath.Join(repo, "scripts"), 0o750))
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "install-git-hooks.sh"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repo, "scripts", "install-git-hooks.sh"), src, 0o755))
	// Keep the work tree clean so the hook does not prompt about uncommitted changes.
	require.NoError(t, os.WriteFile(filepath.Join(repo, ".git", "info", "exclude"), []byte("scripts/\nmake.out\n"), 0o600))

	env := testutil.GitEnv(t.TempDir())
	install := exec.Command("bash", filepath.Join(repo, "scripts", "install-git-hooks.sh"))
	install.Dir = repo
	install.Env = env
	out, err := install.CombinedOutput()
	require.NoError(t, err, string(out))

	// Fake make records every git repository variable it can see.
	binDir := t.TempDir()
	record := filepath.Join(binDir, "make.out")
	localVars, err := exec.Command("git", "rev-parse", "--local-env-vars").Output() // #nosec G204 -- fixed args
	require.NoError(t, err)
	vars := strings.Join(strings.Fields(string(localVars)), " ")
	writeMockTool(t, binDir, "make", `for v in `+vars+`; do
  if [ -n "$(printenv "$v")" ]; then echo "$v" >> "`+record+`"; fi
done
echo ran >> "`+record+`"`)

	hook := exec.Command("bash", filepath.Join(repo, ".git", "hooks", "pre-push"), "origin", "file:///nowhere")
	hook.Dir = repo
	hook.Env = append(env,
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_DIR="+filepath.Join(repo, ".git"),
		"GIT_INDEX_FILE="+filepath.Join(repo, ".git", "index"),
		"GIT_WORK_TREE="+repo,
		"GIT_PREFIX=",
	)
	hook.Stdin = strings.NewReader("")
	out, err = hook.CombinedOutput()
	require.NoError(t, err, string(out))

	got, err := os.ReadFile(record)
	require.NoError(t, err, "fake make never ran: %s", out)
	require.Equal(t, "ran\n", string(got), "make test inherited git repository variables")
}
