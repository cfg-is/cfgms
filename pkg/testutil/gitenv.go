// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package testutil

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fallbackGitLocalEnvVars is used when `git rev-parse --local-env-vars` cannot
// be run. It is the set git itself reports as repository-local.
var fallbackGitLocalEnvVars = []string{
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_CONFIG",
	"GIT_CONFIG_PARAMETERS",
	"GIT_CONFIG_COUNT",
	"GIT_OBJECT_DIRECTORY",
	"GIT_DIR",
	"GIT_WORK_TREE",
	"GIT_IMPLICIT_WORK_TREE",
	"GIT_GRAFT_FILE",
	"GIT_INDEX_FILE",
	"GIT_NO_REPLACE_OBJECTS",
	"GIT_REPLACE_REF_BASE",
	"GIT_PREFIX",
	"GIT_SHALLOW_FILE",
	"GIT_COMMON_DIR",
}

var (
	gitLocalEnvOnce sync.Once
	gitLocalEnv     []string
)

// extraGitLocalEnvVars are always cleared in addition to git's own list: they
// redirect git at another repository or config even though git does not
// classify them as repository-local.
var extraGitLocalEnvVars = []string{"GIT_COMMON_DIR", "GIT_PREFIX", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}

// GitLocalEnvVars returns the environment variables git treats as
// repository-location state (`git rev-parse --local-env-vars`), plus a few
// that also redirect git at another repository or config. Git exports these to
// hooks; a git command that inherits them acts on the calling repository.
func GitLocalEnvVars() []string {
	gitLocalEnvOnce.Do(func() {
		seen := map[string]bool{}
		add := func(n string) {
			if n != "" && !seen[n] {
				seen[n] = true
				gitLocalEnv = append(gitLocalEnv, n)
			}
		}
		// #nosec G204 -- fixed git binary and arguments.
		if out, err := exec.Command("git", "rev-parse", "--local-env-vars").Output(); err == nil {
			for _, n := range strings.Fields(string(out)) {
				add(n)
			}
		}
		for _, n := range fallbackGitLocalEnvVars {
			add(n)
		}
		for _, n := range extraGitLocalEnvVars {
			add(n)
		}
	})
	return append([]string(nil), gitLocalEnv...)
}

// GitEnv returns the process environment with every git repository-location
// variable removed and global/system git config isolated: system config is
// disabled and HOME / GIT_CONFIG_GLOBAL point into home. home should be a
// per-test temporary directory.
func GitEnv(home string) []string {
	drop := map[string]bool{"HOME": true, "USERPROFILE": true, "XDG_CONFIG_HOME": true, "GIT_CONFIG_NOSYSTEM": true}
	for _, n := range GitLocalEnvVars() {
		drop[n] = true
	}
	var env []string
	for _, kv := range os.Environ() {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		if drop[name] || (os.PathSeparator == '\\' && drop[strings.ToUpper(name)]) {
			continue
		}
		env = append(env, kv)
	}
	return append(env,
		"GIT_CONFIG_NOSYSTEM=1",
		"HOME="+home,
		"USERPROFILE="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"GIT_CONFIG_GLOBAL="+filepath.Join(home, ".gitconfig"),
	)
}

// GitCommand builds a git command that runs in dir (when non-empty) with the
// isolated environment from GitEnv and a fresh temporary HOME.
func GitCommand(t testing.TB, dir string, args ...string) *exec.Cmd {
	t.Helper()
	// #nosec G204 -- fixed git binary; arguments are test-controlled.
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = GitEnv(t.TempDir())
	return cmd
}

// IsolateGitEnv clears the git repository-location variables from the test
// process environment and points HOME / global config at a temporary
// directory, restoring everything when the test ends. Use it in tests that call
// production code which itself runs git, so that code cannot reach the
// repository that invoked the test (for example from a git hook).
func IsolateGitEnv(t testing.TB) {
	t.Helper()
	for _, n := range GitLocalEnvVars() {
		if _, ok := os.LookupEnv(n); ok {
			t.Setenv(n, "") // registers restore of the original value
			_ = os.Unsetenv(n)
		}
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(home, ".gitconfig"))
}
