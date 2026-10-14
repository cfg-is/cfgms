// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package git_test

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func currentPlatform() string { return runtime.GOOS + "-" + runtime.GOARCH }

// runGitInput runs git in dir with stdin and returns trimmed stdout.
func runGitInput(t *testing.T, dir, stdin string, args ...string) string {
	t.Helper()
	// #nosec G204 -- fixed git binary; arguments are test-controlled.
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	require.NoError(t, err, "git %s", strings.Join(args, " "))
	return strings.TrimSpace(string(out))
}
