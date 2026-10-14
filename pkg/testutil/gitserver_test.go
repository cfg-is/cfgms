// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package testutil_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/testutil"
)

// Not parallel: GIT_SSL_CAINFO is set with t.Setenv.
func TestNewGitServer_ServesRepoOverVerifiedTLS(t *testing.T) {
	reposRoot := t.TempDir()
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "served"})
	sb.CommitToRepo(t, filepath.Join(reposRoot, "served"))

	baseURL, caFile := testutil.NewGitServer(t, reposRoot)
	require.True(t, strings.HasPrefix(baseURL, "https://"))

	lsRemote := func() ([]byte, error) {
		// #nosec G204 -- fixed binary; URL produced by the test server.
		return exec.Command("git", "ls-remote", baseURL+"/served").CombinedOutput()
	}

	t.Setenv("GIT_SSL_CAINFO", "")
	_, err := lsRemote()
	assert.Error(t, err, "without the server CA the self-signed certificate must be refused")

	t.Setenv("GIT_SSL_CAINFO", caFile)
	out, err := lsRemote()
	require.NoError(t, err, string(out))
	assert.Contains(t, string(out), "HEAD")
}
