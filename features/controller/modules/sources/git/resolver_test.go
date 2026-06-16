// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package git_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
)

// skipIfNoGit skips the test if the git binary is not available.
// git is an external binary dependency required for clone operations.
func skipIfNoGit(t *testing.T) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not found in PATH; required for git resolver integration tests")
	}
	return gitBin
}

// initLocalGitRepo creates a bare-ish local git repository at dir with a valid
// module.yaml, a fake binary under binaries/, and commits everything.
// Returns the absolute path to the repo (usable as a file:// clone URL).
func initLocalGitRepo(t *testing.T, gitBin, repoDir, publisher, name, version string) {
	t.Helper()

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = repoDir
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "git %v: %s", args, string(out))
	}

	git("init", repoDir)
	git("-C", repoDir, "config", "user.email", "test@cfgms.test")
	git("-C", repoDir, "config", "user.name", "CFGMS Test")

	// Write module.yaml.
	meta := modules.ModuleMetadata{
		Name:        name,
		Version:     version,
		Publisher:   publisher,
		Description: "Test module for git resolver",
		Executors:   []string{"steward"},
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "module.yaml"), metaBytes, 0640))

	// Write a fake binary.
	binDir := filepath.Join(repoDir, "binaries")
	require.NoError(t, os.MkdirAll(binDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "linux-amd64"), []byte("fake-binary-content"), 0640))

	git("add", "module.yaml", filepath.Join("binaries", "linux-amd64"))
	git("commit", "-m", "Initial module commit")
}

// [REQUIRED TEST] git resolver maps publisher namespace to git base URL and returns a parsed Bundle.
func TestGitSourceResolver_Resolve_ReturnsBundle(t *testing.T) {
	gitBin := skipIfNoGit(t)

	// Create a local git repo acting as the module source.
	repoDir := t.TempDir()
	initLocalGitRepo(t, gitBin, repoDir, "cfgms", "test-module", "1.0.0")

	// Configure the resolver to use the local repo dir as the base URL.
	// file:// protocol lets git clone from local paths.
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + filepath.Dir(repoDir)},
	}
	// The repo dir name is the "name" segment.
	repoName := filepath.Base(repoDir)

	cloneRoot := t.TempDir()
	logger := logging.NewNoopLogger()
	r, err := gitresolver.New(sources, cloneRoot, logger)
	require.NoError(t, err)

	ref := "cfgms/" + repoName + "@1.0.0"
	b, err := r.Resolve(context.Background(), ref)
	require.NoError(t, err, "Resolve must succeed for a valid local git module")

	assert.NotNil(t, b)
	assert.NotEmpty(t, b.ContentHash, "resolved bundle must have a content hash")
	assert.Equal(t, "test-module", b.Manifest.Name)
	assert.Equal(t, "1.0.0", b.Manifest.Version)
	assert.Equal(t, "cfgms", b.Manifest.Publisher)
	assert.Contains(t, b.Binaries, "linux-amd64", "binaries map must contain linux-amd64 key")
}

// TestGitSourceResolver_ResolveURL_MapsPublisherToURL verifies URL construction without cloning.
func TestGitSourceResolver_ResolveURL_MapsPublisherToURL(t *testing.T) {
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "https://modules.example.com/cfgms"},
	}
	r, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	url, err := r.ResolveURL("cfgms/hyperv@0.2.1")
	require.NoError(t, err)
	assert.Equal(t, "https://modules.example.com/cfgms/hyperv", url)
}

// TestGitSourceResolver_ResolveURL_UnknownPublisher returns an error.
func TestGitSourceResolver_ResolveURL_UnknownPublisher(t *testing.T) {
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "https://modules.example.com/cfgms"},
	}
	r, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	_, err = r.ResolveURL("unknown-vendor/tool@1.0.0")
	assert.Error(t, err)
}

// TestGitSourceResolver_ParseRef_Invalid returns an error for malformed refs.
func TestGitSourceResolver_ParseRef_Invalid(t *testing.T) {
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "https://modules.example.com"},
	}
	r, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	invalidRefs := []string{
		"no-at-sign",
		"@version",
		"publisher/name",
		"../evil/name@version",
		"publisher/../name@version",
	}

	for _, ref := range invalidRefs {
		_, err := r.ResolveURL(ref)
		assert.Error(t, err, "expected error for ref %q", ref)
	}
}

// TestGitSourceResolver_Resolve_Idempotent verifies that resolving twice uses cached clone.
func TestGitSourceResolver_Resolve_Idempotent(t *testing.T) {
	gitBin := skipIfNoGit(t)

	repoDir := t.TempDir()
	initLocalGitRepo(t, gitBin, repoDir, "cfgms", "my-module", "2.0.0")
	repoName := filepath.Base(repoDir)

	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + filepath.Dir(repoDir)},
	}

	cloneRoot := t.TempDir()
	r, err := gitresolver.New(sources, cloneRoot, logging.NewNoopLogger())
	require.NoError(t, err)

	ref := "cfgms/" + repoName + "@2.0.0"

	b1, err := r.Resolve(context.Background(), ref)
	require.NoError(t, err)

	b2, err := r.Resolve(context.Background(), ref)
	require.NoError(t, err)

	assert.Equal(t, b1.ContentHash, b2.ContentHash, "repeated Resolve must return same content hash")
}
