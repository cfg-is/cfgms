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
	// The resolver pins to the requested version by checking out a git ref of
	// that exact name (Issue #4409), so the fixture must tag the commit with
	// the version string used in the test's ref, not just record it in
	// module.yaml's Version field.
	git("tag", version)
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
		// A leading "-" on any component would let a crafted ref be parsed as a
		// git flag rather than a ref name by the ls-remote/fetch/checkout calls
		// in cloneRepo (Issue #4409 hardening).
		"-publisher/name@version",
		"publisher/-name@version",
		"publisher/name@-version",
	}

	for _, ref := range invalidRefs {
		_, err := r.ResolveURL(ref)
		assert.Error(t, err, "expected error for ref %q", ref)
	}
}

// initLocalGitRepoWithTags creates a local git repository with two commits, each
// tagged with a distinct version and carrying a distinct module.yaml Version
// field and binary content. This lets a test tell "resolver pinned to the
// requested tag" apart from "resolver silently served whatever HEAD is" — the
// latter would make both b1.Manifest.Version and b2.Manifest.Version read
// "2.0.0" (the last commit made), since parseBundleFromDir reads Version out of
// the checked-out module.yaml, not out of the requested ref string.
func initLocalGitRepoWithTags(t *testing.T, gitBin, repoDir, publisher, name string) {
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

	writeCommitAndTag := func(version, binContent, tag string) {
		meta := modules.ModuleMetadata{
			Name:        name,
			Version:     version,
			Publisher:   publisher,
			Description: "Test module for git resolver pinning",
			Executors:   []string{"steward"},
		}
		metaBytes, err := yaml.Marshal(meta)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(repoDir, "module.yaml"), metaBytes, 0640))

		binDir := filepath.Join(repoDir, "binaries")
		require.NoError(t, os.MkdirAll(binDir, 0750))
		require.NoError(t, os.WriteFile(filepath.Join(binDir, "linux-amd64"), []byte(binContent), 0640))

		git("add", "module.yaml", filepath.Join("binaries", "linux-amd64"))
		git("commit", "-m", "module version "+version)
		git("tag", tag)
	}

	writeCommitAndTag("1.0.0", "v1-binary-content", "1.0.0")
	writeCommitAndTag("2.0.0", "v2-binary-content", "2.0.0")
}

// [REQUIRED TEST] Issue #4409: the resolver must check out the exact tag named
// by the requested version, not whatever the source repository's default
// branch currently points to. Against the pre-fix code (plain "git clone
// --depth 1" with no checkout of the resolved ref) both resolutions below
// observe the tip commit — tagged 2.0.0 — regardless of which version was
// requested, so this test fails on that code with b1.Manifest.Version == "2.0.0"
// and b1.ContentHash == b2.ContentHash. Confirmed failing against the pre-fix
// cloneRepo before the pinning fix was applied, and passing after.
func TestGitSourceResolver_Resolve_PinsToRequestedTag(t *testing.T) {
	gitBin := skipIfNoGit(t)

	repoDir := t.TempDir()
	initLocalGitRepoWithTags(t, gitBin, repoDir, "cfgms", "pinned-module")
	repoName := filepath.Base(repoDir)

	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + filepath.Dir(repoDir)},
	}
	cloneRoot := t.TempDir()
	r, err := gitresolver.New(sources, cloneRoot, logging.NewNoopLogger())
	require.NoError(t, err)

	b1, err := r.Resolve(context.Background(), "cfgms/"+repoName+"@1.0.0")
	require.NoError(t, err)
	b2, err := r.Resolve(context.Background(), "cfgms/"+repoName+"@2.0.0")
	require.NoError(t, err)

	assert.Equal(t, "1.0.0", b1.Manifest.Version, "resolving @1.0.0 must check out the 1.0.0 tag's content, not HEAD")
	assert.Equal(t, "2.0.0", b2.Manifest.Version, "resolving @2.0.0 must check out the 2.0.0 tag's content, not HEAD")
	assert.NotEqual(t, b1.ContentHash, b2.ContentHash, "different tags with different content must produce different content hashes")

	// Re-resolving the same version must reproduce the same, correctly-pinned
	// content — the fix must not just "sometimes" pin correctly on a cold cache.
	b1Again, err := r.Resolve(context.Background(), "cfgms/"+repoName+"@1.0.0")
	require.NoError(t, err)
	assert.Equal(t, b1.ContentHash, b1Again.ContentHash)
	assert.Equal(t, "1.0.0", b1Again.Manifest.Version)
}

// [REQUIRED TEST] Issue #4409: an unresolvable ref must fail closed with an
// error naming the ref, and must never fall back to resolving the source
// repository's default branch instead.
func TestGitSourceResolver_Resolve_UnresolvableRefFailsClosed(t *testing.T) {
	gitBin := skipIfNoGit(t)

	repoDir := t.TempDir()
	initLocalGitRepoWithTags(t, gitBin, repoDir, "cfgms", "strict-module")
	repoName := filepath.Base(repoDir)

	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + filepath.Dir(repoDir)},
	}
	cloneRoot := t.TempDir()
	r, err := gitresolver.New(sources, cloneRoot, logging.NewNoopLogger())
	require.NoError(t, err)

	const missingRef = "9.9.9-does-not-exist"
	b, err := r.Resolve(context.Background(), "cfgms/"+repoName+"@"+missingRef)
	require.Error(t, err, "resolving a nonexistent ref must fail, never silently fall back to the default branch")
	assert.Nil(t, b)
	assert.Contains(t, err.Error(), missingRef, "the error must name the ref that could not be resolved")
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
