// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package git_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// runGit runs git in dir and returns trimmed stdout, failing the test on error.
func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	full := append([]string{"-C", dir,
		"-c", "user.name=cfgms-test", "-c", "user.email=test@example.invalid",
		"-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", "-c", "protocol.file.allow=always"}, args...)
	// #nosec G204 -- fixed git binary; arguments are test-controlled.
	out, err := exec.Command("git", full...).CombinedOutput()
	require.NoError(t, err, "git %s: %s", strings.Join(args, " "), out)
	return strings.TrimSpace(string(out))
}

// fixture is a served module repository plus a resolver pointed at it.
type fixture struct {
	repoDir  string
	root     string
	name     string
	resolver *gitresolver.GitSourceResolver
	tagged   bool // set when a test tagged a hand-built commit itself
}

// serveRepo serves every repository under root over verified TLS and returns a
// resolver for publisher "cfgms". Tests using it must not call t.Parallel().
func serveRepo(t *testing.T, root, name string) *fixture {
	t.Helper()
	baseURL, caFile := testutil.NewGitServer(t, root)
	t.Setenv("GIT_SSL_CAINFO", caFile)
	r, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: baseURL},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)
	return &fixture{repoDir: filepath.Join(root, name), root: root, name: name, resolver: r}
}

// publish commits sb as the root of a repository named after the module, tags it
// with its version and serves it.
func publish(t *testing.T, sb *testutil.SignedBundle) *fixture {
	t.Helper()
	root := t.TempDir()
	name := sb.Manifest.Name
	sb.CommitToRepo(t, filepath.Join(root, name))
	runGit(t, filepath.Join(root, name), "tag", sb.Manifest.Version)
	return serveRepo(t, root, name)
}

func (f *fixture) ref(version string) string { return "cfgms/" + f.name + "@" + version }

func TestValidateBase(t *testing.T) {
	good := []string{
		"https://modules.example.com/cfgms",
		"https://modules.example.com:8443/cfgms/",
		"ssh://git@modules.example.com/cfgms",
		"ssh://modules.example.com/cfgms",
	}
	for _, b := range good {
		assert.NoError(t, gitresolver.ValidateBase(b), b)
	}

	bad := map[string]string{
		"empty":         "",
		"file":          "file:///srv/modules",
		"http":          "http://modules.example.com/cfgms",
		"ext":           "ext::sh -c touch% /tmp/pwned",
		"git":           "git://modules.example.com/cfgms",
		"userinfo":      "https://user:pass@modules.example.com/cfgms",
		"https user":    "https://user@modules.example.com/cfgms",
		"ssh password":  "ssh://git:secret@modules.example.com/cfgms",
		"space":         "https://modules.example.com/c fgms",
		"newline":       "https://modules.example.com/cfgms\n",
		"scp style":     "git@modules.example.com:cfgms",
		"bare path":     "/srv/modules",
		"no host":       "https:///cfgms",
		"option host":   "ssh://-oProxyCommand=touch/cfgms",
		"query":         "https://modules.example.com/cfgms?x=1",
		"fragment":      "https://modules.example.com/cfgms#x",
		"backslash":     `https://modules.example.com\cfgms`,
		"unknown proto": "ftp://modules.example.com/cfgms",
	}
	for label, b := range bad {
		assert.Error(t, gitresolver.ValidateBase(b), label)
		_, err := gitresolver.New(map[string]gitresolver.SourceConfig{"cfgms": {Type: "git", Base: b}}, t.TempDir(), nil)
		assert.Error(t, err, "New must refuse base: %s", label)
	}
}

// [REQUIRED TEST] only an exact-semver tag resolves; every other ref form is refused.
func TestResolve_RefMustBeExactSemverTag(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "tagged", Version: "1.0.0"})
	f := publish(t, sb)
	sha := runGit(t, f.repoDir, "rev-parse", "HEAD")
	runGit(t, f.repoDir, "tag", "v1.0.0")

	for _, version := range []string{"main", "HEAD", sha, "v1.0.0", "1.0", "^1.0.0", "latest"} {
		b, err := f.resolver.Resolve(context.Background(), f.ref(version))
		require.Error(t, err, version)
		assert.Nil(t, b, version)
	}

	b, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, "tagged", b.Manifest.Name)
}

// [REQUIRED TEST] fixture provenance: Assemble+Sign output, committed, tagged,
// served over https and resolved verifies against the publisher's key.
func TestResolve_ReturnsSignedPayloadBundle(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{
		Name: "fixture", Platforms: []string{"linux-amd64", "windows-amd64", "darwin-arm64"},
	})
	f := publish(t, sb)

	b, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, sb.ContentHash, b.ContentHash)
	assert.Len(t, b.Binaries, 3, "a multi-platform module carries every platform from the one root")
	assert.NotEmpty(t, b.ManifestBytes)
	assert.Len(t, b.BinaryContent, 3)
	require.NotEmpty(t, b.Signatures)

	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name: "cfgms", PublicKey: []byte(sb.PublicKey), Algorithm: "ed25519",
	}))
	for _, sig := range b.Signatures {
		assert.NoError(t, trust.VerifyBundleSignature(b, sig, store))
	}
}

// Different tags resolve to their own content and the same tag is stable.
func TestResolve_PinsToRequestedTag(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "pinned")
	v1 := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "pinned", Version: "1.0.0"})
	v1.CommitToRepo(t, repo)
	runGit(t, repo, "tag", "1.0.0")
	v2 := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "pinned", Version: "2.0.0"})
	v2.CommitToRepo(t, repo)
	runGit(t, repo, "tag", "2.0.0")
	f := serveRepo(t, root, "pinned")

	b1, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.NoError(t, err)
	b2, err := f.resolver.Resolve(context.Background(), f.ref("2.0.0"))
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", b1.Manifest.Version)
	assert.Equal(t, "2.0.0", b2.Manifest.Version)
	assert.NotEqual(t, b1.ContentHash, b2.ContentHash)

	again, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.NoError(t, err)
	assert.Equal(t, b1.ContentHash, again.ContentHash)

	_, err = f.resolver.Resolve(context.Background(), f.ref("9.9.9"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "9.9.9")
}

// [REQUIRED TEST] a self-signed https source without the operator's CA is refused.
func TestResolve_SelfSignedSourceWithoutCARefused(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "tlsmod"})
	f := publish(t, sb)
	t.Setenv("GIT_SSL_CAINFO", "")

	b, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.Error(t, err)
	assert.Nil(t, b)
}

// [REQUIRED TEST] the error for an unreachable source contains no URL.
func TestResolve_UnreachableSourceErrorHasNoURL(t *testing.T) {
	r, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "https://127.0.0.1:1/secret-prefix"},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	_, err = r.Resolve(context.Background(), "cfgms/mod@1.0.0")
	require.Error(t, err)
	for _, leak := range []string{"127.0.0.1", "secret-prefix", "https://"} {
		assert.NotContains(t, err.Error(), leak)
	}
}

// [REQUIRED TEST] a binary changed after signing is refused with ErrContentHashMismatch.
func TestResolve_BinaryChangedAfterSigningRefused(t *testing.T) {
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "tampered"})
	f := publish(t, sb)
	bin := testutil.BinaryFileName("tampered", currentPlatform())
	require.NoError(t, os.WriteFile(filepath.Join(f.repoDir, bin), []byte("evil"), 0o600))
	runGit(t, f.repoDir, "commit", "-qam", "tamper")
	runGit(t, f.repoDir, "tag", "-f", "1.0.0")

	b, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.ErrorIs(t, err, bundle.ErrContentHashMismatch)
	assert.Nil(t, b)
	assert.NotContains(t, err.Error(), f.root, "error must not leak filesystem paths")
}

// [REQUIRED TEST] manifest identity must equal the request: one case each.
func TestResolve_ManifestIdentityMustMatchRef(t *testing.T) {
	cases := map[string]struct {
		opts    testutil.BundleOptions
		version string
	}{
		"publisher": {testutil.BundleOptions{Publisher: "other", Name: "idmod", Version: "1.0.0"}, "1.0.0"},
		"name":      {testutil.BundleOptions{Name: "othername", Version: "1.0.0"}, "1.0.0"},
		"version":   {testutil.BundleOptions{Name: "idmod", Version: "2.0.0"}, "1.0.0"},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			sb := testutil.NewSignedBundle(t, tc.opts)
			root := t.TempDir()
			sb.CommitToRepo(t, filepath.Join(root, "idmod"))
			runGit(t, filepath.Join(root, "idmod"), "tag", tc.version)
			f := serveRepo(t, root, "idmod")

			b, err := f.resolver.Resolve(context.Background(), f.ref(tc.version))
			require.Error(t, err)
			assert.Nil(t, b)
			assert.Contains(t, err.Error(), "does not match")
		})
	}
}

// [REQUIRED TEST] strict layout: symlinks, oversize files and extra entries are refused.
func TestResolve_StrictLayoutRefusals(t *testing.T) {
	bin := testutil.BinaryFileName("strict", currentPlatform())

	// symlink replaces path in a new commit that is tagged 1.0.0.
	symlink := func(path string) func(t *testing.T, f *fixture) {
		return func(t *testing.T, f *fixture) {
			blob := runGitInput(t, f.repoDir, "decoy-target", "hash-object", "-w", "--stdin")
			runGit(t, f.repoDir, "rm", "-q", "--cached", path)
			runGit(t, f.repoDir, "update-index", "--add", "--cacheinfo", "120000,"+blob+","+path)
		}
	}
	cases := map[string]func(t *testing.T, f *fixture){
		"symlinked module.yaml": symlink("module.yaml"),
		"symlinked bundle.yaml": symlink("bundle.yaml"),
		"symlinked binary":      symlink(bin),
		"oversize file": func(t *testing.T, f *fixture) {
			p := filepath.Join(f.repoDir, bin)
			require.NoError(t, os.WriteFile(p, nil, 0o600))
			require.NoError(t, os.Truncate(p, bundle.MaxBundleFileBytes+1))
			runGit(t, f.repoDir, "add", bin)
		},
		"extra file": func(t *testing.T, f *fixture) {
			require.NoError(t, os.WriteFile(filepath.Join(f.repoDir, "README.md"), []byte("hi"), 0o600))
			runGit(t, f.repoDir, "add", "README.md")
		},
		".git file entry": func(t *testing.T, f *fixture) {
			blob := runGitInput(t, f.repoDir, "gitdir: /tmp/elsewhere\n", "hash-object", "-w", "--stdin")
			tree := runGit(t, f.repoDir, "ls-tree", "HEAD")
			tree += "\n100644 blob " + blob + "\t.git"
			treeID := runGitInput(t, f.repoDir, tree+"\n", "mktree", "--missing")
			commit := runGit(t, f.repoDir, "commit-tree", treeID, "-m", "dotgit")
			// Git refuses to stage a ".git" path, so tag the hand-built commit directly.
			runGit(t, f.repoDir, "tag", "-f", "1.0.0", commit)
			f.tagged = true
		},
	}
	for label, mutate := range cases {
		t.Run(label, func(t *testing.T) {
			sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "strict"})
			f := publish(t, sb)
			mutate(t, f)
			if !f.tagged {
				runGit(t, f.repoDir, "commit", "-q", "--allow-empty", "-m", "mutate")
				runGit(t, f.repoDir, "tag", "-f", "1.0.0")
			}

			b, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
			require.Error(t, err)
			assert.Nil(t, b)
			assert.NotContains(t, err.Error(), f.root)
		})
	}
}

// [REQUIRED TEST] a hook (delivered through git's template mechanism) does not
// run, and a submodule entry is neither fetched nor tolerated.
func TestResolve_HooksDoNotRunAndSubmodulesAreNotFetched(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hook-ran")
	tpl := t.TempDir()
	hooks := filepath.Join(tpl, "hooks")
	require.NoError(t, os.MkdirAll(hooks, 0o750))
	script := "#!/bin/sh\ntouch '" + filepath.ToSlash(marker) + "'\n"
	for _, h := range []string{"post-checkout", "post-merge", "reference-transaction"} {
		require.NoError(t, os.WriteFile(filepath.Join(hooks, h), []byte(script), 0o700))
	}
	t.Setenv("GIT_TEMPLATE_DIR", tpl)

	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "hooky"})
	f := publish(t, sb)
	// Add a submodule entry (gitlink + .gitmodules) pointing at another served repo.
	other := filepath.Join(f.root, "other")
	testutil.NewSignedBundle(t, testutil.BundleOptions{Name: "other"}).CommitToRepo(t, other)
	require.NoError(t, os.WriteFile(filepath.Join(f.repoDir, ".gitmodules"),
		[]byte("[submodule \"sub\"]\n\tpath = sub\n\turl = https://127.0.0.1:1/other\n"), 0o600))
	runGit(t, f.repoDir, "add", ".gitmodules")
	runGit(t, f.repoDir, "update-index", "--add", "--cacheinfo", "160000,"+runGit(t, other, "rev-parse", "HEAD")+",sub")
	runGit(t, f.repoDir, "commit", "-q", "-m", "submodule")
	runGit(t, f.repoDir, "tag", "-f", "1.0.0")
	_ = os.Remove(marker) // hooks from the template also ran for the fixture's own git calls

	b, err := f.resolver.Resolve(context.Background(), f.ref("1.0.0"))
	require.ErrorIs(t, err, bundle.ErrUnexpectedEntry, "a submodule entry is an unexpected root entry")
	assert.Nil(t, b)
	_, statErr := os.Stat(marker)
	assert.True(t, os.IsNotExist(statErr), "no git hook may run during resolution")
}

func TestResolveURL_MapsPublisherToURL(t *testing.T) {
	r, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "https://modules.example.com/cfgms"},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	url, err := r.ResolveURL("cfgms/hyperv@0.2.1")
	require.NoError(t, err)
	assert.Equal(t, "https://modules.example.com/cfgms/hyperv", url)

	_, err = r.ResolveURL("unknown-vendor/tool@1.0.0")
	assert.Error(t, err)
}

func TestParseRef_Invalid(t *testing.T) {
	r, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "https://modules.example.com"},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	for _, ref := range []string{
		"no-at-sign", "@version", "publisher/name", "../evil/name@version",
		"publisher/../name@version", "-publisher/name@version",
		"publisher/-name@version", "publisher/name@-version",
	} {
		_, err := r.ResolveURL(ref)
		assert.Error(t, err, "expected error for ref %q", ref)
	}
}
