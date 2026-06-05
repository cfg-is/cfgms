// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package resolution_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// skipIfNoGit skips the test if git is not available.
func skipIfNoGit(t *testing.T) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not found in PATH; required for git resolver integration tests")
	}
	return gitBin
}

// makeTestBundle creates a Bundle with a stable fake content hash for cache tests.
func makeTestBundle(publisher, name, version string) *bundle.Bundle {
	return &bundle.Bundle{
		Manifest: &modules.ModuleMetadata{
			Name:      name,
			Version:   version,
			Publisher: publisher,
			Executors: []string{"steward"},
		},
		Binaries:    map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures:  []bundle.BundleSignature{{Publisher: publisher, Algorithm: "ed25519", Signature: make([]byte, 64)}},
		ContentHash: publisher + "-" + name + "-" + version + "-testhash",
	}
}

// makeTestCache creates a real ModuleCache rooted at a temp directory.
func makeTestCache(t *testing.T) *cache.ModuleCache {
	t.Helper()
	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	return c
}

// emptyResolver returns a GitSourceResolver with no sources configured.
// If Resolve is accidentally called, it returns "no module source configured" error.
func emptyResolver(t *testing.T) *gitresolver.GitSourceResolver {
	t.Helper()
	r, err := gitresolver.New(map[string]gitresolver.SourceConfig{}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)
	return r
}

// initSignedGitRepo creates a local git repo for publisher/moduleName@version with
// a valid Ed25519 signature. Returns the signing public key for the trust store.
func initSignedGitRepo(t *testing.T, gitBin, repoDir, publisher, moduleName, version string) ed25519.PublicKey {
	t.Helper()

	// Disable git line-ending conversion so module.yaml and binaries are
	// byte-identical after clone on every platform. Without this the Windows
	// runner default (core.autocrlf=true) rewrites LF→CRLF on checkout, the
	// resolver re-reads different bytes than the test signed, and signature
	// verification fails. "* -text" treats every path as binary.
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, ".gitattributes"), []byte("* -text\n"), 0640))

	// Write module.yaml
	meta := &modules.ModuleMetadata{
		Name:      moduleName,
		Version:   version,
		Publisher: publisher,
		Executors: []string{"steward"},
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "module.yaml"), metaBytes, 0640))

	// Write a fake binary
	binContent := []byte("fake-binary-content")
	binDir := filepath.Join(repoDir, "binaries")
	require.NoError(t, os.MkdirAll(binDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "linux-amd64"), binContent, 0640))

	// Compute the content hash (identical to parseBundleFromDir's algorithm)
	contentHash, err := bundle.ComputeContentHash(
		map[string][]byte{"linux-amd64": binContent},
		metaBytes,
	)
	require.NoError(t, err)

	// Generate an Ed25519 key pair and sign the content hash
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig := ed25519.Sign(privKey, []byte(contentHash))

	// Write signature file under signatures/
	sigEntry := bundle.BundleSignature{
		Publisher: publisher,
		Algorithm: "ed25519",
		Signature: sig,
	}
	sigDir := filepath.Join(repoDir, "signatures")
	require.NoError(t, os.MkdirAll(sigDir, 0750))
	sigBytes, err := yaml.Marshal(sigEntry)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sigDir, publisher+".yaml"), sigBytes, 0640))

	// Initialise git repo and commit
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = repoDir
		out, runErr := cmd.CombinedOutput()
		require.NoError(t, runErr, "git %v: %s", args, string(out))
	}
	git("init", repoDir)
	git("-C", repoDir, "config", "user.email", "test@cfgms.test")
	git("-C", repoDir, "config", "user.name", "CFGMS Test")
	git("add", ".")
	git("commit", "-m", "Initial module commit")

	return pubKey
}

// initUnsignedGitRepo creates a local git repo with no signature files.
// The bundle returned by the resolver will have no valid signatures.
func initUnsignedGitRepo(t *testing.T, gitBin, repoDir, publisher, moduleName, version string) {
	t.Helper()

	// See initSignedGitRepo for why this is required on Windows runners.
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, ".gitattributes"), []byte("* -text\n"), 0640))

	meta := &modules.ModuleMetadata{
		Name:      moduleName,
		Version:   version,
		Publisher: publisher,
		Executors: []string{"steward"},
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "module.yaml"), metaBytes, 0640))

	binDir := filepath.Join(repoDir, "binaries")
	require.NoError(t, os.MkdirAll(binDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "linux-amd64"), []byte("fake-binary"), 0640))

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command(gitBin, args...)
		cmd.Dir = repoDir
		out, runErr := cmd.CombinedOutput()
		require.NoError(t, runErr, "git %v: %s", args, string(out))
	}
	git("init", repoDir)
	git("-C", repoDir, "config", "user.email", "test@cfgms.test")
	git("-C", repoDir, "config", "user.name", "CFGMS Test")
	git("add", ".")
	git("commit", "-m", "Initial module commit")
}

// --- tests ---

// No required modules → always succeeds without touching cache or resolver.
func TestResolveCfgRequiredModules_NoRequiredModules_ReturnsNil(t *testing.T) {
	c := makeTestCache(t)
	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	err := resolution.ResolveCfgRequiredModules(context.Background(), nil, c, r, wf, store)
	assert.NoError(t, err)

	err = resolution.ResolveCfgRequiredModules(context.Background(), []stewardtypes.RequiredModule{}, c, r, wf, store)
	assert.NoError(t, err)
}

// All modules already in cache with approved status → resolver never called, returns nil.
func TestResolveCfgRequiredModules_AllModulesApprovedInCache_ReturnsNil(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "firewall", "1.0.0")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	// emptyResolver would error if accidentally called — proving the cache path is used.
	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, r, wf, store)
	assert.NoError(t, err)
}

// [REQUIRED TEST] Uncached module: GitSourceResolver + ApprovalWorkflow called; AutoApprove → nil.
func TestResolveCfgRequiredModules_UncachedModule_AutoApprove_ReturnsNil(t *testing.T) {
	gitBin := skipIfNoGit(t)

	// Create a local git repo with a properly signed "firewall" module.
	modulesDir := t.TempDir()
	firewallDir := filepath.Join(modulesDir, "firewall")
	require.NoError(t, os.MkdirAll(firewallDir, 0750))
	pubKey := initSignedGitRepo(t, gitBin, firewallDir, "cfgms", "firewall", "1.0.0")

	// Configure resolver to use file:// URL pointing at the local modules directory.
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + modulesDir},
	}
	resolver, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	// Real cache + approval workflow.
	c := makeTestCache(t)
	wf := approval.New(c)

	// Trust store that knows "cfgms" with the matching public key → AutoApprove.
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pubKey),
		Algorithm: "ed25519",
	}))

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err = resolution.ResolveCfgRequiredModules(context.Background(), required, c, resolver, wf, store)
	assert.NoError(t, err)
}

// [REQUIRED TEST] Uncached module: resolver + workflow called; QueueForReview → blocking error.
func TestResolveCfgRequiredModules_UncachedModule_QueueForReview_BlocksDeployment(t *testing.T) {
	gitBin := skipIfNoGit(t)

	// Create a local git repo with an unsigned (no signatures/) module.
	modulesDir := t.TempDir()
	firewallDir := filepath.Join(modulesDir, "firewall")
	require.NoError(t, os.MkdirAll(firewallDir, 0750))
	initUnsignedGitRepo(t, gitBin, firewallDir, "cfgms", "firewall", "1.0.0")

	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + modulesDir},
	}
	resolver, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	c := makeTestCache(t)
	wf := approval.New(c)

	// Trust store with no publishers → "cfgms" is unknown → QueueForReview.
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err = resolution.ResolveCfgRequiredModules(context.Background(), required, c, resolver, wf, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfgms/firewall@1.0.0")
	assert.Contains(t, err.Error(), "requires approval")
}

// [REQUIRED TEST] Module in cache with pending status → error naming the pending module.
func TestResolveCfgRequiredModules_PendingModule_ReturnsErrorNamingModule(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "firewall", "1.0.0")
	require.NoError(t, c.Put(b))
	// Default status after Put is pending — verified by TestModuleCache_List in cache_test.go.

	// emptyResolver would error if accidentally called — the pending cache path must not call it.
	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, r, wf, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfgms/firewall@1.0.0")
	assert.Contains(t, err.Error(), "requires approval")
}

// Rejected module in cache → also blocks deployment.
func TestResolveCfgRequiredModules_RejectedModule_BlocksDeployment(t *testing.T) {
	c := makeTestCache(t)
	b := makeTestBundle("cfgms", "firewall", "1.0.0")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusRejected))

	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, r, wf, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfgms/firewall@1.0.0")
}

// Multiple modules: one approved, one pending → error names only the pending module.
func TestResolveCfgRequiredModules_MultipleModules_OnePending_NamesBlockedModule(t *testing.T) {
	c := makeTestCache(t)

	bFirewall := makeTestBundle("cfgms", "firewall", "1.0.0")
	require.NoError(t, c.Put(bFirewall))
	require.NoError(t, c.SetApprovalStatus(bFirewall.ContentAddress(), cache.ApprovalStatusApproved))

	bPackage := makeTestBundle("cfgms", "package", "2.0.0")
	require.NoError(t, c.Put(bPackage))
	// package is pending (default after Put)

	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
		{Name: "cfgms/package", Version: "2.0.0"},
	}

	err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, r, wf, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfgms/package@2.0.0")
	assert.NotContains(t, err.Error(), "cfgms/firewall@1.0.0")
}

// Cache list error propagates as a wrapped error.
func TestResolveCfgRequiredModules_CacheListError_Propagates(t *testing.T) {
	cacheRoot := t.TempDir()
	c, err := cache.New(cacheRoot)
	require.NoError(t, err)

	// Replace the cache root directory with a regular file so os.ReadDir fails.
	require.NoError(t, os.RemoveAll(cacheRoot))
	require.NoError(t, os.WriteFile(cacheRoot, []byte("not-a-dir"), 0640))

	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err = resolution.ResolveCfgRequiredModules(context.Background(), required, c, r, wf, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list module cache")
}

// Resolver returns an error for an uncached module → error propagates.
// Uses a real GitSourceResolver configured with no sources for the publisher.
func TestResolveCfgRequiredModules_ResolverError_Propagates(t *testing.T) {
	c := makeTestCache(t) // empty cache — module is not cached

	// Resolver has no source configured for "cfgms" → returns "no module source configured".
	r := emptyResolver(t)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()

	required := []stewardtypes.RequiredModule{
		{Name: "cfgms/firewall", Version: "1.0.0"},
	}

	err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, r, wf, store)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cfgms/firewall@1.0.0")
}
