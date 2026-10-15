// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package resolution_test

import (
	"context"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	"github.com/cfgis/cfgms/features/controller/modules/resolution"
	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/testutil"
)

// makeTestBundle creates a signed payload Bundle through the production
// assemble/sign path for cache tests.
func makeTestBundle(t *testing.T, publisher, name, version string) *bundle.Bundle {
	t.Helper()
	return testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher: publisher, Name: name, Version: version, Platforms: []string{"linux-amd64"},
	}).Bundle
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

// serveModule publishes a module signed by a fresh key as the root of a git
// repository tagged with its version, serves it over verified TLS and returns the
// source base URL plus the public key to register in a trust store. It sets
// GIT_SSL_CAINFO, so callers must not use t.Parallel().
func serveModule(t *testing.T, publisher, name, version string) (string, ed25519.PublicKey) {
	t.Helper()
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: publisher, Name: name, Version: version})
	root := t.TempDir()
	repo := filepath.Join(root, name)
	sb.CommitToRepo(t, repo)
	// #nosec G204 -- fixed git binary; arguments are test-controlled.
	out, err := exec.Command("git", "-C", repo, "tag", version).CombinedOutput()
	require.NoError(t, err, string(out))
	baseURL, caFile := testutil.NewGitServer(t, root)
	t.Setenv("GIT_SSL_CAINFO", caFile)
	return baseURL, sb.PublicKey
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
	b := makeTestBundle(t, "cfgms", "firewall", "1.0.0")
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

// [REQUIRED TEST] Uncached module from a trusted publisher with a valid signature:
// queued for a human (no automatic approval), blocks until approved, then passes.
func TestResolveCfgRequiredModules_UncachedModule_TrustedValid_QueuedUntilApproved(t *testing.T) {
	baseURL, pubKey := serveModule(t, "cfgms", "firewall", "1.0.0")
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: baseURL},
	}
	resolver, err := gitresolver.New(sources, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	c := makeTestCache(t)
	wf := approval.New(c)

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
	require.Error(t, err, "a trusted publisher's bundle still waits for a human")
	assert.Contains(t, err.Error(), "requires approval")

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, cache.ApprovalStatusPending, entries[0].Status)
	require.NoError(t, wf.Approve(entries[0].Addr))

	assert.NoError(t, resolution.ResolveCfgRequiredModules(context.Background(), required, c, resolver, wf, store))
}

// [REQUIRED TEST] Non-exact versions are refused with a clear error before any
// source is contacted (the resolver has no source: contacting it would yield a
// different error); 1.0.0 proceeds to the resolver.
func TestResolveCfgRequiredModules_NonExactVersion_Refused(t *testing.T) {
	for _, version := range []string{"^1.0.0", "v1.0.0", "latest", "", ">=1.0.0", "1.0"} {
		t.Run("version="+version, func(t *testing.T) {
			c := makeTestCache(t)
			required := []stewardtypes.RequiredModule{{Name: "cfgms/firewall", Version: version}}

			err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, emptyResolver(t),
				approval.New(c), trust.NewInMemoryTrustStore())
			require.Error(t, err)
			assert.ErrorIs(t, err, resolution.ErrVersionNotExact)
			assert.Contains(t, err.Error(), "exact version")
			assert.Contains(t, err.Error(), "cfgms/firewall")
			assert.NotContains(t, err.Error(), "no module source", "the source must not be contacted")
		})
	}

	c := makeTestCache(t)
	required := []stewardtypes.RequiredModule{{Name: "cfgms/firewall", Version: "1.0.0"}}
	err := resolution.ResolveCfgRequiredModules(context.Background(), required, c, emptyResolver(t),
		approval.New(c), trust.NewInMemoryTrustStore())
	require.Error(t, err)
	assert.NotErrorIs(t, err, resolution.ErrVersionNotExact, "1.0.0 is exact and proceeds to resolution")
}

// [REQUIRED TEST] Uncached module: resolver + workflow called; QueueForReview → blocking error.
func TestResolveCfgRequiredModules_UncachedModule_QueueForReview_BlocksDeployment(t *testing.T) {
	// The module is signed, but its publisher is unknown to the trust store below.
	baseURL, _ := serveModule(t, "cfgms", "firewall", "1.0.0")
	sources := map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: baseURL},
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
	b := makeTestBundle(t, "cfgms", "firewall", "1.0.0")
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
	b := makeTestBundle(t, "cfgms", "firewall", "1.0.0")
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

	bFirewall := makeTestBundle(t, "cfgms", "firewall", "1.0.0")
	require.NoError(t, c.Put(bFirewall))
	require.NoError(t, c.SetApprovalStatus(bFirewall.ContentAddress(), cache.ApprovalStatusApproved))

	bPackage := makeTestBundle(t, "cfgms", "package", "2.0.0")
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
