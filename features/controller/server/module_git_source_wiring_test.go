// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for newModuleGitSourceResolver and its wiring into the production
// startup path (Issue #4409). Issue #1884 declared api.Server.moduleBundleResolver
// and Server.SetModuleResolution long before anything supplied a resolver — the
// moduleCache-nil block in New already called SetModuleResolution with an
// explicit nil resolver. Asserting only that SetModuleResolution is reachable
// would not catch a regression that reintroduces that nil: these tests assert
// on the resolver actually observed on the running *api.Server after the full
// startup path, and on newModuleGitSourceResolver's own construction rules.
package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
)

// TestNew_WiresGitModuleSourceResolverWhenSourcesConfigured is the AC guard:
// after the normal startup path (New) runs with module_sources configured, the
// API server's moduleBundleResolver must be non-nil. Reachability of
// SetModuleResolution alone would not catch a regression that leaves the
// resolver argument nil, as it was before this story.
func TestNew_WiresGitModuleSourceResolverWhenSourcesConfigured(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
		ModuleSources: map[string]config.ModuleSourceConfig{
			"cfgms": {Type: "git", Base: "https://git.example.com/cfgms"},
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.httpServer, "sanity: startup must construct the HTTP API server")
	assert.NotNil(t, srv.httpServer.ModuleBundleResolver(),
		"startup with module_sources configured must wire a live git source resolver, not leave the Issue #1884 nil in place")
}

// TestNew_NoGitModuleSourceResolverWhenSourcesAbsent covers the companion case:
// with no module_sources configured, startup must leave the resolver nil rather
// than constructing one against an empty sources map — there would be nothing
// for it to resolve, and a non-nil-but-useless resolver would misrepresent
// which controllers actually have git-backed module resolution available.
func TestNew_NoGitModuleSourceResolverWhenSourcesAbsent(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		ListenAddr: "127.0.0.1:0",
		Certificate: &config.CertificateConfig{
			EnableCertManagement: false,
		},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	require.NotNil(t, srv)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.httpServer)
	assert.Nil(t, srv.httpServer.ModuleBundleResolver(),
		"no module_sources configured means no publisher can be resolved via git — the resolver must stay nil")
}

// TestNewModuleGitSourceResolver_NoSourcesReturnsUntypedNil guards the classic Go
// footgun: returning a nil *GitSourceResolver assigned to an interface-typed
// variable produces a NON-nil interface (it has a concrete type, just a nil
// value), which would make every "== nil" check downstream (including this
// test's sibling above) silently wrong. newModuleGitSourceResolver must return
// a literal nil interface value when there is nothing to construct.
func TestNewModuleGitSourceResolver_NoSourcesReturnsUntypedNil(t *testing.T) {
	resolver := newModuleGitSourceResolver(&config.Config{}, logging.NewNoopLogger())
	assert.Nil(t, resolver)
	assert.True(t, resolver == nil, "must be a literal nil interface, not a typed nil pointer wrapped in a non-nil interface")
}

// TestNewModuleGitSourceResolver_UsesDataRootNotHardcodedPath verifies the
// resolver's clone root is derived from the controller's configured data root
// (resolveDNADataRoot), not a hard-coded path, by pointing DataDir at a
// t.TempDir() and confirming construction succeeds and creates its clone
// directory underneath it.
func TestNewModuleGitSourceResolver_UsesDataRootNotHardcodedPath(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &config.Config{
		DataDir: tempDir,
		ModuleSources: map[string]config.ModuleSourceConfig{
			"cfgms": {Type: "git", Base: "https://git.example.com/cfgms"},
		},
	}

	resolver := newModuleGitSourceResolver(cfg, logging.NewNoopLogger())
	require.NotNil(t, resolver)

	expectedRoot := filepath.Join(resolveDNADataRoot(cfg), "module-sources")
	assert.DirExists(t, expectedRoot, "resolver construction must create its clone root under the controller's configured data root")
}
