// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for the module trust store construction and its wiring into the
// production startup path (Issue #4984), mirroring module_git_source_wiring_test.go.
package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

func moduleWiringConfig(t *testing.T) *config.Config {
	t.Helper()
	tempDir := t.TempDir()
	return &config.Config{
		ListenAddr:  "127.0.0.1:0",
		Certificate: &config.CertificateConfig{EnableCertManagement: false},
		Storage: &config.StorageConfig{
			Provider:     "flatfile",
			FlatfileRoot: tempDir + "/flatfile",
			SQLitePath:   tempDir + "/cfgms.db",
		},
	}
}

func newPublisherKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub
}

// TestNew_WiresModuleApproverAndTrustStore is the AC guard: production startup
// passes a non-nil approver and trust store to SetModuleResolution, and the
// trust store holds the publishers declared in controller.cfg.
func TestNew_WiresModuleApproverAndTrustStore(t *testing.T) {
	cfg := moduleWiringConfig(t)
	pub := newPublisherKey(t)
	cfg.ModuleTrust = &config.ModuleTrustConfig{Publishers: []config.ModuleTrustPublisher{
		{Name: "acme-corp", PublicKey: base64.StdEncoding.EncodeToString(pub)},
	}}

	srv, err := New(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Stop() })

	require.NotNil(t, srv.httpServer)
	assert.NotNil(t, srv.httpServer.ModuleBundleApprover(), "startup must wire the approval workflow")
	store := srv.httpServer.ModuleTrustStore()
	require.NotNil(t, store, "startup must wire the trust store")
	id, ok := store.GetPublisher("acme-corp")
	require.True(t, ok, "a publisher declared in module_trust must be trusted")
	assert.Equal(t, []byte(pub), id.PublicKey)
}

// Without a module_trust section the store holds the CFGMS identity only (when
// its baked-in key is usable; the all-zero placeholder of an unsigned build is not).
func TestNewModuleTrustStore_EmptySectionIsCFGMSOnly(t *testing.T) {
	store, err := newModuleTrustStore(moduleWiringConfig(t), logging.NewNoopLogger())
	require.NoError(t, err)

	names := []string{}
	for _, id := range store.ListPublishers() {
		names = append(names, id.Name)
	}
	if trust.IsUsableIdentityKey(trust.CFGMSPublisherIdentity()) {
		assert.Equal(t, []string{"cfgms"}, names)
	} else {
		assert.Empty(t, names, "an unusable baked-in key must not anchor trust")
	}
}

func TestNewModuleTrustStore_DeclaredPublishersAdded(t *testing.T) {
	cfg := moduleWiringConfig(t)
	pubA, pubB := newPublisherKey(t), newPublisherKey(t)
	cfg.ModuleTrust = &config.ModuleTrustConfig{Publishers: []config.ModuleTrustPublisher{
		{Name: "acme-corp", PublicKey: base64.StdEncoding.EncodeToString(pubA)},
		{Name: "vendor-a", PublicKey: base64.StdEncoding.EncodeToString(pubB)},
	}}
	store, err := newModuleTrustStore(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	assert.True(t, store.IsTrusted("acme-corp", pubA))
	assert.True(t, store.IsTrusted("vendor-a", pubB))
	assert.False(t, store.IsTrusted("acme-corp", pubB))
}

// Invalid module_trust or module_sources configuration fails startup, never skipped.
func TestNew_InvalidModuleConfigFailsStartup(t *testing.T) {
	cases := map[string]func(*config.Config){
		"bad base64": func(c *config.Config) {
			c.ModuleTrust = &config.ModuleTrustConfig{Publishers: []config.ModuleTrustPublisher{{Name: "acme-corp", PublicKey: "%%%"}}}
		},
		"reserved name": func(c *config.Config) {
			c.ModuleTrust = &config.ModuleTrustConfig{Publishers: []config.ModuleTrustPublisher{
				{Name: "cfgms", PublicKey: base64.StdEncoding.EncodeToString(newPublisherKey(t))}}}
		},
		"bad source base": func(c *config.Config) {
			c.ModuleSources = map[string]config.ModuleSourceConfig{"acme-corp": {Type: "git", Base: "http://git.acme-corp.example/m"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := moduleWiringConfig(t)
			mutate(cfg)
			srv, err := New(cfg, logging.NewNoopLogger())
			if srv != nil {
				_ = srv.Stop()
			}
			require.Error(t, err)
			assert.Nil(t, srv)
		})
	}
}

// TestAddPublisherCallSitesOutsideTests keeps the trusted-publisher set
// controller.cfg-only: within features/controller, the module trust store is
// populated only by module_trust_wiring.go. The two other non-test call sites
// build the separate steward-binary verification store (CFGMS identity, or a
// test key behind CFGMS_SEED_TEST_API_KEYS), not the module trust store.
func TestAddPublisherCallSitesOutsideTests(t *testing.T) {
	allowed := map[string]bool{
		"server/module_trust_wiring.go":  true,
		"api/handlers_steward_binary.go": true,
		"api/server.go":                  true,
	}
	root := ".."
	found := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		data, readErr := os.ReadFile(path) // #nosec G304 -- walks the repository's own source tree
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(data), ".AddPublisher(") {
			rel, _ := filepath.Rel(root, path)
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	require.NoError(t, err)
	assert.True(t, found["server/module_trust_wiring.go"], "module_trust_wiring.go is the module trust store's builder")
	for rel := range found {
		assert.True(t, allowed[rel], "unexpected AddPublisher call site %s: the module trust set may only change in module_trust_wiring.go", rel)
	}
}
