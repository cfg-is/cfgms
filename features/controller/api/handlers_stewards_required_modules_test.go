// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for the handleUpdateStewardConfig wiring of required_modules: resolution
// against the controller module cache + approval workflow (Issue #1884).
package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
)

// requiredModulesValidCfgBody returns a minimal valid StewardConfig body with
// the supplied required_modules: block. Uses YAML so that the same body parses
// identically through the production cfg push path (Content-Type: application/yaml).
func requiredModulesValidCfgBody(t *testing.T, stewardID string, required []map[string]string) []byte {
	t.Helper()
	cfg := map[string]any{
		"steward": map[string]any{
			"id":   stewardID,
			"mode": "controller",
			"logging": map[string]any{
				"level":  "info",
				"format": "text",
			},
			"error_handling": map[string]any{
				"module_load_failure": "continue",
				"resource_failure":    "warn",
				"configuration_error": "fail",
			},
		},
		"modules":          map[string]any{"file": "file"},
		"resources":        []any{},
		"required_modules": required,
	}
	body, err := yaml.Marshal(cfg)
	require.NoError(t, err)
	return body
}

// testBundle returns a Bundle with a stable fake content hash so cache.Put + List
// produce a deterministic CacheEntry the resolver/handler can match against.
func testBundle(publisher, name, version string) *bundle.Bundle {
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

// skipIfNoGitForRequiredModules skips when git is unavailable (parity with
// resolution_test.go which exercises the same GitSourceResolver code path).
func skipIfNoGitForRequiredModules(t *testing.T) string {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git binary not found in PATH; required for GitSourceResolver integration")
	}
	return gitBin
}

// initUnsignedModuleRepo creates a local git repo for a module with no signature
// files — the resolver will surface it but the approval workflow will queue it.
func initUnsignedModuleRepo(t *testing.T, gitBin, repoDir, publisher, name, version string) {
	t.Helper()
	// Disable git CRLF rewriting so module.yaml + binaries are byte-identical
	// after clone on every platform (mirrors resolution_test.go).
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, ".gitattributes"), []byte("* -text\n"), 0640))

	meta := &modules.ModuleMetadata{
		Name:      name,
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

// initSignedModuleRepo creates a local git repo for a module signed by a fresh
// Ed25519 key pair. Returns the public key so the test can register the
// publisher in the trust store, making the approval workflow auto-approve.
func initSignedModuleRepo(t *testing.T, gitBin, repoDir, publisher, name, version string) ed25519.PublicKey {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, ".gitattributes"), []byte("* -text\n"), 0640))

	meta := &modules.ModuleMetadata{
		Name:      name,
		Version:   version,
		Publisher: publisher,
		Executors: []string{"steward"},
	}
	metaBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "module.yaml"), metaBytes, 0640))

	binContent := []byte("fake-binary-content")
	binDir := filepath.Join(repoDir, "binaries")
	require.NoError(t, os.MkdirAll(binDir, 0750))
	require.NoError(t, os.WriteFile(filepath.Join(binDir, "linux-amd64"), binContent, 0640))

	contentHash, err := bundle.ComputeContentHash(
		map[string][]byte{"linux-amd64": binContent},
		metaBytes,
	)
	require.NoError(t, err)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	sig := ed25519.Sign(privKey, []byte(contentHash))

	sigDir := filepath.Join(repoDir, "signatures")
	require.NoError(t, os.MkdirAll(sigDir, 0750))
	sigBytes, err := yaml.Marshal(bundle.BundleSignature{
		Publisher: publisher,
		Algorithm: "ed25519",
		Signature: sig,
	})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(sigDir, publisher+".yaml"), sigBytes, 0640))

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

// TestHandleUpdateStewardConfig_RequiredModules_PendingInCache_Returns422 wires
// the resolution dependencies, seeds the cache with the required module in
// pending state, and asserts that the cfg push is blocked with HTTP 422 and the
// error response names the unapproved module.
func TestHandleUpdateStewardConfig_RequiredModules_PendingInCache_Returns422(t *testing.T) {
	server := setupTestServer(t)

	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	// Cache the bundle but leave it in the default pending status.
	require.NoError(t, c.Put(testBundle("cfgms", "firewall", "1.0.0")))

	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()
	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	server.SetModuleResolution(c, resolver, wf, store)

	body := requiredModulesValidCfgBody(t, "test-steward-required-pending", []map[string]string{
		{"name": "cfgms/firewall", "version": "1.0.0"},
	})

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-pending/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, "pending module must block deployment; body: %s", rec.Body.String())

	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "REQUIRED_MODULE_NOT_APPROVED", resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "cfgms/firewall@1.0.0",
		"error must name the blocked module so the operator knows what to approve")
	assert.Contains(t, resp.Error.Message, "requires approval")
}

// TestHandleUpdateStewardConfig_RequiredModules_ApprovedInCache_Returns200 wires
// the resolution dependencies, seeds the cache with the module in approved state,
// and asserts that the cfg push proceeds normally.
func TestHandleUpdateStewardConfig_RequiredModules_ApprovedInCache_Returns200(t *testing.T) {
	server := setupTestServer(t)

	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	b := testBundle("cfgms", "firewall", "1.0.0")
	require.NoError(t, c.Put(b))
	require.NoError(t, c.SetApprovalStatus(b.ContentAddress(), cache.ApprovalStatusApproved))

	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()
	// Empty source map — Resolve should never be called because the module is
	// already in the cache as approved. If it is called the test will fail.
	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	server.SetModuleResolution(c, resolver, wf, store)

	body := requiredModulesValidCfgBody(t, "test-steward-required-approved", []map[string]string{
		{"name": "cfgms/firewall", "version": "1.0.0"},
	})

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-approved/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "approved module must allow deployment; body: %s", rec.Body.String())
}

// TestHandleUpdateStewardConfig_RequiredModules_UncachedQueuedByResolver_Returns422
// covers the end-to-end uncached path described in the AC: cfg push references a
// module that is not in the cache, so the handler must invoke the resolver and
// approval workflow. With an unsigned module + empty trust store the workflow
// returns QueueForReview, which must block the deployment with HTTP 422.
func TestHandleUpdateStewardConfig_RequiredModules_UncachedQueuedByResolver_Returns422(t *testing.T) {
	gitBin := skipIfNoGitForRequiredModules(t)
	server := setupTestServer(t)

	modulesDir := t.TempDir()
	firewallDir := filepath.Join(modulesDir, "firewall")
	require.NoError(t, os.MkdirAll(firewallDir, 0750))
	initUnsignedModuleRepo(t, gitBin, firewallDir, "cfgms", "firewall", "1.0.0")

	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + modulesDir},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore() // unknown publisher → QueueForReview

	server.SetModuleResolution(c, resolver, wf, store)

	body := requiredModulesValidCfgBody(t, "test-steward-required-uncached", []map[string]string{
		{"name": "cfgms/firewall", "version": "1.0.0"},
	})

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-uncached/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnprocessableEntity, rec.Code, "queued uncached module must block deployment; body: %s", rec.Body.String())
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	assert.Equal(t, "REQUIRED_MODULE_NOT_APPROVED", resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "cfgms/firewall@1.0.0")
}

// TestHandleUpdateStewardConfig_RequiredModules_UncachedAutoApprovedByResolver_Returns200
// covers the happy uncached path: cfg push references a module not in the cache,
// the resolver fetches it, the trust store recognises the publisher signature,
// the approval workflow returns AutoApprove, and the cfg push succeeds.
func TestHandleUpdateStewardConfig_RequiredModules_UncachedAutoApprovedByResolver_Returns200(t *testing.T) {
	gitBin := skipIfNoGitForRequiredModules(t)
	server := setupTestServer(t)

	modulesDir := t.TempDir()
	firewallDir := filepath.Join(modulesDir, "firewall")
	require.NoError(t, os.MkdirAll(firewallDir, 0750))
	pubKey := initSignedModuleRepo(t, gitBin, firewallDir, "cfgms", "firewall", "1.0.0")

	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: "file://" + modulesDir},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)

	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	wf := approval.New(c)
	store := trust.NewInMemoryTrustStore()
	require.NoError(t, store.AddPublisher(trust.PublisherIdentity{
		Name:      "cfgms",
		PublicKey: []byte(pubKey),
		Algorithm: "ed25519",
	}))

	server.SetModuleResolution(c, resolver, wf, store)

	body := requiredModulesValidCfgBody(t, "test-steward-required-autoapprove", []map[string]string{
		{"name": "cfgms/firewall", "version": "1.0.0"},
	})

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-autoapprove/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "auto-approved module must allow deployment; body: %s", rec.Body.String())
}

// TestHandleUpdateStewardConfig_RequiredModules_DependenciesNotWired_Returns200
// verifies that deployments without the module subsystem wired continue to work:
// required_modules: is parsed and stored but not enforced. This nil-tolerance is
// what keeps every other server test (which never calls SetModuleResolution)
// passing — and lets operators upgrade the controller binary before standing up
// the module cache.
func TestHandleUpdateStewardConfig_RequiredModules_DependenciesNotWired_Returns200(t *testing.T) {
	server := setupTestServer(t)

	// Intentionally do NOT call server.SetModuleResolution.
	body := requiredModulesValidCfgBody(t, "test-steward-required-unwired", []map[string]string{
		{"name": "cfgms/firewall", "version": "1.0.0"},
	})

	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-unwired/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "unwired controller must continue to accept cfg pushes; body: %s", rec.Body.String())
}
