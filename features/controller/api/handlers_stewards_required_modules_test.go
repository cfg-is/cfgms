// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors

// Tests for the handleUpdateStewardConfig wiring of required_modules: resolution
// against the controller module cache + approval workflow (Issue #1884).
package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	gitresolver "github.com/cfgis/cfgms/features/controller/modules/sources/git"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/modules/trust"
	"github.com/cfgis/cfgms/pkg/testutil"
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

// testBundle returns a signed payload Bundle built through the production
// assemble/sign path, so cache.Put + List produce a deterministic CacheEntry the
// resolver/handler can match against.
func testBundle(t *testing.T, publisher, name, version string) *bundle.Bundle {
	t.Helper()
	return testutil.NewSignedBundle(t, testutil.BundleOptions{
		Publisher: publisher, Name: name, Version: version, Platforms: []string{"linux-amd64"},
	}).Bundle
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

// TestHandleUpdateStewardConfig_RequiredModules_PendingInCache_Returns422 wires
// the resolution dependencies, seeds the cache with the required module in
// pending state, and asserts that the cfg push is blocked with HTTP 422 and the
// error response names the unapproved module.
func TestHandleUpdateStewardConfig_RequiredModules_PendingInCache_Returns422(t *testing.T) {
	server := setupTestServer(t)

	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	// Cache the bundle but leave it in the default pending status.
	require.NoError(t, c.Put(testBundle(t, "cfgms", "firewall", "1.0.0")))

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
	b := testBundle(t, "cfgms", "firewall", "1.0.0")
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
	server := setupTestServer(t)

	// Signed, but the publisher is unknown to the trust store below.
	baseURL, _ := serveModule(t, "cfgms", "firewall", "1.0.0")

	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: baseURL},
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

// serveModuleWith is serveModule for a bundle the caller shapes: mutate may drop
// or corrupt signatures before the bundle is committed to the served repository.
func serveModuleWith(t *testing.T, publisher, name, version string, mutate func(*testutil.SignedBundle)) (string, ed25519.PublicKey) {
	t.Helper()
	sb := testutil.NewSignedBundle(t, testutil.BundleOptions{Publisher: publisher, Name: name, Version: version})
	if mutate != nil {
		mutate(sb)
	}
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

// pushRequiredModule wires the real resolver, cache and approval workflow with
// store and PUTs a cfg requiring publisher/name@version. It returns the HTTP
// status, the error code (empty on success) and the module cache.
func pushRequiredModule(t *testing.T, baseURL, publisher, name, version string, store trust.TrustStore) (int, string, *cache.ModuleCache) {
	t.Helper()
	server := setupTestServer(t)
	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		publisher: {Type: "git", Base: baseURL},
	}, t.TempDir(), logging.NewNoopLogger())
	require.NoError(t, err)
	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	server.SetModuleResolution(c, resolver, approval.New(c), store)

	code, errCode := putRequiredModule(t, server, publisher+"/"+name, version)
	return code, errCode, c
}

func putRequiredModule(t *testing.T, server *Server, name, version string) (int, string) {
	t.Helper()
	body := requiredModulesValidCfgBody(t, "test-steward-required-fixture", []map[string]string{{"name": name, "version": version}})
	req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-fixture/config", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		return rec.Code, ""
	}
	var resp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	require.NotNil(t, resp.Error)
	return rec.Code, resp.Error.Code
}

func onlyCacheStatus(t *testing.T, c *cache.ModuleCache) (cache.ApprovalStatus, bool) {
	t.Helper()
	entries, err := c.List()
	require.NoError(t, err)
	if len(entries) == 0 {
		return "", false
	}
	require.Len(t, entries, 1)
	return entries[0].Status, true
}

// [REQUIRED TEST] Fixture provenance: bundles built by the production
// Assemble/Sign path, served by the git test server, fetched by the real resolver
// into the real cache, through the real handleUpdateStewardConfig.
func TestHandleUpdateStewardConfig_RequiredModules_AdmissionDecisions(t *testing.T) {
	trusted := func(t *testing.T, pub []byte) trust.TrustStore {
		store := trust.NewInMemoryTrustStore()
		require.NoError(t, store.AddPublisher(trust.PublisherIdentity{Name: "acme-corp", PublicKey: pub, Algorithm: "ed25519"}))
		return store
	}

	t.Run("unknown publisher is queued pending and blocks the push", func(t *testing.T) {
		baseURL, _ := serveModule(t, "acme-corp", "firewall", "1.0.0")
		code, errCode, c := pushRequiredModule(t, baseURL, "acme-corp", "firewall", "1.0.0", trust.NewInMemoryTrustStore())
		assert.Equal(t, http.StatusUnprocessableEntity, code)
		assert.Equal(t, "REQUIRED_MODULE_NOT_APPROVED", errCode)
		status, found := onlyCacheStatus(t, c)
		require.True(t, found)
		assert.Equal(t, cache.ApprovalStatusPending, status)
	})

	t.Run("trusted publisher with a valid signature is queued pending, then a human approval lets the push through", func(t *testing.T) {
		baseURL, pub := serveModule(t, "acme-corp", "firewall", "1.0.0")
		store := trusted(t, pub)
		server := setupTestServer(t)
		resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{"acme-corp": {Type: "git", Base: baseURL}}, t.TempDir(), logging.NewNoopLogger())
		require.NoError(t, err)
		c, err := cache.New(t.TempDir() + "/module-cache")
		require.NoError(t, err)
		wf := approval.New(c)
		server.SetModuleResolution(c, resolver, wf, store)

		code, errCode := putRequiredModule(t, server, "acme-corp/firewall", "1.0.0")
		assert.Equal(t, http.StatusUnprocessableEntity, code)
		assert.Equal(t, "REQUIRED_MODULE_NOT_APPROVED", errCode)
		status, found := onlyCacheStatus(t, c)
		require.True(t, found)
		require.Equal(t, cache.ApprovalStatusPending, status)

		entries, err := c.List()
		require.NoError(t, err)
		require.NoError(t, wf.Approve(entries[0].Addr))

		code, errCode = putRequiredModule(t, server, "acme-corp/firewall", "1.0.0")
		assert.Equal(t, http.StatusOK, code, errCode)
	})

	t.Run("trusted publisher with a bad signature is rejected and never queued", func(t *testing.T) {
		baseURL, pub := serveModuleWith(t, "acme-corp", "firewall", "1.0.0", func(sb *testutil.SignedBundle) {
			sb.Signatures[0].Signature[0] ^= 0xff
		})
		code, errCode, c := pushRequiredModule(t, baseURL, "acme-corp", "firewall", "1.0.0", trusted(t, pub))
		assert.Equal(t, http.StatusUnprocessableEntity, code)
		assert.Equal(t, "REQUIRED_MODULE_NOT_APPROVED", errCode)
		status, found := onlyCacheStatus(t, c)
		require.True(t, found, "the rejected bundle is stored for audit")
		assert.Equal(t, cache.ApprovalStatusRejected, status, "a bad signature must never be pending")
	})

	t.Run("zero signatures is rejected and never queued", func(t *testing.T) {
		baseURL, _ := serveModuleWith(t, "acme-corp", "firewall", "1.0.0", func(sb *testutil.SignedBundle) {
			sb.Signatures = nil
		})
		code, errCode, c := pushRequiredModule(t, baseURL, "acme-corp", "firewall", "1.0.0", trust.NewInMemoryTrustStore())
		assert.Equal(t, http.StatusUnprocessableEntity, code)
		assert.NotEmpty(t, errCode)
		status, found := onlyCacheStatus(t, c)
		require.True(t, found, "the rejected bundle is stored for audit")
		assert.Equal(t, cache.ApprovalStatusRejected, status, "an unsigned bundle must never be pending")
	})
}

// [REQUIRED TEST] required_modules versions must be exact: ^1.0.0, v1.0.0 and
// latest are refused with a clear error before any source is contacted; 1.0.0
// proceeds to resolution.
func TestHandleUpdateStewardConfig_RequiredModules_NonExactVersionRefused(t *testing.T) {
	for _, version := range []string{"^1.0.0", "v1.0.0", "latest"} {
		t.Run(version, func(t *testing.T) {
			server := setupTestServer(t)
			// An unreachable https base: contacting it would fail differently from the
			// exact-version refusal, and the empty trust store would queue, not refuse.
			resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{
				"acme-corp": {Type: "git", Base: "https://127.0.0.1:1/never-contacted"},
			}, t.TempDir(), logging.NewNoopLogger())
			require.NoError(t, err)
			c, err := cache.New(t.TempDir() + "/module-cache")
			require.NoError(t, err)
			server.SetModuleResolution(c, resolver, approval.New(c), trust.NewInMemoryTrustStore())

			body := requiredModulesValidCfgBody(t, "test-steward-required-exact", []map[string]string{{"name": "acme-corp/firewall", "version": version}})
			req := makeAdminRequest(t, "PUT", "/api/v1/stewards/test-steward-required-exact/config", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/yaml")
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusUnprocessableEntity, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "exact version")
			entries, err := c.List()
			require.NoError(t, err)
			assert.Empty(t, entries)
		})
	}

	t.Run("1.0.0 proceeds", func(t *testing.T) {
		baseURL, _ := serveModule(t, "acme-corp", "firewall", "1.0.0")
		_, errCode, c := pushRequiredModule(t, baseURL, "acme-corp", "firewall", "1.0.0", trust.NewInMemoryTrustStore())
		assert.Equal(t, "REQUIRED_MODULE_NOT_APPROVED", errCode, "an exact version is resolved and queued")
		_, found := onlyCacheStatus(t, c)
		assert.True(t, found)
	})
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
