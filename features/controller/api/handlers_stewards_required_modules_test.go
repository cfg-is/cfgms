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

// TestHandleUpdateStewardConfig_RequiredModules_UncachedAutoApprovedByResolver_Returns200
// covers the happy uncached path: cfg push references a module not in the cache,
// the resolver fetches it, the trust store recognises the publisher signature,
// the approval workflow returns AutoApprove, and the cfg push succeeds.
func TestHandleUpdateStewardConfig_RequiredModules_UncachedAutoApprovedByResolver_Returns200(t *testing.T) {
	server := setupTestServer(t)

	baseURL, pubKey := serveModule(t, "cfgms", "firewall", "1.0.0")

	resolver, err := gitresolver.New(map[string]gitresolver.SourceConfig{
		"cfgms": {Type: "git", Base: baseURL},
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
