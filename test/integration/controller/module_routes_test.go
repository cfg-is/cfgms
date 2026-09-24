// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package controller

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	controllerConfig "github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
)

// seedModuleBundle stores a real, signed bundle in c and returns its address.
// Mirrors features/controller/api/handlers_module_approval_test.go's makePendingBundle —
// this package cannot import that test-only helper, so the construction is duplicated.
func seedModuleBundle(t *testing.T, c *cache.ModuleCache, publisher, name, version string) bundle.ContentAddress {
	t.Helper()
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	meta := &modules.ModuleMetadata{
		Name:      name,
		Version:   version,
		Publisher: publisher,
		Executors: []string{"steward"},
	}
	binaries := map[string][]byte{"linux-amd64": []byte("fake-binary-" + name)}
	manifestBytes, err := yaml.Marshal(meta)
	require.NoError(t, err)

	contentHash, err := bundle.ComputeContentHash(binaries, manifestBytes)
	require.NoError(t, err)

	sig := ed25519.Sign(privKey, []byte(contentHash))
	b := &bundle.Bundle{
		Manifest: meta,
		Binaries: map[string]string{"linux-amd64": "binaries/linux-amd64"},
		Signatures: []bundle.BundleSignature{
			{Publisher: publisher, Algorithm: "ed25519", Signature: sig},
		},
		ContentHash: contentHash,
	}

	require.NoError(t, c.Put(b))
	return b.ContentAddress()
}

// moduleCacheDirFor mirrors features/controller/server/server.go's
// filepath.Join(resolveDNADataRoot(cfg), "module-cache"): resolveDNADataRoot returns
// cfg.DataDir unmodified whenever it is already an absolute path, which is true of
// every controllerConfig.Config built by newHealthTestControllerConfig (rooted under
// t.TempDir()).
func moduleCacheDirFor(cfg *controllerConfig.Config) string {
	return filepath.Join(cfg.DataDir, "module-cache")
}

// decodeEnvelope unwraps the standard {"data": ..., "timestamp": ...} APIResponse
// envelope (features/controller/api/middleware.go's writeSuccessResponse) into v.
func decodeEnvelope(t *testing.T, body []byte, v interface{}) {
	t.Helper()
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(body, &envelope))
	require.NoError(t, json.Unmarshal(envelope.Data, v))
}

// TestModuleListAndApprove_EndToEnd is the AC4 [REQUIRED TEST]: against a real
// controller (real storage, real certs, real HTTP — mirroring
// TestHealthDetailRoutes_EndToEnd's pattern), seed one pending and one approved
// bundle directly in the on-disk module cache the controller will read at startup,
// then exercise GET /api/v1/modules (Issue #4270's new route) and the
// GET /api/v1/modules/approvals lookup cfg module approve performs before resolving
// an address to POST.
//
// The actual POST .../approve mutation is exercised directly against the same
// on-disk cache via approval.ApprovalWorkflow — the identical call
// handleApproveModuleBundle makes (features/controller/api/handlers_module_approval.go)
// — rather than through raw HTTP. module:approve carries RequireUserPresence: true
// (ADR-021 Decision 4): a real POST needs a fresh WebAuthn assertion's X-Presence-Token,
// which requires a physical/virtual FIDO2 authenticator entirely unrelated to this
// issue's routing fix, and which cmd/cfg/cmd/stepup.go itself documents the CLI cannot
// complete (errPresenceCeremonyUnsupported) — a separate, pre-existing gap filed
// independently. This test instead proves the two things #4270 actually changed: (1)
// the new GET /api/v1/modules route serves the real cache contents end-to-end, and (2)
// the address resolved from GET /api/v1/modules/approvals — the exact value
// runModuleApprove now POSTs to — is the one that, when approved, is reflected back
// through that same GET /api/v1/modules route.
func TestModuleListAndApprove_EndToEnd(t *testing.T) {
	var seedCache *cache.ModuleCache
	var pendingAddr, approvedAddr bundle.ContentAddress

	_, _, base, _, client := startHealthTestControllerWithConfig(t, func(cfg *controllerConfig.Config) {
		var err error
		seedCache, err = cache.New(moduleCacheDirFor(cfg))
		require.NoError(t, err, "seed module cache")

		pendingAddr = seedModuleBundle(t, seedCache, "cfgms", "hyperv", "0.2.1")
		approvedAddr = seedModuleBundle(t, seedCache, "cfgms", "firewall", "1.0.0")
		require.NoError(t, seedCache.SetApprovalStatus(approvedAddr, cache.ApprovalStatusApproved))
	})

	t.Run("GET /api/v1/modules returns every status", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/modules")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Modules []struct {
				Publisher   string `json:"publisher"`
				Name        string `json:"name"`
				Version     string `json:"version"`
				ContentHash string `json:"content_hash"`
				Status      string `json:"status"`
			} `json:"modules"`
			Total int `json:"total"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Modules, 2)
		assert.Equal(t, 2, result.Total)

		byName := map[string]string{}
		for _, m := range result.Modules {
			byName[m.Name] = m.Status
		}
		assert.Equal(t, string(cache.ApprovalStatusPending), byName["hyperv"])
		assert.Equal(t, string(cache.ApprovalStatusApproved), byName["firewall"])
	})

	t.Run("GET /api/v1/modules?status=pending returns only the pending entry", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/modules?status=pending")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Modules []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"modules"`
			Total int `json:"total"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Modules, 1)
		assert.Equal(t, 1, result.Total)
		assert.Equal(t, "hyperv", result.Modules[0].Name)
		assert.Equal(t, string(cache.ApprovalStatusPending), result.Modules[0].Status)
	})

	var pendingAddress string
	t.Run("GET /api/v1/modules/approvals resolves the address cfg module approve POSTs to", func(t *testing.T) {
		resp, err := client.Get(base + "/api/v1/modules/approvals")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Pending []struct {
				Address   string `json:"address"`
				Publisher string `json:"publisher"`
				Name      string `json:"name"`
				Version   string `json:"version"`
			} `json:"pending"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Pending, 1, "only the unapproved bundle is queued for review")
		entry := result.Pending[0]
		assert.Equal(t, pendingAddr.Publisher, entry.Publisher)
		assert.Equal(t, pendingAddr.Name, entry.Name)
		assert.Equal(t, pendingAddr.Version, entry.Version)
		require.NotEmpty(t, entry.Address)
		pendingAddress = entry.Address
	})

	t.Run("POST .../approve without a presence token is a registered-but-gated route, not a 404", func(t *testing.T) {
		require.NotEmpty(t, pendingAddress, "requires the previous subtest to have resolved an address")
		resp, err := client.Post(base+"/api/v1/modules/approvals/"+pendingAddress+"/approve", "application/json", nil)
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		// AC5's own route-registration test treats this exact body as proof a path is
		// unregistered; asserting its absence here pins that this route is real.
		body, _ := io.ReadAll(resp.Body)
		assert.NotContains(t, string(body), routerCatchAll404)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode,
			"module:approve requires a presence token (ADR-021 Decision 4); a bare admin mTLS request gets a step-up challenge, not success or 404")
	})

	t.Run("approving via the real ApprovalWorkflow is reflected through GET /api/v1/modules", func(t *testing.T) {
		// Exercises the same mutation handleApproveModuleBundle performs
		// (s.moduleBundleReviewer.Approve(addr)) against the identical on-disk cache,
		// bypassing only the WebAuthn presence ceremony HTTP requires (see test doc
		// comment) — not the approval logic itself.
		require.NoError(t, approval.New(seedCache).Approve(pendingAddr))

		resp, err := client.Get(base + "/api/v1/modules?status=approved")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var result struct {
			Modules []struct {
				Name   string `json:"name"`
				Status string `json:"status"`
			} `json:"modules"`
			Total int `json:"total"`
		}
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		decodeEnvelope(t, body, &result)

		require.Len(t, result.Modules, 2, "both bundles are now approved")
		names := map[string]bool{}
		for _, m := range result.Modules {
			assert.Equal(t, string(cache.ApprovalStatusApproved), m.Status)
			names[m.Name] = true
		}
		assert.True(t, names["hyperv"], "the formerly-pending bundle must now show as approved")
		assert.True(t, names["firewall"])
	})
}
