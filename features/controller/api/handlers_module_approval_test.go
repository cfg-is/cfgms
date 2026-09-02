// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 CFGMS Contributors
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/cfgis/cfgms/features/controller/modules/approval"
	"github.com/cfgis/cfgms/features/controller/modules/cache"
	modules "github.com/cfgis/cfgms/features/modules"
	"github.com/cfgis/cfgms/pkg/modules/bundle"
	"github.com/cfgis/cfgms/pkg/session"
)

// ---- Test helpers -----------------------------------------------------------

func makeTestModuleCache(t *testing.T) *cache.ModuleCache {
	t.Helper()
	c, err := cache.New(t.TempDir() + "/module-cache")
	require.NoError(t, err)
	return c
}

func makeTestApprovalWorkflow(t *testing.T, c *cache.ModuleCache) *approval.ApprovalWorkflow {
	t.Helper()
	return approval.New(c)
}

// makePendingBundle stores a bundle in pending state in the cache and returns its address.
func makePendingBundle(t *testing.T, c *cache.ModuleCache, publisher, name, version string) bundle.ContentAddress {
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

// setupModuleApprovalServer creates a test server wired with module approval dependencies.
func setupModuleApprovalServer(t *testing.T) (*Server, *cache.ModuleCache, *approval.ApprovalWorkflow) {
	t.Helper()
	server := setupTestServer(t)

	mc := makeTestModuleCache(t)
	wf := makeTestApprovalWorkflow(t, mc)

	server.SetModuleResolution(mc, nil, nil, nil)
	server.SetModuleBundleReviewer(wf)

	return server, mc, wf
}

// strongPrincipal builds a Strong-assurance principal for testing AssuranceStrong gates.
func moduleTestStrongPrincipal() *Principal {
	return &Principal{
		ID:            "cert-admin",
		Name:          "mtls-cert:cert-admin",
		Assurance:     session.AssuranceStrong,
		CertSerial:    "test-serial",
		ImplicitAdmin: true,
	}
}

// ---- Tests ------------------------------------------------------------------

// TestHandleListModuleApprovals_ReturnsPending verifies that only pending bundles are returned.
func TestHandleListModuleApprovals_ReturnsPending(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)

	// Store one pending and one approved bundle.
	pendingAddr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	approvedAddr := makePendingBundle(t, mc, "cfgms", "firewall", "1.0.0")
	require.NoError(t, mc.SetApprovalStatus(approvedAddr, cache.ApprovalStatusApproved))

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules/approvals", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))

	data, ok := resp.Data.(map[string]interface{})
	require.True(t, ok)
	pending, ok := data["pending"].([]interface{})
	require.True(t, ok)

	// Only the pending bundle should be in the list.
	require.Len(t, pending, 1)
	entry, ok := pending[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, pendingAddr.Publisher, entry["publisher"])
	assert.Equal(t, pendingAddr.Name, entry["name"])
	assert.Equal(t, pendingAddr.Version, entry["version"])
	assert.NotEmpty(t, entry["address"], "address field must be present for client to reference the bundle")
}

// TestHandleListModuleApprovals_EmptyCache returns an empty pending list.
func TestHandleListModuleApprovals_EmptyCache(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules/approvals", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp APIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	data := resp.Data.(map[string]interface{})
	pending := data["pending"].([]interface{})
	assert.Empty(t, pending)
}

// TestHandleListModuleApprovals_ReachableByNonMTLSAdmin verifies the list endpoint
// is reachable by a non-mTLS admin principal (assurance check not applicable to reads).
func TestHandleListModuleApprovals_ReachableByNonMTLSAdmin(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	// A Machine-assurance principal with module:list-approvals can reach the list endpoint
	// (reads are not in permissionAssurance, so no AssuranceStrong gate fires).
	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules/approvals", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Must not be rejected by the assurance gate.
	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"non-mTLS API key must not be rejected by the assurance gate on the list endpoint")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"valid API key must pass authentication on list endpoint")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// makeApproveRequest builds a request for POST .../approve with the address as a mux var
// and injects a fresh single-use presence token (Issue #2784: module:approve requires
// RequireUserPresence enforcement).
func makeApproveRequest(t *testing.T, s *Server, addressParam string, principal *Principal) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/modules/approvals/"+addressParam+"/approve", nil)
	req = mux.SetURLVars(req, map[string]string{"address": addressParam})
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, principal))
	// Inject a presence token so requirePermission's RequireUserPresence check passes.
	token := mintPresenceToken(t, s, principal.ID)
	req.Header.Set(presenceTokenHeader, token)
	return req
}

// makeRejectRequest builds a request for POST .../reject with the address as a mux var
// and injects a fresh single-use presence token (Issue #2784: module:reject requires
// RequireUserPresence enforcement).
func makeRejectRequest(t *testing.T, s *Server, addressParam string, principal *Principal) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/modules/approvals/"+addressParam+"/reject", nil)
	req = mux.SetURLVars(req, map[string]string{"address": addressParam})
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, principal))
	// Inject a presence token so requirePermission's RequireUserPresence check passes.
	token := mintPresenceToken(t, s, principal.ID)
	req.Header.Set(presenceTokenHeader, token)
	return req
}

// TestHandleApproveModuleBundle_Success verifies that approving a pending bundle
// transitions it to approved.
func TestHandleApproveModuleBundle_Success(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)

	addr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	addressParam := formatModuleAddress(addr)

	req := makeApproveRequest(t, server, addressParam, moduleTestStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "approve")(http.HandlerFunc(server.handleApproveModuleBundle))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	status, err := mc.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusApproved, status)
}

// TestHandleRejectModuleBundle_Success verifies that rejecting a pending bundle
// transitions it to rejected.
func TestHandleRejectModuleBundle_Success(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)

	addr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	addressParam := formatModuleAddress(addr)

	req := makeRejectRequest(t, server, addressParam, moduleTestStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "reject")(http.HandlerFunc(server.handleRejectModuleBundle))
	handler.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	status, err := mc.GetApprovalStatus(addr)
	require.NoError(t, err)
	assert.Equal(t, cache.ApprovalStatusRejected, status)
}

// TestHandleRejectModuleBundle_NonPending verifies that rejecting a non-pending
// bundle returns an error, not a silent no-op.
func TestHandleRejectModuleBundle_NonPending(t *testing.T) {
	server, mc, _ := setupModuleApprovalServer(t)

	// Store a bundle and approve it first.
	addr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
	require.NoError(t, mc.SetApprovalStatus(addr, cache.ApprovalStatusApproved))

	addressParam := formatModuleAddress(addr)
	req := makeRejectRequest(t, server, addressParam, moduleTestStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "reject")(http.HandlerFunc(server.handleRejectModuleBundle))
	handler.ServeHTTP(rec, req)

	// Must return 409 Conflict, not 200 or 204.
	assert.Equal(t, http.StatusConflict, rec.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "NOT_PENDING", errResp.Error.Code)
}

// TestHandleApproveModuleBundle_NotFound verifies that approving a missing bundle
// returns 404.
func TestHandleApproveModuleBundle_NotFound(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	missing := bundle.ContentAddress{
		Publisher:   "cfgms",
		Name:        "missing",
		Version:     "1.0.0",
		ContentHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	addressParam := formatModuleAddress(missing)
	req := makeApproveRequest(t, server, addressParam, moduleTestStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "approve")(http.HandlerFunc(server.handleApproveModuleBundle))
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestHandleApproveModuleBundle_APIKeyRejected verifies that an API-key principal
// (Machine assurance) is rejected on the approve endpoint.
func TestHandleApproveModuleBundle_APIKeyRejected(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	apiKey := NewTestKey(t, server, []string{"module:approve"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/modules/approvals/cfgms:hyperv:0.2.1:fakehash/approve", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	// Machine-assurance API keys must be blocked (403) by the AssuranceStrong gate.
	assert.Equal(t, http.StatusForbidden, rec.Code,
		"API-key principal must be rejected with 403 on the approve endpoint (AssuranceStrong gate)")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Machine-assurance 403 must not include a step-up challenge")
}

// TestHandleRejectModuleBundle_APIKeyRejected verifies that an API-key principal
// (Machine assurance) is rejected on the reject endpoint.
func TestHandleRejectModuleBundle_APIKeyRejected(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	apiKey := NewTestKey(t, server, []string{"module:reject"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/modules/approvals/cfgms:hyperv:0.2.1:fakehash/reject", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"API-key principal must be rejected with 403 on the reject endpoint (AssuranceStrong gate)")
	assert.Empty(t, rec.Header().Get("WWW-Authenticate"),
		"Machine-assurance 403 must not include a step-up challenge")
}

// TestHandleApproveModuleBundle_InvalidAddressFormat verifies that a malformed
// {address} returns 400.
func TestHandleApproveModuleBundle_InvalidAddressFormat(t *testing.T) {
	server, _, _ := setupModuleApprovalServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/modules/approvals/not-valid-address/approve", nil)
	req = mux.SetURLVars(req, map[string]string{"address": "not-valid-address"})
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, moduleTestStrongPrincipal()))
	// Inject presence token so the RequireUserPresence gate passes (Issue #2784).
	presToken := mintPresenceToken(t, server, moduleTestStrongPrincipal().ID)
	req.Header.Set(presenceTokenHeader, presToken)
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "approve")(http.HandlerFunc(server.handleApproveModuleBundle))
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestHandleListModuleApprovals_NilCacheReturns503 verifies that the list endpoint
// returns 503 when moduleCacheLister is not configured.
func TestHandleListModuleApprovals_NilCacheReturns503(t *testing.T) {
	server := setupTestServer(t)
	// moduleCacheLister is nil (no SetModuleResolution call).

	listKey := NewTestKey(t, server, []string{"module:list-approvals"})
	req := httptest.NewRequest(http.MethodGet, "/api/v1/modules/approvals", nil)
	req.Header.Set("X-API-Key", listKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "SERVICE_UNAVAILABLE", errResp.Error.Code)
}

// TestHandleApproveModuleBundle_NilReviewerReturns503 verifies that the approve
// endpoint returns 503 when moduleBundleReviewer is not configured.
func TestHandleApproveModuleBundle_NilReviewerReturns503(t *testing.T) {
	server := setupTestServer(t)
	// moduleBundleReviewer is nil (no SetModuleBundleReviewer call).

	addr := bundle.ContentAddress{
		Publisher: "cfgms", Name: "hyperv", Version: "0.2.1",
		ContentHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	addressParam := formatModuleAddress(addr)

	req := makeApproveRequest(t, server, addressParam, moduleTestStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "approve")(http.HandlerFunc(server.handleApproveModuleBundle))
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestHandleRejectModuleBundle_NilReviewerReturns503 verifies that the reject
// endpoint returns 503 when moduleBundleReviewer is not configured.
func TestHandleRejectModuleBundle_NilReviewerReturns503(t *testing.T) {
	server := setupTestServer(t)
	// moduleBundleReviewer is nil (no SetModuleBundleReviewer call).

	addr := bundle.ContentAddress{
		Publisher: "cfgms", Name: "hyperv", Version: "0.2.1",
		ContentHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	addressParam := formatModuleAddress(addr)

	req := makeRejectRequest(t, server, addressParam, moduleTestStrongPrincipal())
	rec := httptest.NewRecorder()

	handler := server.requirePermission("module", "reject")(http.HandlerFunc(server.handleRejectModuleBundle))
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// TestModuleBundleApprovalHandlers_SucceedOnNonAuthoritativeNode is the [REQUIRED TEST]
// for this file (Issue #3761, ADR-031 Decision 1): handleApproveModuleBundle and
// handleRejectModuleBundle used to return 503 and leave the bundle pending when the
// serving node held no lease-backed leadership. Any-node service means every cluster
// node accepts both writes — the shared module cache is the serialization point, not
// leadership — so against a real, deliberately non-authoritative *ha.Manager
// (ClusterMode, no lease ever acquired) each handler must reach the reviewer and the
// bundle's approval status must actually change.
func TestModuleBundleApprovalHandlers_SucceedOnNonAuthoritativeNode(t *testing.T) {
	newNonAuthoritativeServer := func(t *testing.T) (*Server, *cache.ModuleCache) {
		t.Helper()
		server, mc, _ := setupModuleApprovalServer(t)
		server.haManager = newNonAuthoritativeHAManager(t)
		return server, mc
	}

	t.Run("approve succeeds and invokes the reviewer", func(t *testing.T) {
		server, mc := newNonAuthoritativeServer(t)
		addr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
		addressParam := formatModuleAddress(addr)

		req := makeApproveRequest(t, server, addressParam, moduleTestStrongPrincipal())
		rec := httptest.NewRecorder()

		handler := server.requirePermission("module", "approve")(http.HandlerFunc(server.handleApproveModuleBundle))
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code,
			"approval must succeed regardless of leadership: %s", rec.Body.String())

		status, err := mc.GetApprovalStatus(addr)
		require.NoError(t, err)
		assert.Equal(t, cache.ApprovalStatusApproved, status,
			"moduleBundleReviewer.Approve must run on a non-authoritative node")
	})

	t.Run("reject succeeds and invokes the reviewer", func(t *testing.T) {
		server, mc := newNonAuthoritativeServer(t)
		addr := makePendingBundle(t, mc, "cfgms", "hyperv", "0.2.1")
		addressParam := formatModuleAddress(addr)

		req := makeRejectRequest(t, server, addressParam, moduleTestStrongPrincipal())
		rec := httptest.NewRecorder()

		handler := server.requirePermission("module", "reject")(http.HandlerFunc(server.handleRejectModuleBundle))
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code,
			"rejection must succeed regardless of leadership: %s", rec.Body.String())

		status, err := mc.GetApprovalStatus(addr)
		require.NoError(t, err)
		assert.Equal(t, cache.ApprovalStatusRejected, status,
			"moduleBundleReviewer.RejectPending must run on a non-authoritative node")
	})
}

// TestFormatAndParseModuleAddress verifies round-trip encoding of ContentAddress.
func TestFormatAndParseModuleAddress(t *testing.T) {
	cases := []bundle.ContentAddress{
		{Publisher: "cfgms", Name: "hyperv", Version: "0.2.1", ContentHash: "abc+def/ghi="},
		{Publisher: "vendor-a", Name: "firewall", Version: "2.0.0", ContentHash: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	for _, addr := range cases {
		param := formatModuleAddress(addr)
		decoded, err := parseModuleAddress(param)
		require.NoError(t, err)
		assert.Equal(t, addr, decoded)
	}
}
