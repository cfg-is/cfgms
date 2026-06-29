// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tier3RouteEntry is a single entry in the Tier-3 route table for parity testing.
type tier3RouteEntry struct {
	method     string
	path       string
	permission string
}

// tier3RouteTable is the authoritative list of all 19 Tier-3 routes wired in server.go.
// Each entry maps to exactly one permission in tier3Permissions. The parity test
// (TestTier3Enforcement_RouteSetMatchesCanonicalSet) asserts this set equals tier3Permissions.
var tier3RouteTable = []tier3RouteEntry{
	{"POST", "/api/v1/certificates/provision", "certificate:provision"},
	{"POST", "/api/v1/certificates/signing/rotate", "certificate:rotate"},
	{"POST", "/api/v1/rbac/roles", "rbac:create-role"},
	{"PUT", "/api/v1/rbac/roles/test-id", "rbac:update-role"},
	{"DELETE", "/api/v1/rbac/roles/test-id", "rbac:delete-role"},
	{"POST", "/api/v1/api-keys", "api-key:create"},
	{"DELETE", "/api/v1/api-keys/test-id", "api-key:delete"},
	{"POST", "/api/v1/registration/tokens", "registration:create-token"},
	{"DELETE", "/api/v1/registration/tokens/test-token", "registration:delete-token"},
	{"POST", "/api/v1/registration/tokens/test-token/revoke", "registration:revoke-token"},
	{"POST", "/api/v1/registration/tokens/test-tenant/rotate", "registration:rotate-token"},
	{"POST", "/api/v1/registration/reg-123/approve", "registration:approve"},
	{"POST", "/api/v1/registration/approve-all", "registration:approve"},
	{"POST", "/api/v1/registration/approve-by-cidr", "registration:approve"},
	{"POST", "/api/v1/registration/ip-trust", "registration:manage-ip-trust"},
	{"DELETE", "/api/v1/registration/ip-trust/test-tenant/192.168.1.0/24", "registration:manage-ip-trust"},
	{"POST", "/api/v1/tenants", "tenant:create"},
	{"POST", "/api/v1/stewards/refresh/pending-123/approve", "refresh:approve"},
	{"PUT", "/api/v1/tenants/test-tenant/refresh-policy", "refresh:set-policy"},
}

// TestTier3Enforcement_APIKeyWithAdminPermissions_Gets403 verifies that an API-key
// principal carrying the exact admin permissions for a Tier-3 endpoint is still rejected
// with HTTP 403 MTLS_REQUIRED, and that the handler is never called.
func TestTier3Enforcement_APIKeyWithAdminPermissions_Gets403(t *testing.T) {
	server := setupTestServer(t)

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{
		IsAdmin:     false,
		Permissions: []string{"api-key:create", "rbac:create-role", "tenant:create", "certificate:provision"},
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, handlerCalled, "handler must not be called for API-key principal on Tier-3 endpoint")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "MTLS_REQUIRED", errResp.Error.Code)
}

// TestTier3Enforcement_AdminCertPrincipal_Passes verifies that an mTLS admin-cert
// principal (IsAdmin: true) passes the Tier-3 check and reaches the inner handler.
func TestTier3Enforcement_AdminCertPrincipal_Passes(t *testing.T) {
	server := setupTestServer(t)

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{
		IsAdmin:    true,
		CertSerial: "abc123",
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusForbidden, rec.Code, "admin cert principal must not receive 403")
	assert.True(t, handlerCalled, "inner handler must be called for admin cert principal")
}

// TestTier3Enforcement_RelayPrincipal_Gets403 verifies that a relay-style principal
// (IsAdmin: false, permissions from a grant scope) is rejected at the Tier-3 gate.
// This explicitly closes the Issue #1675 relay-bypass vector.
func TestTier3Enforcement_RelayPrincipal_Gets403(t *testing.T) {
	server := setupTestServer(t)

	handlerCalled := false
	probe := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	})

	wrapped := server.requireTier(TierMTLSOnly)(probe)

	// Relay principal: IsAdmin is false (relay_handler.go sets this), but the grant
	// scope carries the matching permission — simulating a relay that could otherwise
	// appear to have authorization.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-keys", nil)
	req = req.WithContext(context.WithValue(req.Context(), principalContextKey, &Principal{
		IsAdmin:     false,
		Permissions: []string{"api-key:create"},
		ID:          "relay-principal-id",
		TenantID:    "relay-tenant",
	}))
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code,
		"relay principal (IsAdmin: false) must be rejected at Tier-3 gate")
	assert.False(t, handlerCalled, "handler must not be called for relay principal")

	var errResp ErrorResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
	require.NotNil(t, errResp.Error)
	assert.Equal(t, "MTLS_REQUIRED", errResp.Error.Code)
}

// TestTier3Enforcement_RouteSetMatchesCanonicalSet verifies two invariants:
//
//	(a) Every route in tier3RouteTable returns HTTP 403 MTLS_REQUIRED when called
//	    by an API-key principal — even one carrying the matching admin permissions.
//
//	(b) The unique permission set in tier3RouteTable exactly equals tier3Permissions
//	    (the canonical set from auth_tiers.go). No drift in either direction.
func TestTier3Enforcement_RouteSetMatchesCanonicalSet(t *testing.T) {
	server := setupTestServer(t)

	// API key carries all Tier-3 permissions — proving the tier gate fires before
	// the permission gate and rejects regardless of what permissions the key holds.
	allTier3Perms := make([]string, 0, len(tier3Permissions))
	for perm := range tier3Permissions {
		allTier3Perms = append(allTier3Perms, perm)
	}
	apiKey := NewTestKey(t, server, allTier3Perms)

	// Part (a): each route returns 403 MTLS_REQUIRED to an API-key principal.
	for _, entry := range tier3RouteTable {
		entry := entry
		t.Run(entry.method+" "+entry.path, func(t *testing.T) {
			req := httptest.NewRequest(entry.method, entry.path, nil)
			req.Header.Set("X-API-Key", apiKey)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)

			require.Equal(t, http.StatusForbidden, rec.Code,
				"Tier-3 route must reject API-key principal with 403")

			var errResp ErrorResponse
			require.NoError(t, json.NewDecoder(rec.Body).Decode(&errResp))
			require.NotNil(t, errResp.Error)
			assert.Equal(t, "MTLS_REQUIRED", errResp.Error.Code,
				"rejection must use MTLS_REQUIRED error code")
		})
	}

	// Part (b): unique permissions in the route table must exactly match tier3Permissions.
	tablePerms := make(map[string]struct{})
	for _, entry := range tier3RouteTable {
		tablePerms[entry.permission] = struct{}{}
	}
	assert.Equal(t, tier3Permissions, tablePerms,
		"route table permissions must exactly match the tier3Permissions canonical set — add missing routes or remove stale entries")
}

// TestTier1Endpoint_RemainsReachableByAPIKey verifies that wrapping Tier-3 routes did
// not accidentally elevate Tier-1 routes. A valid API-key principal must still reach
// GET /api/v1/stewards (which uses only requirePermission, no requireTier(TierMTLSOnly)).
func TestTier1Endpoint_RemainsReachableByAPIKey(t *testing.T) {
	server := setupTestServer(t)
	apiKey := NewTestKey(t, server, []string{"steward:list"})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)

	assert.NotEqual(t, http.StatusForbidden, rec.Code,
		"Tier-1 endpoint must remain reachable by API-key principal after Tier-3 wiring")
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code,
		"Tier-1 endpoint must authenticate valid API-key principal")
}
