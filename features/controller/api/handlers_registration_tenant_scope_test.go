// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/registration"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// newTenantScopeTestServer creates a server with pendingStore, tokenStore, and ipTrustStore
// wired, for cross-tenant isolation contract tests.
func newTenantScopeTestServer(t *testing.T) (*Server, business.PendingRegistrationStore, registration.Store, business.IPTrustStore) {
	t.Helper()
	tokenStore := newTestRegistrationStore(t)
	server, _ := newHandleRegisterServer(t, tokenStore, nil)

	sm := pkgtesting.SetupTestStorage(t)
	pendingStore := sm.GetPendingRegistrationStore()
	require.NotNil(t, pendingStore)
	server.SetPendingStore(pendingStore)

	ipStore := newInMemIPTrustStore()
	server.SetIPTrustStore(ipStore)

	return server, pendingStore, tokenStore, ipStore
}

// TestF1_PendingRegistrationTenantScope verifies that a tenant-A caller cannot observe or
// mutate tenant-B's pending registrations (Issue #2932 F1 contract test).
func TestF1_PendingRegistrationTenantScope(t *testing.T) {
	server, pendingStore, _, _ := newTenantScopeTestServer(t)
	ctx := context.Background()

	// Seed a pending entry for tenant-b.
	entryB := &business.PendingRegistrationEntry{
		PendingID:    "pending-b-1",
		StewardID:    "steward-b-1",
		TenantID:     "tenant-b",
		TokenStr:     "tok-b",
		SourceIP:     "10.0.0.1",
		RegisteredAt: time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}
	require.NoError(t, pendingStore.AddPending(ctx, entryB))

	// Seed a pending entry for tenant-a.
	entryA := &business.PendingRegistrationEntry{
		PendingID:    "pending-a-1",
		StewardID:    "steward-a-1",
		TenantID:     "tenant-a",
		TokenStr:     "tok-a",
		SourceIP:     "10.0.1.1",
		RegisteredAt: time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		Status:       business.PendingRegistrationStatusPending,
	}
	require.NoError(t, pendingStore.AddPending(ctx, entryA))

	t.Run("list does not include tenant-b entries", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/registration/pending", nil)
		req = withScopedPrincipal(req, "tenant-a")
		server.handleListPendingRegistrations(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var entries []PendingRegistration
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))

		for _, e := range entries {
			assert.NotEqual(t, "tenant-b", e.TenantID,
				"tenant-a caller must never see tenant-b pending registration")
		}
		// Exactly one entry should be visible: tenant-a's own.
		assert.Len(t, entries, 1)
		assert.Equal(t, "tenant-a", entries[0].TenantID)
	})

	t.Run("tenant-a cannot approve tenant-b pending ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/pending-b-1/approve", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"id": "pending-b-1"})
		rec := httptest.NewRecorder()
		server.handleApproveRegistration(rec, req)

		// Must be 404 (no existence disclosure).
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("tenant-a cannot deny tenant-b pending ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/pending-b-1/deny", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"id": "pending-b-1"})
		rec := httptest.NewRecorder()
		server.handleDenyRegistration(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("tenant-a can approve its own pending ID", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/pending-a-1/approve", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"id": "pending-a-1"})
		rec := httptest.NewRecorder()
		server.handleApproveRegistration(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("unscoped admin sees all entries", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/pending", nil)
		req = withAdminPrincipal(req)
		rec := httptest.NewRecorder()
		server.handleListPendingRegistrations(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var entries []PendingRegistration
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
		assert.GreaterOrEqual(t, len(entries), 2, "unscoped admin must see all tenants")
	})
}

// TestF2_RegistrationTokenTenantScope verifies that a tenant-A caller cannot list or get
// tenant-B's tokens, and that list/get responses never contain the full raw secret
// (Issue #2932 F2 contract test).
func TestF2_RegistrationTokenTenantScope(t *testing.T) {
	server, _, tokenStore, _ := newTenantScopeTestServer(t)
	ctx := context.Background()

	// Create a token for tenant-b.
	tokB, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "tenant-b",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "group-b",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, tokB))

	// Create a token for tenant-a.
	tokA, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "tenant-a",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "group-a",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, tokA))

	t.Run("tenant-a list does not include tenant-b tokens", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens", nil)
		req = withScopedPrincipal(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleListRegistrationTokens(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp TokenListResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		for _, tok := range resp.Tokens {
			assert.NotEqual(t, "tenant-b", tok.TenantID,
				"tenant-a caller must never see tenant-b tokens")
		}
	})

	t.Run("listed token body contains no raw secret", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens", nil)
		req = withScopedPrincipal(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleListRegistrationTokens(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()

		var resp TokenListResponse
		require.NoError(t, json.Unmarshal([]byte(body), &resp))

		for _, tok := range resp.Tokens {
			// The full token secret must not appear in the JSON response body.
			assert.False(t, strings.Contains(body, tokA.Token),
				"list response must not contain the raw token secret")
			// Token field in the response must be empty.
			assert.Empty(t, tok.Token, "Token field must not be set in list response")
			// TokenPrefix must be present and be the first 6 chars.
			assert.NotEmpty(t, tok.TokenPrefix)
			if len(tokA.Token) >= 6 {
				assert.Equal(t, tokA.Token[:6], tok.TokenPrefix)
			}
		}
	})

	t.Run("tenant-a cannot get tenant-b token by its secret", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+tokB.Token, nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"token": tokB.Token})
		rec := httptest.NewRecorder()
		server.handleGetRegistrationToken(rec, req)

		// 404 to avoid existence disclosure.
		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("get response contains no raw secret", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+tokA.Token, nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"token": tokA.Token})
		rec := httptest.NewRecorder()
		server.handleGetRegistrationToken(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp TokenResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))

		assert.Empty(t, resp.Token, "Token field must not be set in get response")
		assert.NotEmpty(t, resp.TokenPrefix)
		assert.False(t, strings.Contains(rec.Body.String(), tokA.Token),
			"get response must not contain the raw token secret")
	})

	t.Run("unscoped admin sees all tokens in list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens", nil)
		req = withAdminPrincipal(req)
		rec := httptest.NewRecorder()
		server.handleListRegistrationTokens(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp TokenListResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.GreaterOrEqual(t, resp.Total, 2, "unscoped admin must see all tenant tokens")
	})

	t.Run("tenant-a cannot create a token for tenant-b", func(t *testing.T) {
		body, _ := json.Marshal(registration.TokenCreateRequest{
			TenantID:      "tenant-b",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withScopedPrincipal(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleCreateRegistrationToken(rec, req)

		// Outside-subtree target is forbidden (403), and no token is minted for tenant-b.
		assert.Equal(t, http.StatusForbidden, rec.Code)
		listed, err := tokenStore.ListTokens(ctx, "tenant-b")
		require.NoError(t, err)
		assert.Len(t, listed, 1, "tenant-b must still have only its original token")
	})

	t.Run("tenant-a can create a token within its own subtree", func(t *testing.T) {
		body, _ := json.Marshal(registration.TokenCreateRequest{
			TenantID:      "tenant-a/child",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withScopedPrincipal(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleCreateRegistrationToken(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
	})

	t.Run("tenant-a cannot delete tenant-b token", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/registration/tokens/"+tokB.Token, nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"token": tokB.Token})
		rec := httptest.NewRecorder()
		server.handleDeleteRegistrationToken(rec, req)

		// 404 to avoid existence disclosure, and tenant-b's token survives.
		assert.Equal(t, http.StatusNotFound, rec.Code)
		_, err := tokenStore.GetToken(ctx, tokB.Token)
		assert.NoError(t, err, "tenant-b token must not be deleted by a tenant-a caller")
	})

	t.Run("tenant-a cannot revoke tenant-b token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/"+tokB.Token+"/revoke", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"token": tokB.Token})
		rec := httptest.NewRecorder()
		server.handleRevokeRegistrationToken(rec, req)

		// 404 to avoid existence disclosure, and tenant-b's token stays active.
		assert.Equal(t, http.StatusNotFound, rec.Code)
		got, err := tokenStore.GetToken(ctx, tokB.Token)
		require.NoError(t, err)
		assert.False(t, got.Revoked, "tenant-b token must not be revoked by a tenant-a caller")
	})

	t.Run("tenant-a cannot rotate tokens for tenant-b", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/tenant-b/rotate", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"tenant_id": "tenant-b"})
		rec := httptest.NewRecorder()
		server.handleRotateRegistrationToken(rec, req)

		// Outside-subtree target is forbidden (403), and tenant-b's token is untouched.
		assert.Equal(t, http.StatusForbidden, rec.Code)
		got, err := tokenStore.GetToken(ctx, tokB.Token)
		require.NoError(t, err)
		assert.False(t, got.Revoked, "tenant-b token must not be rotated by a tenant-a caller")
	})

	t.Run("tenant-a can rotate tokens within its own subtree", func(t *testing.T) {
		// Seed an active groupless token for tenant-a so rotation has something to rotate.
		seed, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "tenant-a",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, seed))

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/tenant-a/rotate", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"tenant_id": "tenant-a"})
		rec := httptest.NewRecorder()
		server.handleRotateRegistrationToken(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)
	})
}

// TestF3_IPTrustTenantScope verifies that a tenant-A caller cannot list, add, or revoke
// tenant-B's IP trust ranges (Issue #2932 F3 contract test).
func TestF3_IPTrustTenantScope(t *testing.T) {
	server, _, _, ipStore := newTenantScopeTestServer(t)
	ctx := context.Background()

	// Seed a trusted range for tenant-b.
	require.NoError(t, ipStore.AddTrustedRange(ctx, "tenant-b", "192.168.1.0/24", true))
	// Seed a trusted range for tenant-a.
	require.NoError(t, ipStore.AddTrustedRange(ctx, "tenant-a", "10.0.0.0/8", false))

	t.Run("list returns only tenant-a ranges for tenant-a caller", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/ip-trust", nil)
		req = withScopedPrincipal(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var envelope struct {
			Data []IPTrustEntryResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))

		for _, e := range envelope.Data {
			assert.NotEqual(t, "tenant-b", e.TenantID,
				"tenant-a caller must never see tenant-b ip-trust ranges")
		}
	})

	t.Run("tenant-a cannot add a range for tenant-b", func(t *testing.T) {
		body, _ := json.Marshal(addIPTrustRequest{TenantID: "tenant-b", CIDR: "172.16.0.0/12"})
		req := httptest.NewRequest("POST", "/api/v1/registration/ip-trust", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withScopedPrincipal(req, "tenant-a")
		rec := httptest.NewRecorder()
		server.handleAddIPTrust(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("tenant-a cannot revoke tenant-b's range", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/registration/ip-trust/tenant-b/192.168.1.0/24", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"tenant_id": "tenant-b", "cidr": "192.168.1.0/24"})
		rec := httptest.NewRecorder()
		server.handleRevokeIPTrust(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("tenant-a can revoke its own range", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/registration/ip-trust/tenant-a/10.0.0.0/8", nil)
		req = withScopedPrincipal(req, "tenant-a")
		req = mux.SetURLVars(req, map[string]string{"tenant_id": "tenant-a", "cidr": "10.0.0.0/8"})
		rec := httptest.NewRecorder()
		server.handleRevokeIPTrust(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
	})

	t.Run("unscoped admin can list any tenant by query param", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/ip-trust?tenant_id=tenant-b", nil)
		req = withAdminPrincipal(req)
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var envelope struct {
			Data []IPTrustEntryResponse `json:"data"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &envelope))
		assert.NotEmpty(t, envelope.Data, "unscoped admin with tenant_id=tenant-b must see tenant-b ranges")
	})

	t.Run("unscoped admin without tenant_id returns 400", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/ip-trust", nil)
		req = withAdminPrincipal(req)
		rec := httptest.NewRecorder()
		server.handleListIPTrust(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}
