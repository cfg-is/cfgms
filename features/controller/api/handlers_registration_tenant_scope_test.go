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

	t.Run("approved entry leaves the pending list", func(t *testing.T) {
		// pending-a-1 was approved by the preceding sub-test, so it must no longer be
		// listed for its own tenant (Issue #3173).
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/v1/registration/pending", nil)
		req = withScopedPrincipal(req, "tenant-a")
		server.handleListPendingRegistrations(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var entries []PendingRegistration
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
		for _, e := range entries {
			assert.NotEqual(t, "pending-a-1", e.PendingID,
				"an approved registration must not remain in the pending list")
		}
	})

	t.Run("unscoped admin sees all entries", func(t *testing.T) {
		// Seed a fresh tenant-a entry: the originally seeded pending-a-1 was approved by
		// an earlier sub-test and is therefore no longer pending. This sub-test asserts
		// cross-tenant visibility, so it must supply its own un-resolved tenant-a entry
		// rather than depend on state mutated upstream.
		require.NoError(t, pendingStore.AddPending(ctx, &business.PendingRegistrationEntry{
			PendingID:    "pending-a-2",
			StewardID:    "steward-a-2",
			TenantID:     "tenant-a",
			TokenStr:     "tok-a-2",
			SourceIP:     "10.0.1.2",
			RegisteredAt: time.Now().UTC(),
			ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}))

		req := httptest.NewRequest("GET", "/api/v1/registration/pending", nil)
		req = withAdminPrincipal(req)
		rec := httptest.NewRecorder()
		server.handleListPendingRegistrations(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var entries []PendingRegistration
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
		require.GreaterOrEqual(t, len(entries), 2, "unscoped admin must see all tenants")

		seenTenants := make(map[string]bool, len(entries))
		for _, e := range entries {
			seenTenants[e.TenantID] = true
		}
		assert.True(t, seenTenants["tenant-a"], "unscoped admin must see tenant-a entries")
		assert.True(t, seenTenants["tenant-b"], "unscoped admin must see tenant-b entries")
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
		createTestTenant(t, server, "tenant-a", "")
		createTestTenant(t, server, "tenant-a-child", "tenant-a")
		body, _ := json.Marshal(registration.TokenCreateRequest{
			TenantID:      "tenant-a-child",
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

// subtreeScopeFixture is a seeded tenant tree with one pending registration per tenant:
//
//	root
//	├── msp-a
//	│   └── client-a1
//	│       └── site-a1
//	├── msp-b
//	│   └── client-b1
//	└── msp-a-evil   (ID-prefix lookalike of msp-a, not in its subtree)
type subtreeScopeFixture struct {
	server       *Server
	pendingStore business.PendingRegistrationStore
	// pendingByTenant maps tenant ID to the pending ID seeded for it.
	pendingByTenant map[string]string
}

func newSubtreeScopeFixture(t *testing.T) *subtreeScopeFixture {
	t.Helper()
	server, pendingStore, _, _ := newTenantScopeTestServer(t)

	createTestTenant(t, server, "msp-a", "")
	createTestTenant(t, server, "client-a1", "msp-a")
	createTestTenant(t, server, "site-a1", "client-a1")
	createTestTenant(t, server, "msp-b", "")
	createTestTenant(t, server, "client-b1", "msp-b")
	createTestTenant(t, server, "msp-a-evil", "")

	f := &subtreeScopeFixture{server: server, pendingStore: pendingStore, pendingByTenant: map[string]string{}}
	// Seeded out of subtree order, with distinct RegisteredAt values, so the merged
	// list order is observable. All sources sit in 10.20.0.0/16.
	base := time.Now().UTC().Add(-time.Hour)
	seed := []struct {
		tenant string
		ip     string
		offset time.Duration
	}{
		{"client-a1", "10.20.1.1", 3 * time.Minute},
		{"msp-b", "10.20.2.1", 4 * time.Minute},
		{"msp-a", "10.20.0.1", 1 * time.Minute},
		{"msp-a-evil", "10.20.3.1", 5 * time.Minute},
		{"site-a1", "10.20.1.2", 2 * time.Minute},
		{"client-b1", "10.20.2.2", 6 * time.Minute},
	}
	for _, s := range seed {
		id := "pending-" + s.tenant
		f.pendingByTenant[s.tenant] = id
		require.NoError(t, pendingStore.AddPending(context.Background(), &business.PendingRegistrationEntry{
			PendingID:    id,
			StewardID:    "steward-" + s.tenant,
			TenantID:     s.tenant,
			TokenStr:     "tok-" + s.tenant,
			SourceIP:     s.ip,
			RegisteredAt: base.Add(s.offset),
			ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
			Status:       business.PendingRegistrationStatusPending,
		}))
	}
	return f
}

func (f *subtreeScopeFixture) listAs(t *testing.T, tenantID string) []PendingRegistration {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/registration/pending", nil)
	if tenantID == "" {
		req = withAdminPrincipal(req)
	} else {
		req = withScopedPrincipal(req, tenantID)
	}
	rec := httptest.NewRecorder()
	f.server.handleListPendingRegistrations(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var entries []PendingRegistration
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &entries))
	return entries
}

func (f *subtreeScopeFixture) statusOf(t *testing.T, tenant string) string {
	t.Helper()
	got, err := f.pendingStore.GetPendingByID(context.Background(), f.pendingByTenant[tenant])
	require.NoError(t, err)
	return got.Status
}

func pendingTenantIDs(entries []PendingRegistration) []string {
	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.TenantID)
	}
	return ids
}

// bulkRequest builds a bulk-approval request carrying the scoped caller and an acting principal.
func bulkRequest(method, target, body, tenantID string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withScopedPrincipal(req, tenantID)
	return req.WithContext(withActor(req.Context(), &Principal{ID: "operator-1", TenantID: tenantID}))
}

// TestPendingRegistrationSubtreeScope verifies the pending list and the bulk approval
// verbs cover the caller's tenant subtree and nothing outside it.
func TestPendingRegistrationSubtreeScope(t *testing.T) {
	t.Run("msp caller lists its own tenant and descendants only, oldest first", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		entries := f.listAs(t, "msp-a")
		assert.Equal(t, []string{"msp-a", "site-a1", "client-a1"}, pendingTenantIDs(entries),
			"msp-a sees msp-a, client-a1 and site-a1 ordered by RegisteredAt ascending; never msp-b, client-b1 or msp-a-evil")
	})

	t.Run("client caller sees only its own and descendant entries", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		entries := f.listAs(t, "client-a1")
		assert.Equal(t, []string{"site-a1", "client-a1"}, pendingTenantIDs(entries),
			"client-a1 must not see its parent msp-a's entry")
	})

	t.Run("leaf caller sees only its own entry", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		assert.Equal(t, []string{"site-a1"}, pendingTenantIDs(f.listAs(t, "site-a1")))
	})

	t.Run("lookalike tenant sees only itself", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		assert.Equal(t, []string{"msp-a-evil"}, pendingTenantIDs(f.listAs(t, "msp-a-evil")))
	})

	t.Run("root caller still sees every tenant", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		seen := map[string]bool{}
		for _, e := range f.listAs(t, "") {
			seen[e.TenantID] = true
		}
		for tenantID := range f.pendingByTenant {
			assert.True(t, seen[tenantID], "root caller must see %s", tenantID)
		}
	})

	t.Run("approve-by-cidr approves the subtree and leaves other tenants pending", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		rec := httptest.NewRecorder()
		f.server.handleApproveByCIDR(rec, bulkRequest(http.MethodPost, "/api/v1/registration/approve-by-cidr",
			`{"cidr":"10.20.1.0/24"}`, "msp-a"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		assert.Equal(t, business.PendingRegistrationStatusApproved, f.statusOf(t, "client-a1"))
		assert.Equal(t, business.PendingRegistrationStatusApproved, f.statusOf(t, "site-a1"))
		assert.Equal(t, business.PendingRegistrationStatusPending, f.statusOf(t, "msp-a"), "outside the CIDR")
		assert.Equal(t, business.PendingRegistrationStatusPending, f.statusOf(t, "msp-b"))
	})

	t.Run("approve-by-cidr leaves a matching other-tenant entry pending", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		rec := httptest.NewRecorder()
		f.server.handleApproveByCIDR(rec, bulkRequest(http.MethodPost, "/api/v1/registration/approve-by-cidr",
			`{"cidr":"10.20.0.0/16"}`, "msp-a"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		for _, tenantID := range []string{"msp-a", "client-a1", "site-a1"} {
			assert.Equal(t, business.PendingRegistrationStatusApproved, f.statusOf(t, tenantID), tenantID)
		}
		for _, tenantID := range []string{"msp-b", "client-b1", "msp-a-evil"} {
			assert.Equal(t, business.PendingRegistrationStatusPending, f.statusOf(t, tenantID),
				"%s matches the CIDR but is outside msp-a's subtree", tenantID)
		}
	})

	t.Run("approve-by-cidr preview lists the same set the approval acts on", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		req := httptest.NewRequest(http.MethodGet,
			"/api/v1/registration/approve-by-cidr/preview?cidr=10.20.0.0/16", nil)
		req = withScopedPrincipal(req, "msp-a")
		rec := httptest.NewRecorder()
		f.server.handleApproveByCIDRPreview(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var preview approveByCIDRPreviewResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preview))
		assert.Equal(t, []string{
			f.pendingByTenant["msp-a"], f.pendingByTenant["site-a1"], f.pendingByTenant["client-a1"],
		}, preview.PendingIDs)
		assert.Equal(t, 3, preview.Count)
	})

	t.Run("approve-all approves the subtree and not other tenants", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		rec := httptest.NewRecorder()
		f.server.handleApproveAllRegistrations(rec, bulkRequest(http.MethodPost,
			"/api/v1/registration/approve-all", "", "msp-a"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

		var resp approveAllResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, 3, resp.Approved)
		for _, tenantID := range []string{"msp-a", "client-a1", "site-a1"} {
			assert.Equal(t, business.PendingRegistrationStatusApproved, f.statusOf(t, tenantID), tenantID)
		}
		for _, tenantID := range []string{"msp-b", "client-b1", "msp-a-evil"} {
			assert.Equal(t, business.PendingRegistrationStatusPending, f.statusOf(t, tenantID), tenantID)
		}
	})

	t.Run("client caller approve-all does not touch its parent's entry", func(t *testing.T) {
		f := newSubtreeScopeFixture(t)
		rec := httptest.NewRecorder()
		f.server.handleApproveAllRegistrations(rec, bulkRequest(http.MethodPost,
			"/api/v1/registration/approve-all", "", "client-a1"))
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		assert.Equal(t, business.PendingRegistrationStatusPending, f.statusOf(t, "msp-a"))
		assert.Equal(t, business.PendingRegistrationStatusApproved, f.statusOf(t, "client-a1"))
	})
}
