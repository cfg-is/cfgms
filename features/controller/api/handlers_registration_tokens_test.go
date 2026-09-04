// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

// setupTestServerWithTokenStore creates a test server with a real registration token store
func setupTestServerWithTokenStore(t *testing.T) (*Server, registration.Store) {
	t.Helper()

	// Isolate secrets storage per test to prevent shared-path contention on Windows CI.
	setTestSecretsEnv(t)

	// Create test configuration
	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false // Disable for testing

	// Create test logger
	logger := logging.NewNoopLogger()

	// Initialize RBAC system with OSS composite storage
	storageManager := pkgtesting.SetupTestStorage(t)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	err := rbacManager.Initialize(context.Background())
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = rbacManager.Close(closeCtx)
	})

	// Initialize tenant management with durable storage
	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	// Create registration token store. In-memory for the same reason as
	// newTestRegistrationStore in handlers_registration_test.go: the file-backed
	// path runs the full schema DDL against a WAL journal on disk (0.4s-2.6s under
	// -race) where the in-memory path takes the provider's deserialize fast-path
	// (~10ms). openDB gives every in-memory request a private, single-connection
	// database, so this store stays isolated from every other test's.
	regTokenStore, err := interfaces.CreateRegistrationTokenStoreFromConfig(
		"sqlite",
		map[string]interface{}{"path": ":memory:"},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = regTokenStore.Close() })
	err = regTokenStore.Initialize(context.Background())
	require.NoError(t, err)

	tokenStore := registration.NewStorageAdapter(regTokenStore)

	// Create services
	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationServiceV2(logger, storageManager, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	// Create audit manager backed by the SQLite audit store
	auditMgr, err := audit.NewManager(storageManager.GetAuditStore(), "controller")
	require.NoError(t, err)
	t.Cleanup(func() { _ = auditMgr.Stop(context.Background()) })

	// Create REST API server with token store
	server, err := New(
		cfg,
		logger,
		controllerService,
		configService,
		nil, // No cert provisioning for basic tests
		rbacService,
		nil, // No cert manager for basic tests
		tenantManager,
		rbacManager,
		nil, // No system monitor for basic tests
		nil, // No HA manager for basic tests
		tokenStore,
		"",       // No signer cert serial for basic tests
		nil,      // No health collector for basic tests
		auditMgr, // Issue #775: registration audit events
		nil,      // No command publisher for basic tests
		nil,      // No push store for basic tests
		nil,      // No blob store for basic tests
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Close(closeCtx); err != nil {
			t.Errorf("server.Close: %v", err)
		}
	})

	return server, tokenStore
}

// makeScopedTokenRequest builds a request for a tenant-scoped (web session) caller
// addressing a registration token by path variable. Delete and revoke require
// AssuranceStrong, which an API key can never hold, so scope-enforcement tests
// invoke the handler directly with the tenant in context and the mux var set.
func makeScopedTokenRequest(t *testing.T, method, path, tenantID, tokenVar string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxkeys.TenantID, tenantID))
	return mux.SetURLVars(req, map[string]string{"token": tokenVar})
}

func TestCreateRegistrationToken(t *testing.T) {
	server, _ := setupTestServerWithTokenStore(t)

	t.Run("successful token creation", func(t *testing.T) {
		reqBody := registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
			Group:         "production",
			ExpiresIn:     "7d",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var resp TokenResponse
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.Token)
		assert.True(t, len(resp.Token) > 10, "Token should be a reasonable length")
		assert.Equal(t, "test-tenant", resp.TenantID)
		assert.Equal(t, "grpc://controller.example.com:7443", resp.ControllerURL)
		assert.Equal(t, "production", resp.Group)
		assert.NotNil(t, resp.ExpiresAt)
	})

	t.Run("single_use field returns 400", func(t *testing.T) {
		// single_use was removed in Issue #1690; sending it must return 400
		body := []byte(`{"tenant_id":"test-tenant","controller_url":"grpc://controller.example.com:7443","single_use":true}`)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "single_use")
	})

	t.Run("missing tenant_id returns error", func(t *testing.T) {
		reqBody := registration.TokenCreateRequest{
			ControllerURL: "grpc://controller.example.com:7443",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "tenant_id")
	})

	t.Run("missing controller_url returns error", func(t *testing.T) {
		reqBody := registration.TokenCreateRequest{
			TenantID: "test-tenant",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "controller_url")
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader([]byte("not json")))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		reqBody := registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("forbidden without permission", func(t *testing.T) {
		// Create key with wrong permission
		wrongKey := NewTestKey(t, server, []string{"steward:list"})

		reqBody := registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("X-API-Key", wrongKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestListRegistrationTokens(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)

	// Create API key with list permission
	apiKey := NewTestKey(t, server, []string{"registration:list-tokens"})
	ctx := context.Background()

	// Create some test tokens
	for i := 0; i < 3; i++ {
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		err = tokenStore.SaveToken(ctx, token)
		require.NoError(t, err)
	}

	// Create a token for a different tenant
	otherToken, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "other-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
	})
	require.NoError(t, err)
	err = tokenStore.SaveToken(ctx, otherToken)
	require.NoError(t, err)

	t.Run("list all tokens — scoped caller sees only own tenant", func(t *testing.T) {
		// apiKey is scoped to "test-tenant" (via NewTestKey). After Issue #2932, scoped callers
		// always see only their own tenant's tokens regardless of any query param.
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		// Scoped caller sees only the 3 "test-tenant" tokens, not the "other-tenant" one.
		assert.Equal(t, 3, resp.Total)
		assert.Len(t, resp.Tokens, 3)
		for _, tok := range resp.Tokens {
			assert.Equal(t, "test-tenant", tok.TenantID)
			assert.Empty(t, tok.Token, "list response must not include the raw secret")
			assert.NotEmpty(t, tok.TokenPrefix, "list response must include token_prefix")
		}
	})

	t.Run("filter by tenant_id", func(t *testing.T) {
		// Scoped caller: query param is ignored; they still see their own tenant tokens.
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens?tenant_id=test-tenant", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, 3, resp.Total)
		assert.Len(t, resp.Tokens, 3)

		for _, token := range resp.Tokens {
			assert.Equal(t, "test-tenant", token.TenantID)
		}
	})

	t.Run("scoped caller ignores tenant_id query param — sees own tenant only", func(t *testing.T) {
		// Before Issue #2932: scoped caller with ?tenant_id=nonexistent returned 0 entries.
		// After: scoped caller ignores the query param and returns their own tenant's tokens.
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens?tenant_id=nonexistent", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		// The query param is ignored; the scoped key's own tenant (test-tenant) is used.
		assert.Equal(t, 3, resp.Total)
		for _, tok := range resp.Tokens {
			assert.Equal(t, "test-tenant", tok.TenantID)
		}
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestGetRegistrationToken(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)

	// Create API key with read permission
	apiKey := NewTestKey(t, server, []string{"registration:read-token"})
	ctx := context.Background()

	// Create a test token
	token, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "test-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "test-group",
	})
	require.NoError(t, err)
	err = tokenStore.SaveToken(ctx, token)
	require.NoError(t, err)

	t.Run("get existing token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+token.Token, nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		// After Issue #2932: GET redacts the token secret; only token_prefix is returned.
		assert.Empty(t, resp.Token, "GET response must not include the raw token secret")
		assert.Equal(t, token.Token[:6], resp.TokenPrefix, "GET response must include the first 6 chars as token_prefix")
		assert.Equal(t, "test-tenant", resp.TenantID)
		assert.Equal(t, "grpc://controller.example.com:7443", resp.ControllerURL)
		assert.Equal(t, "test-group", resp.Group)
	})

	t.Run("get non-existent token returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/nonexistent-token", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+token.Token, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestDeleteRegistrationToken(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	t.Run("delete existing token", func(t *testing.T) {
		// Create a test token
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		err = tokenStore.SaveToken(ctx, token)
		require.NoError(t, err)

		req := makeAdminRequest(t, "DELETE", "/api/v1/registration/tokens/"+token.Token, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify token is deleted
		_, err = tokenStore.GetToken(ctx, token.Token)
		assert.Error(t, err)
	})

	// Issue #2970: the web UI never holds the secret, so it addresses a token by its
	// stable UUID. The handler falls back to a GetTokenByID lookup for that caller.
	t.Run("delete by token_id", func(t *testing.T) {
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, token))
		require.NotEmpty(t, token.ID)
		require.NotEqual(t, token.Token, token.ID)

		req := makeAdminRequest(t, "DELETE", "/api/v1/registration/tokens/"+token.ID, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)

		// The row keyed by the secret must be gone — the handler must delete by
		// token.Token, not by the UUID it was addressed with.
		_, err = tokenStore.GetToken(ctx, token.Token)
		assert.Error(t, err)
		_, err = tokenStore.GetTokenByID(ctx, token.ID)
		assert.Error(t, err)
	})

	t.Run("delete non-existent token returns 404", func(t *testing.T) {
		req := makeAdminRequest(t, "DELETE", "/api/v1/registration/tokens/nonexistent-token", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("delete unknown token_id returns 404 not 500", func(t *testing.T) {
		req := makeAdminRequest(t, "DELETE",
			"/api/v1/registration/tokens/aaaaaaaa-0000-4000-8000-0000000000ff", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code,
			"an unknown UUID must be a clean 404, never a store error surfaced as 500")
	})

	t.Run("scoped caller cannot delete another tenant's token by token_id", func(t *testing.T) {
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "other-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, token))

		// Scoped (web session) caller: tenant scope comes from the request context.
		// The handler is invoked directly because AssuranceStrong routes cannot be
		// reached with an API key.
		req := makeScopedTokenRequest(t, "DELETE",
			"/api/v1/registration/tokens/"+token.ID, "scoped-tenant", token.ID)
		rec := httptest.NewRecorder()

		server.handleDeleteRegistrationToken(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code,
			"tenant-scope enforcement must apply to the token_id path too")

		// The token must still exist.
		_, err = tokenStore.GetTokenByID(ctx, token.ID)
		require.NoError(t, err)
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/registration/tokens/some-token", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestRevokeRegistrationToken(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	t.Run("revoke existing token", func(t *testing.T) {
		// Create a test token
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		err = tokenStore.SaveToken(ctx, token)
		require.NoError(t, err)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/"+token.Token+"/revoke", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Revoked)
		assert.NotNil(t, resp.RevokedAt)

		// Verify token is revoked in store
		updated, err := tokenStore.GetToken(ctx, token.Token)
		require.NoError(t, err)
		assert.True(t, updated.Revoked)
		assert.False(t, updated.IsValid())
	})

	// Issue #2970: the web UI revokes by stable UUID because it never holds the secret.
	t.Run("revoke by token_id", func(t *testing.T) {
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, token))
		require.NotEmpty(t, token.ID)
		require.NotEqual(t, token.Token, token.ID)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/"+token.ID+"/revoke", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.True(t, resp.Revoked)
		assert.NotNil(t, resp.RevokedAt)
		assert.Equal(t, token.ID, resp.TokenID, "the response must echo the stable token_id")
		assert.Empty(t, resp.Token, "revoke must never return the raw secret")
		assert.Equal(t, token.Token[:6], resp.TokenPrefix)

		// The stored row (keyed by the secret) must be the one that got revoked.
		updated, err := tokenStore.GetToken(ctx, token.Token)
		require.NoError(t, err)
		assert.True(t, updated.Revoked)
		assert.False(t, updated.IsValid())

		// It must remain addressable by id after revocation (delete-after-revoke).
		byID, err := tokenStore.GetTokenByID(ctx, token.ID)
		require.NoError(t, err)
		assert.True(t, byID.Revoked)
	})

	t.Run("revoke unknown token_id returns 404 not 500", func(t *testing.T) {
		req := makeAdminRequest(t, "POST",
			"/api/v1/registration/tokens/aaaaaaaa-0000-4000-8000-0000000000ff/revoke", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code,
			"an unknown UUID must be a clean 404, never a store error surfaced as 500")
	})

	t.Run("scoped caller cannot revoke another tenant's token by token_id", func(t *testing.T) {
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "other-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
		})
		require.NoError(t, err)
		require.NoError(t, tokenStore.SaveToken(ctx, token))

		// Scoped (web session) caller: tenant scope comes from the request context.
		// The handler is invoked directly because AssuranceStrong routes cannot be
		// reached with an API key.
		req := makeScopedTokenRequest(t, "POST",
			"/api/v1/registration/tokens/"+token.ID+"/revoke", "scoped-tenant", token.ID)
		rec := httptest.NewRecorder()

		server.handleRevokeRegistrationToken(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code,
			"tenant-scope enforcement must apply to the token_id path too")

		still, err := tokenStore.GetTokenByID(ctx, token.ID)
		require.NoError(t, err)
		assert.False(t, still.Revoked, "the token must not be revoked by an out-of-scope caller")
	})

	t.Run("revoke non-existent token returns 404", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/nonexistent-token/revoke", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/some-token/revoke", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestRotateRegistrationToken(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	// Seed a token for rotation
	seed, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "rotate-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "rotate-group",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, seed))

	t.Run("rotate returns new token and revokes old", func(t *testing.T) {
		body := []byte(`{"group":"rotate-group"}`)
		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/rotate-tenant/rotate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.NotEmpty(t, resp.Token)
		assert.NotEqual(t, seed.Token, resp.Token, "rotated token must differ from seed")
		assert.Equal(t, "rotate-tenant", resp.TenantID)
		assert.Equal(t, "grpc://controller.example.com:7443", resp.ControllerURL)
		assert.Equal(t, "rotate-group", resp.Group)
		assert.False(t, resp.Revoked)

		// Old token must be revoked in the store
		old, err := tokenStore.GetToken(ctx, seed.Token)
		require.NoError(t, err)
		assert.True(t, old.Revoked, "seed token must be revoked after rotation")
	})

	t.Run("rotate with no active tokens returns 404", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/nonexistent-tenant/rotate", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/rotate-tenant/rotate", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestRegistrationTokenCRUDFlow(t *testing.T) {
	server, _ := setupTestServerWithTokenStore(t)

	var createdToken string

	// 1. Create a token (Tier-3: requires admin cert)
	t.Run("1_create_token", func(t *testing.T) {
		reqBody := registration.TokenCreateRequest{
			TenantID:      "crud-test-tenant",
			ControllerURL: "grpc://controller.example.com:7443",
			Group:         "crud-test-group",
			ExpiresIn:     "24h",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusCreated, rec.Code)

		var resp TokenResponse
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		createdToken = resp.Token
		assert.NotEmpty(t, createdToken)
	})

	// 2. List tokens and verify our token is included (Tier-1: admin cert still works)
	t.Run("2_list_tokens", func(t *testing.T) {
		req := makeAdminRequest(t, "GET", "/api/v1/registration/tokens?tenant_id=crud-test-tenant", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, resp.Total, 1)

		// After Issue #2932: list responses redact the token secret; match by TokenPrefix.
		wantPrefix := createdToken[:6]
		found := false
		for _, token := range resp.Tokens {
			if token.TokenPrefix == wantPrefix {
				found = true
				break
			}
		}
		assert.True(t, found, "Created token should be in the list (matched by token_prefix)")
	})

	// 3. Get specific token (Tier-1)
	t.Run("3_get_token", func(t *testing.T) {
		req := makeAdminRequest(t, "GET", "/api/v1/registration/tokens/"+createdToken, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		// After Issue #2932: GET redacts the token secret; verify via token_prefix.
		assert.Empty(t, resp.Token, "GET response must not include the raw token secret")
		assert.Equal(t, createdToken[:6], resp.TokenPrefix, "GET response must include the first 6 chars as token_prefix")
		assert.Equal(t, "crud-test-tenant", resp.TenantID)
		assert.Equal(t, "crud-test-group", resp.Group)
		assert.False(t, resp.Revoked)
	})

	// 4. Revoke the token (Tier-3)
	t.Run("4_revoke_token", func(t *testing.T) {
		req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/"+createdToken+"/revoke", nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Revoked)
	})

	// 5. Verify token is revoked when getting it again (Tier-1)
	t.Run("5_verify_revoked", func(t *testing.T) {
		req := makeAdminRequest(t, "GET", "/api/v1/registration/tokens/"+createdToken, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Revoked)
		assert.NotNil(t, resp.RevokedAt)
	})

	// 6. Delete the token (Tier-3)
	t.Run("6_delete_token", func(t *testing.T) {
		req := makeAdminRequest(t, "DELETE", "/api/v1/registration/tokens/"+createdToken, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
	})

	// 7. Verify token is deleted (Tier-1)
	t.Run("7_verify_deleted", func(t *testing.T) {
		req := makeAdminRequest(t, "GET", "/api/v1/registration/tokens/"+createdToken, nil)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestTokenResponseFormat(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	// Create a token with all fields populated.
	// Use the token's literal value as the raw secret (len >= 6 required for prefix check).
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	revokedAt := now.Add(2 * time.Hour)

	token := &registration.Token{
		Token:         "testformat123",
		TenantID:      "format-test-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "format-group",
		CreatedAt:     now,
		ExpiresAt:     &expiresAt,
		Revoked:       true,
		RevokedAt:     &revokedAt,
	}

	err := tokenStore.SaveToken(ctx, token)
	require.NoError(t, err)

	// Use an unscoped mTLS admin request: "format-test-tenant" is outside "test-tenant"
	// so a scoped API key would receive 404 after Issue #2932's tenant-scope enforcement.
	req := makeAdminRequest(t, "GET", "/api/v1/registration/tokens/"+token.Token, nil)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// After Issue #2932: GET redacts the token secret; token_prefix (first 6 chars) is returned.
	assert.Empty(t, resp.Token, "GET response must not include the raw token secret")
	assert.Equal(t, token.Token[:6], resp.TokenPrefix, "token_prefix should be the first 6 chars of the secret")
	assert.Equal(t, "format-test-tenant", resp.TenantID)
	assert.Equal(t, "grpc://controller.example.com:7443", resp.ControllerURL)
	assert.Equal(t, "format-group", resp.Group)
	assert.NotEmpty(t, resp.CreatedAt)
	assert.NotNil(t, resp.ExpiresAt)
	assert.True(t, resp.Revoked)
	assert.NotNil(t, resp.RevokedAt)

	// Verify timestamps are ISO 8601 format
	_, err = time.Parse(time.RFC3339, resp.CreatedAt)
	assert.NoError(t, err, "CreatedAt should be RFC3339 format")
}

// findAuditEntryByAction returns the first entry whose Action matches, or fails the test.
func findAuditEntryByAction(t *testing.T, entries []*business.AuditEntry, action string) *business.AuditEntry {
	t.Helper()
	for _, e := range entries {
		if e.Action == action {
			return e
		}
	}
	t.Fatalf("no audit entry with action %q found among %d entries", action, len(entries))
	return nil
}

// The four token-management mutation handlers (create, delete, revoke, rotate) each
// emit a durable audit event via emitTokenManagementAudit. These tests flush the audit
// manager and assert the event actually reaches the store with the correct action,
// tenant, and resource fields — mirroring the register-path assertions in
// handlers_registration_test.go.

func TestCreateRegistrationToken_EmitsAuditEvent(t *testing.T) {
	server, _ := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	reqBody := registration.TokenCreateRequest{
		TenantID:      "audit-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
	}
	body, err := json.Marshal(reqBody)
	require.NoError(t, err)

	req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Token)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "audit-tenant"})
	require.NoError(t, err)

	entry := findAuditEntryByAction(t, entries, "registration_token.created")
	assert.Equal(t, "audit-tenant", entry.TenantID)
	assert.Equal(t, "registration_token", entry.ResourceType)
	assert.Equal(t, resp.Token[:6], entry.ResourceID, "audit resource must record the token prefix")
	assert.Equal(t, resp.TokenID, entry.ResourceName, "audit resource name must record the stable token id")
	assert.NotContains(t, entry.ResourceName, resp.Token, "audit resource name must never contain the secret")
	assert.Equal(t, string(business.AuditEventSystemAccess), string(entry.EventType))
	assert.Equal(t, string(business.AuditResultSuccess), string(entry.Result))
}

func TestDeleteRegistrationToken_EmitsAuditEvent(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	token, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "audit-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, token))

	req := makeAdminRequest(t, "DELETE", "/api/v1/registration/tokens/"+token.Token, nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusNoContent, rec.Code)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "audit-tenant"})
	require.NoError(t, err)

	entry := findAuditEntryByAction(t, entries, "registration_token.deleted")
	assert.Equal(t, "audit-tenant", entry.TenantID)
	assert.Equal(t, "registration_token", entry.ResourceType)
	assert.Equal(t, token.Token[:6], entry.ResourceID, "audit resource must record the token prefix")
	assert.Equal(t, token.ID, entry.ResourceName, "audit resource name must record the stable token id")
	assert.NotContains(t, entry.ResourceName, token.Token, "audit resource name must never contain the secret")
	assert.Equal(t, string(business.AuditEventSystemAccess), string(entry.EventType))
	assert.Equal(t, string(business.AuditResultSuccess), string(entry.Result))
}

func TestRevokeRegistrationToken_EmitsAuditEvent(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	token, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "audit-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, token))

	req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/"+token.Token+"/revoke", nil)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "audit-tenant"})
	require.NoError(t, err)

	entry := findAuditEntryByAction(t, entries, "registration_token.revoked")
	assert.Equal(t, "audit-tenant", entry.TenantID)
	assert.Equal(t, "registration_token", entry.ResourceType)
	assert.Equal(t, token.Token[:6], entry.ResourceID, "audit resource must record the token prefix")
	assert.Equal(t, token.ID, entry.ResourceName, "audit resource name must record the stable token id")
	assert.NotContains(t, entry.ResourceName, token.Token, "audit resource name must never contain the secret")
	assert.Equal(t, string(business.AuditEventSystemAccess), string(entry.EventType))
	assert.Equal(t, string(business.AuditResultSuccess), string(entry.Result))
}

func TestRotateRegistrationToken_EmitsAuditEvent(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	seed, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "audit-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "rotate-group",
	})
	require.NoError(t, err)
	require.NoError(t, tokenStore.SaveToken(ctx, seed))

	body := []byte(`{"group":"rotate-group"}`)
	req := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/audit-tenant/rotate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var resp TokenResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.Token)

	require.NoError(t, server.auditManager.Flush(ctx))
	entries, err := server.auditManager.QueryEntries(ctx, &business.AuditFilter{TenantID: "audit-tenant"})
	require.NoError(t, err)

	entry := findAuditEntryByAction(t, entries, "registration_token.rotated")
	assert.Equal(t, "audit-tenant", entry.TenantID)
	assert.Equal(t, "registration_token", entry.ResourceType)
	assert.Equal(t, resp.Token[:6], entry.ResourceID, "audit resource must record the new token prefix")
	assert.Equal(t, resp.TokenID, entry.ResourceName, "audit resource name must record the stable token id")
	assert.NotContains(t, entry.ResourceName, resp.Token, "audit resource name must never contain the secret")
	assert.Equal(t, string(business.AuditEventSystemAccess), string(entry.EventType))
	assert.Equal(t, string(business.AuditResultSuccess), string(entry.Result))
}

// --- any-node service (Issue #3761, ADR-031 Decision 1) ---

// TestRegistrationTokenMutations_SucceedOnNonAuthoritativeNode is the [REQUIRED TEST] for
// this file: the four mutating registration-token handlers (create, delete, revoke,
// rotate) used to answer 503 on any node that held no lease-backed leadership. Any-node
// service means every cluster node serves them — the registration token store is the
// serialization point, not leadership. Driven against a real, deliberately
// non-authoritative *ha.Manager (ClusterMode, no lease ever acquired), create and revoke
// (the representative mint and state-change paths) must return their normal success codes
// and the mutation must be durable in the store.
func TestRegistrationTokenMutations_SucceedOnNonAuthoritativeNode(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)
	ctx := context.Background()

	server.haManager = newNonAuthoritativeHAManager(t)

	body, err := json.Marshal(registration.TokenCreateRequest{
		TenantID:      "nonauthoritative-tenant",
		ControllerURL: "grpc://controller.example.com:7443",
		Group:         "production",
		ExpiresIn:     "7d",
	})
	require.NoError(t, err)

	createReq := makeAdminRequest(t, "POST", "/api/v1/registration/tokens", bytes.NewReader(body))
	createReq.Header.Set("Content-Type", "application/json")
	createRec := httptest.NewRecorder()
	server.router.ServeHTTP(createRec, createReq)
	require.Equal(t, http.StatusCreated, createRec.Code, createRec.Body.String())

	var created TokenResponse
	require.NoError(t, json.Unmarshal(createRec.Body.Bytes(), &created))
	require.NotEmpty(t, created.Token)

	stored, err := tokenStore.GetToken(ctx, created.Token)
	require.NoError(t, err)
	require.NotNil(t, stored, "a non-authoritative node must persist the minted token")
	assert.Equal(t, "nonauthoritative-tenant", stored.TenantID)

	revokeReq := makeAdminRequest(t, "POST", "/api/v1/registration/tokens/"+created.Token+"/revoke", nil)
	revokeRec := httptest.NewRecorder()
	server.router.ServeHTTP(revokeRec, revokeReq)
	require.Equal(t, http.StatusOK, revokeRec.Code, revokeRec.Body.String())

	revoked, err := tokenStore.GetToken(ctx, created.Token)
	require.NoError(t, err)
	assert.True(t, revoked.Revoked, "the revocation must be durable on a non-authoritative node")
	assert.False(t, revoked.IsValid())
}
