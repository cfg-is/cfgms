// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/registration"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/providers/git"
)

// setupTestServerWithTokenStore creates a test server with a real registration token store
func setupTestServerWithTokenStore(t *testing.T) (*Server, registration.Store) {
	t.Helper()

	// Create test configuration
	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false // Disable for testing

	// Create test logger
	logger := logging.NewNoopLogger()

	// Create temporary directory for storage
	tempDir := t.TempDir()

	// Initialize RBAC system with git storage
	storageConfig := map[string]interface{}{
		"repository_path": tempDir,
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", storageConfig)
	require.NoError(t, err)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	err = rbacManager.Initialize(context.Background())
	require.NoError(t, err)

	// Initialize tenant management with durable storage
	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	// Create registration token store
	tokenStorePath, err := os.MkdirTemp("", "token-store-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(tokenStorePath) })

	gitTokenStore, err := git.NewGitRegistrationTokenStore(tokenStorePath, "")
	require.NoError(t, err)
	err = gitTokenStore.Initialize(context.Background())
	require.NoError(t, err)

	tokenStore := registration.NewStorageAdapter(gitTokenStore)

	// Create mock services
	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationService(logger, controllerService)
	rbacService := service.NewRBACService(rbacManager)

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
		nil, // No platform monitor for basic tests
		nil, // No tracer for basic tests
		nil, // No HA manager for basic tests
		tokenStore,
	)
	require.NoError(t, err)

	return server, tokenStore
}

func TestCreateRegistrationToken(t *testing.T) {
	server, _ := setupTestServerWithTokenStore(t)

	// Create API key with token creation permission
	apiKey := NewTestKey(t, server, []string{"registration:create-token"})

	t.Run("successful token creation", func(t *testing.T) {
		reqBody := TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
			Group:         "production",
			ExpiresIn:     "7d",
			SingleUse:     false,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
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
		assert.Equal(t, "mqtt://controller.example.com:8883", resp.ControllerURL)
		assert.Equal(t, "production", resp.Group)
		assert.False(t, resp.SingleUse)
		assert.NotNil(t, resp.ExpiresAt)
	})

	t.Run("single-use token creation", func(t *testing.T) {
		reqBody := TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
			SingleUse:     true,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code)

		var resp TokenResponse
		err = json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.SingleUse)
	})

	t.Run("missing tenant_id returns error", func(t *testing.T) {
		reqBody := TokenCreateRequest{
			ControllerURL: "mqtt://controller.example.com:8883",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "tenant_id")
	})

	t.Run("missing controller_url returns error", func(t *testing.T) {
		reqBody := TokenCreateRequest{
			TenantID: "test-tenant",
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "controller_url")
	})

	t.Run("invalid JSON returns error", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader([]byte("not json")))
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("unauthorized without API key", func(t *testing.T) {
		reqBody := TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
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

		reqBody := TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
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
			ControllerURL: "mqtt://controller.example.com:8883",
		})
		require.NoError(t, err)
		err = tokenStore.SaveToken(ctx, token)
		require.NoError(t, err)
	}

	// Create a token for a different tenant
	otherToken, err := registration.CreateToken(&registration.TokenCreateRequest{
		TenantID:      "other-tenant",
		ControllerURL: "mqtt://controller.example.com:8883",
	})
	require.NoError(t, err)
	err = tokenStore.SaveToken(ctx, otherToken)
	require.NoError(t, err)

	t.Run("list all tokens", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, 4, resp.Total)
		assert.Len(t, resp.Tokens, 4)
	})

	t.Run("filter by tenant_id", func(t *testing.T) {
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

	t.Run("filter returns empty for non-existent tenant", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens?tenant_id=nonexistent", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, 0, resp.Total)
		assert.Len(t, resp.Tokens, 0)
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
		ControllerURL: "mqtt://controller.example.com:8883",
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

		assert.Equal(t, token.Token, resp.Token)
		assert.Equal(t, "test-tenant", resp.TenantID)
		assert.Equal(t, "mqtt://controller.example.com:8883", resp.ControllerURL)
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

	// Create API key with delete permission
	apiKey := NewTestKey(t, server, []string{"registration:delete-token"})
	ctx := context.Background()

	t.Run("delete existing token", func(t *testing.T) {
		// Create a test token
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
		})
		require.NoError(t, err)
		err = tokenStore.SaveToken(ctx, token)
		require.NoError(t, err)

		req := httptest.NewRequest("DELETE", "/api/v1/registration/tokens/"+token.Token, nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)

		// Verify token is deleted
		_, err = tokenStore.GetToken(ctx, token.Token)
		assert.Error(t, err)
	})

	t.Run("delete non-existent token returns 404", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/registration/tokens/nonexistent-token", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
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

	// Create API key with revoke permission
	apiKey := NewTestKey(t, server, []string{"registration:revoke-token"})
	ctx := context.Background()

	t.Run("revoke existing token", func(t *testing.T) {
		// Create a test token
		token, err := registration.CreateToken(&registration.TokenCreateRequest{
			TenantID:      "test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
		})
		require.NoError(t, err)
		err = tokenStore.SaveToken(ctx, token)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/"+token.Token+"/revoke", nil)
		req.Header.Set("X-API-Key", apiKey)
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

	t.Run("revoke non-existent token returns 404", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/nonexistent-token/revoke", nil)
		req.Header.Set("X-API-Key", apiKey)
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

func TestRegistrationTokenCRUDFlow(t *testing.T) {
	server, _ := setupTestServerWithTokenStore(t)

	// Create API key with all token permissions
	apiKey := NewTestKey(t, server, []string{
		"registration:create-token",
		"registration:list-tokens",
		"registration:read-token",
		"registration:revoke-token",
		"registration:delete-token",
	})

	var createdToken string

	// 1. Create a token
	t.Run("1_create_token", func(t *testing.T) {
		reqBody := TokenCreateRequest{
			TenantID:      "crud-test-tenant",
			ControllerURL: "mqtt://controller.example.com:8883",
			Group:         "crud-test-group",
			ExpiresIn:     "24h",
			SingleUse:     false,
		}

		body, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/registration/tokens", bytes.NewReader(body))
		req.Header.Set("X-API-Key", apiKey)
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

	// 2. List tokens and verify our token is included
	t.Run("2_list_tokens", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens?tenant_id=crud-test-tenant", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenListResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.GreaterOrEqual(t, resp.Total, 1)

		found := false
		for _, token := range resp.Tokens {
			if token.Token == createdToken {
				found = true
				break
			}
		}
		assert.True(t, found, "Created token should be in the list")
	})

	// 3. Get specific token
	t.Run("3_get_token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+createdToken, nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.Equal(t, createdToken, resp.Token)
		assert.Equal(t, "crud-test-tenant", resp.TenantID)
		assert.Equal(t, "crud-test-group", resp.Group)
		assert.False(t, resp.Revoked)
	})

	// 4. Revoke the token
	t.Run("4_revoke_token", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/registration/tokens/"+createdToken+"/revoke", nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Revoked)
	})

	// 5. Verify token is revoked when getting it again
	t.Run("5_verify_revoked", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+createdToken, nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)

		var resp TokenResponse
		err := json.Unmarshal(rec.Body.Bytes(), &resp)
		require.NoError(t, err)

		assert.True(t, resp.Revoked)
		assert.NotNil(t, resp.RevokedAt)
	})

	// 6. Delete the token
	t.Run("6_delete_token", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/registration/tokens/"+createdToken, nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		require.Equal(t, http.StatusNoContent, rec.Code)
	})

	// 7. Verify token is deleted
	t.Run("7_verify_deleted", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+createdToken, nil)
		req.Header.Set("X-API-Key", apiKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestTokenResponseFormat(t *testing.T) {
	server, tokenStore := setupTestServerWithTokenStore(t)

	// Create API key with read permission
	apiKey := NewTestKey(t, server, []string{"registration:read-token"})
	ctx := context.Background()

	// Create a token with all fields populated
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)
	usedAt := now.Add(1 * time.Hour)
	revokedAt := now.Add(2 * time.Hour)

	token := &registration.Token{
		Token:         "cfgms_reg_testformat123",
		TenantID:      "format-test-tenant",
		ControllerURL: "mqtt://controller.example.com:8883",
		Group:         "format-group",
		CreatedAt:     now,
		ExpiresAt:     &expiresAt,
		SingleUse:     true,
		UsedAt:        &usedAt,
		UsedBy:        "steward-001",
		Revoked:       true,
		RevokedAt:     &revokedAt,
	}

	err := tokenStore.SaveToken(ctx, token)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/api/v1/registration/tokens/"+token.Token, nil)
	req.Header.Set("X-API-Key", apiKey)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var resp TokenResponse
	err = json.Unmarshal(rec.Body.Bytes(), &resp)
	require.NoError(t, err)

	// Verify all fields are present and correctly formatted
	assert.Equal(t, "cfgms_reg_testformat123", resp.Token)
	assert.Equal(t, "format-test-tenant", resp.TenantID)
	assert.Equal(t, "mqtt://controller.example.com:8883", resp.ControllerURL)
	assert.Equal(t, "format-group", resp.Group)
	assert.NotEmpty(t, resp.CreatedAt)
	assert.NotNil(t, resp.ExpiresAt)
	assert.True(t, resp.SingleUse)
	assert.NotNil(t, resp.UsedAt)
	assert.Equal(t, "steward-001", resp.UsedBy)
	assert.True(t, resp.Revoked)
	assert.NotNil(t, resp.RevokedAt)

	// Verify timestamps are ISO 8601 format
	_, err = time.Parse(time.RFC3339, resp.CreatedAt)
	assert.NoError(t, err, "CreatedAt should be RFC3339 format")
}
