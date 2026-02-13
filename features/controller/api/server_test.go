// SPDX-License-Identifier: Apache-2.0
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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/config"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"

	// Import storage providers for testing
	_ "github.com/cfgis/cfgms/pkg/storage/providers/git"
)

func setupTestServer(t *testing.T) *Server {
	// Create test configuration
	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false // Disable for testing

	// Create test logger
	logger := logging.NewNoopLogger()

	// Initialize RBAC system with git storage
	config := map[string]interface{}{
		"repository_path": t.TempDir(),
		"branch":          "main",
		"auto_init":       true,
	}
	storageManager, err := interfaces.CreateAllStoresFromConfig("git", config)
	require.NoError(t, err)

	rbacManager := rbac.NewManagerWithStorage(
		storageManager.GetAuditStore(),
		storageManager.GetClientTenantStore(),
		storageManager.GetRBACStore(),
	)
	err = rbacManager.Initialize(context.Background())
	require.NoError(t, err)

	// Initialize tenant management with durable storage (git-backed)
	tenantStore := tenant.NewStorageAdapter(storageManager.GetTenantStore())
	tenantManager := tenant.NewManager(tenantStore, rbacManager)

	// Create mock services
	controllerService := service.NewControllerService(logger)
	configService := service.NewConfigurationService(logger, controllerService)
	rbacService := service.NewRBACService(rbacManager)

	// Create REST API server
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
		nil, // No registration token store for basic tests
		"",  // No signer cert serial for basic tests
	)
	require.NoError(t, err)

	return server
}

// NewEphemeralTestKey creates a short-lived API key for test scenarios
func NewEphemeralTestKey(t *testing.T, server *Server, permissions []string, tenantID string, ttl time.Duration) string {
	t.Helper()

	// Generate ephemeral test key
	apiKey, err := server.generateEphemeralKey(
		"Test Key "+time.Now().Format("15:04:05.999"),
		permissions,
		ttl,
		tenantID,
	)
	require.NoError(t, err, "Failed to generate ephemeral test key")

	t.Cleanup(func() {
		// Clean up the key when test ends
		server.mu.Lock()
		delete(server.apiKeys, apiKey.Key)
		server.mu.Unlock()
	})

	return apiKey.Key
}

// NewTestKey creates a 5-minute ephemeral API key for standard test scenarios
func NewTestKey(t *testing.T, server *Server, permissions []string) string {
	t.Helper()
	return NewEphemeralTestKey(t, server, permissions, "test-tenant", 5*time.Minute)
}

// NewJITTestKey creates a 1-hour ephemeral API key for JIT test scenarios
func NewJITTestKey(t *testing.T, server *Server, permissions []string) string {
	t.Helper()
	return NewEphemeralTestKey(t, server, permissions, "test-tenant", 1*time.Hour)
}

func TestHealthEndpoint(t *testing.T) {
	server := setupTestServer(t)

	// Create request
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	// Execute request
	server.router.ServeHTTP(rec, req)

	// Check response
	assert.Equal(t, http.StatusOK, rec.Code)

	var response APIResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check health status
	healthData, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "healthy", healthData["status"])
	assert.Contains(t, healthData, "services")
}

func TestAPIKeyAuthentication(t *testing.T) {
	server := setupTestServer(t)

	// Use ephemeral key for valid authentication tests (more secure)
	validAPIKey := NewTestKey(t, server, []string{"steward:list"})

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "Valid API key in X-API-Key header",
			headers:        map[string]string{"X-API-Key": validAPIKey},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid API key in Authorization header",
			headers:        map[string]string{"Authorization": "Bearer " + validAPIKey},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Missing API key",
			headers:        map[string]string{},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "Invalid API key",
			headers:        map[string]string{"X-API-Key": "invalid-key"},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			rec := httptest.NewRecorder()

			server.router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code)
		})
	}
}

func TestListStewards(t *testing.T) {
	server := setupTestServer(t)

	// Use ephemeral key for steward list operations (more secure)
	stewardAPIKey := NewTestKey(t, server, []string{"steward:list"})

	t.Run("empty list", func(t *testing.T) {
		// Create request with authentication
		req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
		req.Header.Set("X-API-Key", stewardAPIKey)
		rec := httptest.NewRecorder()

		// Execute request
		server.router.ServeHTTP(rec, req)

		// Check response
		assert.Equal(t, http.StatusOK, rec.Code)

		var response APIResponse
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		// Should return empty list initially
		stewards, ok := response.Data.([]interface{})
		require.True(t, ok)
		assert.Len(t, stewards, 0)
	})

	t.Run("list format validation", func(t *testing.T) {
		// Test that the endpoint returns proper format even with empty data
		req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
		req.Header.Set("X-API-Key", stewardAPIKey)
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

		// Validate response structure
		var response APIResponse
		err := json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.NotNil(t, response.Data)
		assert.NotEmpty(t, response.Timestamp)
	})
}

func TestAPIKeyManagement(t *testing.T) {
	server := setupTestServer(t)

	// Use ephemeral key for API key management (more secure for testing)
	adminAPIKey := NewTestKey(t, server, []string{"api-key:create", "api-key:list"})

	// Test creating a new API key
	createReq := APIKeyCreateRequest{
		Name:        "Test Key",
		Permissions: []string{"stewards:read"},
		TenantID:    "test-tenant",
	}

	reqBody, err := json.Marshal(createReq)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader(reqBody))
	req.Header.Set("X-API-Key", adminAPIKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusCreated, rec.Code)

	var response APIResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check created key data
	keyData, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "Test Key", keyData["name"])
	assert.Contains(t, keyData, "key") // Should include the actual key on creation
	assert.Contains(t, keyData, "id")

	// Test listing API keys
	req = httptest.NewRequest("GET", "/api/v1/api-keys", nil)
	req.Header.Set("X-API-Key", adminAPIKey)
	rec = httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	// Should return list with at least the created key
	keys, ok := response.Data.([]interface{})
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(keys), 1)
}

func TestCORSHeaders(t *testing.T) {
	server := setupTestServer(t)

	// H-AUTH-3: Test CORS with allowed origin (security audit finding)
	t.Run("allowed origin returns correct CORS headers", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
		req.Header.Set("Origin", "http://localhost:3000") // Default allowed origin
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "http://localhost:3000", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "GET")
		assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "X-API-Key")
	})

	// H-AUTH-3: Test CORS with disallowed origin (security audit finding)
	t.Run("disallowed origin is rejected", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
		req.Header.Set("Origin", "https://evil.com")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Methods"))
	})

	// H-AUTH-3: Test request without origin header
	t.Run("request without origin header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		// No Origin header
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestConfigurationValidation(t *testing.T) {
	server := setupTestServer(t)

	// Use ephemeral key for configuration validation (more secure)
	configAPIKey := NewTestKey(t, server, []string{"steward:validate-config"})

	// Test configuration validation
	validationReq := ConfigValidationRequest{
		Config: map[string]interface{}{
			"test_module": map[string]interface{}{
				"setting1": "value1",
				"setting2": 42,
			},
		},
		Version: "1.0.0",
	}

	reqBody, err := json.Marshal(validationReq)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/api/v1/stewards/test-steward/config/validate", bytes.NewReader(reqBody))
	req.Header.Set("X-API-Key", configAPIKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	// Should return validation result (even if service is mock)
	assert.Equal(t, http.StatusOK, rec.Code)

	var response APIResponse
	err = json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check validation result structure
	validationData, ok := response.Data.(map[string]interface{})
	require.True(t, ok)
	assert.Contains(t, validationData, "valid")
}

func TestErrorResponses(t *testing.T) {
	server := setupTestServer(t)

	// Use ephemeral keys for error response testing (more secure)
	apiKeyCreateKey := NewTestKey(t, server, []string{"api-key:create"})
	stewardReadKey := NewTestKey(t, server, []string{"steward:read"})

	// Test invalid JSON
	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("X-API-Key", apiKeyCreateKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)

	var errorResponse ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &errorResponse)
	require.NoError(t, err)
	assert.Equal(t, "INVALID_JSON", errorResponse.Error.Code)

	// Test not found
	req = httptest.NewRequest("GET", "/api/v1/stewards/nonexistent", nil)
	req.Header.Set("X-API-Key", stewardReadKey)
	rec = httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestPermissionDenial specifically tests that insufficient permissions are correctly denied
func TestPermissionDenial(t *testing.T) {
	server := setupTestServer(t)

	tests := []struct {
		name           string
		endpoint       string
		method         string
		permissions    []string
		expectedStatus int
		body           []byte
	}{
		{
			name:           "Insufficient permissions for steward list",
			endpoint:       "/api/v1/stewards",
			method:         "GET",
			permissions:    []string{"api-key:read"}, // Wrong permission
			expectedStatus: http.StatusForbidden,
		},
		{
			name:           "Insufficient permissions for API key creation",
			endpoint:       "/api/v1/api-keys",
			method:         "POST",
			permissions:    []string{"steward:list"}, // Wrong permission
			expectedStatus: http.StatusForbidden,
			body:           []byte(`{"name":"Test","permissions":["test"],"tenant_id":"test"}`),
		},
		{
			name:           "Insufficient permissions for config validation",
			endpoint:       "/api/v1/stewards/test/config/validate",
			method:         "POST",
			permissions:    []string{"steward:list"}, // Wrong permission
			expectedStatus: http.StatusForbidden,
			body:           []byte(`{"config":{},"version":"1.0.0"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create key with insufficient permissions
			insufficientKey := NewTestKey(t, server, tt.permissions)

			var req *http.Request
			if tt.body != nil {
				req = httptest.NewRequest(tt.method, tt.endpoint, bytes.NewReader(tt.body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req = httptest.NewRequest(tt.method, tt.endpoint, nil)
			}
			req.Header.Set("X-API-Key", insufficientKey)
			rec := httptest.NewRecorder()

			server.router.ServeHTTP(rec, req)

			assert.Equal(t, tt.expectedStatus, rec.Code, "Should be denied for insufficient permissions")

			if rec.Code == http.StatusForbidden {
				var errorResponse ErrorResponse
				err := json.Unmarshal(rec.Body.Bytes(), &errorResponse)
				require.NoError(t, err)
				assert.Contains(t, errorResponse.Error.Code, "INSUFFICIENT_PERMISSIONS")
			}
		})
	}
}

// TestActualAPIFunctionality tests that APIs work correctly with proper permissions (not just permission failures)
func TestActualAPIFunctionality(t *testing.T) {
	server := setupTestServer(t)

	t.Run("API Key CRUD operations work with proper permissions", func(t *testing.T) {
		// Use proper admin permissions for full API key management
		adminKey := NewTestKey(t, server, []string{"api-key:create", "api-key:list", "api-key:read", "api-key:delete"})

		// 1. Create a new API key
		createReq := APIKeyCreateRequest{
			Name:        "Functional Test Key",
			Permissions: []string{"steward:list"},
			TenantID:    "func-test-tenant",
		}

		reqBody, err := json.Marshal(createReq)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader(reqBody))
		req.Header.Set("X-API-Key", adminKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusCreated, rec.Code, "API key creation should succeed with proper permissions")

		var createResponse APIResponse
		err = json.Unmarshal(rec.Body.Bytes(), &createResponse)
		require.NoError(t, err)

		keyData, ok := createResponse.Data.(map[string]interface{})
		require.True(t, ok)
		createdKeyID := keyData["id"].(string)
		actualKey := keyData["key"].(string)

		// 2. Verify the created key actually works for its intended purpose
		req = httptest.NewRequest("GET", "/api/v1/stewards", nil)
		req.Header.Set("X-API-Key", actualKey)
		rec = httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "New API key should work for steward:list")

		// 3. List API keys should include the created key
		req = httptest.NewRequest("GET", "/api/v1/api-keys", nil)
		req.Header.Set("X-API-Key", adminKey)
		rec = httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Listing API keys should work")
		var listResponse APIResponse
		err = json.Unmarshal(rec.Body.Bytes(), &listResponse)
		require.NoError(t, err)

		keys, ok := listResponse.Data.([]interface{})
		require.True(t, ok)
		assert.GreaterOrEqual(t, len(keys), 1, "Should have at least one key")

		// 4. Get specific API key by ID
		req = httptest.NewRequest("GET", "/api/v1/api-keys/"+createdKeyID, nil)
		req.Header.Set("X-API-Key", adminKey)
		rec = httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Get API key by ID should work")
		var getResponse APIResponse
		err = json.Unmarshal(rec.Body.Bytes(), &getResponse)
		require.NoError(t, err)

		keyDetails, ok := getResponse.Data.(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, "Functional Test Key", keyDetails["name"])

		// 5. Delete the API key
		req = httptest.NewRequest("DELETE", "/api/v1/api-keys/"+createdKeyID, nil)
		req.Header.Set("X-API-Key", adminKey)
		rec = httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "API key deletion should work")

		// 6. Verify deleted key no longer works
		req = httptest.NewRequest("GET", "/api/v1/stewards", nil)
		req.Header.Set("X-API-Key", actualKey)
		rec = httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "Deleted API key should no longer work")
	})

	t.Run("Configuration validation works with proper permissions", func(t *testing.T) {
		configKey := NewTestKey(t, server, []string{"steward:validate-config"})

		validationReq := ConfigValidationRequest{
			Config: map[string]interface{}{
				"file": map[string]interface{}{
					"path":    "/tmp/test.txt",
					"content": "test content",
					"mode":    "0644",
				},
			},
			Version: "1.0.0",
		}

		reqBody, err := json.Marshal(validationReq)
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/api/v1/stewards/test-steward/config/validate", bytes.NewReader(reqBody))
		req.Header.Set("X-API-Key", configKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		server.router.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code, "Config validation should work with proper permissions")

		var response APIResponse
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		require.NoError(t, err)

		validationData, ok := response.Data.(map[string]interface{})
		require.True(t, ok)
		assert.Contains(t, validationData, "valid", "Validation response should contain 'valid' field")
	})

	t.Run("Cross-permission functionality isolation", func(t *testing.T) {
		// Create key with only steward:list permission
		stewardKey := NewTestKey(t, server, []string{"steward:list"})

		// Should work for steward endpoints
		req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
		req.Header.Set("X-API-Key", stewardKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "Steward key should work for steward endpoints")

		// Should be denied for API key endpoints (different permission)
		req = httptest.NewRequest("GET", "/api/v1/api-keys", nil)
		req.Header.Set("X-API-Key", stewardKey)
		rec = httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "Steward key should be denied for API key endpoints")
	})
}

func TestResponseFormat(t *testing.T) {
	server := setupTestServer(t)

	// Test health endpoint response format
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var response APIResponse
	err := json.Unmarshal(rec.Body.Bytes(), &response)
	require.NoError(t, err)

	// Check response structure
	assert.NotNil(t, response.Data)
	assert.False(t, response.Timestamp.IsZero())
}

func TestAPIKeyExpiration(t *testing.T) {
	server := setupTestServer(t)

	// Create an expired API key
	expiredTime := time.Now().Add(-1 * time.Hour)
	expiredKey := &APIKey{
		ID:          "expired-key",
		Key:         "expired-test-key",
		Name:        "Expired Key",
		Permissions: []string{"test"},
		CreatedAt:   time.Now().Add(-2 * time.Hour),
		ExpiresAt:   &expiredTime,
		TenantID:    "test",
	}

	server.mu.Lock()
	server.apiKeys[expiredKey.Key] = expiredKey
	server.mu.Unlock()

	// Try to use expired key
	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", expiredKey.Key)
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	var errorResponse ErrorResponse
	err := json.Unmarshal(rec.Body.Bytes(), &errorResponse)
	require.NoError(t, err)
	assert.Equal(t, "EXPIRED_API_KEY", errorResponse.Error.Code)
}

func TestEphemeralAPIKeys(t *testing.T) {
	server := setupTestServer(t)

	t.Run("create ephemeral key with TTL", func(t *testing.T) {
		permissions := []string{"steward:list"} // Correct permission for /api/v1/stewards endpoint

		// Create ephemeral key with 1 minute TTL
		ephemeralKey := NewEphemeralTestKey(t, server, permissions, "test-tenant", 1*time.Minute)

		// Verify key works immediately
		req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
		req.Header.Set("X-API-Key", ephemeralKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "Ephemeral key should work immediately")

		// Verify key has expiration set
		server.mu.RLock()
		keyInfo, exists := server.apiKeys[ephemeralKey]
		server.mu.RUnlock()

		require.True(t, exists, "Ephemeral key should exist")
		require.NotNil(t, keyInfo.ExpiresAt, "Ephemeral key should have expiration")
		assert.True(t, keyInfo.ExpiresAt.After(time.Now()), "Key should not be expired yet")
		assert.True(t, keyInfo.ExpiresAt.Before(time.Now().Add(2*time.Minute)), "Key should expire within TTL")
	})

	t.Run("test key convenience function", func(t *testing.T) {
		permissions := []string{"api-key:list"} // Correct permission for /api/v1/api-keys endpoint

		// Use convenience function for 5-minute test key
		testKey := NewTestKey(t, server, permissions)

		// Verify it works
		req := httptest.NewRequest("GET", "/api/v1/api-keys", nil)
		req.Header.Set("X-API-Key", testKey)
		rec := httptest.NewRecorder()
		server.router.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "Test key should work")
	})

	t.Run("JIT key convenience function", func(t *testing.T) {
		permissions := []string{"stewards:execute-scripts"}

		// Use convenience function for 1-hour JIT key
		jitKey := NewJITTestKey(t, server, permissions)

		// Verify key has 1-hour TTL
		server.mu.RLock()
		keyInfo, exists := server.apiKeys[jitKey]
		server.mu.RUnlock()

		require.True(t, exists, "JIT key should exist")
		require.NotNil(t, keyInfo.ExpiresAt, "JIT key should have expiration")

		// Should expire in approximately 1 hour (within 10 seconds tolerance for CI)
		expectedExpiry := time.Now().Add(1 * time.Hour)
		assert.WithinDuration(t, expectedExpiry, *keyInfo.ExpiresAt, 10*time.Second)
	})

	t.Run("automatic cleanup removes expired keys", func(t *testing.T) {
		// Create a key that expires in 1 second
		ephemeralKey := NewEphemeralTestKey(t, server, []string{"test"}, "test", 1*time.Second)

		// Verify key exists
		server.mu.RLock()
		_, exists := server.apiKeys[ephemeralKey]
		server.mu.RUnlock()
		require.True(t, exists, "Key should exist initially")

		// Wait for key to expire
		time.Sleep(2 * time.Second)

		// Manually trigger cleanup (normally happens every 10 minutes)
		server.cleanupExpiredAPIKeys()

		// Verify key is cleaned up
		server.mu.RLock()
		_, exists = server.apiKeys[ephemeralKey]
		server.mu.RUnlock()
		assert.False(t, exists, "Expired key should be cleaned up")
	})

	t.Run("helper functions generate different keys", func(t *testing.T) {
		permissions := []string{"test"}

		// Generate multiple keys
		key1 := NewTestKey(t, server, permissions)
		key2 := NewTestKey(t, server, permissions)
		key3 := NewJITTestKey(t, server, permissions)

		// All keys should be different
		assert.NotEqual(t, key1, key2, "Each test key should be unique")
		assert.NotEqual(t, key1, key3, "Test and JIT keys should be different")
		assert.NotEqual(t, key2, key3, "Each key should be unique")

		// All should work
		for i, key := range []string{key1, key2, key3} {
			req := httptest.NewRequest("GET", "/api/v1/health", nil)
			req.Header.Set("X-API-Key", key)
			rec := httptest.NewRecorder()
			server.router.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "Key %d should work", i+1)
		}
	})
}
