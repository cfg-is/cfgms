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
	tenantmemory "github.com/cfgis/cfgms/features/tenant/memory"
	"github.com/cfgis/cfgms/pkg/logging"
)

func setupTestServer(t *testing.T) (*Server, string) {
	// Create test configuration
	cfg := config.DefaultConfig()
	cfg.Certificate.EnableCertManagement = false // Disable for testing

	// Create test logger
	logger := logging.NewNoopLogger()

	// Initialize RBAC system
	rbacManager := rbac.NewManager()
	require.NoError(t, rbacManager.Initialize(context.Background()))

	// Initialize tenant management
	tenantStore := tenantmemory.NewStore()
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
	)
	require.NoError(t, err)

	// Get the default API key for testing
	server.mu.RLock()
	var testAPIKey string
	for key := range server.apiKeys {
		testAPIKey = key
		break
	}
	server.mu.RUnlock()

	require.NotEmpty(t, testAPIKey, "Test API key should be generated")

	return server, testAPIKey
}

func TestHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)

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
	server, apiKey := setupTestServer(t)

	tests := []struct {
		name           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:           "Valid API key in X-API-Key header",
			headers:        map[string]string{"X-API-Key": apiKey},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Valid API key in Authorization header",
			headers:        map[string]string{"Authorization": "Bearer " + apiKey},
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
	server, apiKey := setupTestServer(t)

	// Create request with authentication
	req := httptest.NewRequest("GET", "/api/v1/stewards", nil)
	req.Header.Set("X-API-Key", apiKey)
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
}

func TestAPIKeyManagement(t *testing.T) {
	server, adminAPIKey := setupTestServer(t)

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
	server, _ := setupTestServer(t)

	// Test OPTIONS request (preflight)
	req := httptest.NewRequest("OPTIONS", "/api/v1/health", nil)
	req.Header.Set("Origin", "https://example.com")
	rec := httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, rec.Header().Get("Access-Control-Allow-Headers"), "X-API-Key")
}

func TestConfigurationValidation(t *testing.T) {
	server, apiKey := setupTestServer(t)

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
	req.Header.Set("X-API-Key", apiKey)
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
	server, apiKey := setupTestServer(t)

	// Test invalid JSON
	req := httptest.NewRequest("POST", "/api/v1/api-keys", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("X-API-Key", apiKey)
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
	req.Header.Set("X-API-Key", apiKey)
	rec = httptest.NewRecorder()

	server.router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestResponseFormat(t *testing.T) {
	server, _ := setupTestServer(t)

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
	server, _ := setupTestServer(t)

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
