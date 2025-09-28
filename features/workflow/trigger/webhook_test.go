package trigger

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)


func TestHTTPWebhookHandler_NewHTTPWebhookHandler(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	assert.NotNil(t, handler)
	assert.Equal(t, "localhost", handler.address)
	assert.Equal(t, 8080, handler.port)
	assert.NotNil(t, handler.router)
	assert.NotNil(t, handler.webhooks)
	assert.NotNil(t, handler.rateLimiters)
	assert.False(t, handler.running)
}

func TestHTTPWebhookHandler_RegisterWebhook(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	tests := []struct {
		name        string
		trigger     *Trigger
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid webhook trigger",
			trigger: &Trigger{
				ID:   "webhook-1",
				Type: TriggerTypeWebhook,
				Webhook: &WebhookConfig{
					Path:    "/webhook/test",
					Method:  []string{"POST"},
					Enabled: true,
				},
			},
			expectError: false,
		},
		{
			name: "webhook trigger with rate limit",
			trigger: &Trigger{
				ID:   "webhook-2",
				Type: TriggerTypeWebhook,
				Webhook: &WebhookConfig{
					Path:    "/webhook/ratelimited",
					Method:  []string{"POST"},
					Enabled: true,
					RateLimit: &WebhookRateLimit{
						RequestsPerMinute: 60,
						BurstSize:         10,
					},
				},
			},
			expectError: false,
		},
		{
			name: "non-webhook trigger",
			trigger: &Trigger{
				ID:   "schedule-1",
				Type: TriggerTypeSchedule,
			},
			expectError: true,
			errorMsg:    "trigger schedule-1 is not a webhook trigger",
		},
		{
			name: "webhook trigger without config",
			trigger: &Trigger{
				ID:      "webhook-3",
				Type:    TriggerTypeWebhook,
				Webhook: nil,
			},
			expectError: true,
			errorMsg:    "trigger webhook-3 is not a webhook trigger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := handler.RegisterWebhook(ctx, tt.trigger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, handler.webhooks, tt.trigger.ID)
				if tt.trigger.Webhook.RateLimit != nil {
					assert.Contains(t, handler.rateLimiters, tt.trigger.ID)
				}
			}
		})
	}
}

func TestHTTPWebhookHandler_UnregisterWebhook(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	// Register a webhook first
	trigger := &Trigger{
		ID:   "webhook-1",
		Type: TriggerTypeWebhook,
		Webhook: &WebhookConfig{
			Path:    "/webhook/test",
			Enabled: true,
		},
	}
	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		triggerID   string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "unregister existing webhook",
			triggerID:   "webhook-1",
			expectError: false,
		},
		{
			name:        "unregister non-existent webhook",
			triggerID:   "webhook-999",
			expectError: true,
			errorMsg:    "webhook trigger webhook-999 is not registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.UnregisterWebhook(ctx, tt.triggerID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.NotContains(t, handler.webhooks, tt.triggerID)
			}
		})
	}
}

func TestHTTPWebhookHandler_AuthenticateRequest(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name        string
		webhook     *WebhookConfig
		payload     []byte
		headers     map[string]string
		expectError bool
		errorMsg    string
	}{
		{
			name: "no authentication",
			webhook: &WebhookConfig{
				Authentication: nil,
			},
			expectError: false,
		},
		{
			name: "none authentication",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type: WebhookAuthNone,
				},
			},
			expectError: false,
		},
		{
			name: "valid HMAC authentication",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:            WebhookAuthHMAC,
					Secret:          "secret-key",
					SignatureHeader: "X-Signature-256",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-Signature-256": generateHMACSignature("secret-key", []byte(`{"test": "data"}`)),
			},
			expectError: false,
		},
		{
			name: "invalid HMAC signature",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:            WebhookAuthHMAC,
					Secret:          "secret-key",
					SignatureHeader: "X-Signature-256",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-Signature-256": "invalid-signature",
			},
			expectError: true,
			errorMsg:    "HMAC signature validation failed",
		},
		{
			name: "missing HMAC signature header",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:            WebhookAuthHMAC,
					Secret:          "secret-key",
					SignatureHeader: "X-Signature-256",
				},
			},
			payload:     []byte(`{"test": "data"}`),
			headers:     map[string]string{},
			expectError: true,
			errorMsg:    "signature header X-Signature-256 not found",
		},
		{
			name: "valid API key authentication",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:         WebhookAuthAPIKey,
					APIKey:       "valid-api-key",
					APIKeyHeader: "X-API-Key",
				},
			},
			headers: map[string]string{
				"X-API-Key": "valid-api-key",
			},
			expectError: false,
		},
		{
			name: "invalid API key",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:         WebhookAuthAPIKey,
					APIKey:       "valid-api-key",
					APIKeyHeader: "X-API-Key",
				},
			},
			headers: map[string]string{
				"X-API-Key": "invalid-api-key",
			},
			expectError: true,
			errorMsg:    "invalid API key",
		},
		{
			name: "valid Bearer token authentication",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:        WebhookAuthBearer,
					BearerToken: "valid-bearer-token",
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer valid-bearer-token",
			},
			expectError: false,
		},
		{
			name: "invalid Bearer token",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:        WebhookAuthBearer,
					BearerToken: "valid-bearer-token",
				},
			},
			headers: map[string]string{
				"Authorization": "Bearer invalid-bearer-token",
			},
			expectError: true,
			errorMsg:    "invalid Bearer token",
		},
		{
			name: "unsupported authentication type",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type: WebhookAuthType("unsupported"),
				},
			},
			expectError: true,
			errorMsg:    "unsupported authentication type: unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.authenticateRequest(tt.webhook, tt.payload, tt.headers)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTPWebhookHandler_ValidatePayload(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name        string
		webhook     *WebhookConfig
		payload     []byte
		expectError bool
		errorMsg    string
	}{
		{
			name: "no validation config",
			webhook: &WebhookConfig{
				PayloadValidation: nil,
			},
			payload:     []byte(`{"test": "data"}`),
			expectError: false,
		},
		{
			name: "valid payload size",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					MaxSize: 1024,
				},
			},
			payload:     []byte(`{"test": "data"}`),
			expectError: false,
		},
		{
			name: "payload too large",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					MaxSize: 10,
				},
			},
			payload:     []byte(`{"test": "data with more content"}`),
			expectError: true,
			errorMsg:    "payload size",
		},
		{
			name: "valid JSON with required fields",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"id", "type"},
				},
			},
			payload:     []byte(`{"id": "123", "type": "event", "data": "test"}`),
			expectError: false,
		},
		{
			name: "missing required field",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"id", "type"},
				},
			},
			payload:     []byte(`{"id": "123", "data": "test"}`),
			expectError: true,
			errorMsg:    "required field type is missing",
		},
		{
			name: "invalid JSON payload",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"id"},
				},
			},
			payload:     []byte(`{"invalid": json}`),
			expectError: true,
			errorMsg:    "cannot validate required fields: payload is not valid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validatePayload(tt.webhook, tt.payload)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHTTPWebhookHandler_MapPayloadToVariables(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name             string
		trigger          *Trigger
		payload          []byte
		headers          map[string]string
		expectedVars     map[string]interface{}
		expectError      bool
	}{
		{
			name: "JSON payload with mapping",
			trigger: &Trigger{
				Variables: map[string]interface{}{
					"default_var": "default_value",
				},
				Webhook: &WebhookConfig{
					PayloadMapping: map[string]string{
						"event_id":   "id",
						"event_type": "type",
					},
				},
			},
			payload: []byte(`{"id": "evt_123", "type": "user.created", "timestamp": "2023-01-01T00:00:00Z"}`),
			headers: map[string]string{
				"Content-Type": "application/json",
				"X-Source":     "webhook",
			},
			expectedVars: map[string]interface{}{
				"default_var":       "default_value",
				"event_id":          "evt_123",
				"event_type":        "user.created",
				"header_content-type": "application/json",
				"header_x-source":   "webhook",
			},
			expectError: false,
		},
		{
			name: "JSON payload without mapping",
			trigger: &Trigger{
				Webhook: &WebhookConfig{},
			},
			payload: []byte(`{"id": "evt_123", "type": "user.created"}`),
			headers: map[string]string{},
			expectedVars: map[string]interface{}{
				"webhook_id":   "evt_123",
				"webhook_type": "user.created",
			},
			expectError: false,
		},
		{
			name: "non-JSON payload",
			trigger: &Trigger{
				Webhook: &WebhookConfig{},
			},
			payload: []byte("plain text payload"),
			headers: map[string]string{},
			expectedVars: map[string]interface{}{
				"webhook_payload": "plain text payload",
			},
			expectError: false,
		},
		{
			name: "empty payload",
			trigger: &Trigger{
				Variables: map[string]interface{}{
					"default_var": "default_value",
				},
				Webhook: &WebhookConfig{},
			},
			payload: []byte{},
			headers: map[string]string{
				"X-Event": "test",
			},
			expectedVars: map[string]interface{}{
				"default_var":    "default_value",
				"header_x-event": "test",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			variables, err := handler.mapPayloadToVariables(tt.trigger, tt.payload, tt.headers)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				for key, expectedValue := range tt.expectedVars {
					assert.Equal(t, expectedValue, variables[key], "Variable %s should equal %v", key, expectedValue)
				}
			}
		})
	}
}

func TestHTTPWebhookHandler_IsMethodAllowed(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name     string
		webhook  *WebhookConfig
		method   string
		expected bool
	}{
		{
			name: "no methods specified - defaults to POST",
			webhook: &WebhookConfig{
				Method: []string{},
			},
			method:   "POST",
			expected: true,
		},
		{
			name: "no methods specified - rejects GET",
			webhook: &WebhookConfig{
				Method: []string{},
			},
			method:   "GET",
			expected: false,
		},
		{
			name: "POST allowed",
			webhook: &WebhookConfig{
				Method: []string{"POST"},
			},
			method:   "POST",
			expected: true,
		},
		{
			name: "multiple methods allowed",
			webhook: &WebhookConfig{
				Method: []string{"POST", "PUT", "PATCH"},
			},
			method:   "PUT",
			expected: true,
		},
		{
			name: "method not allowed",
			webhook: &WebhookConfig{
				Method: []string{"POST"},
			},
			method:   "DELETE",
			expected: false,
		},
		{
			name: "case insensitive method matching",
			webhook: &WebhookConfig{
				Method: []string{"post"},
			},
			method:   "POST",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isMethodAllowed(tt.webhook, tt.method)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPWebhookHandler_IsIPAllowed(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name       string
		webhook    *WebhookConfig
		remoteAddr string
		expected   bool
	}{
		{
			name: "no IP restrictions",
			webhook: &WebhookConfig{
				AllowedIPs: []string{},
			},
			remoteAddr: "192.168.1.1:12345",
			expected:   true,
		},
		{
			name: "exact IP match",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.1", "10.0.0.1"},
			},
			remoteAddr: "192.168.1.1:12345",
			expected:   true,
		},
		{
			name: "IP not in allowlist",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.1", "10.0.0.1"},
			},
			remoteAddr: "192.168.1.2:12345",
			expected:   false,
		},
		{
			name: "CIDR range match",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
			remoteAddr: "192.168.1.100:12345",
			expected:   true,
		},
		{
			name: "CIDR range no match",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
			remoteAddr: "192.168.2.100:12345",
			expected:   false,
		},
		{
			name: "address without port",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"127.0.0.1"},
			},
			remoteAddr: "127.0.0.1",
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isIPAllowed(tt.webhook, tt.remoteAddr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHTTPWebhookHandler_HandleWebhookRequest(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	// Register a test webhook
	trigger := &Trigger{
		ID:           "webhook-1",
		Type:         TriggerTypeWebhook,
		WorkflowName: "test-workflow",
		Webhook: &WebhookConfig{
			Path:    "/webhook/test",
			Method:  []string{"POST"},
			Enabled: true,
			Authentication: &WebhookAuth{
				Type:   WebhookAuthAPIKey,
				APIKey: "test-api-key",
			},
		},
	}

	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	// Mock successful workflow execution
	mockWorkflowTrigger.On("TriggerWorkflow", mock.Anything, mock.Anything, mock.Anything).Return(
		&WorkflowExecution{
			ID:           "exec-123",
			WorkflowName: "test-workflow",
			Status:       "running",
			StartTime:    time.Now(),
		}, nil)

	tests := []struct {
		name           string
		method         string
		url            string
		headers        map[string]string
		body           string
		expectedStatus int
		expectedError  string
	}{
		{
			name:   "successful webhook request",
			method: "POST",
			url:    "/webhook/test",
			headers: map[string]string{
				"Content-Type": "application/json",
				"X-API-Key":    "test-api-key",
			},
			body:           `{"event": "test", "data": "payload"}`,
			expectedStatus: http.StatusAccepted,
		},
		{
			name:           "webhook not found",
			method:         "POST",
			url:            "/webhook/non-existent",
			headers:        map[string]string{},
			expectedStatus: http.StatusNotFound,
			expectedError:  "Webhook trigger not found",
		},
		{
			name:   "method not allowed",
			method: "GET",
			url:    "/webhook/test",
			headers: map[string]string{
				"X-API-Key": "test-api-key",
			},
			expectedStatus: http.StatusMethodNotAllowed,
			expectedError:  "Method not allowed",
		},
		{
			name:   "authentication failed",
			method: "POST",
			url:    "/webhook/test",
			headers: map[string]string{
				"Content-Type": "application/json",
				"X-API-Key":    "wrong-api-key",
			},
			body:           `{"event": "test"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "Failed to process webhook",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			require.NoError(t, err)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()
			handler.router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)

			if tt.expectedError != "" {
				assert.Contains(t, rr.Body.String(), tt.expectedError)
			}
		})
	}
}

func TestHTTPWebhookHandler_HealthCheck(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	req, err := http.NewRequest("GET", "/health", nil)
	require.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))

	var response map[string]string
	err = json.Unmarshal(rr.Body.Bytes(), &response)
	require.NoError(t, err)

	assert.Equal(t, "healthy", response["status"])
	assert.NotEmpty(t, response["time"])
}

func TestHTTPWebhookHandler_RateLimit(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	// Register a rate-limited webhook
	trigger := &Trigger{
		ID:   "webhook-ratelimited",
		Type: TriggerTypeWebhook,
		Webhook: &WebhookConfig{
			Path:    "/webhook/ratelimited",
			Method:  []string{"POST"},
			Enabled: true,
			RateLimit: &WebhookRateLimit{
				RequestsPerMinute: 2, // Very low limit for testing
				BurstSize:         1,
			},
		},
	}

	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	// Mock workflow execution
	mockWorkflowTrigger.On("TriggerWorkflow", mock.Anything, mock.Anything, mock.Anything).Return(
		&WorkflowExecution{ID: "exec-1", WorkflowName: "test", Status: "running", StartTime: time.Now()}, nil)

	// First request should succeed
	req1, _ := http.NewRequest("POST", "/webhook/webhook-ratelimited", strings.NewReader(`{"test": "data"}`))
	rr1 := httptest.NewRecorder()
	handler.router.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusAccepted, rr1.Code)

	// Second request should be rate limited
	req2, _ := http.NewRequest("POST", "/webhook/webhook-ratelimited", strings.NewReader(`{"test": "data"}`))
	rr2 := httptest.NewRecorder()
	handler.router.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
}

// Helper function to generate HMAC signature for tests
func generateHMACSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}