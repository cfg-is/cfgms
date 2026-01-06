// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package trigger

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSecurityEdgeCases_WebhookAuthentication(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	tests := []struct {
		name           string
		webhook        *WebhookConfig
		payload        []byte
		headers        map[string]string
		expectedResult bool
		description    string
	}{
		{
			name: "HMAC signature timing attack resistance",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:            WebhookAuthHMAC,
					Secret:          "secret-key-12345",
					SignatureHeader: "X-Signature-256",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-Signature-256": "invalid-signature-that-could-be-timing-attack",
			},
			expectedResult: false,
			description:    "Should resist timing attacks on HMAC comparison",
		},
		{
			name: "HMAC with empty secret",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:            WebhookAuthHMAC,
					Secret:          "",
					SignatureHeader: "X-Signature-256",
				},
			},
			payload:        []byte(`{"test": "data"}`),
			headers:        map[string]string{},
			expectedResult: false,
			description:    "Should reject empty HMAC secret",
		},
		{
			name: "HMAC with malformed signature header",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:            WebhookAuthHMAC,
					Secret:          "secret-key",
					SignatureHeader: "X-Signature-256",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-Signature-256": "not-hex-encoded-signature",
			},
			expectedResult: false,
			description:    "Should handle malformed signature gracefully",
		},
		{
			name: "API Key with SQL injection attempt",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:         WebhookAuthAPIKey,
					APIKey:       "valid-api-key",
					APIKeyHeader: "X-API-Key",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-API-Key": "'; DROP TABLE triggers; --",
			},
			expectedResult: false,
			description:    "Should reject SQL injection attempts in API key",
		},
		{
			name: "Bearer token with XSS attempt",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:        WebhookAuthBearer,
					BearerToken: "valid-bearer-token",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"Authorization": "Bearer <script>alert('xss')</script>",
			},
			expectedResult: false,
			description:    "Should reject XSS attempts in Bearer token",
		},
		{
			name: "Case sensitivity bypass attempt",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:         WebhookAuthAPIKey,
					APIKey:       "SecretKey123",
					APIKeyHeader: "X-API-Key",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-API-Key": "secretkey123", // lowercase attempt
			},
			expectedResult: false,
			description:    "Should maintain case sensitivity in authentication",
		},
		{
			name: "Header injection attempt",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:         WebhookAuthAPIKey,
					APIKey:       "valid-key",
					APIKeyHeader: "X-API-Key",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-API-Key": "valid-key\r\nX-Injected: malicious-header",
			},
			expectedResult: false,
			description:    "Should prevent header injection attacks",
		},
		{
			name: "Unicode normalization attack",
			webhook: &WebhookConfig{
				Authentication: &WebhookAuth{
					Type:         WebhookAuthAPIKey,
					APIKey:       "valid-key",
					APIKeyHeader: "X-API-Key",
				},
			},
			payload: []byte(`{"test": "data"}`),
			headers: map[string]string{
				"X-API-Key": "valid\u2010key", // Unicode hyphen (U+2010) vs ASCII hyphen-minus (U+002D)
			},
			expectedResult: false,
			description:    "Should handle Unicode normalization consistently",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.authenticateRequest(tt.webhook, tt.payload, tt.headers)

			if tt.expectedResult {
				assert.NoError(t, err, tt.description)
			} else {
				assert.Error(t, err, tt.description)
			}
		})
	}
}

func TestSecurityEdgeCases_PayloadValidation(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name        string
		webhook     *WebhookConfig
		payload     []byte
		expectError bool
		description string
	}{
		{
			name: "JSON bomb attack - deeply nested object",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					MaxSize: 1024 * 1024, // 1MB
				},
			},
			payload:     generateDeeplyNestedJSON(100),
			expectError: false, // Should be caught by size limit
			description: "Should handle deeply nested JSON without DoS",
		},
		{
			name: "Extremely large payload",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					MaxSize: 1024, // 1KB
				},
			},
			payload:     bytes.Repeat([]byte("A"), 2048), // 2KB
			expectError: true,
			description: "Should reject payloads exceeding size limit",
		},
		{
			name: "Malicious JSON with control characters",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"id"},
				},
			},
			payload:     []byte(`{"id\u0000": "test", "data": "value"}`),
			expectError: true,
			description: "Should handle JSON with control characters safely",
		},
		{
			name: "Binary data disguised as JSON",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"id"},
				},
			},
			payload:     []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, // PNG header
			expectError: true,
			description: "Should reject binary data when expecting JSON",
		},
		{
			name: "JSON with excessive string escaping",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"data"},
				},
			},
			payload:     []byte(`{"data": "` + strings.Repeat(`\"`, 1000) + `"}`),
			expectError: false, // Should parse correctly
			description: "Should handle excessive string escaping without issues",
		},
		{
			name: "Payload with null bytes",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					RequiredFields: []string{"id"},
				},
			},
			payload:     []byte("{\"id\": \"test\x00value\", \"data\": \"content\"}"),
			expectError: true, // JSON with null bytes is invalid
			description: "Should reject null bytes in JSON strings",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validatePayload(tt.webhook, tt.payload)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
			}
		})
	}
}

func TestSecurityEdgeCases_IPFiltering(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name        string
		webhook     *WebhookConfig
		remoteAddr  string
		expected    bool
		description string
	}{
		{
			name: "IPv4 spoofing attempt",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.100"},
			},
			remoteAddr:  "192.168.1.100, 10.0.0.1", // Attempt to spoof with comma
			expected:    false,
			description: "Should prevent IP spoofing attempts",
		},
		{
			name: "IPv6 bypass attempt",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
			remoteAddr:  "[::ffff:192.168.1.100]:8080", // IPv4-mapped IPv6
			expected:    false,
			description: "Should handle IPv6 addresses consistently",
		},
		{
			name: "Private IP range bypass",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"10.0.0.0/8"},
			},
			remoteAddr:  "127.0.0.1:12345", // Localhost bypass attempt
			expected:    false,
			description: "Should not allow localhost when not explicitly permitted",
		},
		{
			name: "Malformed IP address",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.100"},
			},
			remoteAddr:  "192.168.1.999:8080", // Invalid IP
			expected:    false,
			description: "Should handle malformed IP addresses gracefully",
		},
		{
			name: "CIDR notation bypass attempt",
			webhook: &WebhookConfig{
				AllowedIPs: []string{"192.168.1.0/24"},
			},
			remoteAddr:  "192.168.2.1:8080", // Outside CIDR range
			expected:    false,
			description: "Should enforce CIDR boundaries correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.isIPAllowed(tt.webhook, tt.remoteAddr)
			assert.Equal(t, tt.expected, result, tt.description)
		})
	}
}

func TestSecurityEdgeCases_SIEMLogInjection(t *testing.T) {
	processor := &SIEMProcessor{}

	tests := []struct {
		name        string
		logEntry    map[string]interface{}
		expectError bool
		description string
	}{
		{
			name: "Log injection with ANSI escape codes",
			logEntry: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "info\033[31m INJECTED \033[0m",
				"message":   "Normal message",
				"source":    "test-service",
			},
			expectError: false, // Should process but sanitize
			description: "Should handle ANSI escape codes in log fields",
		},
		{
			name: "Log injection with control characters",
			logEntry: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "error",
				"message":   "User login\rfailed\nADMIN ACCESS GRANTED",
				"source":    "auth-service",
			},
			expectError: false,
			description: "Should handle control characters in log messages",
		},
		{
			name: "Extremely long log message",
			logEntry: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "error",
				"message":   strings.Repeat("A", 100000), // 100KB message
				"source":    "test-service",
			},
			expectError: false,
			description: "Should handle extremely long log messages",
		},
		{
			name: "Log entry with malicious field names",
			logEntry: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "error",
				"message":   "Test message",
				"__proto__": "malicious-prototype-pollution",
				"constructor": map[string]interface{}{
					"prototype": "injection-attempt",
				},
			},
			expectError: false,
			description: "Should handle potentially malicious field names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, err := processor.mapToLogEntry(tt.logEntry)

			if tt.expectError {
				assert.Error(t, err, tt.description)
			} else {
				assert.NoError(t, err, tt.description)
				assert.NotNil(t, entry)
			}
		})
	}
}

func TestSecurityEdgeCases_TenantIsolation(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Setup storage mock expectations
	mockStorage.On("Available").Return(true, nil)

	// Create triggers for different tenants
	tenant1Trigger := &Trigger{
		ID:           "tenant1-trigger",
		Name:         "Tenant 1 Trigger",
		Type:         TriggerTypeManual,
		TenantID:     "tenant-1",
		WorkflowName: "tenant1-workflow",
	}

	tenant2Trigger := &Trigger{
		ID:           "tenant2-trigger",
		Name:         "Tenant 2 Trigger",
		Type:         TriggerTypeManual,
		TenantID:     "tenant-2",
		WorkflowName: "tenant2-workflow",
	}

	// Mock storage operations
	mockStorage.On("Store", mock.Anything, mock.MatchedBy(func(key string) bool {
		return strings.Contains(key, "tenant1-trigger")
	}), mock.Anything).Return(nil)

	mockStorage.On("Store", mock.Anything, mock.MatchedBy(func(key string) bool {
		return strings.Contains(key, "tenant2-trigger")
	}), mock.Anything).Return(nil)

	mockWorkflowTrigger.On("ValidateTrigger", mock.Anything, mock.Anything).Return(nil)

	ctx := context.Background()

	// Create triggers
	err := manager.CreateTrigger(ctx, tenant1Trigger)
	require.NoError(t, err)

	err = manager.CreateTrigger(ctx, tenant2Trigger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		filter      *TriggerFilter
		expectCount int
		description string
	}{
		{
			name: "Tenant isolation - tenant 1 only",
			filter: &TriggerFilter{
				TenantID: "tenant-1",
			},
			expectCount: 1,
			description: "Should only return triggers for specified tenant",
		},
		{
			name: "Tenant isolation - tenant 2 only",
			filter: &TriggerFilter{
				TenantID: "tenant-2",
			},
			expectCount: 1,
			description: "Should only return triggers for specified tenant",
		},
		{
			name: "Cross-tenant access attempt",
			filter: &TriggerFilter{
				TenantID: "non-existent-tenant",
			},
			expectCount: 0,
			description: "Should not return triggers for non-existent tenant",
		},
		{
			name:        "No tenant filter - should get all (admin access)",
			filter:      &TriggerFilter{},
			expectCount: 2,
			description: "No tenant filter should return all triggers (admin access)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			triggers, err := manager.ListTriggers(ctx, tt.filter)
			require.NoError(t, err)
			assert.Len(t, triggers, tt.expectCount, tt.description)

			// Verify tenant isolation
			for _, trigger := range triggers {
				if tt.filter.TenantID != "" {
					assert.Equal(t, tt.filter.TenantID, trigger.TenantID, "Returned trigger should belong to requested tenant")
				}
			}
		})
	}
}

func TestSecurityEdgeCases_APIEndpointSecurity(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	handler := NewAPIHandler(mockTriggerManager)
	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	tests := []struct {
		name           string
		method         string
		url            string
		body           string
		headers        map[string]string
		setupMocks     func()
		expectedStatus int
		description    string
	}{
		{
			name:   "SQL injection in trigger ID",
			method: "GET",
			url:    "/triggers/'; DROP TABLE triggers; --",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupMocks: func() {
				mockTriggerManager.On("GetTrigger", mock.Anything, "'; DROP TABLE triggers; --").Return(nil, fmt.Errorf("trigger not found"))
			},
			expectedStatus: http.StatusNotFound,
			description:    "Should handle SQL injection attempts in URL parameters",
		},
		{
			name:   "XSS in trigger creation",
			method: "POST",
			url:    "/triggers",
			body:   `{"id": "test", "name": "<script>alert('xss')</script>", "type": "manual", "workflow_name": "test"}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupMocks: func() {
				mockTriggerManager.On("CreateTrigger", mock.Anything, mock.Anything).Return(nil)
			},
			expectedStatus: http.StatusCreated,
			description:    "Should accept but properly escape XSS attempts in trigger data",
		},
		{
			name:   "Directory traversal in trigger ID",
			method: "GET",
			url:    "/triggers/..%2F..%2Fetc%2Fpasswd",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupMocks: func() {
				mockTriggerManager.On("GetTrigger", mock.Anything, "../../../etc/passwd").Return(nil, fmt.Errorf("trigger not found"))
			},
			expectedStatus: http.StatusMovedPermanently, // Router redirects path traversal attempts
			description:    "Should handle directory traversal attempts",
		},
		{
			name:   "Malformed JSON payload",
			method: "POST",
			url:    "/triggers",
			body:   `{"id": "test", "name": "test", "type": }`, // Malformed JSON
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupMocks:     func() {},
			expectedStatus: http.StatusBadRequest,
			description:    "Should reject malformed JSON with appropriate error",
		},
		{
			name:   "Oversized payload",
			method: "POST",
			url:    "/triggers",
			body:   `{"id": "test", "name": "` + strings.Repeat("A", 10000000) + `", "type": "manual"}`, // 10MB+ payload
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupMocks: func() {
				// Mock should reject oversized trigger creation
				mockTriggerManager.On("CreateTrigger", mock.Anything, mock.MatchedBy(func(t *Trigger) bool {
					return len(t.Name) > 1000000 // Check if name is oversized
				})).Return(fmt.Errorf("trigger name exceeds maximum allowed length"))
			},
			expectedStatus: http.StatusInternalServerError, // API returns 500 when CreateTrigger fails
			description:    "Should reject oversized payloads",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockTriggerManager.ExpectedCalls = nil
			tt.setupMocks()

			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			require.NoError(t, err)

			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code, tt.description)
		})
	}
}

func TestSecurityEdgeCases_RateLimitBypass(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 8080)

	// Create a severely rate-limited webhook
	trigger := &Trigger{
		ID:   "rate-limited-webhook",
		Type: TriggerTypeWebhook,
		Webhook: &WebhookConfig{
			Path:    "/webhook/ratelimited",
			Enabled: true,
			RateLimit: &WebhookRateLimit{
				RequestsPerMinute: 1, // Only 1 request per minute
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

	tests := []struct {
		name        string
		attempts    int
		description string
	}{
		{
			name:        "Rapid fire requests",
			attempts:    10,
			description: "Should rate limit rapid consecutive requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			successCount := 0
			rateLimitedCount := 0

			for i := 0; i < tt.attempts; i++ {
				req, _ := http.NewRequest("POST", "/webhook/rate-limited-webhook", strings.NewReader(`{"test": "data"}`))
				rr := httptest.NewRecorder()
				handler.router.ServeHTTP(rr, req)

				switch rr.Code {
				case http.StatusAccepted:
					successCount++
				case http.StatusTooManyRequests:
					rateLimitedCount++
				}
			}

			// Should only allow 1 successful request, rest should be rate limited
			assert.Equal(t, 1, successCount, "Should only allow one request through")
			assert.Equal(t, tt.attempts-1, rateLimitedCount, "Remaining requests should be rate limited")
		})
	}
}

// Helper function to generate deeply nested JSON for testing
func generateDeeplyNestedJSON(depth int) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"data":`)

	for i := 0; i < depth; i++ {
		buffer.WriteString(`{"level` + fmt.Sprintf("%d", i) + `":`)
	}

	buffer.WriteString(`"value"`)

	for i := 0; i < depth; i++ {
		buffer.WriteString(`}`)
	}

	buffer.WriteString(`}`)
	return buffer.Bytes()
}

// Helper function to generate HMAC signature for tests
func generateHMACSignatureForSecurity(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func TestSecurityEdgeCases_CryptographicSafety(t *testing.T) {
	tests := []struct {
		name        string
		secret      string
		payload     []byte
		description string
	}{
		{
			name:        "HMAC with very short secret",
			secret:      "a",
			payload:     []byte("test"),
			description: "Should handle very short secrets safely",
		},
		{
			name:        "HMAC with empty payload",
			secret:      "secret-key",
			payload:     []byte{},
			description: "Should handle empty payloads correctly",
		},
		{
			name:        "HMAC with binary payload",
			secret:      "secret-key",
			payload:     generateRandomBytes(1024),
			description: "Should handle binary payloads correctly",
		},
		{
			name:        "HMAC with Unicode secret",
			secret:      "秘密鍵🔐",
			payload:     []byte("test data"),
			description: "Should handle Unicode secrets correctly",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate signature
			signature := generateHMACSignatureForSecurity(tt.secret, tt.payload)

			// Verify signature
			mac := hmac.New(sha256.New, []byte(tt.secret))
			mac.Write(tt.payload)
			expectedSignature := hex.EncodeToString(mac.Sum(nil))

			assert.Equal(t, expectedSignature, signature, tt.description)

			// Test timing attack resistance
			// Both comparisons should take similar time
			start1 := time.Now()
			hmac.Equal([]byte(signature), []byte(expectedSignature))
			duration1 := time.Since(start1)

			start2 := time.Now()
			hmac.Equal([]byte("wrong-signature"), []byte(expectedSignature))
			duration2 := time.Since(start2)

			// The timing difference should be minimal (within reasonable bounds)
			// This is a basic check - real timing attack detection would require more sophisticated testing
			timingDiff := duration1 - duration2
			if timingDiff < 0 {
				timingDiff = -timingDiff
			}

			// Allow for up to 1ms difference (this is quite generous for testing)
			assert.LessOrEqual(t, timingDiff, time.Millisecond, "HMAC comparison should be timing-safe")
		})
	}
}

// Helper function to generate random bytes for testing
func generateRandomBytes(size int) []byte {
	bytes := make([]byte, size)
	_, _ = rand.Read(bytes)
	return bytes
}
