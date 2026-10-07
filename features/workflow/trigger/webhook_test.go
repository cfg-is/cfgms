// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	_ "github.com/cfgis/cfgms/pkg/logging/providers/file" // registers the "file" provider used by TestHTTPWebhookHandler_SanitizesRemoteAddrAndUserAgentInLogFile
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
			err := handler.authenticateRequest(tt.webhook, tt.payload, tt.headers, "test-trigger-id")

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
		name         string
		trigger      *Trigger
		payload      []byte
		headers      map[string]string
		expectedVars map[string]interface{}
		expectError  bool
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
				"default_var":         "default_value",
				"event_id":            "evt_123",
				"event_type":          "user.created",
				"header_content-type": "application/json",
				"header_x-source":     "webhook",
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
		&workflow.WorkflowExecution{
			ID:           "exec-123",
			WorkflowName: "test-workflow",
			Status:       workflow.StatusRunning,
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

// TestHTTPWebhookHandler_SanitizesRemoteAddrAndUserAgentInLogFile covers the
// log-injection findings at webhook.go:417-418 (Issue #4087): the
// "Received webhook request" InfoCtx call logs r.RemoteAddr and
// r.Header.Get("User-Agent") directly off the inbound request, before any
// trigger lookup or auth check.
//
// HTTPWebhookHandler.logger is a concrete *logging.ModuleLogger with no
// injectable interface, and NewHTTPWebhookHandler takes no logger parameter,
// so — following #4086's debug_api_test.go pattern rather than
// constructor-injecting a fake — this points the global logging manager at a
// real file provider and reads back the written JSON line, exercising the
// real ModuleLogger -> LoggingManager -> FileProvider path end to end.
//
// Honesty note on what this test can and cannot prove, discovered while
// writing it and worth recording rather than silently working around: unlike
// debug_api.go's DebugAction field (a distinct named type,
// features/workflow/debug_api_test.go), r.RemoteAddr and
// r.Header.Get("User-Agent") are plain Go `string` values. Every field value
// passed through a *logging.ModuleLogger's *Ctx methods is independently run
// through pkg/logging's own sanitizeValueRecursive
// (logWithProvider -> keysAndValuesToMap -> sanitizeMapValues, pkg/logging/
// logger.go and sanitize.go), whose type switch already calls
// SanitizeLogValue on any bare `string` -- regardless of whether the call
// site itself wraps the value. Verified directly: temporarily reverting the
// webhook.go:417-418 wraps back to bare r.RemoteAddr / r.Header.Get(...) and
// re-running this exact scenario still produces a sanitized
// "10.0.0.1_evil:1234" / "ua_evil" in the log file, not the raw
// control-character input. So this test cannot fail on revert of the
// call-site wrap alone (the same limitation #4086 already documented for
// this file's execution_id/error-shaped fields) -- the wrap remains required
// because `make lint-log-injection` is a static syntactic check with no
// knowledge of this runtime sanitization, and as defense-in-depth if the
// value ever flows through a path that skips ModuleLogger's own sanitizer.
// What this test DOES verify, genuinely: the field reaches the log file
// sanitized end-to-end, which is real regression coverage against breaking
// SanitizeLogValue or ModuleLogger's sanitization pipeline itself.
//
// Global logging state is process-wide; this test cannot run t.Parallel()
// and must be the only test in this package touching it.
func TestHTTPWebhookHandler_SanitizesRemoteAddrAndUserAgentInLogFile(t *testing.T) {
	if manager := logging.GetGlobalLoggingManager(); manager != nil {
		_ = manager.Close()
	}
	logging.InitializeGlobalLoggerFactory("", "")

	tmpDir := t.TempDir()
	loggingConfig := &logging.LoggingConfig{
		Provider:      "file",
		Level:         "DEBUG",
		ServiceName:   "test-service",
		Component:     "workflow-trigger-webhook",
		AsyncWrites:   false,
		BatchSize:     1,
		FlushInterval: time.Second,
		Config: map[string]interface{}{
			"directory":        tmpDir,
			"file_prefix":      "test",
			"max_file_size":    1024 * 1024,
			"max_files":        5,
			"compress_rotated": false,
		},
	}
	require.NoError(t, logging.InitializeGlobalLogging(loggingConfig))
	logging.InitializeGlobalLoggerFactory("test-service", "workflow-trigger-webhook")

	t.Cleanup(func() {
		if manager := logging.GetGlobalLoggingManager(); manager != nil {
			_ = manager.Close()
		}
		logging.InitializeGlobalLoggerFactory("", "")
	})

	// CFGMS mandates real-component testing, so the webhook handler is wired
	// with the genuine TriggerManagerImpl (real in-memory storage provider and
	// real workflow trigger) rather than a mock of the TriggerManager /
	// WorkflowTrigger interfaces — matching how api_test.go exercises the
	// sibling API-handler path.
	workflowTrigger := NewTestWorkflowTrigger()
	handler := NewHTTPWebhookHandler(
		NewControllerTriggerManager(NewTestStorageProvider(), workflowTrigger),
		workflowTrigger,
		"localhost",
		8080,
	)

	const controlRemoteAddr = "10.0.0.1\x07evil:1234"
	const controlUserAgent = "ua\x07evil"

	req, err := http.NewRequest(http.MethodPost, "/webhook/nonexistent-trigger", strings.NewReader("{}"))
	require.NoError(t, err)
	req.RemoteAddr = controlRemoteAddr
	req.Header.Set("User-Agent", controlUserAgent)

	rr := httptest.NewRecorder()
	handler.router.ServeHTTP(rr, req)
	// The trigger doesn't exist, so the handler 404s after logging the
	// request -- expected, and irrelevant to what this test is checking.
	require.Equal(t, http.StatusNotFound, rr.Code)

	require.NoError(t, logging.GetGlobalLoggingManager().Flush(context.Background()))

	entries := readWebhookLogEntries(t, tmpDir)
	found := false
	for _, e := range entries {
		if e["message"] != "Received webhook request" {
			continue
		}
		fields, _ := e["fields"].(map[string]interface{})
		remoteAddr, _ := fields["remote_addr"].(string)
		userAgent, _ := fields["user_agent"].(string)
		found = true

		if strings.Contains(remoteAddr, controlRemoteAddr) || strings.ContainsAny(remoteAddr, "\x07") {
			t.Fatalf("log entry contains the raw control-character remote_addr: %q", remoteAddr)
		}
		if strings.Contains(userAgent, controlUserAgent) || strings.ContainsAny(userAgent, "\x07") {
			t.Fatalf("log entry contains the raw control-character user_agent: %q", userAgent)
		}
		require.Equal(t, logging.SanitizeLogValue(controlRemoteAddr), remoteAddr)
		require.Equal(t, logging.SanitizeLogValue(controlUserAgent), userAgent)
	}
	require.True(t, found, "expected a 'Received webhook request' log entry")
}

// readWebhookLogEntries reads every JSON-lines log file under dir and decodes
// each line into a generic map for field-level assertions.
func readWebhookLogEntries(t *testing.T, dir string) []map[string]interface{} {
	t.Helper()
	files, err := os.ReadDir(dir)
	require.NoError(t, err)

	var entries []map[string]interface{}
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		file, err := os.Open(filepath.Join(dir, f.Name()))
		require.NoError(t, err)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var entry map[string]interface{}
			require.NoError(t, json.Unmarshal(line, &entry))
			entries = append(entries, entry)
		}
		require.NoError(t, scanner.Err())
		require.NoError(t, file.Close())
	}
	return entries
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
		&workflow.WorkflowExecution{ID: "exec-1", WorkflowName: "test", Status: workflow.StatusRunning, StartTime: time.Now()}, nil)

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

// TestValidateBearerTokenConstantTimeCompare verifies that validateBearerToken uses
// subtle.ConstantTimeCompare and NFC normalization. Wall-clock timing is statistically
// unreliable on shared CI runners at sub-microsecond resolution, so we use a structural
// source inspection check (same pattern as TestWebhookHandlerUsesHmacEqual in security_test.go).
func TestValidateBearerTokenConstantTimeCompare(t *testing.T) {
	source, err := os.ReadFile("webhook.go")
	require.NoError(t, err, "failed to read webhook.go")
	assert.True(t, strings.Contains(string(source), "subtle.ConstantTimeCompare("),
		"webhook.go must use subtle.ConstantTimeCompare() in validateBearerToken to prevent timing attacks")
	assert.True(t, strings.Contains(string(source), "norm.NFC.String("),
		"webhook.go must apply NFC normalization before bearer token comparison to prevent Unicode normalization attacks")
}

// TestValidateBearerTokenFailClosed asserts that an empty BearerToken config rejects all requests.
func TestValidateBearerTokenFailClosed(t *testing.T) {
	handler := &HTTPWebhookHandler{}
	auth := &WebhookAuth{
		BearerToken: "",
	}

	headers := map[string]string{
		"Authorization": "Bearer anything",
	}

	err := handler.validateBearerToken(auth, headers, "test-trigger")
	require.Error(t, err)
	assert.Equal(t, "invalid Bearer token", err.Error())
	assert.NotContains(t, err.Error(), "anything")
}

// TestAuthFailureRateLimit asserts that 11 consecutive bearer auth failures for the same
// trigger ID return HTTP 429 on the 11th attempt.
func TestAuthFailureRateLimit(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 0)

	trigger := &Trigger{
		ID:   "rate-limit-trigger",
		Type: TriggerTypeWebhook,
		Webhook: &WebhookConfig{
			Path:    "/webhook/rate-limit-trigger",
			Method:  []string{"POST"},
			Enabled: true,
			Authentication: &WebhookAuth{
				Type:        WebhookAuthBearer,
				BearerToken: "correct-token",
			},
		},
	}

	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	// First 10 failures should return 500 (auth failed, limiter not yet exhausted)
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("POST", "/webhook/rate-limit-trigger",
			strings.NewReader(`{"test": "data"}`))
		req.Header.Set("Authorization", "Bearer wrong-token")
		rr := httptest.NewRecorder()
		handler.router.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusInternalServerError, rr.Code,
			fmt.Sprintf("request %d should fail with 500 (auth error)", i+1))
	}

	// 11th failure should return 429 (rate limit exhausted)
	req, _ := http.NewRequest("POST", "/webhook/rate-limit-trigger",
		strings.NewReader(`{"test": "data"}`))
	req.Header.Set("Authorization", "Bearer wrong-token")
	rr := httptest.NewRecorder()
	handler.router.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code,
		"11th consecutive auth failure should return HTTP 429")
}

// TestMapPayloadToVariablesHeaderSanitization asserts that auth-related headers are stripped
// from the workflow variable bag to prevent credential leaks into execution records.
func TestMapPayloadToVariablesHeaderSanitization(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	trigger := &Trigger{
		Webhook: &WebhookConfig{},
	}
	payload := []byte(`{"event": "test"}`)
	headers := map[string]string{
		"Authorization":   "Bearer super-secret-token",
		"Cookie":          "session=abc123",
		"X-Api-Key":       "api-key-value",
		"X-Auth-Token":    "auth-token-value",
		"Content-Type":    "application/json",
		"X-Custom-Header": "allowed-value",
	}

	variables, err := handler.mapPayloadToVariables(trigger, payload, headers)
	require.NoError(t, err)

	// Blocked headers must not appear in any form
	for key, val := range variables {
		assert.NotContains(t, key, "authorization", "authorization header must be stripped from variable bag")
		assert.NotContains(t, key, "cookie", "cookie header must be stripped from variable bag")
		assert.NotContains(t, key, "x-api-key", "x-api-key header must be stripped from variable bag")
		assert.NotContains(t, key, "x-auth-token", "x-auth-token header must be stripped from variable bag")
		// Token values must not appear in any variable value
		assert.NotContains(t, fmt.Sprintf("%v", val), "super-secret-token")
		assert.NotContains(t, fmt.Sprintf("%v", val), "session=abc123")
		assert.NotContains(t, fmt.Sprintf("%v", val), "api-key-value")
		assert.NotContains(t, fmt.Sprintf("%v", val), "auth-token-value")
	}

	// Allowed headers must still be present
	assert.Equal(t, "application/json", variables["header_content-type"])
	assert.Equal(t, "allowed-value", variables["header_x-custom-header"])
}

// TestHandleWebhookNoAuthHeadersInWorkflowVariables asserts that auth-related headers
// never reach TriggerWorkflow via webhook_headers or any other path in HandleWebhook.
func TestHandleWebhookNoAuthHeadersInWorkflowVariables(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 0)

	trigger := &Trigger{
		ID:           "sanitize-e2e",
		Type:         TriggerTypeWebhook,
		WorkflowName: "test-workflow",
		Webhook: &WebhookConfig{
			Path:    "/webhook/sanitize-e2e",
			Method:  []string{"POST"},
			Enabled: true,
			Authentication: &WebhookAuth{
				Type:        WebhookAuthBearer,
				BearerToken: "correct-token",
			},
		},
	}

	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	// Use a channel to synchronize with the async goroutine in HandleWebhook.
	// The channel send happens-before the receive, ensuring capturedVariables is
	// visible to the test goroutine without a data race.
	triggerCalled := make(chan struct{}, 1)
	var capturedVariables map[string]interface{}
	mockWorkflowTrigger.On("TriggerWorkflow", mock.Anything, mock.Anything, mock.MatchedBy(func(vars map[string]interface{}) bool {
		capturedVariables = vars
		select {
		case triggerCalled <- struct{}{}:
		default:
		}
		return true
	})).Return(
		&workflow.WorkflowExecution{ID: "exec-sanitize", WorkflowName: "test-workflow", Status: workflow.StatusRunning, StartTime: time.Now()},
		nil,
	)

	headers := map[string]string{
		"Authorization":   "Bearer correct-token",
		"Cookie":          "session=secret123",
		"X-Api-Key":       "api-key-secret",
		"X-Auth-Token":    "auth-secret",
		"Content-Type":    "application/json",
		"X-Custom-Header": "safe-value",
	}

	payload := []byte(`{"event": "test"}`)
	_, err = handler.HandleWebhook(ctx, "sanitize-e2e", payload, headers)
	require.NoError(t, err)

	// Wait for the async goroutine to invoke TriggerWorkflow.
	select {
	case <-triggerCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("TriggerWorkflow was not called within 2 seconds")
	}

	require.NotNil(t, capturedVariables, "TriggerWorkflow must have been called with variables")

	// Stringify all variable values and assert no auth credentials appear.
	combined := fmt.Sprintf("%v", capturedVariables)
	assert.NotContains(t, combined, "correct-token", "bearer token must not reach workflow variables")
	assert.NotContains(t, combined, "secret123", "cookie value must not reach workflow variables")
	assert.NotContains(t, combined, "api-key-secret", "x-api-key value must not reach workflow variables")
	assert.NotContains(t, combined, "auth-secret", "x-auth-token value must not reach workflow variables")

	// Auth header keys must not appear either.
	assert.NotContains(t, combined, "authorization", "authorization key must not appear in workflow variables")
	assert.NotContains(t, combined, "cookie", "cookie key must not appear in workflow variables")

	// Safe headers must still be present.
	assert.Contains(t, combined, "safe-value", "non-auth headers must still be present")
}

// TestWebhookPayloadSchemaValidation covers valid payload, invalid payload, and no-schema cases.
func TestWebhookPayloadSchemaValidation(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	tests := []struct {
		name          string
		webhook       *WebhookConfig
		payload       []byte
		expectError   bool
		errorContains string
	}{
		{
			name: "no schema configured accepts any payload",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					JSONSchema: "",
				},
			},
			payload:     []byte(`{"anything": "accepted"}`),
			expectError: false,
		},
		{
			name: "valid payload matching schema",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					JSONSchema: `{"type": "object", "required": ["id", "name"], "properties": {"id": {"type": "string"}, "name": {"type": "string"}}}`,
				},
			},
			payload:     []byte(`{"id": "123", "name": "test", "extra": "ignored"}`),
			expectError: false,
		},
		{
			name: "payload missing required field rejected with schema error",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					JSONSchema: `{"type": "object", "required": ["id", "name"]}`,
				},
			},
			payload:       []byte(`{"id": "123"}`),
			expectError:   true,
			errorContains: "payload does not match JSON schema",
		},
		{
			name: "payload wrong root type rejected",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					JSONSchema: `{"type": "object"}`,
				},
			},
			payload:       []byte(`["not", "an", "object"]`),
			expectError:   true,
			errorContains: "payload does not match JSON schema",
		},
		{
			name: "property type mismatch rejected",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					JSONSchema: `{"type": "object", "properties": {"count": {"type": "integer"}}}`,
				},
			},
			payload:       []byte(`{"count": "not-a-number"}`),
			expectError:   true,
			errorContains: "payload does not match JSON schema",
		},
		{
			name: "invalid JSON schema config returns error",
			webhook: &WebhookConfig{
				PayloadValidation: &PayloadValidation{
					JSONSchema: `{invalid json`,
				},
			},
			payload:       []byte(`{"id": "123"}`),
			expectError:   true,
			errorContains: "invalid JSON schema",
		},
		{
			name: "no validation config accepts payload",
			webhook: &WebhookConfig{
				PayloadValidation: nil,
			},
			payload:     []byte(`{"anything": "accepted"}`),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validatePayload(tt.webhook, tt.payload)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestWebhookBasicAuth covers correct credentials, wrong password, and missing header cases.
func TestWebhookBasicAuth(t *testing.T) {
	handler := &HTTPWebhookHandler{}

	auth := &WebhookAuth{
		BasicAuth: &BasicAuth{
			Username: "admin",
			Password: "s3cr3t!",
		},
	}

	basicHeader := func(username, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	tests := []struct {
		name        string
		headers     map[string]string
		expectError bool
		errorIs     error
	}{
		{
			name:        "correct credentials accepted",
			headers:     map[string]string{"Authorization": basicHeader("admin", "s3cr3t!")},
			expectError: false,
		},
		{
			name:        "wrong password rejected",
			headers:     map[string]string{"Authorization": basicHeader("admin", "wrong")},
			expectError: true,
			errorIs:     errBasicAuthUnauthorized,
		},
		{
			name:        "wrong username rejected",
			headers:     map[string]string{"Authorization": basicHeader("other", "s3cr3t!")},
			expectError: true,
			errorIs:     errBasicAuthUnauthorized,
		},
		{
			name:        "missing Authorization header rejected",
			headers:     map[string]string{},
			expectError: true,
			errorIs:     errBasicAuthUnauthorized,
		},
		{
			name:        "malformed base64 rejected",
			headers:     map[string]string{"Authorization": "Basic not-valid-base64!!!"},
			expectError: true,
			errorIs:     errBasicAuthUnauthorized,
		},
		{
			name:        "non-Basic scheme rejected",
			headers:     map[string]string{"Authorization": "Bearer some-token"},
			expectError: true,
			errorIs:     errBasicAuthUnauthorized,
		},
		{
			name:        "password mismatch confirms split on first colon only",
			headers:     map[string]string{"Authorization": basicHeader("admin", "s3cr3t!:extra")},
			expectError: true, // "s3cr3t!:extra" != "s3cr3t!" — correct first-colon split, wrong password
			errorIs:     errBasicAuthUnauthorized,
		},
	}

	// Nil BasicAuth config tested separately since it requires a different auth struct.
	t.Run("nil BasicAuth config returns configuration error", func(t *testing.T) {
		err := handler.validateBasicAuth(&WebhookAuth{BasicAuth: nil}, map[string]string{
			"Authorization": basicHeader("admin", "s3cr3t!"),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "basic auth configuration is required")
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateBasicAuth(auth, tt.headers)
			if tt.expectError {
				require.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestWebhookBasicAuthHTTP verifies that the HTTP handler returns 401 for missing or wrong
// Basic auth credentials and 202 for correct credentials.
func TestWebhookBasicAuthHTTP(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 0)

	trigger := &Trigger{
		ID:           "webhook-basic",
		Type:         TriggerTypeWebhook,
		WorkflowName: "test-workflow",
		Webhook: &WebhookConfig{
			Path:    "/webhook/basic-auth-test",
			Method:  []string{"POST"},
			Enabled: true,
			Authentication: &WebhookAuth{
				Type: WebhookAuthBasic,
				BasicAuth: &BasicAuth{
					Username: "user",
					Password: "pass",
				},
			},
		},
	}

	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	mockWorkflowTrigger.On("TriggerWorkflow", mock.Anything, mock.Anything, mock.Anything).Return(
		&workflow.WorkflowExecution{
			ID:           "exec-basic",
			WorkflowName: "test-workflow",
			Status:       workflow.StatusRunning,
			StartTime:    time.Now(),
		}, nil)

	basicHeader := func(username, password string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	}

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
	}{
		{
			name:           "missing Authorization header returns 401",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "wrong password returns 401",
			authHeader:     basicHeader("user", "wrong"),
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "correct credentials returns 202",
			authHeader:     basicHeader("user", "pass"),
			expectedStatus: http.StatusAccepted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/webhook/basic-auth-test",
				strings.NewReader(`{"event": "test"}`))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rr := httptest.NewRecorder()
			handler.router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

// TestWebhookPayloadSchemaValidationHTTP verifies that the HTTP handler returns 400 for
// payloads that fail JSON schema validation and 202 for valid payloads.
func TestWebhookPayloadSchemaValidationHTTP(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	handler := NewHTTPWebhookHandler(mockTriggerManager, mockWorkflowTrigger, "localhost", 0)

	trigger := &Trigger{
		ID:           "webhook-schema",
		Type:         TriggerTypeWebhook,
		WorkflowName: "test-workflow",
		Webhook: &WebhookConfig{
			Path:    "/webhook/schema-test",
			Method:  []string{"POST"},
			Enabled: true,
			PayloadValidation: &PayloadValidation{
				JSONSchema: `{"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}`,
			},
		},
	}

	ctx := context.Background()
	err := handler.RegisterWebhook(ctx, trigger)
	require.NoError(t, err)

	mockWorkflowTrigger.On("TriggerWorkflow", mock.Anything, mock.Anything, mock.Anything).Return(
		&workflow.WorkflowExecution{
			ID:           "exec-schema",
			WorkflowName: "test-workflow",
			Status:       workflow.StatusRunning,
			StartTime:    time.Now(),
		}, nil)

	tests := []struct {
		name           string
		payload        string
		expectedStatus int
	}{
		{
			name:           "schema-invalid payload returns 400",
			payload:        `{"name": "missing-id-field"}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "wrong root type returns 400",
			payload:        `["not", "an", "object"]`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "valid payload returns 202",
			payload:        `{"id": "abc123"}`,
			expectedStatus: http.StatusAccepted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("POST", "/webhook/schema-test",
				strings.NewReader(tt.payload))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			rr := httptest.NewRecorder()
			handler.router.ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatus, rr.Code)
		})
	}
}

// Helper function to generate HMAC signature for tests
func generateHMACSignature(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}
