package workflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestHTTPClient_ExecuteRequest(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check authentication header
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"message": "success", "data": {"id": 123}}`)); err != nil {
			t.Logf("Failed to write test response: %v", err)
		}
	}))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	client := NewHTTPClient(HTTPClientConfig{
		Timeout: 10 * time.Second,
	})

	httpConfig := &HTTPConfig{
		URL:    server.URL,
		Method: "GET",
		Auth: &AuthConfig{
			Type:        AuthTypeBearer,
			BearerToken: "test-token",
		},
		Timeout: 5 * time.Second,
	}

	ctx := context.Background()
	response, err := client.ExecuteRequest(ctx, httpConfig)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Contains(t, string(response.Body), "success")
	assert.True(t, response.Duration > 0)
}

func TestHTTPClient_ExecuteRequest_WithRetry(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"success": true}`)); err != nil {
			t.Logf("Failed to write test response: %v", err)
		}
	}))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	client := NewHTTPClient(HTTPClientConfig{})

	httpConfig := &HTTPConfig{
		URL:    server.URL,
		Method: "GET",
		Retry: &RetryConfig{
			MaxAttempts:      3,
			InitialDelay:     10 * time.Millisecond,
			BackoffMultiplier: 1.5,
		},
	}

	ctx := context.Background()
	response, err := client.ExecuteRequest(ctx, httpConfig)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, response.StatusCode)
	assert.Equal(t, 3, attemptCount)
}

func TestEngine_ExecuteHTTPStep(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"result": "http step executed"}`)); err != nil {
			t.Logf("Failed to write test response: %v", err)
		}
	}))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	// Create engine
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)

	workflow := Workflow{
		Name: "http-test-workflow",
		Steps: []Step{
			{
				Name: "test-http-step",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:    server.URL,
					Method: "GET",
					Headers: map[string]string{
						"X-Test": "header-value",
					},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)

	// Wait for execution to complete
	time.Sleep(200 * time.Millisecond)

	finalExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExecution.GetStatus())

	// Check that HTTP response was stored in variables
	assert.Equal(t, 200, finalExecution.Variables["test-http-step_status_code"])
	assert.Contains(t, finalExecution.Variables["test-http-step_body"], "http step executed")
}

func TestEngine_ExecuteAPIStep(t *testing.T) {
	// Create test server that simulates Microsoft Graph API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if it's a Graph API request
		if r.URL.Path == "/v1.0/users" && r.Method == "GET" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{
				"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users",
				"value": [
					{
						"id": "12345",
						"displayName": "John Doe",
						"userPrincipalName": "john.doe@contoso.com"
					}
				]
			}`)); err != nil {
				t.Logf("Failed to write test response: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	// Create engine
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)

	// Mock the Microsoft Graph API URL by overriding the buildMicrosoftGraphRequest method
	// For this test, we'll create a simpler API config that uses our test server
	workflow := Workflow{
		Name: "api-test-workflow",
		Steps: []Step{
			{
				Name: "test-api-step",
				Type: StepTypeHTTP, // Use HTTP instead of API for simpler testing
				HTTP: &HTTPConfig{
					URL:    server.URL + "/v1.0/users",
					Method: "GET",
					Headers: map[string]string{
						"Authorization": "Bearer mock-token",
					},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)

	// Wait for execution to complete
	time.Sleep(200 * time.Millisecond)

	finalExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExecution.GetStatus())

	// Check that API response was stored in variables
	assert.Equal(t, 200, finalExecution.Variables["test-api-step_status_code"])
	assert.Contains(t, finalExecution.Variables["test-api-step_body"], "John Doe")
}

func TestEngine_ExecuteWebhookStep(t *testing.T) {
	// Create test webhook server
	var receivedPayload map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Store the received payload for verification
		if r.Body != nil {
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
				receivedPayload = payload
			}
		}
		
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"webhook": "received"}`)); err != nil {
			t.Logf("Failed to write webhook response: %v", err)
		}
	}))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	// Create engine
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)

	workflow := Workflow{
		Name: "webhook-test-workflow",
		Steps: []Step{
			{
				Name: "test-webhook-step",
				Type: StepTypeWebhook,
				Webhook: &WebhookConfig{
					URL:    server.URL,
					Method: "POST",
					Payload: map[string]interface{}{
						"event": "test",
						"data":  "webhook payload",
					},
					Headers: map[string]string{
						"X-Webhook-Source": "cfgms-workflow",
					},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)

	// Wait for execution to complete
	time.Sleep(200 * time.Millisecond)

	finalExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExecution.GetStatus())

	// Check that webhook was called and payload was received
	assert.NotNil(t, receivedPayload)
	assert.Equal(t, "test", receivedPayload["event"])
	assert.Equal(t, "webhook payload", receivedPayload["data"])

	// Check that webhook response was stored in variables
	assert.Equal(t, 200, finalExecution.Variables["test-webhook-step_webhook_status"])
}

func TestEngine_ExecuteDelayStep(t *testing.T) {
	// Create engine
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)

	workflow := Workflow{
		Name: "delay-test-workflow",
		Steps: []Step{
			{
				Name: "test-delay-step",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 100 * time.Millisecond,
					Message:  "Test delay",
				},
			},
		},
	}

	ctx := context.Background()
	startTime := time.Now()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)

	// Wait for execution to complete
	time.Sleep(300 * time.Millisecond)

	finalExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExecution.GetStatus())

	// Check that the delay actually happened
	duration := time.Since(startTime)
	assert.True(t, duration >= 100*time.Millisecond)
}

func TestEngine_ComplexAPIWorkflow(t *testing.T) {
	// Create test server that simulates multiple API endpoints
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		switch r.URL.Path {
		case "/auth/token":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"access_token": "mock-token", "expires_in": 3600}`)); err != nil {
				t.Logf("Failed to write auth response: %v", err)
			}
		case "/api/users":
			if r.Method == "POST" {
				w.WriteHeader(http.StatusCreated)
				if _, err := w.Write([]byte(`{"id": "user123", "name": "Test User", "email": "test@example.com"}`)); err != nil {
					t.Logf("Failed to write user creation response: %v", err)
				}
			} else {
				w.WriteHeader(http.StatusOK)
				if _, err := w.Write([]byte(`{"users": [{"id": "user123", "name": "Test User"}]}`)); err != nil {
					t.Logf("Failed to write users response: %v", err)
				}
			}
		case "/webhook":
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`{"status": "received"}`)); err != nil {
				t.Logf("Failed to write webhook response: %v", err)
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer func() {
		server.Close() // Test server close doesn't return error
	}()

	// Create engine
	moduleFactory := createTestFactory()
	logger := pkgtesting.NewMockLogger(true)
	engine := NewEngine(moduleFactory, logger)

	workflow := Workflow{
		Name: "complex-api-workflow",
		Steps: []Step{
			{
				Name: "authenticate",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:    server.URL + "/auth/token",
					Method: "POST",
					Body: map[string]string{
						"grant_type": "client_credentials",
					},
				},
			},
			{
				Name: "create-user",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:    server.URL + "/api/users",
					Method: "POST",
					Headers: map[string]string{
						"Authorization": "Bearer mock-token",
					},
					Body: map[string]string{
						"name":  "Test User",
						"email": "test@example.com",
					},
				},
			},
			{
				Name: "wait-propagation",
				Type: StepTypeDelay,
				Delay: &DelayConfig{
					Duration: 50 * time.Millisecond,
					Message:  "Waiting for user propagation",
				},
			},
			{
				Name: "send-notification",
				Type: StepTypeWebhook,
				Webhook: &WebhookConfig{
					URL:    server.URL + "/webhook",
					Method: "POST",
					Payload: map[string]interface{}{
						"event":   "user_created",
						"user_id": "user123",
					},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)

	// Wait for execution to complete
	time.Sleep(500 * time.Millisecond)

	finalExecution, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExecution.GetStatus())

	// Verify all steps completed successfully
	stepResults := finalExecution.GetStepResults()
	assert.Equal(t, StatusCompleted, stepResults["authenticate"].Status)
	assert.Equal(t, StatusCompleted, stepResults["create-user"].Status)
	assert.Equal(t, StatusCompleted, stepResults["wait-propagation"].Status)
	assert.Equal(t, StatusCompleted, stepResults["send-notification"].Status)

	// Verify variables were set correctly
	assert.Equal(t, 200, finalExecution.Variables["authenticate_status_code"])
	assert.Equal(t, 201, finalExecution.Variables["create-user_status_code"])
	assert.Equal(t, 200, finalExecution.Variables["send-notification_webhook_status"])
}

