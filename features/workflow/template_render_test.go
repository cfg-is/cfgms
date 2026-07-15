// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

// TestHTTPStep_TemplateRendering verifies that {{ .var }} fields on step.HTTP
// are rendered against execution variables before the request is dispatched.
// The HTTP client must receive the resolved value, not the literal template string.
func TestHTTPStep_TemplateRendering(t *testing.T) {
	var receivedURL atomic.Value
	var receivedBody atomic.Value
	var receivedAuthHeader atomic.Value

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL.Store(r.URL.Path)
		receivedAuthHeader.Store(r.Header.Get("Authorization"))
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedBody.Store(body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"runner-42","status":"created"}`))
	}))
	defer ts.Close()

	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	workflow := Workflow{
		Name: "template-render-test",
		Steps: []Step{
			{
				Name: "provision",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:    ts.URL + "/runners/{{ .org_name }}/register",
					Method: "POST",
					Headers: map[string]string{
						"Authorization": "Bearer {{ .registration_token }}",
					},
					Body:           `{"runner_name":"{{ .runner_name }}"}`,
					ExpectedStatus: []int{200},
				},
			},
		},
	}

	ctx := context.Background()
	variables := map[string]interface{}{
		"org_name":           "my-org",
		"registration_token": "tok-abc123",
		"runner_name":        "runner-01",
	}

	execution, err := engine.ExecuteWorkflow(ctx, workflow, variables)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExec.GetStatus(), "workflow must complete successfully")

	// The HTTP client must have received resolved values, not template literals.
	assert.Equal(t, "/runners/my-org/register", receivedURL.Load(), "URL must be rendered")
	assert.Equal(t, "Bearer tok-abc123", receivedAuthHeader.Load(), "auth header must be rendered")

	gotBody, ok := receivedBody.Load().(map[string]interface{})
	require.True(t, ok, "body must be a JSON object")
	assert.Equal(t, "runner-01", gotBody["runner_name"], "body field must be rendered")
}

// TestHTTPStep_TemplateRendering_UndefinedVar verifies that an undefined variable
// produces an explicit step error instead of a silently empty string.
func TestHTTPStep_TemplateRendering_UndefinedVar(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	workflow := Workflow{
		Name: "undefined-var-test",
		Steps: []Step{
			{
				Name: "bad-step",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:            ts.URL + "/{{ .missing_var }}",
					Method:         "GET",
					ExpectedStatus: []int{200},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, finalExec.GetStatus(), "workflow must fail on undefined variable")
}

// TestHTTPStep_JSONResponseBinding verifies that HTTP step responses with a JSON body
// are decoded into a <step>_response_json variable in addition to the raw <step>_body string.
func TestHTTPStep_JSONResponseBinding(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"runner-42","token":"reg-tok-xyz","status":"active"}`))
	}))
	defer ts.Close()

	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	workflow := Workflow{
		Name: "json-response-test",
		Steps: []Step{
			{
				Name: "fetch",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:            ts.URL + "/registration",
					Method:         "GET",
					ExpectedStatus: []int{200},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExec.GetStatus())

	// Raw body string must be stored.
	rawBody, exists := finalExec.GetVariable("fetch_body")
	assert.True(t, exists, "fetch_body must be stored")
	assert.Contains(t, rawBody.(string), "runner-42")

	// Parsed JSON must also be stored as an addressable variable.
	jsonVar, exists := finalExec.GetVariable("fetch_response_json")
	assert.True(t, exists, "fetch_response_json must be populated on JSON response")
	jsonMap, ok := jsonVar.(map[string]interface{})
	require.True(t, ok, "fetch_response_json must be a map")
	assert.Equal(t, "runner-42", jsonMap["id"])
	assert.Equal(t, "reg-tok-xyz", jsonMap["token"])
}

// TestHTTPStep_JSONResponse_DownstreamTemplate verifies that a JSON response field
// can be used as a variable in a downstream step's template.
func TestHTTPStep_JSONResponse_DownstreamTemplate(t *testing.T) {
	var receivedBody atomic.Value

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/registration" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"reg-tok-xyz"}`))
			return
		}
		// Second request: capture the body for assertion
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedBody.Store(body)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()

	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	workflow := Workflow{
		Name: "downstream-template-test",
		Steps: []Step{
			{
				// Underscore name so the variable key is a valid Go template identifier.
				Name: "get_token",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:            ts.URL + "/registration",
					Method:         "GET",
					ExpectedStatus: []int{200},
				},
			},
			{
				Name: "use_token",
				Type: StepTypeHTTP,
				HTTP: &HTTPConfig{
					URL:    ts.URL + "/register",
					Method: "POST",
					// Reference the parsed JSON field from the previous step via index.
					Body:           `{"registration_token":"{{ index .get_token_response_json "token" }}"}`,
					ExpectedStatus: []int{201},
				},
			},
		},
	}

	ctx := context.Background()
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExec.GetStatus(), "workflow must complete: %s", finalExec.GetError())

	body, ok := receivedBody.Load().(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "reg-tok-xyz", body["registration_token"])
}

// TestWhileCondition_TemplateSupport verifies that a while condition using
// {{ }} template syntax evaluates correctly.
func TestWhileCondition_TemplateSupport(t *testing.T) {
	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	// Counter starts at 3, loop should run while counter != 0.
	workflow := Workflow{
		Name: "while-template-condition-test",
		Steps: []Step{
			{
				Name: "count-down",
				Type: StepTypeWhile,
				Loop: &LoopConfig{
					Type: LoopTypeWhile,
					Condition: &Condition{
						Type: ConditionTypeExpression,
						// Template expression: renders to "true" while counter != 0
						Expression: `{{ ne .counter 0 }}`,
					},
					MaxIterations: 10,
				},
				Steps: []Step{
					{
						// Decrement counter via a delay step (no sub-loop step type available)
						// We use a sequential step with a variable update via delay.
						// Since we can't directly set variables in a step type, use delay
						// and rely on the engine variable store being tested separately.
						// For this test, just verify the condition parsing doesn't error.
						Name: "tick",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	// counter=0 means the while condition is false from the start → loop executes 0 times.
	variables := map[string]interface{}{
		"counter": 0,
	}

	execution, err := engine.ExecuteWorkflow(ctx, workflow, variables)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	// Loop should have evaluated the condition (which is false immediately) and completed.
	assert.Equal(t, StatusCompleted, finalExec.GetStatus(), "workflow must complete: %s", finalExec.GetError())
}

// TestWhileCondition_TemplateSupport_UndefinedVar verifies that a while condition
// whose template expression references an undefined variable produces an explicit
// step error (StatusFailed) rather than silently evaluating to false. This exercises
// the error path in evaluateExpression where renderStepString fails.
func TestWhileCondition_TemplateSupport_UndefinedVar(t *testing.T) {
	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	workflow := Workflow{
		Name: "while-template-condition-undefined-var-test",
		Steps: []Step{
			{
				Name: "count-down",
				Type: StepTypeWhile,
				Loop: &LoopConfig{
					Type: LoopTypeWhile,
					Condition: &Condition{
						Type: ConditionTypeExpression,
						// References an undefined variable: template rendering must fail.
						Expression: `{{ ne .missing 0 }}`,
					},
					MaxIterations: 10,
				},
				Steps: []Step{
					{
						Name: "tick",
						Type: StepTypeDelay,
						Delay: &DelayConfig{
							Duration: 1 * time.Millisecond,
						},
					},
				},
			},
		},
	}

	ctx := context.Background()
	// No variables provided, so `.missing` is undefined.
	execution, err := engine.ExecuteWorkflow(ctx, workflow, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusFailed, finalExec.GetStatus(),
		"workflow must fail when while condition expression references an undefined variable")
}

// TestRenderHTTPConfig_Auth verifies that renderHTTPConfig renders all auth
// string fields (BearerToken, APIKey, Username, Password, CustomHeaders) and
// returns an explicit error on undefined variables.
func TestRenderHTTPConfig_Auth(t *testing.T) {
	t.Run("all auth fields rendered", func(t *testing.T) {
		vars := map[string]interface{}{
			"tok":    "bearer-xyz",
			"key":    "apikey-abc",
			"hdr":    "X-Custom-Token",
			"user":   "admin",
			"pass":   "s3cr3t",
			"cust_v": "cust-val",
		}
		cfg := &HTTPConfig{
			URL:    "https://example.com",
			Method: "GET",
			Auth: &AuthConfig{
				BearerToken:   "{{ .tok }}",
				APIKey:        "{{ .key }}",
				APIKeyHeader:  "{{ .hdr }}",
				Username:      "{{ .user }}",
				Password:      "{{ .pass }}",
				CustomHeaders: map[string]string{"X-Custom": "{{ .cust_v }}"},
			},
		}
		got, err := renderHTTPConfig(cfg, vars)
		require.NoError(t, err)
		require.NotNil(t, got.Auth)
		assert.Equal(t, "bearer-xyz", got.Auth.BearerToken)
		assert.Equal(t, "apikey-abc", got.Auth.APIKey)
		assert.Equal(t, "X-Custom-Token", got.Auth.APIKeyHeader)
		assert.Equal(t, "admin", got.Auth.Username)
		assert.Equal(t, "s3cr3t", got.Auth.Password)
		assert.Equal(t, "cust-val", got.Auth.CustomHeaders["X-Custom"])
		// Original must not be mutated.
		assert.Equal(t, "{{ .tok }}", cfg.Auth.BearerToken)
	})

	t.Run("nil auth passthrough", func(t *testing.T) {
		cfg := &HTTPConfig{URL: "https://example.com", Method: "GET"}
		got, err := renderHTTPConfig(cfg, nil)
		require.NoError(t, err)
		assert.Nil(t, got.Auth)
	})

	t.Run("undefined var in bearer_token produces error", func(t *testing.T) {
		cfg := &HTTPConfig{
			URL:    "https://example.com",
			Method: "GET",
			Auth:   &AuthConfig{BearerToken: "{{ .missing }}"},
		}
		_, err := renderHTTPConfig(cfg, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "http.auth.bearer_token")
	})

	t.Run("undefined var in custom_headers produces error", func(t *testing.T) {
		cfg := &HTTPConfig{
			URL:    "https://example.com",
			Method: "GET",
			Auth:   &AuthConfig{CustomHeaders: map[string]string{"X-Hdr": "{{ .missing }}"}},
		}
		_, err := renderHTTPConfig(cfg, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "http.auth.custom_headers")
	})
}

// TestRenderAPIConfig verifies that renderAPIConfig renders Provider, Service,
// Operation, and string-valued Parameters while passing non-string parameter
// values through unchanged, returns an explicit error on undefined variables,
// and does not mutate the original config.
func TestRenderAPIConfig(t *testing.T) {
	t.Run("provider, service, operation, and mixed params rendered", func(t *testing.T) {
		vars := map[string]interface{}{
			"prov": "microsoft",
			"svc":  "graph",
			"op":   "createUser",
			"name": "alice",
		}
		cfg := &APIConfig{
			Provider:  "{{ .prov }}",
			Service:   "{{ .svc }}",
			Operation: "{{ .op }}",
			Parameters: map[string]interface{}{
				"displayName":    "{{ .name }}",
				"accountEnabled": true,
				"retryCount":     3,
			},
		}
		got, err := renderAPIConfig(cfg, vars)
		require.NoError(t, err)
		assert.Equal(t, "microsoft", got.Provider)
		assert.Equal(t, "graph", got.Service)
		assert.Equal(t, "createUser", got.Operation)
		// String parameter value is rendered.
		assert.Equal(t, "alice", got.Parameters["displayName"])
		// Non-string parameter values pass through unchanged.
		assert.Equal(t, true, got.Parameters["accountEnabled"])
		assert.Equal(t, 3, got.Parameters["retryCount"])
		// Original must not be mutated.
		assert.Equal(t, "{{ .prov }}", cfg.Provider)
		assert.Equal(t, "{{ .name }}", cfg.Parameters["displayName"])
	})

	t.Run("nil config passthrough", func(t *testing.T) {
		got, err := renderAPIConfig(nil, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("empty parameters left untouched", func(t *testing.T) {
		cfg := &APIConfig{Provider: "microsoft", Service: "graph", Operation: "listUsers"}
		got, err := renderAPIConfig(cfg, nil)
		require.NoError(t, err)
		assert.Nil(t, got.Parameters)
	})

	t.Run("undefined var in operation produces error", func(t *testing.T) {
		cfg := &APIConfig{Provider: "microsoft", Service: "graph", Operation: "{{ .missing }}"}
		_, err := renderAPIConfig(cfg, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api.operation")
	})

	t.Run("undefined var in string parameter produces error", func(t *testing.T) {
		cfg := &APIConfig{
			Provider:   "microsoft",
			Service:    "graph",
			Operation:  "createUser",
			Parameters: map[string]interface{}{"displayName": "{{ .missing }}"},
		}
		_, err := renderAPIConfig(cfg, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), `api.parameters["displayName"]`)
	})
}

// TestRenderWebhookConfig verifies that renderWebhookConfig renders URL, Method,
// Headers, and a string Payload, passes a non-string Payload through unchanged,
// returns an explicit error on undefined variables, and does not mutate the
// original config.
func TestRenderWebhookConfig(t *testing.T) {
	t.Run("url, method, headers, and string payload rendered", func(t *testing.T) {
		vars := map[string]interface{}{
			"org":   "my-org",
			"verb":  "POST",
			"tok":   "tok-abc",
			"actor": "runner-01",
		}
		cfg := &WebhookConfig{
			URL:    "https://hooks.example.com/{{ .org }}",
			Method: "{{ .verb }}",
			Headers: map[string]string{
				"Authorization": "Bearer {{ .tok }}",
			},
			Payload: `{"actor":"{{ .actor }}"}`,
		}
		got, err := renderWebhookConfig(cfg, vars)
		require.NoError(t, err)
		assert.Equal(t, "https://hooks.example.com/my-org", got.URL)
		assert.Equal(t, "POST", got.Method)
		assert.Equal(t, "Bearer tok-abc", got.Headers["Authorization"])
		assert.Equal(t, `{"actor":"runner-01"}`, got.Payload)
		// Original must not be mutated.
		assert.Equal(t, "https://hooks.example.com/{{ .org }}", cfg.URL)
		assert.Equal(t, "Bearer {{ .tok }}", cfg.Headers["Authorization"])
		assert.Equal(t, `{"actor":"{{ .actor }}"}`, cfg.Payload)
	})

	t.Run("nil config passthrough", func(t *testing.T) {
		got, err := renderWebhookConfig(nil, nil)
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("non-string payload passes through unchanged", func(t *testing.T) {
		payload := map[string]interface{}{"count": 5}
		cfg := &WebhookConfig{
			URL:     "https://hooks.example.com/hook",
			Payload: payload,
		}
		got, err := renderWebhookConfig(cfg, nil)
		require.NoError(t, err)
		gotPayload, ok := got.Payload.(map[string]interface{})
		require.True(t, ok, "non-string payload must retain its type")
		assert.Equal(t, 5, gotPayload["count"])
	})

	t.Run("undefined var in url produces error", func(t *testing.T) {
		cfg := &WebhookConfig{URL: "https://hooks.example.com/{{ .missing }}"}
		_, err := renderWebhookConfig(cfg, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "webhook.url")
	})

	t.Run("undefined var in string payload produces error", func(t *testing.T) {
		cfg := &WebhookConfig{
			URL:     "https://hooks.example.com/hook",
			Payload: "{{ .missing }}",
		}
		_, err := renderWebhookConfig(cfg, map[string]interface{}{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "webhook.payload")
	})
}

// TestRenderStepString verifies the renderStepString function directly.
func TestRenderStepString(t *testing.T) {
	cases := []struct {
		name    string
		tmpl    string
		vars    map[string]interface{}
		want    string
		wantErr bool
	}{
		{
			name: "plain string passthrough",
			tmpl: "https://example.com/api",
			vars: nil,
			want: "https://example.com/api",
		},
		{
			name: "simple variable substitution",
			tmpl: "{{ .org }}",
			vars: map[string]interface{}{"org": "my-org"},
			want: "my-org",
		},
		{
			name: "variable in URL path",
			tmpl: "https://api.example.com/v1/{{ .resource }}/{{ .id }}",
			vars: map[string]interface{}{"resource": "runners", "id": "42"},
			want: "https://api.example.com/v1/runners/42",
		},
		{
			name: "index function",
			tmpl: `{{ index . "key-with-dash" }}`,
			vars: map[string]interface{}{"key-with-dash": "value"},
			want: "value",
		},
		{
			name: "ne function in expression",
			tmpl: `{{ ne .count 0 }}`,
			vars: map[string]interface{}{"count": 0},
			want: "false",
		},
		{
			name:    "undefined variable produces error",
			tmpl:    "{{ .missing }}",
			vars:    map[string]interface{}{},
			wantErr: true,
		},
		{
			name:    "undefined variable in nil map produces error",
			tmpl:    "{{ .missing }}",
			vars:    nil,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderStepString(tc.tmpl, tc.vars)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// testCapturingMicrosoftProvider extends MicrosoftProvider with capture of the
// received APIConfig for test assertions. It inherits real service/operation
// metadata and config validation from MicrosoftProvider; only ExecuteOperation
// is overridden to record inputs and return a synthetic success response.
// Registered under a test-only name so it does not collide with the built-in
// "microsoft" registration.
type testCapturingMicrosoftProvider struct {
	MicrosoftProvider
	received atomic.Value // *APIConfig
}

func (p *testCapturingMicrosoftProvider) ExecuteOperation(_ context.Context, config *APIConfig) (*APIResponse, error) {
	p.received.Store(config)
	return &APIResponse{Success: true, StatusCode: 200, Data: map[string]interface{}{"ok": true}}, nil
}

// TestAPIStep_TemplateRendering verifies that the executeAPIStep call site
// renders {{ }} fields on step.API before dispatching to the provider registry.
// The registered provider must receive resolved Provider/Service/Operation and
// rendered string parameters, with non-string parameters passed through.
func TestAPIStep_TemplateRendering(t *testing.T) {
	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	provider := &testCapturingMicrosoftProvider{}
	require.NoError(t, engine.providerRegistry.RegisterProvider("capture", provider))

	workflow := Workflow{
		Name: "api-template-render-test",
		Steps: []Step{
			{
				Name: "call_api",
				Type: StepTypeAPI,
				API: &APIConfig{
					Provider:  "{{ .prov }}",
					Service:   "{{ .svc }}",
					Operation: "{{ .op }}",
					Parameters: map[string]interface{}{
						"displayName":    "{{ .name }}",
						"accountEnabled": true,
					},
				},
			},
		},
	}

	ctx := context.Background()
	variables := map[string]interface{}{
		"prov": "capture",
		"svc":  "graph",
		"op":   "createUser",
		"name": "alice",
	}

	execution, err := engine.ExecuteWorkflow(ctx, workflow, variables)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExec.GetStatus(), "workflow must complete: %s", finalExec.GetError())

	got, ok := provider.received.Load().(*APIConfig)
	require.True(t, ok, "testCapturingMicrosoftProvider must have received an APIConfig")
	assert.Equal(t, "capture", got.Provider, "provider must be rendered")
	assert.Equal(t, "graph", got.Service, "service must be rendered")
	assert.Equal(t, "createUser", got.Operation, "operation must be rendered")
	assert.Equal(t, "alice", got.Parameters["displayName"], "string parameter must be rendered")
	assert.Equal(t, true, got.Parameters["accountEnabled"], "non-string parameter must pass through")
}

// TestWebhookStep_TemplateRendering verifies that the executeWebhookStep call
// site renders {{ }} fields on step.Webhook before the request is dispatched.
// The webhook server must receive the resolved URL path, header, and payload.
func TestWebhookStep_TemplateRendering(t *testing.T) {
	var receivedPath atomic.Value
	var receivedAuthHeader atomic.Value
	var receivedBody atomic.Value

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath.Store(r.URL.Path)
		receivedAuthHeader.Store(r.Header.Get("Authorization"))
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		receivedBody.Store(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	moduleFactory := createTestFactory()
	logger := logging.NewLogger("info")
	engine := NewEngine(moduleFactory, logger, nil, nil, nil, nil, nil)

	workflow := Workflow{
		Name: "webhook-template-render-test",
		Steps: []Step{
			{
				Name: "notify",
				Type: StepTypeWebhook,
				Webhook: &WebhookConfig{
					URL:    ts.URL + "/hooks/{{ .org_name }}",
					Method: "POST",
					Headers: map[string]string{
						"Authorization": "Bearer {{ .hook_token }}",
					},
					Payload: `{"actor":"{{ .actor }}"}`,
				},
			},
		},
	}

	ctx := context.Background()
	variables := map[string]interface{}{
		"org_name":   "my-org",
		"hook_token": "tok-hook-1",
		"actor":      "runner-01",
	}

	execution, err := engine.ExecuteWorkflow(ctx, workflow, variables)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)

	finalExec, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	assert.Equal(t, StatusCompleted, finalExec.GetStatus(), "workflow must complete: %s", finalExec.GetError())

	assert.Equal(t, "/hooks/my-org", receivedPath.Load(), "URL must be rendered")
	assert.Equal(t, "Bearer tok-hook-1", receivedAuthHeader.Load(), "auth header must be rendered")

	gotBody, ok := receivedBody.Load().(map[string]interface{})
	require.True(t, ok, "payload must be a JSON object")
	assert.Equal(t, "runner-01", gotBody["actor"], "payload field must be rendered")
}
