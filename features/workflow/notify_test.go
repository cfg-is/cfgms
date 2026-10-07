// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package workflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
)

func newNotifyEngine() *Engine {
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	allowLoopbackHTTP(engine)
	return engine
}

func runNotifyWorkflow(t *testing.T, engine *Engine, step Step, vars map[string]interface{}) *WorkflowExecution {
	t.Helper()
	wf := Workflow{Name: "notify-wf", Variables: vars, Steps: []Step{step}}
	execution, err := engine.ExecuteWorkflow(context.Background(), wf, nil)
	require.NoError(t, err)
	waitForWorkflowCompletion(t, execution, 5*time.Second)
	final, err := engine.GetExecution(execution.ID)
	require.NoError(t, err)
	return final
}

func TestNotifyStep_PostsDocumentedPayload(t *testing.T) {
	var mu sync.Mutex
	var got map[string]interface{}
	var method, contentType, authHeader string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		method = r.Method
		contentType = r.Header.Get("Content-Type")
		authHeader = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	final := runNotifyWorkflow(t, newNotifyEngine(), Step{
		Name: "tell-ops",
		Type: StepTypeNotify,
		Notify: &NotifyConfig{
			URL:      server.URL,
			Title:    "Deploy {{ .env }}",
			Message:  "Finished for {{ .env }}",
			Severity: "warning",
			Auth:     &AuthConfig{Type: AuthTypeBearer, BearerToken: "tok"},
		},
	}, map[string]interface{}{"env": "prod"})

	assert.Equal(t, StatusCompleted, final.GetStatus())
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "POST", method)
	assert.Contains(t, contentType, "application/json")
	assert.Equal(t, "Bearer tok", authHeader)
	assert.Equal(t, "Deploy prod", got["title"])
	assert.Equal(t, "Finished for prod", got["message"])
	assert.Equal(t, "warning", got["severity"])
	assert.Equal(t, "notify-wf", got["workflow"])
	assert.Equal(t, final.ID, got["execution_id"])
	assert.Equal(t, "tell-ops", got["step"])
	assert.Equal(t, 200, final.Variables["tell-ops_notify_status"])
}

func TestNotifyStep_DefaultSeverityIsInfo(t *testing.T) {
	var mu sync.Mutex
	var got map[string]interface{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		_ = json.NewDecoder(r.Body).Decode(&got)
	}))
	defer server.Close()

	final := runNotifyWorkflow(t, newNotifyEngine(), Step{
		Name:   "n",
		Type:   StepTypeNotify,
		Notify: &NotifyConfig{URL: server.URL, Title: "t"},
	}, nil)
	assert.Equal(t, StatusCompleted, final.GetStatus())
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "info", got["severity"])
}

func TestNotifyStep_RetryConfigHonoured(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	final := runNotifyWorkflow(t, newNotifyEngine(), Step{
		Name: "n",
		Type: StepTypeNotify,
		Notify: &NotifyConfig{
			URL:   server.URL,
			Title: "t",
			Retry: &RetryConfig{
				MaxAttempts:          3,
				InitialDelay:         time.Millisecond,
				MaxDelay:             5 * time.Millisecond,
				BackoffMultiplier:    1,
				RetryableStatusCodes: []int{503},
			},
		},
	}, nil)
	assert.Equal(t, StatusCompleted, final.GetStatus())
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls))
}

func TestNotifyStep_NoRetryWithoutConfig(t *testing.T) {
	var calls int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	final := runNotifyWorkflow(t, newNotifyEngine(), Step{
		Name:   "n",
		Type:   StepTypeNotify,
		Notify: &NotifyConfig{URL: server.URL, Title: "t"},
	}, nil)
	assert.Equal(t, StatusFailed, final.GetStatus())
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

func TestNotifyStep_RetryConfigLookup(t *testing.T) {
	r := &RetryConfig{MaxAttempts: 4}
	assert.Same(t, r, retryConfigForStep(Step{Type: StepTypeNotify, Notify: &NotifyConfig{Retry: r}}))
	assert.Nil(t, retryConfigForStep(Step{Type: StepTypeNotify}))
}

func TestNotifyStep_MissingConfigFails(t *testing.T) {
	engine := newNotifyEngine()
	err := engine.executeNotifyStep(context.Background(), Step{Name: "n", Type: StepTypeNotify}, &WorkflowExecution{})
	require.Error(t, err)
}

func TestNotifyStep_PrivateDestinationRefusedByDefaultEngine(t *testing.T) {
	var hit int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hit, 1)
	}))
	defer server.Close()

	// Default engine: no allowLoopbackHTTP.
	engine := NewEngine(createTestFactory(), logging.NewNoopLogger(), nil, nil, nil, nil, nil)
	final := runNotifyWorkflow(t, engine, Step{
		Name:   "n",
		Type:   StepTypeNotify,
		Notify: &NotifyConfig{URL: server.URL, Title: "t"},
	}, nil)
	assert.Equal(t, StatusFailed, final.GetStatus())
	assert.Equal(t, int32(0), atomic.LoadInt32(&hit), "loopback receiver must never be contacted")
}

func TestParser_Notify(t *testing.T) {
	p := NewParser()
	yml := func(notify string) []byte {
		return []byte("workflow:\n  name: w\n  steps:\n    - name: n\n      type: notify\n      notify:\n" + notify)
	}

	wf, err := p.ParseYAML(yml("        url: https://hooks.example.com/x\n        title: T\n        message: M\n        severity: critical\n        timeout: 5s\n        headers:\n          X-A: b\n        retry:\n          max_attempts: 3\n"))
	require.NoError(t, err)
	n := wf.Steps[0].Notify
	require.NotNil(t, n)
	assert.Equal(t, "https://hooks.example.com/x", n.URL)
	assert.Equal(t, "T", n.Title)
	assert.Equal(t, "M", n.Message)
	assert.Equal(t, "critical", n.Severity)
	assert.Equal(t, 5*time.Second, n.Timeout)
	assert.Equal(t, "b", n.Headers["X-A"])
	require.NotNil(t, n.Retry)
	assert.Equal(t, 3, n.Retry.MaxAttempts)

	_, err = p.ParseYAML(yml("        title: T\n"))
	assert.ErrorContains(t, err, "url")
	_, err = p.ParseYAML(yml("        url: https://hooks.example.com/x\n"))
	assert.ErrorContains(t, err, "title")
	_, err = p.ParseYAML(yml("        url: https://hooks.example.com/x\n        title: T\n        severity: panic\n"))
	assert.ErrorContains(t, err, "severity")
	_, err = p.ParseYAML([]byte("workflow:\n  name: w\n  steps:\n    - name: n\n      type: notify\n"))
	assert.ErrorContains(t, err, "notify")
}
