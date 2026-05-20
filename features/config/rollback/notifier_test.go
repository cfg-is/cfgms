// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/config/rollback"
	pkgtesting "github.com/cfgis/cfgms/pkg/testing"
)

func TestNewDefaultRollbackNotifier_nilLogger_usesNoop(t *testing.T) {
	notifier := rollback.NewDefaultRollbackNotifier(nil)
	require.NotNil(t, notifier)
	// Verify it doesn't panic when used
	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-op-1",
		InitiatedBy: "test-user",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   rollback.TargetTypeClient,
			TargetID:     "client-1",
			RollbackType: rollback.RollbackTypeFull,
		},
		Progress: rollback.RollbackProgress{
			Stage:         "executing",
			Percentage:    50,
			CurrentAction: "rolling back",
		},
	}
	err := notifier.NotifyRollbackStarted(ctx, op)
	assert.NoError(t, err)
}

func TestNewDefaultRollbackNotifier_injectsLogger(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewDefaultRollbackNotifier(mock)
	require.NotNil(t, notifier)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-op-1",
		InitiatedBy: "test-user",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   rollback.TargetTypeClient,
			TargetID:     "client-1",
			RollbackType: rollback.RollbackTypeFull,
		},
		Progress: rollback.RollbackProgress{
			Stage:         "executing",
			Percentage:    50,
			CurrentAction: "rolling back",
		},
		Result: &rollback.RollbackResult{},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	assert.NoError(t, err)
	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "rollback started", infoLogs[0].Message)
}

func TestDefaultRollbackNotifier_logsProgress(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewDefaultRollbackNotifier(mock)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-op-2",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{RollbackType: rollback.RollbackTypePartial},
		Progress: rollback.RollbackProgress{
			Stage:         "executing",
			Percentage:    75,
			CurrentAction: "processing",
		},
	}

	err := notifier.NotifyRollbackProgress(ctx, op)
	assert.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "rollback progress", infoLogs[0].Message)
}

func TestDefaultRollbackNotifier_logsCompleted(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewDefaultRollbackNotifier(mock)

	ctx := context.Background()
	completedAt := time.Now()
	op := &rollback.RollbackOperation{
		ID:          "test-op-3",
		InitiatedAt: time.Now().Add(-5 * time.Second),
		CompletedAt: &completedAt,
		Request:     rollback.RollbackRequest{RollbackType: rollback.RollbackTypeFull},
		Result: &rollback.RollbackResult{
			Success:                  true,
			ConfigurationsRolledBack: 3,
			DevicesAffected:          10,
		},
	}

	err := notifier.NotifyRollbackCompleted(ctx, op)
	assert.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "rollback completed", infoLogs[0].Message)
}

func TestDefaultRollbackNotifier_logsFailedAsError(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewDefaultRollbackNotifier(mock)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-op-4",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{RollbackType: rollback.RollbackTypeFull},
		Result:      &rollback.RollbackResult{},
	}

	err := notifier.NotifyRollbackFailed(ctx, op, errors.New("simulated failure"))
	assert.NoError(t, err)

	errorLogs := mock.GetLogs("error")
	require.NotEmpty(t, errorLogs)
	assert.Equal(t, "rollback failed", errorLogs[0].Message)
}

func TestNewWebhookNotifier_nilLogger_usesNoop(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	notifier := rollback.NewWebhookNotifier(server.URL, nil)
	require.NotNil(t, notifier)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-op-5",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{},
		Progress:    rollback.RollbackProgress{Percentage: 0},
	}
	err := notifier.NotifyRollbackStarted(ctx, op)
	assert.NoError(t, err)
}

func TestNewWebhookNotifier_logsDebugOnSend(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewWebhookNotifier(server.URL, mock)
	require.NotNil(t, notifier)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-op-6",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{},
	}
	err := notifier.NotifyRollbackStarted(ctx, op)
	assert.NoError(t, err)

	debugLogs := mock.GetLogs("debug")
	require.NotEmpty(t, debugLogs)
	assert.Equal(t, "webhook notification sent", debugLogs[0].Message)
}

func TestWebhookNotifier_POSTsJSONPayload(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte
	var receivedContentType string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		receivedContentType = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewWebhookNotifier(server.URL, mock)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-payload",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{RollbackType: rollback.RollbackTypeFull},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.NoError(t, err)

	mu.Lock()
	body := receivedBody
	ct := receivedContentType
	mu.Unlock()

	assert.Equal(t, "application/json", ct)
	require.NotEmpty(t, body)

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, "rollback.started", decoded["event"])
	assert.NotNil(t, decoded["operation"])
}

func TestWebhookNotifier_retriesOn5xx(t *testing.T) {
	var mu sync.Mutex
	attempts := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	cfg := rollback.WebhookConfig{RetryBase: 10 * time.Millisecond}
	notifier := rollback.NewWebhookNotifierWithConfig(server.URL, mock, cfg)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-retry-5xx",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.NoError(t, err)

	mu.Lock()
	total := attempts
	mu.Unlock()
	assert.Equal(t, 3, total)

	warnLogs := mock.GetLogs("warn")
	assert.Len(t, warnLogs, 2)
}

func TestWebhookNotifier_permanentFailureAfter3Retries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	cfg := rollback.WebhookConfig{RetryBase: 10 * time.Millisecond}
	notifier := rollback.NewWebhookNotifierWithConfig(server.URL, mock, cfg)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-perm-fail",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.Error(t, err)

	warnLogs := mock.GetLogs("warn")
	assert.Len(t, warnLogs, 3)

	errorLogs := mock.GetLogs("error")
	require.NotEmpty(t, errorLogs)
	assert.Equal(t, "webhook delivery permanently failed", errorLogs[0].Message)
}

func TestWebhookNotifier_retriesOnNetworkError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	serverURL := server.URL
	server.Close()

	mock := pkgtesting.NewMockLogger(true)
	cfg := rollback.WebhookConfig{RetryBase: 10 * time.Millisecond}
	notifier := rollback.NewWebhookNotifierWithConfig(serverURL, mock, cfg)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-network-err",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.Error(t, err)

	warnLogs := mock.GetLogs("warn")
	assert.Len(t, warnLogs, 3)

	errorLogs := mock.GetLogs("error")
	require.NotEmpty(t, errorLogs)
	assert.Equal(t, "webhook delivery permanently failed", errorLogs[0].Message)
}

func TestWebhookNotifier_contextCanceledDuringRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	// Use a long retry base so the context cancel fires during backoff
	cfg := rollback.WebhookConfig{RetryBase: 5 * time.Second}
	notifier := rollback.NewWebhookNotifierWithConfig(server.URL, mock, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	op := &rollback.RollbackOperation{
		ID:          "test-ctx-cancel",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestWebhookNotifier_rejectsNonHTTPScheme(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	for _, badURL := range []string{
		"ftp://example.com/hook",
		"file:///etc/passwd",
		"javascript:alert(1)",
		"://bad",
	} {
		notifier := rollback.NewWebhookNotifier(badURL, mock)
		ctx := context.Background()
		op := &rollback.RollbackOperation{
			ID:          "test-bad-scheme",
			InitiatedAt: time.Now(),
			Request:     rollback.RollbackRequest{},
		}
		err := notifier.NotifyRollbackStarted(ctx, op)
		require.Error(t, err, "URL %q should be rejected", badURL)
		assert.Contains(t, err.Error(), "invalid webhook URL")
	}
}

func TestDefaultRollbackNotifier_delegatesToWebhookWhenURLConfigured(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		receivedBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewDefaultRollbackNotifierWithWebhook(server.URL, mock)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-delegate",
		InitiatedBy: "admin",
		InitiatedAt: time.Now(),
		Request: rollback.RollbackRequest{
			TargetType:   rollback.TargetTypeClient,
			TargetID:     "client-1",
			RollbackType: rollback.RollbackTypeFull,
		},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.NoError(t, err)

	mu.Lock()
	body := receivedBody
	mu.Unlock()

	require.NotEmpty(t, body, "DefaultRollbackNotifier with webhook URL must deliver via HTTP POST")

	var decoded map[string]interface{}
	require.NoError(t, json.Unmarshal(body, &decoded))
	assert.Equal(t, "rollback.started", decoded["event"])

	// Must also log the event
	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "rollback started", infoLogs[0].Message)
}

func TestDefaultRollbackNotifier_noWebhookWhenURLNotConfigured(t *testing.T) {
	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewDefaultRollbackNotifier(mock)

	ctx := context.Background()
	op := &rollback.RollbackOperation{
		ID:          "test-no-webhook",
		InitiatedAt: time.Now(),
		Request:     rollback.RollbackRequest{RollbackType: rollback.RollbackTypeFull},
	}

	err := notifier.NotifyRollbackStarted(ctx, op)
	require.NoError(t, err)

	infoLogs := mock.GetLogs("info")
	require.NotEmpty(t, infoLogs)
	assert.Equal(t, "rollback started", infoLogs[0].Message)
}

func TestWebhookNotifier_allFourLifecycleEventsDeliver(t *testing.T) {
	var mu sync.Mutex
	var events []string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]interface{}
		if err := json.Unmarshal(body, &decoded); err == nil {
			if ev, ok := decoded["event"].(string); ok {
				mu.Lock()
				events = append(events, ev)
				mu.Unlock()
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewWebhookNotifier(server.URL, mock)

	ctx := context.Background()
	completedAt := time.Now()
	op := &rollback.RollbackOperation{
		ID:          "test-lifecycle",
		InitiatedAt: time.Now().Add(-2 * time.Second),
		CompletedAt: &completedAt,
		Request:     rollback.RollbackRequest{RollbackType: rollback.RollbackTypeFull},
		Progress:    rollback.RollbackProgress{Percentage: 25},
		Result: &rollback.RollbackResult{
			Success: true,
		},
	}

	require.NoError(t, notifier.NotifyRollbackStarted(ctx, op))
	require.NoError(t, notifier.NotifyRollbackProgress(ctx, op))
	require.NoError(t, notifier.NotifyRollbackCompleted(ctx, op))
	require.NoError(t, notifier.NotifyRollbackFailed(ctx, op, errors.New("test failure")))

	mu.Lock()
	captured := make([]string, len(events))
	copy(captured, events)
	mu.Unlock()

	// Progress fires only at 25% milestones; 25 % 25 == 0 so it fires
	assert.Contains(t, captured, "rollback.started")
	assert.Contains(t, captured, "rollback.progress")
	assert.Contains(t, captured, "rollback.completed")
	assert.Contains(t, captured, "rollback.failed")
}
