// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/rbac/jit"
)

func TestStaticApproverRegistry_GetApprovers(t *testing.T) {
	t.Run("returns recipients for known escalation type", func(t *testing.T) {
		registry := jit.NewStaticApproverRegistry(map[string][]string{
			"escalation": {"admin@example.com", "security@example.com"},
		})
		recipients, err := registry.GetApprovers(context.Background(), "escalation")
		require.NoError(t, err)
		assert.Equal(t, []string{"admin@example.com", "security@example.com"}, recipients)
	})

	t.Run("falls back to default key for unmapped type", func(t *testing.T) {
		registry := jit.NewStaticApproverRegistry(map[string][]string{
			"": {"fallback@example.com"},
		})
		recipients, err := registry.GetApprovers(context.Background(), "some-other-type")
		require.NoError(t, err)
		assert.Equal(t, []string{"fallback@example.com"}, recipients)
	})

	t.Run("returns nil for unknown type with no fallback", func(t *testing.T) {
		registry := jit.NewStaticApproverRegistry(map[string][]string{})
		recipients, err := registry.GetApprovers(context.Background(), "escalation")
		require.NoError(t, err)
		assert.Nil(t, recipients)
	})

	t.Run("explicit type takes precedence over fallback", func(t *testing.T) {
		registry := jit.NewStaticApproverRegistry(map[string][]string{
			"escalation": {"specific@example.com"},
			"":           {"fallback@example.com"},
		})
		recipients, err := registry.GetApprovers(context.Background(), "escalation")
		require.NoError(t, err)
		assert.Equal(t, []string{"specific@example.com"}, recipients)
	})
}

func TestSendEscalationNotification_UsesRegistry(t *testing.T) {
	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com", "security@example.com"},
	})
	svc := jit.NewSimpleNotificationServiceWithRegistry(registry)

	req := &jit.JITAccessRequest{
		ID:          "req-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.NoError(t, err)

	history, err := svc.GetNotificationHistory(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, []string{"admin@example.com", "security@example.com"}, history[0].Recipients)
}

func TestSendEscalationNotification_HardcodedRecipientsNotUsed(t *testing.T) {
	// Verify old hardcoded values are not present — registry is the sole source of recipients.
	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"custom-admin@example.com"},
	})
	svc := jit.NewSimpleNotificationServiceWithRegistry(registry)

	req := &jit.JITAccessRequest{
		ID:          "req-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 2)
	require.NoError(t, err)

	history, err := svc.GetNotificationHistory(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, history, 1)

	for _, r := range history[0].Recipients {
		assert.NotEqual(t, "security-admin", r, "hardcoded recipient must not appear")
		assert.NotEqual(t, "compliance-officer", r, "hardcoded recipient must not appear")
	}
	assert.Equal(t, []string{"custom-admin@example.com"}, history[0].Recipients)
}

func TestSendEscalationNotification_EmptyRegistryWarnsAndDoesNotDrop(t *testing.T) {
	var logBuf bytes.Buffer
	original := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logBuf, nil)))
	defer slog.SetDefault(original)

	registry := jit.NewStaticApproverRegistry(map[string][]string{})
	svc := jit.NewSimpleNotificationServiceWithRegistry(registry)

	req := &jit.JITAccessRequest{
		ID:          "req-empty",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.NoError(t, err, "empty registry must not drop the escalation")

	logOutput := logBuf.String()
	assert.True(t, strings.Contains(logOutput, "WARN") || strings.Contains(logOutput, "warn"),
		"expected warning log when registry returns empty, got: %q", logOutput)

	history, err := svc.GetNotificationHistory(context.Background(), nil)
	require.NoError(t, err)
	assert.Len(t, history, 1, "escalation must be recorded even with empty recipient list")
}

func TestSendEscalationNotification_RegistryChangeAffectsRecipients(t *testing.T) {
	// Changing the registry config changes the recipients without code modification (AC #2).
	registryV1 := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"v1-admin@example.com"},
	})
	svcV1 := jit.NewSimpleNotificationServiceWithRegistry(registryV1)

	registryV2 := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"v2-admin@example.com", "v2-security@example.com"},
	})
	svcV2 := jit.NewSimpleNotificationServiceWithRegistry(registryV2)

	req := &jit.JITAccessRequest{
		ID:          "req-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	ctx := context.Background()
	require.NoError(t, svcV1.SendEscalationNotification(ctx, req, 1))
	require.NoError(t, svcV2.SendEscalationNotification(ctx, req, 1))

	histV1, err := svcV1.GetNotificationHistory(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"v1-admin@example.com"}, histV1[0].Recipients)

	histV2, err := svcV2.GetNotificationHistory(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, []string{"v2-admin@example.com", "v2-security@example.com"}, histV2[0].Recipients)
}

func TestSendEscalationNotification_RegistryError(t *testing.T) {
	svc := jit.NewSimpleNotificationServiceWithRegistry(&errorRegistry{})

	req := &jit.JITAccessRequest{
		ID:          "req-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approver registry lookup failed")
}

// errorRegistry is a test-only ApproverRegistry that always returns an error.
type errorRegistry struct{}

func (e *errorRegistry) GetApprovers(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("registry unavailable")
}

// --- WebhookNotificationService tests ---

func TestWebhookNotificationService_SendEscalationNotification_DeliversPayload(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received = body
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com", "security@example.com"},
	})
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-webhook-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin", "sudo"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 2)
	require.NoError(t, err)
	require.NotEmpty(t, received)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(received, &payload))

	assert.Equal(t, "jit.escalation", payload["event"])
	assert.NotEmpty(t, payload["escalation_id"])
	assert.Equal(t, "req-webhook-1", payload["request_id"])
	assert.Equal(t, "user1", payload["requesting_user"])
	assert.NotEmpty(t, payload["timestamp"])
	assert.InDelta(t, float64(2), payload["escalation_level"], 0)

	approvers, ok := payload["approvers"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"admin@example.com", "security@example.com"}, approvers)

	perms, ok := payload["requested_permissions"].([]interface{})
	require.True(t, ok)
	assert.ElementsMatch(t, []interface{}{"admin", "sudo"}, perms)
}

func TestWebhookNotificationService_SendEscalationNotification_StoresInMemoryAfterSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com"},
	})
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-mem-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.NoError(t, err)

	history, err := svc.GetNotificationHistory(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, jit.NotificationTypeEscalation, history[0].Type)
	assert.Equal(t, []string{"admin@example.com"}, history[0].Recipients)
}

func TestWebhookNotificationService_SendEscalationNotification_RetriesOnServerError(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		if attemptCount < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com"},
	})
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-retry-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.NoError(t, err)
	assert.Equal(t, 3, attemptCount, "expected 3 attempts before success")
}

func TestWebhookNotificationService_SendEscalationNotification_FailsAfterMaxRetries(t *testing.T) {
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com"},
	})
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-fail-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.Error(t, err)
	assert.Equal(t, 3, attemptCount, "expected exactly 3 attempts before permanent failure")

	// Must NOT record in memory when delivery fails
	history, histErr := svc.GetNotificationHistory(context.Background(), nil)
	require.NoError(t, histErr)
	assert.Empty(t, history, "failed delivery must not leave a phantom record in memory")
}

func TestWebhookNotificationService_SendEscalationNotification_InvalidWebhookURL(t *testing.T) {
	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com"},
	})

	for _, badURL := range []string{"file:///etc/passwd", "ftp://host/path", "not-a-url"} {
		svc := jit.NewWebhookNotificationServiceWithConfig(badURL, registry, jit.WebhookNotificationConfig{
			RetryBase: time.Millisecond,
		})
		req := &jit.JITAccessRequest{
			ID:          "req-ssrf-1",
			RequesterID: "user1",
			TenantID:    "tenant1",
			Permissions: []string{"admin"},
		}
		err := svc.SendEscalationNotification(context.Background(), req, 1)
		require.Error(t, err, "expected error for URL: %s", badURL)
		assert.Contains(t, err.Error(), "invalid webhook URL", "URL: %s", badURL)
	}
}

func TestWebhookNotificationService_SendEscalationNotification_ContextCancellationDuringRetry(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always return 503 to force retries
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com"},
	})
	// retryBase of 2s ensures context expires during backoff sleep (100ms context timeout)
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: 2 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	req := &jit.JITAccessRequest{
		ID:          "req-ctx-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(ctx, req, 1)
	require.Error(t, err, "expected error when context is cancelled")
}

func TestWebhookNotificationService_SendEscalationNotification_RegistryError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, &errorRegistry{}, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-reg-err-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "approver registry lookup failed")
}

func TestWebhookNotificationService_SendEscalationNotification_ClientErrorIsNotRetried(t *testing.T) {
	// 4xx responses indicate permanent misconfiguration (rejected payload) — must return
	// an error immediately without retry so the caller knows the escalation was not delivered.
	attemptCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attemptCount++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	registry := jit.NewStaticApproverRegistry(map[string][]string{
		jit.EscalationTypeDefault: {"admin@example.com"},
	})
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-4xx-1",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.Error(t, err, "4xx response must return an error")
	assert.Contains(t, err.Error(), "webhook rejected")
	assert.Equal(t, 1, attemptCount, "4xx must not be retried")
}

func TestWebhookNotificationService_SendEscalationNotification_EmptyApproversDelivers(t *testing.T) {
	var received []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		received = body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Registry with no recipients for the default escalation type
	registry := jit.NewStaticApproverRegistry(map[string][]string{})
	svc := jit.NewWebhookNotificationServiceWithConfig(server.URL, registry, jit.WebhookNotificationConfig{
		RetryBase: time.Millisecond,
	})

	req := &jit.JITAccessRequest{
		ID:          "req-empty-2",
		RequesterID: "user1",
		TenantID:    "tenant1",
		Permissions: []string{"admin"},
	}

	err := svc.SendEscalationNotification(context.Background(), req, 1)
	require.NoError(t, err, "empty approver list must not block delivery")

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(received, &payload))

	approvers, ok := payload["approvers"].([]interface{})
	require.True(t, ok, "approvers field must be an array even when empty")
	assert.Empty(t, approvers)
}
