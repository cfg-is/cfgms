// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit_test

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

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
	return nil, assert.AnError
}
