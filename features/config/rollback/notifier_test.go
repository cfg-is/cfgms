// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback_test

import (
	"context"
	"errors"
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
	notifier := rollback.NewWebhookNotifier("https://example.com/webhook", nil)
	require.NotNil(t, notifier)
	// Verify no panic
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
	mock := pkgtesting.NewMockLogger(true)
	notifier := rollback.NewWebhookNotifier("https://example.com/webhook", mock)
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
