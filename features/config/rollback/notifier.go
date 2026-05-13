// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback

import (
	"context"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultRollbackNotifier provides a default implementation of RollbackNotifier
type DefaultRollbackNotifier struct {
	// Deferred: tracked in #1441 — add email, webhook, and message queue clients
	logger logging.Logger
}

// NewDefaultRollbackNotifier creates a new default notifier
func NewDefaultRollbackNotifier(logger logging.Logger) RollbackNotifier {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	return &DefaultRollbackNotifier{
		logger: logger,
	}
}

// NotifyRollbackStarted sends a notification when rollback starts
func (n *DefaultRollbackNotifier) NotifyRollbackStarted(ctx context.Context, operation *RollbackOperation) error {
	n.logger.Info("rollback started",
		"id", logging.SanitizeLogValue(operation.ID),
		"target_type", logging.SanitizeLogValue(string(operation.Request.TargetType)),
		"target_id", logging.SanitizeLogValue(operation.Request.TargetID),
		"rollback_type", logging.SanitizeLogValue(string(operation.Request.RollbackType)),
		"initiated_by", logging.SanitizeLogValue(operation.InitiatedBy),
	)

	// Deferred: tracked in #1441 — deliver via email, webhooks, and message queues

	return nil
}

// NotifyRollbackProgress sends progress updates
func (n *DefaultRollbackNotifier) NotifyRollbackProgress(ctx context.Context, operation *RollbackOperation) error {
	n.logger.Info("rollback progress",
		"id", logging.SanitizeLogValue(operation.ID),
		"stage", logging.SanitizeLogValue(operation.Progress.Stage),
		"percentage", operation.Progress.Percentage,
		"current_action", logging.SanitizeLogValue(operation.Progress.CurrentAction),
	)

	// Deferred: tracked in #1441 — milestone throttling; all progress events are logged

	return nil
}

// NotifyRollbackCompleted sends completion notification
func (n *DefaultRollbackNotifier) NotifyRollbackCompleted(ctx context.Context, operation *RollbackOperation) error {
	duration := "unknown"
	if operation.CompletedAt != nil {
		duration = operation.CompletedAt.Sub(operation.InitiatedAt).String()
	}

	n.logger.Info("rollback completed",
		"id", logging.SanitizeLogValue(operation.ID),
		"success", operation.Result.Success,
		"duration", duration,
		"configs_rolled_back", operation.Result.ConfigurationsRolledBack,
		"devices_affected", operation.Result.DevicesAffected,
	)

	// Deferred: tracked in #1441 — deliver completion reports via external channels

	return nil
}

// NotifyRollbackFailed sends failure notification
func (n *DefaultRollbackNotifier) NotifyRollbackFailed(ctx context.Context, operation *RollbackOperation, err error) error {
	// err is expected non-nil (this is the failure-notify path), but guard
	// defensively so a buggy caller can't crash the notifier.
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	n.logger.Error("rollback failed",
		"id", logging.SanitizeLogValue(operation.ID),
		"error", logging.SanitizeLogValue(errMsg),
	)

	if operation.Result != nil && len(operation.Result.Failures) > 0 {
		for _, failure := range operation.Result.Failures {
			n.logger.Error("rollback failure detail",
				"component", logging.SanitizeLogValue(failure.Component),
				"error", logging.SanitizeLogValue(failure.Error),
				"recoverable", failure.Recoverable,
			)
		}
	}

	// Deferred: tracked in #1441 — send alerts, page on-call, create incident tickets

	return nil
}

// WebhookNotifier sends notifications via webhooks
type WebhookNotifier struct {
	webhookURL string
	logger     logging.Logger
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string, logger logging.Logger) RollbackNotifier {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	return &WebhookNotifier{
		webhookURL: webhookURL,
		logger:     logger,
	}
}

// NotifyRollbackStarted sends webhook notification for rollback start
func (w *WebhookNotifier) NotifyRollbackStarted(ctx context.Context, operation *RollbackOperation) error {
	payload := map[string]interface{}{
		"event":     "rollback.started",
		"operation": operation,
		"timestamp": operation.InitiatedAt,
	}

	return w.sendWebhook(ctx, payload)
}

// NotifyRollbackProgress sends webhook notification for progress
func (w *WebhookNotifier) NotifyRollbackProgress(ctx context.Context, operation *RollbackOperation) error {
	// Only send progress updates at major milestones
	if operation.Progress.Percentage%25 != 0 {
		return nil
	}

	payload := map[string]interface{}{
		"event":     "rollback.progress",
		"operation": operation,
		"progress":  operation.Progress,
	}

	return w.sendWebhook(ctx, payload)
}

// NotifyRollbackCompleted sends webhook notification for completion
func (w *WebhookNotifier) NotifyRollbackCompleted(ctx context.Context, operation *RollbackOperation) error {
	payload := map[string]interface{}{
		"event":     "rollback.completed",
		"operation": operation,
		"result":    operation.Result,
		"duration":  operation.CompletedAt.Sub(operation.InitiatedAt).Seconds(),
	}

	return w.sendWebhook(ctx, payload)
}

// NotifyRollbackFailed sends webhook notification for failure
func (w *WebhookNotifier) NotifyRollbackFailed(ctx context.Context, operation *RollbackOperation, err error) error {
	payload := map[string]interface{}{
		"event":     "rollback.failed",
		"operation": operation,
		"error":     err.Error(),
		"result":    operation.Result,
	}

	return w.sendWebhook(ctx, payload)
}

func (w *WebhookNotifier) sendWebhook(ctx context.Context, payload interface{}) error {
	// Deferred: tracked in #1441 — implement HTTP POST with retry and rate-limit handling

	w.logger.Debug("webhook notification sent", "payload", payload)
	return nil
}

// CompositeNotifier combines multiple notifiers
type CompositeNotifier struct {
	notifiers []RollbackNotifier
}

// NewCompositeNotifier creates a notifier that sends to multiple destinations
func NewCompositeNotifier(notifiers ...RollbackNotifier) RollbackNotifier {
	return &CompositeNotifier{
		notifiers: notifiers,
	}
}

// NotifyRollbackStarted sends to all notifiers
func (c *CompositeNotifier) NotifyRollbackStarted(ctx context.Context, operation *RollbackOperation) error {
	var lastErr error
	for _, notifier := range c.notifiers {
		if err := notifier.NotifyRollbackStarted(ctx, operation); err != nil {
			lastErr = err
			// Continue notifying others even if one fails
		}
	}
	return lastErr
}

// NotifyRollbackProgress sends to all notifiers
func (c *CompositeNotifier) NotifyRollbackProgress(ctx context.Context, operation *RollbackOperation) error {
	var lastErr error
	for _, notifier := range c.notifiers {
		if err := notifier.NotifyRollbackProgress(ctx, operation); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// NotifyRollbackCompleted sends to all notifiers
func (c *CompositeNotifier) NotifyRollbackCompleted(ctx context.Context, operation *RollbackOperation) error {
	var lastErr error
	for _, notifier := range c.notifiers {
		if err := notifier.NotifyRollbackCompleted(ctx, operation); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// NotifyRollbackFailed sends to all notifiers
func (c *CompositeNotifier) NotifyRollbackFailed(ctx context.Context, operation *RollbackOperation, err error) error {
	var lastErr error
	for _, notifier := range c.notifiers {
		if err := notifier.NotifyRollbackFailed(ctx, operation, err); err != nil {
			lastErr = err
		}
	}
	return lastErr
}
