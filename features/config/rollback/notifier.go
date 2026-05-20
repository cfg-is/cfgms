// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package rollback

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// DefaultRollbackNotifier provides a default implementation of RollbackNotifier
type DefaultRollbackNotifier struct {
	logger          logging.Logger
	webhookNotifier *WebhookNotifier
}

// NewDefaultRollbackNotifier creates a new default notifier without webhook delivery.
func NewDefaultRollbackNotifier(logger logging.Logger) RollbackNotifier {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}

	return &DefaultRollbackNotifier{
		logger: logger,
	}
}

// NewDefaultRollbackNotifierWithWebhook creates a notifier that logs all events and
// delivers them via webhook when the operation completes.
func NewDefaultRollbackNotifierWithWebhook(webhookURL string, logger logging.Logger) RollbackNotifier {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	wn := &WebhookNotifier{
		webhookURL: webhookURL,
		logger:     logger,
		retryBase:  time.Second,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	return &DefaultRollbackNotifier{
		logger:          logger,
		webhookNotifier: wn,
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

	if n.webhookNotifier != nil {
		return n.webhookNotifier.NotifyRollbackStarted(ctx, operation)
	}

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

	if n.webhookNotifier != nil {
		return n.webhookNotifier.NotifyRollbackProgress(ctx, operation)
	}

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

	if n.webhookNotifier != nil {
		return n.webhookNotifier.NotifyRollbackCompleted(ctx, operation)
	}

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

	if n.webhookNotifier != nil {
		return n.webhookNotifier.NotifyRollbackFailed(ctx, operation, err)
	}

	return nil
}

// WebhookConfig holds configuration for a WebhookNotifier.
type WebhookConfig struct {
	// RetryBase is the initial delay before the first retry. Subsequent delays
	// double with each attempt. Defaults to 1 second when zero.
	RetryBase time.Duration
}

// WebhookNotifier sends notifications via webhooks
type WebhookNotifier struct {
	webhookURL string
	logger     logging.Logger
	retryBase  time.Duration
	httpClient *http.Client
}

// NewWebhookNotifier creates a new webhook notifier with production defaults
// (1-second exponential backoff, 10-second per-request timeout).
func NewWebhookNotifier(webhookURL string, logger logging.Logger) RollbackNotifier {
	return NewWebhookNotifierWithConfig(webhookURL, logger, WebhookConfig{})
}

// NewWebhookNotifierWithConfig creates a webhook notifier with caller-supplied
// configuration. Intended for use in tests where a shorter RetryBase speeds
// up the retry-behavior tests without changing production behavior.
func NewWebhookNotifierWithConfig(webhookURL string, logger logging.Logger, cfg WebhookConfig) RollbackNotifier {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	retryBase := cfg.RetryBase
	if retryBase <= 0 {
		retryBase = time.Second
	}
	return &WebhookNotifier{
		webhookURL: webhookURL,
		logger:     logger,
		retryBase:  retryBase,
		httpClient: &http.Client{Timeout: 10 * time.Second},
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
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	payload := map[string]interface{}{
		"event":     "rollback.failed",
		"operation": operation,
		"error":     errMsg,
		"result":    operation.Result,
	}

	return w.sendWebhook(ctx, payload)
}

// sendWebhook marshals payload to JSON and POSTs it to the configured URL,
// retrying up to 3 times with exponential backoff on 5xx responses or network
// errors. On permanent failure the error is logged and returned.
//
// URL scheme is validated before any network I/O — only http and https are
// accepted to prevent SSRF via exotic schemes. Only the host is logged so that
// secrets embedded in webhook URL paths (e.g. Slack signed URLs) are never
// written to log sinks.
func (w *WebhookNotifier) sendWebhook(ctx context.Context, payload interface{}) error {
	// Validate URL scheme before any network I/O to prevent SSRF via exotic schemes.
	u, err := url.Parse(w.webhookURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid webhook URL: must use http or https scheme")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

	// Log only the host, not the full URL, to avoid leaking webhook secrets
	// that may be embedded in the URL path (e.g. Slack, PagerDuty signed URLs).
	safeHost := logging.SanitizeLogValue(u.Host)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * w.retryBase
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.webhookURL, bytes.NewReader(data))
		if err != nil {
			// Malformed URL after scheme check — no point retrying.
			return fmt.Errorf("create webhook request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := w.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("webhook POST attempt %d: %w", attempt+1, err)
			w.logger.Warn("webhook delivery attempt failed",
				"attempt", attempt+1,
				"host", safeHost,
				"error", logging.SanitizeLogValue(lastErr.Error()),
			)
			continue
		}
		// Drain with a cap to enable connection reuse and bound memory on large responses.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		if err := resp.Body.Close(); err != nil {
			w.logger.Warn("failed to close webhook response body", "error", err)
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("webhook server error on attempt %d: status %d", attempt+1, resp.StatusCode)
			w.logger.Warn("webhook delivery attempt failed",
				"attempt", attempt+1,
				"host", safeHost,
				"status", resp.StatusCode,
			)
			continue
		}

		w.logger.Debug("webhook notification sent", "host", safeHost)
		return nil
	}

	w.logger.Error("webhook delivery permanently failed",
		"host", safeHost,
		"error", logging.SanitizeLogValue(lastErr.Error()),
	)
	return lastErr
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
