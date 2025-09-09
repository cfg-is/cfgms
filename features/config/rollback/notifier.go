package rollback

import (
	"context"
	"log"
)

// DefaultRollbackNotifier provides a default implementation of RollbackNotifier
type DefaultRollbackNotifier struct {
	// In a real implementation, this would have email, webhook, or message queue clients
	logger *log.Logger
}

// NewDefaultRollbackNotifier creates a new default notifier
func NewDefaultRollbackNotifier(logger *log.Logger) RollbackNotifier {
	if logger == nil {
		logger = log.Default()
	}
	
	return &DefaultRollbackNotifier{
		logger: logger,
	}
}

// NotifyRollbackStarted sends a notification when rollback starts
func (n *DefaultRollbackNotifier) NotifyRollbackStarted(ctx context.Context, operation *RollbackOperation) error {
	n.logger.Printf("ROLLBACK STARTED: ID=%s, Target=%s/%s, Type=%s, User=%s",
		operation.ID,
		operation.Request.TargetType,
		operation.Request.TargetID,
		operation.Request.RollbackType,
		operation.InitiatedBy,
	)
	
	// In a real implementation, this would:
	// - Send email notifications to stakeholders
	// - Post to webhook endpoints
	// - Send to message queues (Slack, Teams, etc.)
	// - Update monitoring dashboards
	
	return nil
}

// NotifyRollbackProgress sends progress updates
func (n *DefaultRollbackNotifier) NotifyRollbackProgress(ctx context.Context, operation *RollbackOperation) error {
	n.logger.Printf("ROLLBACK PROGRESS: ID=%s, Stage=%s, Progress=%d%%, Action=%s",
		operation.ID,
		operation.Progress.Stage,
		operation.Progress.Percentage,
		operation.Progress.CurrentAction,
	)
	
	// In a real implementation, this would send progress updates
	// only at significant milestones to avoid notification spam
	
	return nil
}

// NotifyRollbackCompleted sends completion notification
func (n *DefaultRollbackNotifier) NotifyRollbackCompleted(ctx context.Context, operation *RollbackOperation) error {
	duration := "unknown"
	if operation.CompletedAt != nil {
		duration = operation.CompletedAt.Sub(operation.InitiatedAt).String()
	}
	
	n.logger.Printf("ROLLBACK COMPLETED: ID=%s, Success=%v, Duration=%s, Configs=%d, Devices=%d",
		operation.ID,
		operation.Result.Success,
		duration,
		operation.Result.ConfigurationsRolledBack,
		operation.Result.DevicesAffected,
	)
	
	// In a real implementation, this would send detailed completion reports
	
	return nil
}

// NotifyRollbackFailed sends failure notification
func (n *DefaultRollbackNotifier) NotifyRollbackFailed(ctx context.Context, operation *RollbackOperation, err error) error {
	n.logger.Printf("ROLLBACK FAILED: ID=%s, Error=%v",
		operation.ID,
		err,
	)
	
	if operation.Result != nil && len(operation.Result.Failures) > 0 {
		for _, failure := range operation.Result.Failures {
			n.logger.Printf("  - Component: %s, Error: %s, Recoverable: %v",
				failure.Component,
				failure.Error,
				failure.Recoverable,
			)
		}
	}
	
	// In a real implementation, this would:
	// - Send high-priority alerts
	// - Page on-call personnel for critical failures
	// - Create incident tickets
	
	return nil
}

// WebhookNotifier sends notifications via webhooks
type WebhookNotifier struct {
	webhookURL string
	logger     *log.Logger
}

// NewWebhookNotifier creates a new webhook notifier
func NewWebhookNotifier(webhookURL string, logger *log.Logger) RollbackNotifier {
	if logger == nil {
		logger = log.Default()
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
	// In a real implementation, this would:
	// - Marshal payload to JSON
	// - Send HTTP POST to webhook URL
	// - Handle retries and failures
	// - Respect rate limits
	
	w.logger.Printf("Webhook notification: %+v", payload)
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