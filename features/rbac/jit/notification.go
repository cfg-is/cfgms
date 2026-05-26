// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package jit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// SimpleNotificationService provides a basic implementation of NotificationService
type SimpleNotificationService struct {
	// Deferred: tracked in #1441 — integrate with email, Slack, and other delivery channels
	notifications []NotificationRecord
	registry      ApproverRegistry
}

// NewSimpleNotificationService creates a new simple notification service without a registry.
// SendEscalationNotification will log a warning and record the notification with no recipients.
func NewSimpleNotificationService() *SimpleNotificationService {
	return &SimpleNotificationService{
		notifications: make([]NotificationRecord, 0),
	}
}

// NewSimpleNotificationServiceWithRegistry creates a notification service that resolves
// escalation recipients from the provided ApproverRegistry.
func NewSimpleNotificationServiceWithRegistry(registry ApproverRegistry) *SimpleNotificationService {
	return &SimpleNotificationService{
		notifications: make([]NotificationRecord, 0),
		registry:      registry,
	}
}

// NotificationRecord represents a notification that was sent
type NotificationRecord struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	Type       NotificationType       `json:"type"`
	Recipients []string               `json:"recipients"`
	Subject    string                 `json:"subject"`
	Message    string                 `json:"message"`
	Channel    NotificationChannel    `json:"channel"`
	Status     NotificationStatus     `json:"status"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// NotificationType defines types of notifications
type NotificationType string

const (
	NotificationTypeRequestCreated   NotificationType = "request_created"
	NotificationTypeRequestApproved  NotificationType = "request_approved"
	NotificationTypeRequestDenied    NotificationType = "request_denied"
	NotificationTypeApprovalRequired NotificationType = "approval_required"
	NotificationTypeApprovalReminder NotificationType = "approval_reminder"
	NotificationTypeAccessGranted    NotificationType = "access_granted"
	NotificationTypeAccessExpiring   NotificationType = "access_expiring"
	NotificationTypeAccessRevoked    NotificationType = "access_revoked"
	NotificationTypeAccessExtended   NotificationType = "access_extended"
	NotificationTypeEscalation       NotificationType = "escalation"
	NotificationTypePolicyViolation  NotificationType = "policy_violation"
	NotificationTypeComplianceAlert  NotificationType = "compliance_alert"
)

// NotificationChannel defines notification delivery channels
type NotificationChannel string

const (
	NotificationChannelEmail   NotificationChannel = "email"
	NotificationChannelSlack   NotificationChannel = "slack"
	NotificationChannelWebhook NotificationChannel = "webhook"
	NotificationChannelInApp   NotificationChannel = "in_app"
	NotificationChannelSMS     NotificationChannel = "sms"
)

// NotificationStatus defines notification delivery status
type NotificationStatus string

const (
	NotificationStatusPending   NotificationStatus = "pending"
	NotificationStatusSent      NotificationStatus = "sent"
	NotificationStatusDelivered NotificationStatus = "delivered"
	NotificationStatusFailed    NotificationStatus = "failed"
	NotificationStatusRead      NotificationStatus = "read"
)

// SendRequestNotification sends notifications for request events
func (sns *SimpleNotificationService) SendRequestNotification(ctx context.Context, request *JITAccessRequest, eventType string) error {
	var notificationType NotificationType
	var recipients []string
	var subject, message string

	switch eventType {
	case "request_created":
		notificationType = NotificationTypeRequestCreated
		recipients = []string{request.RequesterID}
		subject = "JIT Access Request Created"
		message = fmt.Sprintf("Your JIT access request for %v permissions has been submitted and is pending approval.", request.Permissions)

	case "request_approved":
		notificationType = NotificationTypeRequestApproved
		recipients = []string{request.RequesterID}
		subject = "JIT Access Request Approved"
		message = fmt.Sprintf("Your JIT access request has been approved by %s. Access is now active.", request.ApprovedBy)

	case "request_denied":
		notificationType = NotificationTypeRequestDenied
		recipients = []string{request.RequesterID}
		subject = "JIT Access Request Denied"
		message = fmt.Sprintf("Your JIT access request has been denied. Reason: %s", request.DenialReason)

	default:
		return fmt.Errorf("unknown request event type: %s", eventType)
	}

	return sns.sendNotification(ctx, notificationType, recipients, subject, message, map[string]interface{}{
		"request_id": request.ID,
		"tenant_id":  request.TenantID,
		"event_type": eventType,
	})
}

// SendApprovalNotification sends notifications to approvers
func (sns *SimpleNotificationService) SendApprovalNotification(ctx context.Context, request *JITAccessRequest, approvers []string) error {
	subject := "JIT Access Approval Required"
	message := fmt.Sprintf(
		"JIT access approval required for user %s requesting %v permissions. Justification: %s",
		request.RequesterID,
		request.Permissions,
		request.Justification,
	)

	// Add urgency indicators
	if request.EmergencyAccess {
		subject = "[EMERGENCY] " + subject
		message = "[EMERGENCY ACCESS] " + message
	} else if request.Priority == AccessPriorityCritical {
		subject = "[HIGH PRIORITY] " + subject
	}

	return sns.sendNotification(ctx, NotificationTypeApprovalRequired, approvers, subject, message, map[string]interface{}{
		"request_id":         request.ID,
		"tenant_id":          request.TenantID,
		"emergency":          request.EmergencyAccess,
		"priority":           request.Priority,
		"requested_duration": request.Duration.String(),
	})
}

// SendReminderNotification sends reminder notifications
func (sns *SimpleNotificationService) SendReminderNotification(ctx context.Context, request *JITAccessRequest, recipient string) error {
	subject := "JIT Access Approval Reminder"
	message := fmt.Sprintf(
		"Reminder: JIT access approval pending for user %s. Request ID: %s",
		request.RequesterID,
		request.ID,
	)

	return sns.sendNotification(ctx, NotificationTypeApprovalReminder, []string{recipient}, subject, message, map[string]interface{}{
		"request_id": request.ID,
		"tenant_id":  request.TenantID,
		"reminder":   true,
	})
}

// SendGrantNotification sends notifications for grant events
func (sns *SimpleNotificationService) SendGrantNotification(ctx context.Context, grant *JITAccessGrant, eventType string) error {
	var notificationType NotificationType
	var subject, message string

	switch eventType {
	case "access_granted":
		notificationType = NotificationTypeAccessGranted
		subject = "JIT Access Granted"
		message = fmt.Sprintf("JIT access has been activated. Expires at: %s", grant.ExpiresAt.Format(time.RFC3339))

	case "access_extended":
		notificationType = NotificationTypeAccessExtended
		subject = "JIT Access Extended"
		message = fmt.Sprintf("Your JIT access has been extended. New expiration: %s", grant.ExpiresAt.Format(time.RFC3339))

	default:
		return fmt.Errorf("unknown grant event type: %s", eventType)
	}

	recipients := []string{grant.RequesterID}
	if grant.TargetID != "" && grant.TargetID != grant.RequesterID {
		recipients = append(recipients, grant.TargetID)
	}

	return sns.sendNotification(ctx, notificationType, recipients, subject, message, map[string]interface{}{
		"grant_id":   grant.ID,
		"tenant_id":  grant.TenantID,
		"expires_at": grant.ExpiresAt,
		"event_type": eventType,
	})
}

// SendExpirationWarning sends warnings about upcoming access expiration
func (sns *SimpleNotificationService) SendExpirationWarning(ctx context.Context, grant *JITAccessGrant, timeUntilExpiry time.Duration) error {
	subject := "JIT Access Expiring Soon"
	message := fmt.Sprintf(
		"Your JIT access will expire in %s (at %s). Request an extension if needed.",
		timeUntilExpiry.Round(time.Minute).String(),
		grant.ExpiresAt.Format(time.RFC3339),
	)

	recipients := []string{grant.RequesterID}
	if grant.TargetID != "" && grant.TargetID != grant.RequesterID {
		recipients = append(recipients, grant.TargetID)
	}

	return sns.sendNotification(ctx, NotificationTypeAccessExpiring, recipients, subject, message, map[string]interface{}{
		"grant_id":             grant.ID,
		"tenant_id":            grant.TenantID,
		"expires_at":           grant.ExpiresAt,
		"time_until_expiry":    timeUntilExpiry,
		"can_extend":           grant.ExtensionsUsed < grant.MaxExtensions,
		"extensions_remaining": grant.MaxExtensions - grant.ExtensionsUsed,
	})
}

// SendRevocationNotification sends notifications about access revocation
func (sns *SimpleNotificationService) SendRevocationNotification(ctx context.Context, grant *JITAccessGrant, reason string) error {
	subject := "JIT Access Revoked"
	message := fmt.Sprintf(
		"Your JIT access has been revoked by %s. Reason: %s",
		grant.RevokedBy,
		reason,
	)

	recipients := []string{grant.RequesterID}
	if grant.TargetID != "" && grant.TargetID != grant.RequesterID {
		recipients = append(recipients, grant.TargetID)
	}

	return sns.sendNotification(ctx, NotificationTypeAccessRevoked, recipients, subject, message, map[string]interface{}{
		"grant_id":   grant.ID,
		"tenant_id":  grant.TenantID,
		"revoked_by": grant.RevokedBy,
		"reason":     reason,
		"revoked_at": grant.RevokedAt,
	})
}

// SendEscalationNotification sends escalation notifications.
// Recipients are resolved from the ApproverRegistry; if none are configured a warning is
// logged and the notification is still recorded so the event is not silently dropped.
func (sns *SimpleNotificationService) SendEscalationNotification(ctx context.Context, request *JITAccessRequest, escalationLevel int) error {
	subject := fmt.Sprintf("[ESCALATION LEVEL %d] JIT Access Approval Required", escalationLevel)
	message := fmt.Sprintf(
		"JIT access request %s has been escalated to level %d due to lack of approval. Original request from %s for %v permissions.",
		request.ID,
		escalationLevel,
		request.RequesterID,
		request.Permissions,
	)

	var recipients []string
	if sns.registry != nil {
		resolved, err := sns.registry.GetApprovers(ctx, EscalationTypeDefault)
		if err != nil {
			return fmt.Errorf("approver registry lookup failed: %w", err)
		}
		recipients = resolved
	}

	if len(recipients) == 0 {
		slog.Warn("no escalation recipients configured; notification recorded with empty recipient list",
			"request_id", request.ID,
			"tenant_id", request.TenantID,
			"escalation_level", escalationLevel,
		)
	}

	return sns.sendNotification(ctx, NotificationTypeEscalation, recipients, subject, message, map[string]interface{}{
		"request_id":         request.ID,
		"tenant_id":          request.TenantID,
		"escalation_level":   escalationLevel,
		"original_requester": request.RequesterID,
		"emergency_access":   request.EmergencyAccess,
	})
}

// sendNotification is the internal method that handles actual notification sending
func (sns *SimpleNotificationService) sendNotification(ctx context.Context, notificationType NotificationType, recipients []string, subject, message string, metadata map[string]interface{}) error {
	record := NotificationRecord{
		ID:         fmt.Sprintf("notif-%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		Type:       notificationType,
		Recipients: recipients,
		Subject:    subject,
		Message:    message,
		Channel:    NotificationChannelEmail, // Default channel
		Status:     NotificationStatusSent,   // Simulate successful sending
		Metadata:   metadata,
	}

	sns.notifications = append(sns.notifications, record)

	// Deferred: tracked in #1441 — implement multi-channel delivery with retry and delivery tracking

	return nil
}

// GetNotificationHistory returns notification history with optional filtering
func (sns *SimpleNotificationService) GetNotificationHistory(ctx context.Context, filter *NotificationFilter) ([]NotificationRecord, error) {
	var results []NotificationRecord

	for _, record := range sns.notifications {
		if sns.matchesNotificationFilter(record, filter) {
			results = append(results, record)
		}
	}

	return results, nil
}

// NotificationFilter for filtering notifications
type NotificationFilter struct {
	RecipientID string     `json:"recipient_id,omitempty"`
	Type        string     `json:"type,omitempty"`
	Channel     string     `json:"channel,omitempty"`
	Status      string     `json:"status,omitempty"`
	DateFrom    *time.Time `json:"date_from,omitempty"`
	DateTo      *time.Time `json:"date_to,omitempty"`
}

func (sns *SimpleNotificationService) matchesNotificationFilter(record NotificationRecord, filter *NotificationFilter) bool {
	if filter == nil {
		return true
	}

	if filter.RecipientID != "" {
		found := false
		for _, recipient := range record.Recipients {
			if recipient == filter.RecipientID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	if filter.Type != "" && record.Type != NotificationType(filter.Type) {
		return false
	}
	if filter.Channel != "" && record.Channel != NotificationChannel(filter.Channel) {
		return false
	}
	if filter.Status != "" && record.Status != NotificationStatus(filter.Status) {
		return false
	}
	if filter.DateFrom != nil && record.Timestamp.Before(*filter.DateFrom) {
		return false
	}
	if filter.DateTo != nil && record.Timestamp.After(*filter.DateTo) {
		return false
	}

	return true
}

// Additional helper methods for notification management

// MarkAsRead marks a notification as read
func (sns *SimpleNotificationService) MarkAsRead(ctx context.Context, notificationID, recipientID string) error {
	for i, record := range sns.notifications {
		if record.ID == notificationID {
			// Check if recipient is in the list
			for _, recipient := range record.Recipients {
				if recipient == recipientID {
					sns.notifications[i].Status = NotificationStatusRead
					return nil
				}
			}
			return fmt.Errorf("recipient %s not found in notification %s", recipientID, notificationID)
		}
	}
	return fmt.Errorf("notification %s not found", notificationID)
}

// GetUnreadNotifications gets unread notifications for a recipient
func (sns *SimpleNotificationService) GetUnreadNotifications(ctx context.Context, recipientID string) ([]NotificationRecord, error) {
	filter := &NotificationFilter{
		RecipientID: recipientID,
		Status:      string(NotificationStatusSent), // Sent but not read
	}
	return sns.GetNotificationHistory(ctx, filter)
}

// NotificationStats provides statistics about notifications
type NotificationStats struct {
	TotalSent        int                         `json:"total_sent"`
	TotalDelivered   int                         `json:"total_delivered"`
	TotalFailed      int                         `json:"total_failed"`
	TypeBreakdown    map[NotificationType]int    `json:"type_breakdown"`
	ChannelBreakdown map[NotificationChannel]int `json:"channel_breakdown"`
	GeneratedAt      time.Time                   `json:"generated_at"`
}

// EscalationWebhookPayload is the JSON body delivered when a JIT escalation notification
// is sent via webhook. All required fields from the acceptance criteria are included.
type EscalationWebhookPayload struct {
	Event                string    `json:"event"`
	EscalationID         string    `json:"escalation_id"`
	RequestID            string    `json:"request_id"`
	RequestingUser       string    `json:"requesting_user"`
	RequestedPermissions []string  `json:"requested_permissions"`
	Approvers            []string  `json:"approvers"`
	EscalationLevel      int       `json:"escalation_level"`
	Timestamp            time.Time `json:"timestamp"`
}

// WebhookNotificationConfig holds optional overrides for WebhookNotificationService.
// Intended for tests that need a shorter RetryBase or a custom HTTP client.
type WebhookNotificationConfig struct {
	RetryBase  time.Duration
	HTTPClient *http.Client
}

// WebhookNotificationService delivers JIT escalation notifications via HTTP POST webhook
// and records them in memory after successful delivery. All non-escalation notification
// methods are provided by the embedded SimpleNotificationService.
type WebhookNotificationService struct {
	*SimpleNotificationService
	webhookURL string
	retryBase  time.Duration
	httpClient *http.Client
}

// compile-time check: WebhookNotificationService must satisfy NotificationService.
var _ NotificationService = (*WebhookNotificationService)(nil)

// NewWebhookNotificationService creates a production WebhookNotificationService using
// standard retry defaults (1-second base, 10-second per-request timeout).
func NewWebhookNotificationService(webhookURL string, registry ApproverRegistry) *WebhookNotificationService {
	return NewWebhookNotificationServiceWithConfig(webhookURL, registry, WebhookNotificationConfig{})
}

// NewWebhookNotificationServiceWithConfig creates a WebhookNotificationService with
// caller-supplied configuration. Intended for tests where shorter retry delays are needed.
func NewWebhookNotificationServiceWithConfig(webhookURL string, registry ApproverRegistry, cfg WebhookNotificationConfig) *WebhookNotificationService {
	retryBase := cfg.RetryBase
	if retryBase <= 0 {
		retryBase = time.Second
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &WebhookNotificationService{
		SimpleNotificationService: NewSimpleNotificationServiceWithRegistry(registry),
		webhookURL:                webhookURL,
		retryBase:                 retryBase,
		httpClient:                httpClient,
	}
}

// SendEscalationNotification delivers an escalation notification via HTTP POST and records
// it in the in-memory store on success. Delivery is retried up to 3 times with exponential
// backoff on 5xx responses or network errors. Returns an error if all attempts fail;
// no memory record is written on permanent delivery failure.
func (w *WebhookNotificationService) SendEscalationNotification(ctx context.Context, request *JITAccessRequest, escalationLevel int) error {
	approvers := []string{}
	if w.registry != nil {
		resolved, err := w.registry.GetApprovers(ctx, EscalationTypeDefault)
		if err != nil {
			return fmt.Errorf("approver registry lookup failed: %w", err)
		}
		if resolved != nil {
			approvers = resolved
		}
	}

	if len(approvers) == 0 {
		slog.Warn("no escalation recipients configured; webhook will deliver with empty approver list",
			"request_id", request.ID,
			"tenant_id", request.TenantID,
			"escalation_level", escalationLevel,
		)
	}

	escalationID := fmt.Sprintf("esc-%s-l%d-%d", request.ID, escalationLevel, time.Now().UnixNano())
	payload := EscalationWebhookPayload{
		Event:                "jit.escalation",
		EscalationID:         escalationID,
		RequestID:            request.ID,
		RequestingUser:       request.RequesterID,
		RequestedPermissions: request.Permissions,
		Approvers:            approvers,
		EscalationLevel:      escalationLevel,
		Timestamp:            time.Now(),
	}

	if err := w.sendWebhook(ctx, payload); err != nil {
		return err
	}

	subject := fmt.Sprintf("[ESCALATION LEVEL %d] JIT Access Approval Required", escalationLevel)
	message := fmt.Sprintf(
		"JIT access request %s has been escalated to level %d due to lack of approval. Original request from %s for %v permissions.",
		request.ID, escalationLevel, request.RequesterID, request.Permissions,
	)
	return w.sendNotification(ctx, NotificationTypeEscalation, approvers, subject, message, map[string]interface{}{
		"request_id":         request.ID,
		"tenant_id":          request.TenantID,
		"escalation_level":   escalationLevel,
		"original_requester": request.RequesterID,
		"emergency_access":   request.EmergencyAccess,
		"escalation_id":      escalationID,
	})
}

// sendWebhook marshals payload to JSON and POSTs it to the configured URL, retrying up
// to 3 times with exponential backoff on 5xx responses or network errors. Only http and
// https schemes are accepted to prevent SSRF via exotic schemes. Only the host is logged
// so that secrets embedded in URL paths are not written to log sinks.
func (w *WebhookNotificationService) sendWebhook(ctx context.Context, payload interface{}) error {
	u, err := url.Parse(w.webhookURL)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("invalid webhook URL: must use http or https scheme")
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal webhook payload: %w", err)
	}

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
			return fmt.Errorf("create webhook request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := w.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("webhook POST attempt %d: %w", attempt+1, err)
			slog.Warn("webhook delivery attempt failed",
				"attempt", attempt+1,
				"host", safeHost,
				"error", logging.SanitizeLogValue(lastErr.Error()),
			)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		if err := resp.Body.Close(); err != nil {
			slog.Warn("failed to close webhook response body", "error", err)
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("webhook server error on attempt %d: status %d", attempt+1, resp.StatusCode)
			slog.Warn("webhook delivery attempt failed",
				"attempt", attempt+1,
				"host", safeHost,
				"status", resp.StatusCode,
			)
			continue
		}

		// Non-2xx below 500 (e.g. 401/403/404) indicates a permanent misconfiguration —
		// the server received the request but rejected it. Do not retry.
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("webhook rejected escalation notification: status %d", resp.StatusCode)
		}

		slog.Debug("webhook escalation notification sent", "host", safeHost)
		return nil
	}

	slog.Error("webhook escalation delivery permanently failed",
		"host", safeHost,
		"error", logging.SanitizeLogValue(lastErr.Error()),
	)
	return lastErr
}

// GetNotificationStats generates notification statistics
func (sns *SimpleNotificationService) GetNotificationStats(ctx context.Context, period time.Duration) (*NotificationStats, error) {
	cutoff := time.Now().Add(-period)
	stats := &NotificationStats{
		TypeBreakdown:    make(map[NotificationType]int),
		ChannelBreakdown: make(map[NotificationChannel]int),
		GeneratedAt:      time.Now(),
	}

	for _, record := range sns.notifications {
		if record.Timestamp.Before(cutoff) {
			continue
		}

		stats.TotalSent++
		stats.TypeBreakdown[record.Type]++
		stats.ChannelBreakdown[record.Channel]++

		switch record.Status {
		case NotificationStatusDelivered, NotificationStatusRead:
			stats.TotalDelivered++
		case NotificationStatusFailed:
			stats.TotalFailed++
		}
	}

	return stats, nil
}
