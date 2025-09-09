package jit

import (
	"context"
	"fmt"
	"time"
)

// SimpleNotificationService provides a basic implementation of NotificationService
type SimpleNotificationService struct {
	// In a real implementation, this would integrate with email, Slack, etc.
	notifications []NotificationRecord
}

// NewSimpleNotificationService creates a new simple notification service
func NewSimpleNotificationService() *SimpleNotificationService {
	return &SimpleNotificationService{
		notifications: make([]NotificationRecord, 0),
	}
}

// NotificationRecord represents a notification that was sent
type NotificationRecord struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      NotificationType       `json:"type"`
	Recipients []string              `json:"recipients"`
	Subject   string                 `json:"subject"`
	Message   string                 `json:"message"`
	Channel   NotificationChannel    `json:"channel"`
	Status    NotificationStatus     `json:"status"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// NotificationType defines types of notifications
type NotificationType string

const (
	NotificationTypeRequestCreated       NotificationType = "request_created"
	NotificationTypeRequestApproved      NotificationType = "request_approved"
	NotificationTypeRequestDenied        NotificationType = "request_denied"
	NotificationTypeApprovalRequired     NotificationType = "approval_required"
	NotificationTypeApprovalReminder     NotificationType = "approval_reminder"
	NotificationTypeAccessGranted        NotificationType = "access_granted"
	NotificationTypeAccessExpiring       NotificationType = "access_expiring"
	NotificationTypeAccessRevoked        NotificationType = "access_revoked"
	NotificationTypeAccessExtended       NotificationType = "access_extended"
	NotificationTypeEscalation           NotificationType = "escalation"
	NotificationTypePolicyViolation      NotificationType = "policy_violation"
	NotificationTypeComplianceAlert      NotificationType = "compliance_alert"
)

// NotificationChannel defines notification delivery channels
type NotificationChannel string

const (
	NotificationChannelEmail    NotificationChannel = "email"
	NotificationChannelSlack    NotificationChannel = "slack"
	NotificationChannelWebhook  NotificationChannel = "webhook"
	NotificationChannelInApp    NotificationChannel = "in_app"
	NotificationChannelSMS      NotificationChannel = "sms"
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
		"request_id":      request.ID,
		"tenant_id":       request.TenantID,
		"emergency":       request.EmergencyAccess,
		"priority":        request.Priority,
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
		"grant_id":           grant.ID,
		"tenant_id":          grant.TenantID,
		"expires_at":         grant.ExpiresAt,
		"time_until_expiry":  timeUntilExpiry,
		"can_extend":         grant.ExtensionsUsed < grant.MaxExtensions,
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

// SendEscalationNotification sends escalation notifications
func (sns *SimpleNotificationService) SendEscalationNotification(ctx context.Context, request *JITAccessRequest, escalationLevel int) error {
	subject := fmt.Sprintf("[ESCALATION LEVEL %d] JIT Access Approval Required", escalationLevel)
	message := fmt.Sprintf(
		"JIT access request %s has been escalated to level %d due to lack of approval. Original request from %s for %v permissions.",
		request.ID,
		escalationLevel,
		request.RequesterID,
		request.Permissions,
	)

	// In a real implementation, this would determine escalation recipients based on the level
	recipients := []string{"security-admin", "compliance-officer"}

	return sns.sendNotification(ctx, NotificationTypeEscalation, recipients, subject, message, map[string]interface{}{
		"request_id":       request.ID,
		"tenant_id":        request.TenantID,
		"escalation_level": escalationLevel,
		"original_requester": request.RequesterID,
		"emergency_access": request.EmergencyAccess,
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

	// In a real implementation, this would:
	// 1. Determine the best channel for each recipient
	// 2. Format the message appropriately for each channel
	// 3. Send via the appropriate service (email, Slack, etc.)
	// 4. Handle failures and retries
	// 5. Track delivery status

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
	RecipientID string                `json:"recipient_id,omitempty"`
	Type        string                `json:"type,omitempty"`
	Channel     string                `json:"channel,omitempty"`
	Status      string                `json:"status,omitempty"`
	DateFrom    *time.Time            `json:"date_from,omitempty"`
	DateTo      *time.Time            `json:"date_to,omitempty"`
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
	TotalSent       int                               `json:"total_sent"`
	TotalDelivered  int                               `json:"total_delivered"`
	TotalFailed     int                               `json:"total_failed"`
	TypeBreakdown   map[NotificationType]int          `json:"type_breakdown"`
	ChannelBreakdown map[NotificationChannel]int      `json:"channel_breakdown"`
	GeneratedAt     time.Time                         `json:"generated_at"`
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