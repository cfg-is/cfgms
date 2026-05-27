// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package diff implements approval workflow integration for configuration changes
package diff

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// ApprovalWebhookConfig holds configuration for the webhook delivery channel.
type ApprovalWebhookConfig struct {
	// RetryBase is the initial delay before the first retry. Subsequent delays
	// double with each attempt. Defaults to 1 second when zero.
	RetryBase time.Duration
}

// approvalWebhookSender delivers approval notifications via HTTP POST with retry.
type approvalWebhookSender struct {
	webhookURL string
	logger     logging.Logger
	retryBase  time.Duration
	httpClient *http.Client
}

// sendWebhook marshals payload to JSON and POSTs it to the configured URL,
// retrying up to 3 times with exponential backoff on 5xx responses or network
// errors. Only http and https schemes are accepted to prevent SSRF. Only the
// host is logged so that secrets embedded in webhook URL paths are never written
// to log sinks.
func (s *approvalWebhookSender) sendWebhook(ctx context.Context, payload interface{}) error {
	u, err := url.Parse(s.webhookURL)
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
			delay := time.Duration(1<<uint(attempt-1)) * s.retryBase
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("create webhook request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("webhook POST attempt %d: %w", attempt+1, err)
			s.logger.Warn("webhook delivery attempt failed",
				"attempt", attempt+1,
				"host", safeHost,
				"error", logging.SanitizeLogValue(lastErr.Error()),
			)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		if err := resp.Body.Close(); err != nil {
			s.logger.Warn("failed to close webhook response body", "error", err)
		}

		if resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("webhook server error on attempt %d: status %d", attempt+1, resp.StatusCode)
			s.logger.Warn("webhook delivery attempt failed",
				"attempt", attempt+1,
				"host", safeHost,
				"status", resp.StatusCode,
			)
			continue
		}

		s.logger.Debug("webhook notification sent", "host", safeHost)
		return nil
	}

	s.logger.Error("webhook delivery permanently failed",
		"host", safeHost,
		"error", logging.SanitizeLogValue(lastErr.Error()),
	)
	return lastErr
}

// DefaultApprovalIntegration implements the ApprovalIntegration interface
// with basic approval workflow functionality
type DefaultApprovalIntegration struct {
	// requests stores active approval requests
	requests map[string]*ApprovalRequest

	// approvers stores the list of available approvers by type
	approvers map[string][]string

	// defaultExpiry is the default expiration time for approval requests
	defaultExpiry time.Duration

	logger  logging.Logger
	webhook *approvalWebhookSender // nil when no webhook is configured
}

// NewDefaultApprovalIntegration creates a new DefaultApprovalIntegration
func NewDefaultApprovalIntegration(logger logging.Logger) *DefaultApprovalIntegration {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	return &DefaultApprovalIntegration{
		requests:      make(map[string]*ApprovalRequest),
		approvers:     initializeDefaultApprovers(),
		defaultExpiry: 24 * time.Hour,
		logger:        logger,
	}
}

// NewDefaultApprovalIntegrationWithWebhook creates an integration that delivers
// approval notifications to webhookURL in addition to logging.
func NewDefaultApprovalIntegrationWithWebhook(webhookURL string, logger logging.Logger) *DefaultApprovalIntegration {
	return NewDefaultApprovalIntegrationWithWebhookConfig(webhookURL, logger, ApprovalWebhookConfig{})
}

// NewDefaultApprovalIntegrationWithWebhookConfig is the same as
// NewDefaultApprovalIntegrationWithWebhook but accepts caller-supplied config.
// Intended for tests where a shorter RetryBase speeds up retry-behavior tests.
func NewDefaultApprovalIntegrationWithWebhookConfig(webhookURL string, logger logging.Logger, cfg ApprovalWebhookConfig) *DefaultApprovalIntegration {
	if logger == nil {
		logger = logging.NewNoopLogger()
	}
	retryBase := cfg.RetryBase
	if retryBase <= 0 {
		retryBase = time.Second
	}
	return &DefaultApprovalIntegration{
		requests:      make(map[string]*ApprovalRequest),
		approvers:     initializeDefaultApprovers(),
		defaultExpiry: 24 * time.Hour,
		logger:        logger,
		webhook: &approvalWebhookSender{
			webhookURL: webhookURL,
			logger:     logger,
			retryBase:  retryBase,
			httpClient: &http.Client{Timeout: 10 * time.Second},
		},
	}
}

// CreateApprovalRequest creates an approval request for changes
func (ai *DefaultApprovalIntegration) CreateApprovalRequest(ctx context.Context, result *ComparisonResult, assessment *RiskAssessment) (*ApprovalRequest, error) {
	requester, err := ai.getCurrentUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("cannot create approval request: %w", err)
	}

	// Generate unique request ID
	requestID, err := generateRequestID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate request ID: %w", err)
	}

	// Determine required approvers based on assessment
	requiredApprovers := ai.determineRequiredApprovers(assessment)

	// Create approval request
	request := &ApprovalRequest{
		ID:                requestID,
		Title:             ai.generateTitle(result),
		Description:       ai.generateDescription(result, assessment),
		Changes:           result,
		RiskAssessment:    assessment,
		Requester:         requester,
		RequiredApprovers: requiredApprovers,
		Status: ApprovalStatus{
			Status:           "pending",
			Approvals:        []Approval{},
			PendingApprovers: requiredApprovers,
			Comments:         []ApprovalComment{},
			UpdatedAt:        time.Now(),
		},
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ai.defaultExpiry),
	}

	// Store the request
	ai.requests[requestID] = request

	// Send notifications to approvers
	if err := ai.notifyApprovers(ctx, request); err != nil {
		ai.logger.Warn("failed to notify approvers",
			"request_id", logging.SanitizeLogValue(request.ID),
			"error", err,
		)
	}

	return request, nil
}

// UpdateApprovalRequest updates an existing approval request
func (ai *DefaultApprovalIntegration) UpdateApprovalRequest(ctx context.Context, requestID string, result *ComparisonResult) error {
	request, exists := ai.requests[requestID]
	if !exists {
		return fmt.Errorf("approval request %s not found", requestID)
	}

	// Check if request is still active
	if request.Status.Status != "pending" {
		return fmt.Errorf("cannot update approval request in status: %s", request.Status.Status)
	}

	// Update the changes
	request.Changes = result
	request.Description = ai.generateDescription(result, request.RiskAssessment)
	request.Status.UpdatedAt = time.Now()

	// Notify approvers of the update
	if err := ai.notifyApproversOfUpdate(ctx, request); err != nil {
		ai.logger.Warn("failed to notify approvers of update",
			"request_id", logging.SanitizeLogValue(requestID),
			"error", err,
		)
	}

	return nil
}

// GetApprovalStatus gets the status of an approval request
func (ai *DefaultApprovalIntegration) GetApprovalStatus(ctx context.Context, requestID string) (*ApprovalStatus, error) {
	request, exists := ai.requests[requestID]
	if !exists {
		return nil, fmt.Errorf("approval request %s not found", requestID)
	}

	// Check if request has expired
	if time.Now().After(request.ExpiresAt) && request.Status.Status == "pending" {
		request.Status.Status = "expired"
		request.Status.UpdatedAt = time.Now()
	}

	return &request.Status, nil
}

// CancelApprovalRequest cancels an approval request
func (ai *DefaultApprovalIntegration) CancelApprovalRequest(ctx context.Context, requestID string) error {
	request, exists := ai.requests[requestID]
	if !exists {
		return fmt.Errorf("approval request %s not found", requestID)
	}

	// Check if request can be cancelled
	if request.Status.Status != "pending" {
		return fmt.Errorf("cannot cancel approval request in status: %s", request.Status.Status)
	}

	// Update status
	request.Status.Status = "cancelled"
	request.Status.UpdatedAt = time.Now()

	// Notify approvers of cancellation
	if err := ai.notifyApproversOfCancellation(ctx, request); err != nil {
		ai.logger.Warn("failed to notify approvers of cancellation",
			"request_id", logging.SanitizeLogValue(requestID),
			"error", err,
		)
	}

	return nil
}

// AddApproval adds an approval to a request
func (ai *DefaultApprovalIntegration) AddApproval(ctx context.Context, requestID, approver, decision, comment string) error {
	request, exists := ai.requests[requestID]
	if !exists {
		return fmt.Errorf("approval request %s not found", requestID)
	}

	// Check if request is still pending
	if request.Status.Status != "pending" {
		return fmt.Errorf("cannot add approval to request in status: %s", request.Status.Status)
	}

	// Check if approver is required
	if !ai.isRequiredApprover(approver, request.RequiredApprovers) {
		return fmt.Errorf("approver %s is not required for this request", approver)
	}

	// Check if approver has already provided approval
	for _, approval := range request.Status.Approvals {
		if approval.Approver == approver {
			return fmt.Errorf("approver %s has already provided approval", approver)
		}
	}

	// Add the approval
	approval := Approval{
		Approver:   approver,
		Decision:   decision,
		Comment:    comment,
		ApprovedAt: time.Now(),
	}

	request.Status.Approvals = append(request.Status.Approvals, approval)

	// Remove from pending once any decision is recorded (approved or rejected).
	request.Status.PendingApprovers = ai.removePendingApprover(request.Status.PendingApprovers, approver)

	// Update status
	request.Status.UpdatedAt = time.Now()

	// Check if all required approvals are received
	if ai.allApprovalsReceived(request) {
		if ai.allApproved(request) {
			request.Status.Status = "approved"
		} else {
			request.Status.Status = "rejected"
		}

		if err := ai.notifyApprovalDecision(ctx, request); err != nil {
			ai.logger.Warn("failed to notify approvers of decision",
				"request_id", logging.SanitizeLogValue(requestID),
				"error", err,
			)
		}
	}

	return nil
}

// AddComment adds a comment to an approval request
func (ai *DefaultApprovalIntegration) AddComment(ctx context.Context, requestID, author, comment string) error {
	request, exists := ai.requests[requestID]
	if !exists {
		return fmt.Errorf("approval request %s not found", requestID)
	}

	// Add the comment
	approvalComment := ApprovalComment{
		Author:    author,
		Comment:   comment,
		CreatedAt: time.Now(),
	}

	request.Status.Comments = append(request.Status.Comments, approvalComment)
	request.Status.UpdatedAt = time.Now()

	return nil
}

// Helper methods

// generateRequestID generates a unique request ID
func generateRequestID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("req_%x", bytes), nil
}

// generateTitle generates a title for the approval request
func (ai *DefaultApprovalIntegration) generateTitle(result *ComparisonResult) string {
	changeSummary := ""
	if result.Summary.TotalChanges == 1 {
		changeSummary = "1 configuration change"
	} else {
		changeSummary = fmt.Sprintf("%d configuration changes", result.Summary.TotalChanges)
	}

	if result.Summary.BreakingChanges > 0 {
		changeSummary += fmt.Sprintf(" (%d breaking)", result.Summary.BreakingChanges)
	}

	return fmt.Sprintf("Configuration Update: %s", changeSummary)
}

// generateDescription generates a description for the approval request
func (ai *DefaultApprovalIntegration) generateDescription(result *ComparisonResult, assessment *RiskAssessment) string {
	description := fmt.Sprintf("Configuration changes from %s to %s\n\n",
		result.FromRef.Commit[:8], result.ToRef.Commit[:8])

	description += "**Summary:**\n"
	description += fmt.Sprintf("- Total Changes: %d\n", result.Summary.TotalChanges)
	description += fmt.Sprintf("- Added: %d\n", result.Summary.AddedItems)
	description += fmt.Sprintf("- Modified: %d\n", result.Summary.ModifiedItems)
	description += fmt.Sprintf("- Deleted: %d\n", result.Summary.DeletedItems)

	if result.Summary.BreakingChanges > 0 {
		description += fmt.Sprintf("- **Breaking Changes: %d**\n", result.Summary.BreakingChanges)
	}

	if result.Summary.SecurityChanges > 0 {
		description += fmt.Sprintf("- **Security Changes: %d**\n", result.Summary.SecurityChanges)
	}

	description += fmt.Sprintf("\n**Risk Assessment:** %s\n", assessment.OverallRisk)

	if len(assessment.RiskFactors) > 0 {
		description += "\n**Risk Factors:**\n"
		for _, factor := range assessment.RiskFactors {
			description += fmt.Sprintf("- %s (%s): %s\n", factor.Factor, factor.Level, factor.Description)
		}
	}

	if len(assessment.Recommendations) > 0 {
		description += "\n**Recommendations:**\n"
		for _, rec := range assessment.Recommendations {
			description += fmt.Sprintf("- %s\n", rec)
		}
	}

	return description
}

// getCurrentUser gets the current user from context
func (ai *DefaultApprovalIntegration) getCurrentUser(ctx context.Context) (string, error) {
	userID, ok := ctx.Value(ctxkeys.UserIDKey).(string)
	if !ok || userID == "" {
		return "", fmt.Errorf("unauthenticated: no user identity in context")
	}
	return userID, nil
}

// determineRequiredApprovers determines who needs to approve based on risk assessment
func (ai *DefaultApprovalIntegration) determineRequiredApprovers(assessment *RiskAssessment) []string {
	var required []string

	// Add approvers based on required approvals in assessment
	for _, requirement := range assessment.RequiredApprovals {
		if requirement.Required {
			required = append(required, requirement.Approvers...)
		}
	}

	// Default approvers based on risk level
	if len(required) == 0 {
		switch assessment.OverallRisk {
		case ImpactLevelCritical:
			required = append(required, ai.approvers["security"]...)
			required = append(required, ai.approvers["management"]...)
		case ImpactLevelHigh:
			required = append(required, ai.approvers["senior"]...)
		case ImpactLevelMedium:
			required = append(required, ai.approvers["peer"]...)
		}
	}

	// Remove duplicates
	return ai.removeDuplicates(required)
}

// removeDuplicates removes duplicate approvers from a list
func (ai *DefaultApprovalIntegration) removeDuplicates(approvers []string) []string {
	seen := make(map[string]bool)
	var unique []string

	for _, approver := range approvers {
		if !seen[approver] {
			seen[approver] = true
			unique = append(unique, approver)
		}
	}

	return unique
}

// isRequiredApprover checks if an approver is required for a request
func (ai *DefaultApprovalIntegration) isRequiredApprover(approver string, required []string) bool {
	for _, req := range required {
		if req == approver {
			return true
		}
	}
	return false
}

// removePendingApprover removes an approver from the pending list
func (ai *DefaultApprovalIntegration) removePendingApprover(pending []string, approver string) []string {
	var updated []string
	for _, p := range pending {
		if p != approver {
			updated = append(updated, p)
		}
	}
	return updated
}

// allApprovalsReceived checks if all required approvals have been received
func (ai *DefaultApprovalIntegration) allApprovalsReceived(request *ApprovalRequest) bool {
	return len(request.Status.PendingApprovers) == 0
}

// allApproved checks if all approvals are positive
func (ai *DefaultApprovalIntegration) allApproved(request *ApprovalRequest) bool {
	for _, approval := range request.Status.Approvals {
		if approval.Decision != "approved" {
			return false
		}
	}
	return true
}

// notifyApprovers sends notifications to required approvers when a request is created.
func (ai *DefaultApprovalIntegration) notifyApprovers(ctx context.Context, request *ApprovalRequest) error {
	ai.logger.Info("notifying approvers",
		"request_id", logging.SanitizeLogValue(request.ID),
		"approver_count", len(request.RequiredApprovers),
	)
	if ai.webhook == nil {
		return nil
	}
	return ai.webhook.sendWebhook(ctx, map[string]interface{}{
		"event":          "approval.requested",
		"diff_id":        request.ID,
		"initiator":      request.Requester,
		"approvers":      request.RequiredApprovers,
		"approver_count": len(request.RequiredApprovers),
		"timestamp":      time.Now(),
	})
}

// notifyApproversOfUpdate notifies approvers when the underlying changes are updated.
func (ai *DefaultApprovalIntegration) notifyApproversOfUpdate(ctx context.Context, request *ApprovalRequest) error {
	ai.logger.Info("notifying approvers of update",
		"request_id", logging.SanitizeLogValue(request.ID),
	)
	if ai.webhook == nil {
		return nil
	}
	return ai.webhook.sendWebhook(ctx, map[string]interface{}{
		"event":     "approval.updated",
		"diff_id":   request.ID,
		"initiator": request.Requester,
		"approvers": request.RequiredApprovers,
		"timestamp": time.Now(),
	})
}

// notifyApproversOfCancellation notifies approvers when a request is cancelled.
func (ai *DefaultApprovalIntegration) notifyApproversOfCancellation(ctx context.Context, request *ApprovalRequest) error {
	ai.logger.Info("notifying approvers of cancellation",
		"request_id", logging.SanitizeLogValue(request.ID),
	)
	if ai.webhook == nil {
		return nil
	}
	return ai.webhook.sendWebhook(ctx, map[string]interface{}{
		"event":     "approval.cancelled",
		"diff_id":   request.ID,
		"initiator": request.Requester,
		"approvers": request.RequiredApprovers,
		"timestamp": time.Now(),
	})
}

// notifyApprovalDecision fires an "approval.approved" or "approval.rejected" webhook
// once all required approvers have responded.
func (ai *DefaultApprovalIntegration) notifyApprovalDecision(ctx context.Context, request *ApprovalRequest) error {
	if ai.webhook == nil {
		return nil
	}
	return ai.webhook.sendWebhook(ctx, map[string]interface{}{
		"event":     "approval." + request.Status.Status,
		"diff_id":   request.ID,
		"initiator": request.Requester,
		"approvers": request.RequiredApprovers,
		"timestamp": time.Now(),
	})
}

// initializeDefaultApprovers initializes the default approvers by type
func initializeDefaultApprovers() map[string][]string {
	return map[string][]string{
		"peer":       {"senior-dev-1", "senior-dev-2", "tech-lead"},
		"senior":     {"tech-lead", "principal-engineer", "architect"},
		"security":   {"security-team-lead", "security-architect"},
		"management": {"engineering-manager", "director-engineering"},
	}
}

// GetRequest returns a request by ID (for testing/debugging)
func (ai *DefaultApprovalIntegration) GetRequest(requestID string) (*ApprovalRequest, bool) {
	request, exists := ai.requests[requestID]
	return request, exists
}

// ListRequests returns all requests (for testing/debugging)
func (ai *DefaultApprovalIntegration) ListRequests() map[string]*ApprovalRequest {
	return ai.requests
}
