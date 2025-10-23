// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
// Package diff implements approval workflow integration for configuration changes
package diff

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"
)

// DefaultApprovalIntegration implements the ApprovalIntegration interface
// with basic approval workflow functionality
type DefaultApprovalIntegration struct {
	// requests stores active approval requests
	requests map[string]*ApprovalRequest

	// approvers stores the list of available approvers by type
	approvers map[string][]string

	// defaultExpiry is the default expiration time for approval requests
	defaultExpiry time.Duration
}

// NewDefaultApprovalIntegration creates a new DefaultApprovalIntegration
func NewDefaultApprovalIntegration() *DefaultApprovalIntegration {
	return &DefaultApprovalIntegration{
		requests:      make(map[string]*ApprovalRequest),
		approvers:     initializeDefaultApprovers(),
		defaultExpiry: 24 * time.Hour, // 24 hours default
	}
}

// CreateApprovalRequest creates an approval request for changes
func (ai *DefaultApprovalIntegration) CreateApprovalRequest(ctx context.Context, result *ComparisonResult, assessment *RiskAssessment) (*ApprovalRequest, error) {
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
		Requester:         ai.getCurrentUser(ctx),
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
		// Log warning but don't fail the request creation
		// In a real implementation, this would use proper logging
		fmt.Printf("Warning: Failed to notify approvers: %v\n", err)
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
		fmt.Printf("Warning: Failed to notify approvers of update: %v\n", err)
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
		fmt.Printf("Warning: Failed to notify approvers of cancellation: %v\n", err)
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

	// Remove from pending approvers if approved
	if decision == "approved" {
		request.Status.PendingApprovers = ai.removePendingApprover(request.Status.PendingApprovers, approver)
	}

	// Update status
	request.Status.UpdatedAt = time.Now()

	// Check if all required approvals are received
	if ai.allApprovalsReceived(request) {
		if ai.allApproved(request) {
			request.Status.Status = "approved"
		} else {
			request.Status.Status = "rejected"
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
func (ai *DefaultApprovalIntegration) getCurrentUser(ctx context.Context) string {
	// In a real implementation, this would extract user from context
	return "system"
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

// notifyApprovers sends notifications to required approvers
func (ai *DefaultApprovalIntegration) notifyApprovers(ctx context.Context, request *ApprovalRequest) error {
	// In a real implementation, this would send emails, Slack messages, etc.
	fmt.Printf("Notifying approvers %v for request %s: %s\n",
		request.RequiredApprovers, request.ID, request.Title)
	return nil
}

// notifyApproversOfUpdate notifies approvers of request updates
func (ai *DefaultApprovalIntegration) notifyApproversOfUpdate(ctx context.Context, request *ApprovalRequest) error {
	fmt.Printf("Notifying approvers of update for request %s\n", request.ID)
	return nil
}

// notifyApproversOfCancellation notifies approvers of request cancellation
func (ai *DefaultApprovalIntegration) notifyApproversOfCancellation(ctx context.Context, request *ApprovalRequest) error {
	fmt.Printf("Notifying approvers of cancellation for request %s\n", request.ID)
	return nil
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
