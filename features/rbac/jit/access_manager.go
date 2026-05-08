// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// WorkflowProvider selects an approval workflow for a JIT access request.
// When set on JITAccessManager via SetWorkflowProvider, it replaces the built-in
// single-stage default with tenant-specific, risk-based, or environment-specific
// workflow policies without forking the core manager.
type WorkflowProvider func(ctx context.Context, request *JITAccessRequest) (*ApprovalWorkflow, error)

// JITAccessManager manages Just-In-Time access requests and grants
type JITAccessManager struct {
	rbacManager         rbac.RBACManager
	requests            map[string]*JITAccessRequest
	activeGrants        map[string]*JITAccessGrant
	approvalWorkflows   map[string]*ApprovalWorkflow
	auditManager        *audit.Manager
	notificationService NotificationService
	workflowProvider    WorkflowProvider
	grantStore          business.SessionStore
	stopCh              chan struct{}
	doneCh              chan struct{}
	mutex               sync.RWMutex
}

// NewJITAccessManager creates a new JIT access manager without a backing store (memory-only).
func NewJITAccessManager(rbacManager rbac.RBACManager, notificationService NotificationService) *JITAccessManager {
	return NewJITAccessManagerWithStore(rbacManager, notificationService, nil)
}

// NewJITAccessManagerWithStore creates a new JIT access manager backed by a durable session store.
// Pass nil for store to operate memory-only (equivalent to NewJITAccessManager).
func NewJITAccessManagerWithStore(rbacManager rbac.RBACManager, notificationService NotificationService, store business.SessionStore) *JITAccessManager {
	return &JITAccessManager{
		rbacManager:         rbacManager,
		requests:            make(map[string]*JITAccessRequest),
		activeGrants:        make(map[string]*JITAccessGrant),
		approvalWorkflows:   make(map[string]*ApprovalWorkflow),
		notificationService: notificationService,
		grantStore:          store,
		mutex:               sync.RWMutex{},
	}
}

// Start loads active JIT grants from the store into memory and starts the central cleanup ticker.
// The ticker calls CleanupExpiredGrants and CleanupExpiredRequests on the given interval.
// On a nil store, Start still runs the ticker for in-memory cleanup.
func (jam *JITAccessManager) Start(ctx context.Context, cleanupInterval time.Duration) error {
	jam.mutex.Lock()
	if jam.stopCh != nil {
		jam.mutex.Unlock()
		return fmt.Errorf("JIT access manager already started")
	}
	stopCh := make(chan struct{})
	doneCh := make(chan struct{})
	jam.stopCh = stopCh
	jam.doneCh = doneCh
	jam.mutex.Unlock()

	if err := jam.loadActiveGrants(ctx); err != nil {
		jam.mutex.Lock()
		jam.stopCh = nil
		jam.doneCh = nil
		jam.mutex.Unlock()
		return fmt.Errorf("failed to load active grants: %w", err)
	}

	ticker := time.NewTicker(cleanupInterval)
	go func() {
		defer close(doneCh)
		defer ticker.Stop()
		for {
			select {
			case <-stopCh:
				return
			case <-ticker.C:
				bgCtx := context.Background()
				if err := jam.CleanupExpiredGrants(bgCtx); err != nil {
					slog.Warn("jit cleanup expired grants failed", "error", err)
				}
				if err := jam.CleanupExpiredRequests(bgCtx); err != nil {
					slog.Warn("jit cleanup expired requests failed", "error", err)
				}
			}
		}
	}()

	return nil
}

// Stop signals the cleanup ticker to stop and blocks until any in-flight cleanup cycle completes.
func (jam *JITAccessManager) Stop(ctx context.Context) error {
	jam.mutex.Lock()
	stopCh := jam.stopCh
	doneCh := jam.doneCh
	jam.stopCh = nil
	jam.doneCh = nil
	jam.mutex.Unlock()

	if stopCh == nil {
		return nil
	}

	close(stopCh)

	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// loadActiveGrants populates activeGrants from the store using ListSessions scoped to
// SessionTypeJIT + SessionStatusActive. Sessions whose ExpiresAt is already past are
// immediately marked SessionStatusExpired in the store and are NOT added to activeGrants.
func (jam *JITAccessManager) loadActiveGrants(ctx context.Context) error {
	if jam.grantStore == nil {
		return nil
	}

	sessions, err := jam.grantStore.ListSessions(ctx, &business.SessionFilter{
		Type:   business.SessionTypeJIT,
		Status: business.SessionStatusActive,
	})
	if err != nil {
		return fmt.Errorf("failed to list active JIT sessions: %w", err)
	}

	now := time.Now()
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	for _, session := range sessions {
		jitData, ok := extractJITSessionData(session)
		if !ok {
			slog.Warn("skipping JIT session with unreadable session data", "session_id", session.SessionID)
			continue
		}

		if session.ExpiresAt.Before(now) {
			// Already expired — mark in store and skip
			session.Status = business.SessionStatusExpired
			modAt := now
			session.ModifiedAt = &modAt
			if updateErr := jam.grantStore.UpdateSession(ctx, session.SessionID, session); updateErr != nil {
				slog.Warn("failed to expire already-past session on load", "session_id", session.SessionID, "error", updateErr)
			}
			continue
		}

		grant := &JITAccessGrant{
			ID:                 session.SessionID,
			RequestID:          jitData.RequestID,
			RequesterID:        session.UserID,
			TargetID:           jitData.TargetID,
			TenantID:           session.TenantID,
			Permissions:        jitData.Permissions,
			Roles:              jitData.Roles,
			ResourceIDs:        jitData.ResourceIDs,
			ApprovedBy:         jitData.ApprovedBy,
			ApprovalReason:     jitData.ApprovalReason,
			GrantedAt:          jitData.GrantedAt,
			ExpiresAt:          session.ExpiresAt,
			Status:             JITAccessGrantStatusActive,
			ExtensionsUsed:     jitData.ExtensionsUsed,
			MaxExtensions:      jitData.MaxExtensions,
			ActivationMethod:   ActivationMethodImmediate,
			DeactivationMethod: DeactivationMethodAutomatic,
		}
		jam.activeGrants[grant.ID] = grant
	}

	return nil
}

// CleanupExpiredGrants sweeps activeGrants for grants whose ExpiresAt has passed,
// updates the store to SessionStatusExpired, then removes them from activeGrants.
// A failed store update retains the in-memory entry so the next tick can retry.
func (jam *JITAccessManager) CleanupExpiredGrants(ctx context.Context) error {
	now := time.Now()

	type expiredEntry struct {
		id    string
		grant *JITAccessGrant
	}

	jam.mutex.RLock()
	var expired []expiredEntry
	for id, grant := range jam.activeGrants {
		if grant.Status == JITAccessGrantStatusActive && !grant.ExpiresAt.After(now) {
			expired = append(expired, expiredEntry{id, grant})
		}
	}
	jam.mutex.RUnlock()

	for _, eg := range expired {
		if jam.grantStore != nil {
			session, err := jam.grantStore.GetSession(ctx, eg.id)
			if err != nil {
				slog.Warn("failed to get session for expiry cleanup", "grant_id", eg.id, "error", err)
				continue // retry next tick
			}
			session.Status = business.SessionStatusExpired
			modAt := time.Now()
			session.ModifiedAt = &modAt
			if err := jam.grantStore.UpdateSession(ctx, eg.id, session); err != nil {
				slog.Warn("failed to update session to expired", "grant_id", eg.id, "error", err)
				continue // store update failed — retain in-memory entry, retry next tick
			}
		}

		// Store update succeeded (or no store); remove from activeGrants under mutex.
		jam.mutex.Lock()
		grant, exists := jam.activeGrants[eg.id]
		if exists && grant.Status == JITAccessGrantStatusActive {
			grant.Status = JITAccessGrantStatusExpired
			deactivatedAt := time.Now()
			grant.DeactivatedAt = &deactivatedAt
			delete(jam.activeGrants, eg.id)
			jam.mutex.Unlock()
			jam.recordJITAccessExpiry(ctx, grant)
		} else {
			jam.mutex.Unlock()
		}
	}

	return nil
}

// CleanupExpiredRequests marks pending requests whose RequestTTL has passed as expired.
func (jam *JITAccessManager) CleanupExpiredRequests(ctx context.Context) error {
	now := time.Now()

	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	for _, request := range jam.requests {
		if request.Status == JITAccessRequestStatusPending && request.RequestTTL.Before(now) {
			request.Status = JITAccessRequestStatusExpired
		}
	}

	return nil
}

// SetAuditManager wires a durable audit manager for recording JIT access events.
// It is a no-op when m is nil.
func (jam *JITAccessManager) SetAuditManager(m *audit.Manager) {
	jam.auditManager = m
}

// SetWorkflowProvider replaces the built-in workflow determination logic with a custom
// provider. The provider is called once per request creation and must return a non-nil
// workflow; nil causes request creation to fail.
func (jam *JITAccessManager) SetWorkflowProvider(provider WorkflowProvider) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()
	jam.workflowProvider = provider
}

// recordJITAccessRequest emits a jit_access request audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordJITAccessRequest(ctx context.Context, request *JITAccessRequest, action string) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		request.TenantID, request.RequesterID, "jit_access", request.ID, action,
		business.AuditResultSuccess,
	)); err != nil {
		slog.Warn("failed to record jit access request audit event", "error", err)
	}
}

// recordJITAccessApproval emits a jit_access approval audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordJITAccessApproval(ctx context.Context, request *JITAccessRequest, grant *JITAccessGrant, approverID string) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		request.TenantID, request.RequesterID, "jit_access", request.ID, "approve",
		business.AuditResultSuccess,
	).Detail("approver_id", approverID).Detail("grant_id", grant.ID)); err != nil {
		slog.Warn("failed to record jit access approval audit event", "error", err)
	}
}

// recordJITAccessDenial emits a jit_access denial audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordJITAccessDenial(ctx context.Context, request *JITAccessRequest, reviewerID, reason string) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		request.TenantID, request.RequesterID, "jit_access", request.ID, "deny",
		business.AuditResultDenied,
	).Detail("reviewer_id", reviewerID).Detail("reason", reason)); err != nil {
		slog.Warn("failed to record jit access denial audit event", "error", err)
	}
}

// recordJITAccessExtension emits a jit_access extension audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordJITAccessExtension(ctx context.Context, grant *JITAccessGrant, requesterID string, duration time.Duration, reason string) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		grant.TenantID, requesterID, "jit_access", grant.ID, "extend",
		business.AuditResultSuccess,
	).Detail("duration", duration.String()).Detail("reason", reason)); err != nil {
		slog.Warn("failed to record jit access extension audit event", "error", err)
	}
}

// recordJITAccessRevocation emits a jit_access revocation audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordJITAccessRevocation(ctx context.Context, grant *JITAccessGrant, revokerID, reason string) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		grant.TenantID, revokerID, "jit_access", grant.ID, "revoke",
		business.AuditResultSuccess,
	).Detail("reason", reason)); err != nil {
		slog.Warn("failed to record jit access revocation audit event", "error", err)
	}
}

// recordJITAccessExpiry emits a jit_access expiry audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordJITAccessExpiry(ctx context.Context, grant *JITAccessGrant) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		grant.TenantID, grant.RequesterID, "jit_access", grant.ID, "expired",
		business.AuditResultSuccess,
	)); err != nil {
		slog.Warn("failed to record jit access expiry audit event", "error", err)
	}
}

// RequestAccess creates a new JIT access request
func (jam *JITAccessManager) RequestAccess(ctx context.Context, req *JITAccessRequestSpec) (*JITAccessRequest, error) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	// Validate the request
	if err := jam.validateAccessRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("invalid access request: %w", err)
	}

	// Check if requester already has the permissions
	hasAccess, err := jam.checkCurrentAccess(ctx, req.RequesterID, req.Permissions, req.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to check current access: %w", err)
	}
	if hasAccess {
		return nil, fmt.Errorf("requester already has the requested permissions")
	}

	// Compute request TTL
	requestTTL := 24 * time.Hour
	if req.RequestTTL > 0 {
		requestTTL = req.RequestTTL
	}

	// Create the access request
	request := &JITAccessRequest{
		ID:                uuid.New().String(),
		RequesterID:       req.RequesterID,
		TargetID:          req.TargetID,
		TenantID:          req.TenantID,
		Permissions:       req.Permissions,
		Roles:             req.Roles,
		ResourceIDs:       req.ResourceIDs,
		RequestedFor:      req.RequestedFor,
		Duration:          req.Duration,
		MaxDuration:       req.MaxDuration,
		Priority:          req.Priority,
		Justification:     req.Justification,
		AutoApprove:       req.AutoApprove,
		EmergencyAccess:   req.EmergencyAccess,
		RequesterMetadata: req.RequesterMetadata,
		Status:            JITAccessRequestStatusPending,
		CreatedAt:         time.Now(),
		ExpiresAt:         time.Now().Add(req.Duration),
		RequestTTL:        time.Now().Add(requestTTL),
	}

	// Determine approval workflow
	workflow, err := jam.determineApprovalWorkflow(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to determine approval workflow: %w", err)
	}
	request.ApprovalWorkflow = workflow.ID

	// Store the request
	jam.requests[request.ID] = request

	// Check for auto-approval conditions
	if request.AutoApprove || jam.shouldAutoApprove(ctx, request) {
		grantedAccess, err := jam.approveRequest(ctx, request.ID, "system", "Auto-approved based on policy")
		if err != nil {
			return request, fmt.Errorf("auto-approval failed: %w", err)
		}
		request.GrantedAccess = grantedAccess
	} else {
		// Start approval workflow
		err = jam.startApprovalWorkflow(ctx, request, workflow)
		if err != nil {
			return request, fmt.Errorf("failed to start approval workflow: %w", err)
		}
	}

	// Audit the request
	jam.recordJITAccessRequest(ctx, request, "created")

	// Send notifications
	_ = jam.sendNotifications(ctx, request, "request_created")

	return request, nil
}

// ApproveRequest approves a JIT access request.
// For multi-stage workflows it records the stage approval and only creates the
// grant when the final stage is satisfied. Single-stage workflows grant access
// immediately (existing behaviour).
func (jam *JITAccessManager) ApproveRequest(ctx context.Context, requestID, approverID, reason string) (*JITAccessGrant, error) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	request, exists := jam.requests[requestID]
	if !exists {
		return nil, fmt.Errorf("request %s not found", requestID)
	}

	if request.Status != JITAccessRequestStatusPending {
		return nil, fmt.Errorf("request %s is not in pending status", requestID)
	}

	// Multi-stage path: WorkflowState is only set for workflows with >1 stage.
	if request.WorkflowState != nil {
		workflow, exists := jam.approvalWorkflows[requestID]
		if !exists || workflow == nil {
			return nil, fmt.Errorf("approval workflow not found for request %s", requestID)
		}

		// Stage membership check must come before the RBAC permission check so callers
		// can distinguish the two rejection reasons.
		if err := jam.validateStageApprover(request, approverID); err != nil {
			return nil, err
		}

		stageIdx := request.WorkflowState.CurrentStage
		stage := workflow.Approvers[stageIdx]

		// Idempotency: silently ignore a duplicate approval from the same approver
		// in the same stage — no state change, no audit event.
		if _, already := request.WorkflowState.StageApprovals[stageIdx][approverID]; already {
			return nil, nil
		}

		// RBAC check: approver must hold the jit_access.approve permission.
		if err := jam.validateApprover(ctx, request, approverID); err != nil {
			return nil, fmt.Errorf("approver validation failed: %w", err)
		}

		// Record approval in the per-stage set.
		request.WorkflowState.StageApprovals[stageIdx][approverID] = struct{}{}

		// Emit stage_approved audit event for every new (non-duplicate) approval,
		// including intermediate stages.
		jam.recordStageApproval(ctx, request, stage.ID, approverID)

		// Advance when the stage's MinApprovals threshold is met.
		if len(request.WorkflowState.StageApprovals[stageIdx]) >= stage.MinApprovals {
			nextIdx := stageIdx + 1
			if nextIdx >= len(workflow.Approvers) {
				// Final stage complete — delegate to internal approveRequest for grant creation.
				return jam.approveRequest(ctx, requestID, approverID, reason)
			}
			jam.advanceWorkflowStage(ctx, request, workflow)
		}

		return nil, nil
	}

	// Single-stage path: original immediate-grant behaviour.
	return jam.approveRequest(ctx, requestID, approverID, reason)
}

// approveRequest internal implementation without mutex (already held by caller)
func (jam *JITAccessManager) approveRequest(ctx context.Context, requestID, approverID, reason string) (*JITAccessGrant, error) {
	request, exists := jam.requests[requestID]
	if !exists {
		return nil, fmt.Errorf("request %s not found", requestID)
	}

	if request.Status != JITAccessRequestStatusPending {
		return nil, fmt.Errorf("request %s is not in pending status", requestID)
	}

	// Validate approver authority
	if err := jam.validateApprover(ctx, request, approverID); err != nil {
		return nil, fmt.Errorf("approver validation failed: %w", err)
	}

	// Create the access grant
	grant := &JITAccessGrant{
		ID:                 uuid.New().String(),
		RequestID:          requestID,
		RequesterID:        request.RequesterID,
		TargetID:           request.TargetID,
		TenantID:           request.TenantID,
		Permissions:        request.Permissions,
		Roles:              request.Roles,
		ResourceIDs:        request.ResourceIDs,
		ApprovedBy:         approverID,
		ApprovalReason:     reason,
		GrantedAt:          time.Now(),
		ExpiresAt:          request.ExpiresAt,
		Status:             JITAccessGrantStatusActive,
		MaxExtensions:      3, // Allow up to 3 extensions
		ExtensionsUsed:     0,
		ActivationMethod:   ActivationMethodImmediate,
		DeactivationMethod: DeactivationMethodAutomatic,
		Conditions:         jam.generateAccessConditions(ctx, request),
	}

	// Store the grant
	jam.activeGrants[grant.ID] = grant

	// Update request status
	request.Status = JITAccessRequestStatusApproved
	request.ApprovedBy = approverID
	request.ApprovedAt = &grant.GrantedAt
	request.ApprovalReason = reason
	request.GrantedAccess = grant

	// Activate the access immediately
	err := jam.activateAccess(ctx, grant)
	if err != nil {
		// Rollback the grant
		delete(jam.activeGrants, grant.ID)
		request.Status = JITAccessRequestStatusPending
		request.ApprovedBy = ""
		request.ApprovedAt = nil
		request.ApprovalReason = ""
		request.GrantedAccess = nil
		return nil, fmt.Errorf("failed to activate access: %w", err)
	}

	// Audit the approval
	jam.recordJITAccessApproval(ctx, request, grant, approverID)

	// Send notifications
	_ = jam.sendNotifications(ctx, request, "request_approved")

	// scheduleDeactivation is a no-op; the central ticker handles expiry.
	jam.scheduleDeactivation(ctx, grant)

	return grant, nil
}

// DenyRequest denies a JIT access request
func (jam *JITAccessManager) DenyRequest(ctx context.Context, requestID, reviewerID, reason string) error {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	request, exists := jam.requests[requestID]
	if !exists {
		return fmt.Errorf("request %s not found", requestID)
	}

	if request.Status != JITAccessRequestStatusPending {
		return fmt.Errorf("request %s is not in pending status", requestID)
	}

	// Update request status
	request.Status = JITAccessRequestStatusDenied
	now := time.Now()
	request.ReviewedAt = &now
	request.ReviewedBy = reviewerID
	request.DenialReason = reason

	// Audit the denial
	jam.recordJITAccessDenial(ctx, request, reviewerID, reason)

	// Send notifications
	_ = jam.sendNotifications(ctx, request, "request_denied")

	return nil
}

// ExtendAccess extends an active JIT access grant
func (jam *JITAccessManager) ExtendAccess(ctx context.Context, grantID string, duration time.Duration, requesterID, reason string) error {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	grant, exists := jam.activeGrants[grantID]
	if !exists {
		return fmt.Errorf("grant %s not found", grantID)
	}

	if grant.Status != JITAccessGrantStatusActive {
		return fmt.Errorf("grant %s is not active", grantID)
	}

	// Check extension limits
	if grant.ExtensionsUsed >= grant.MaxExtensions {
		return fmt.Errorf("maximum extensions (%d) reached for grant %s", grant.MaxExtensions, grantID)
	}

	// Validate extension request
	originalRequest := jam.requests[grant.RequestID]
	if originalRequest.MaxDuration > 0 {
		totalDuration := time.Since(grant.GrantedAt) + duration
		if totalDuration > originalRequest.MaxDuration {
			return fmt.Errorf("extension would exceed maximum duration of %v", originalRequest.MaxDuration)
		}
	}

	// Check if requester is authorized to extend
	if requesterID != grant.RequesterID {
		hasPermission, err := jam.checkExtensionPermission(ctx, requesterID, grant)
		if err != nil {
			return fmt.Errorf("failed to check extension permission: %w", err)
		}
		if !hasPermission {
			return fmt.Errorf("requester %s not authorized to extend grant %s", requesterID, grantID)
		}
	}

	// Extend the grant in memory
	grant.ExpiresAt = grant.ExpiresAt.Add(duration)
	grant.ExtensionsUsed++
	grant.LastExtensionAt = &[]time.Time{time.Now()}[0]
	grant.LastExtensionBy = requesterID
	grant.ExtensionReasons = append(grant.ExtensionReasons, ExtensionRecord{
		ExtendedBy: requesterID,
		ExtendedAt: time.Now(),
		Duration:   duration,
		Reason:     reason,
	})

	// Update store record: Session.ExpiresAt and JITSessionData.ExtensionsUsed must both be updated.
	if jam.grantStore != nil {
		session, err := jam.grantStore.GetSession(ctx, grantID)
		if err == nil {
			session.ExpiresAt = grant.ExpiresAt
			jitData, _ := extractJITSessionData(session)
			jitData.ExtensionsUsed = grant.ExtensionsUsed
			session.SessionData = jitData
			if updateErr := jam.grantStore.UpdateSession(ctx, grantID, session); updateErr != nil {
				slog.Warn("failed to update session for extension", "grant_id", grantID, "error", updateErr)
			}
		} else {
			slog.Warn("failed to get session for extension update", "grant_id", grantID, "error", err)
		}
	}

	// Audit the extension
	jam.recordJITAccessExtension(ctx, grant, requesterID, duration, reason)

	// Send notifications
	_ = jam.sendExtensionNotifications(ctx, grant, duration, reason)

	// scheduleDeactivation is a no-op; the central ticker handles expiry.
	jam.scheduleDeactivation(ctx, grant)

	return nil
}

// RevokeAccess immediately revokes an active JIT access grant
func (jam *JITAccessManager) RevokeAccess(ctx context.Context, grantID, revokerID, reason string) error {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

	grant, exists := jam.activeGrants[grantID]
	if !exists {
		return fmt.Errorf("grant %s not found", grantID)
	}

	if grant.Status != JITAccessGrantStatusActive {
		return fmt.Errorf("grant %s is not active", grantID)
	}

	// Validate revoker authority
	if err := jam.validateRevoker(ctx, grant, revokerID); err != nil {
		return fmt.Errorf("revoker validation failed: %w", err)
	}

	// Deactivate the access (updates store to SessionStatusTerminated)
	err := jam.deactivateAccess(ctx, grant)
	if err != nil {
		return fmt.Errorf("failed to deactivate access: %w", err)
	}

	// Update grant status
	grant.Status = JITAccessGrantStatusRevoked
	now := time.Now()
	grant.RevokedAt = &now
	grant.RevokedBy = revokerID
	grant.RevocationReason = reason

	// Audit the revocation
	jam.recordJITAccessRevocation(ctx, grant, revokerID, reason)

	// Send notifications
	_ = jam.sendRevocationNotifications(ctx, grant, reason)

	return nil
}

// GetActiveGrants returns all active grants for a subject
func (jam *JITAccessManager) GetActiveGrants(ctx context.Context, subjectID, tenantID string) ([]*JITAccessGrant, error) {
	jam.mutex.RLock()
	defer jam.mutex.RUnlock()

	var grants []*JITAccessGrant
	now := time.Now()

	for _, grant := range jam.activeGrants {
		// Filter by subject and tenant
		if (grant.RequesterID == subjectID || grant.TargetID == subjectID) && grant.TenantID == tenantID {
			// Check if grant is still active
			if grant.Status == JITAccessGrantStatusActive && grant.ExpiresAt.After(now) {
				grants = append(grants, grant)
			}
		}
	}

	return grants, nil
}

// GetRequest returns a JIT access request by ID
func (jam *JITAccessManager) GetRequest(ctx context.Context, requestID string) (*JITAccessRequest, error) {
	jam.mutex.RLock()
	defer jam.mutex.RUnlock()

	request, exists := jam.requests[requestID]
	if !exists {
		return nil, fmt.Errorf("request %s not found", requestID)
	}

	return request, nil
}

// ListRequests returns JIT access requests with optional filtering
func (jam *JITAccessManager) ListRequests(ctx context.Context, filter *JITAccessRequestFilter) ([]*JITAccessRequest, error) {
	jam.mutex.RLock()
	defer jam.mutex.RUnlock()

	var results []*JITAccessRequest

	for _, request := range jam.requests {
		if jam.matchesFilter(request, filter) {
			results = append(results, request)
		}
	}

	return results, nil
}

// Helper methods

func (jam *JITAccessManager) validateAccessRequest(ctx context.Context, req *JITAccessRequestSpec) error {
	if req.RequesterID == "" {
		return fmt.Errorf("requester ID is required")
	}
	if req.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if len(req.Permissions) == 0 && len(req.Roles) == 0 {
		return fmt.Errorf("at least one permission or role is required")
	}
	if req.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if req.Duration > 24*time.Hour {
		return fmt.Errorf("duration cannot exceed 24 hours")
	}
	if req.Justification == "" {
		return fmt.Errorf("justification is required")
	}

	return nil
}

func (jam *JITAccessManager) checkCurrentAccess(ctx context.Context, subjectID string, permissions []string, tenantID string) (bool, error) {
	for _, permID := range permissions {
		accessRequest := &common.AccessRequest{
			SubjectId:    subjectID,
			PermissionId: permID,
			TenantId:     tenantID,
		}

		response, err := jam.rbacManager.CheckPermission(ctx, accessRequest)
		if err != nil {
			return false, err
		}
		if !response.Granted {
			return false, nil
		}
	}
	return true, nil
}

func (jam *JITAccessManager) determineApprovalWorkflow(ctx context.Context, request *JITAccessRequest) (*ApprovalWorkflow, error) {
	var (
		workflow *ApprovalWorkflow
		err      error
	)

	if jam.workflowProvider != nil {
		workflow, err = jam.workflowProvider(ctx, request)
		if err != nil {
			return nil, err
		}
	} else {
		workflow = jam.defaultApprovalWorkflow(request)
	}

	// Store the resolved workflow keyed by request ID so multi-stage approval can look it up.
	jam.approvalWorkflows[request.ID] = workflow

	return workflow, nil
}

func (jam *JITAccessManager) defaultApprovalWorkflow(request *JITAccessRequest) *ApprovalWorkflow {
	workflow := &ApprovalWorkflow{
		ID:   "default-approval",
		Name: "Default Approval Workflow",
		Type: ApprovalTypeSequential,
		Approvers: []ApprovalStage{
			{
				ID:           "stage-1",
				Type:         ApprovalStageTypeRole,
				Approvers:    []string{"admin", "security_officer"},
				MinApprovals: 1,
				TimeoutHours: 2,
			},
		},
	}

	if request.EmergencyAccess {
		workflow.Approvers[0].TimeoutHours = 0.5
	}

	if jam.isHighPrivilegeRequest(request) {
		workflow.Approvers[0].MinApprovals = 2
	}

	return workflow
}

func (jam *JITAccessManager) shouldAutoApprove(ctx context.Context, request *JITAccessRequest) bool {
	// Auto-approve low-risk requests during business hours
	return jam.isLowRiskRequest(request) && jam.isBusinessHours()
}

func (jam *JITAccessManager) isHighPrivilegeRequest(request *JITAccessRequest) bool {
	highPrivilegePermissions := []string{"admin", "delete", "system_config"}
	for _, perm := range request.Permissions {
		for _, highPerm := range highPrivilegePermissions {
			if perm == highPerm {
				return true
			}
		}
	}
	return false
}

func (jam *JITAccessManager) isLowRiskRequest(request *JITAccessRequest) bool {
	return request.Duration <= time.Hour && !jam.isHighPrivilegeRequest(request)
}

func (jam *JITAccessManager) isBusinessHours() bool {
	now := time.Now()
	hour := now.Hour()
	weekday := now.Weekday()
	return weekday >= time.Monday && weekday <= time.Friday && hour >= 9 && hour <= 17
}

func (jam *JITAccessManager) generateAccessConditions(ctx context.Context, request *JITAccessRequest) []AccessCondition {
	conditions := []AccessCondition{
		{
			Type:  ConditionTypeTimeWindow,
			Value: fmt.Sprintf("%s-%s", time.Now().Format(time.RFC3339), request.ExpiresAt.Format(time.RFC3339)),
		},
	}

	if request.EmergencyAccess {
		conditions = append(conditions, AccessCondition{
			Type:  ConditionTypeAuditEnhanced,
			Value: "true",
		})
	}

	return conditions
}

func (jam *JITAccessManager) matchesFilter(request *JITAccessRequest, filter *JITAccessRequestFilter) bool {
	if filter == nil {
		return true
	}

	if filter.RequesterID != "" && request.RequesterID != filter.RequesterID {
		return false
	}
	if filter.TenantID != "" && request.TenantID != filter.TenantID {
		return false
	}
	if filter.Status != "" && request.Status != JITAccessRequestStatus(filter.Status) {
		return false
	}

	return true
}

// Additional helper methods for access management

func (jam *JITAccessManager) validateApprover(ctx context.Context, request *JITAccessRequest, approverID string) error {
	// Check if approver has permission to approve JIT requests
	accessRequest := &common.AccessRequest{
		SubjectId:    approverID,
		PermissionId: "jit_access.approve",
		TenantId:     request.TenantID,
	}

	response, err := jam.rbacManager.CheckPermission(ctx, accessRequest)
	if err != nil {
		return fmt.Errorf("failed to check approver permission: %w", err)
	}
	if !response.Granted {
		return fmt.Errorf("approver %s does not have permission to approve JIT requests", approverID)
	}

	return nil
}

func (jam *JITAccessManager) validateRevoker(ctx context.Context, grant *JITAccessGrant, revokerID string) error {
	// Allow requester to revoke their own access
	if grant.RequesterID == revokerID {
		return nil
	}

	// Check if revoker has permission to revoke JIT access
	accessRequest := &common.AccessRequest{
		SubjectId:    revokerID,
		PermissionId: "jit_access.revoke",
		TenantId:     grant.TenantID,
	}

	response, err := jam.rbacManager.CheckPermission(ctx, accessRequest)
	if err != nil {
		return fmt.Errorf("failed to check revoker permission: %w", err)
	}
	if !response.Granted {
		return fmt.Errorf("revoker %s does not have permission to revoke JIT access", revokerID)
	}

	return nil
}

func (jam *JITAccessManager) checkExtensionPermission(ctx context.Context, requesterID string, grant *JITAccessGrant) (bool, error) {
	accessRequest := &common.AccessRequest{
		SubjectId:    requesterID,
		PermissionId: "jit_access.extend",
		TenantId:     grant.TenantID,
	}

	response, err := jam.rbacManager.CheckPermission(ctx, accessRequest)
	if err != nil {
		return false, err
	}

	return response.Granted, nil
}

func (jam *JITAccessManager) startApprovalWorkflow(ctx context.Context, request *JITAccessRequest, workflow *ApprovalWorkflow) error {
	if len(workflow.Approvers) > 1 {
		// Multi-stage: initialise WorkflowState so ApproveRequest uses the staged path.
		stageApprovals := make(map[int]map[string]struct{}, len(workflow.Approvers))
		for i := range workflow.Approvers {
			stageApprovals[i] = make(map[string]struct{})
		}
		request.WorkflowState = &WorkflowState{
			CurrentStage:   0,
			StageApprovals: stageApprovals,
		}
	}

	if len(workflow.Approvers) > 0 {
		return jam.sendApprovalNotifications(ctx, request, workflow.Approvers[0].Approvers)
	}
	return nil
}

// validateStageApprover checks that approverID is listed in the current pending stage's
// Approvers slice. It must be called only from the public ApproveRequest path; internal
// approveRequest (used by auto-approval with approverID="system") is exempt.
// Returns a distinct error from the RBAC jit_access.approve permission check so callers
// can tell the two failure modes apart.
func (jam *JITAccessManager) validateStageApprover(request *JITAccessRequest, approverID string) error {
	if request.WorkflowState == nil {
		return nil
	}
	workflow, exists := jam.approvalWorkflows[request.ID]
	if !exists {
		return nil
	}
	stageIdx := request.WorkflowState.CurrentStage
	if stageIdx >= len(workflow.Approvers) {
		return nil
	}
	stage := workflow.Approvers[stageIdx]
	for _, a := range stage.Approvers {
		if a == approverID {
			return nil
		}
	}
	return fmt.Errorf("approver %s is not a member of stage %s", approverID, stage.ID)
}

// recordStageApproval emits a stage_approved audit event. No-op when auditManager is nil.
func (jam *JITAccessManager) recordStageApproval(ctx context.Context, request *JITAccessRequest, stageID, approverID string) {
	if jam.auditManager == nil {
		return
	}
	if err := jam.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		request.TenantID, request.RequesterID, "jit_access", request.ID, "stage_approved",
		business.AuditResultSuccess,
	).Detail("stage_id", stageID).Detail("approver_id", approverID)); err != nil {
		slog.Warn("failed to record jit stage approval audit event", "error", err)
	}
}

// advanceWorkflowStage increments the current stage index and notifies the next stage's approvers.
func (jam *JITAccessManager) advanceWorkflowStage(ctx context.Context, request *JITAccessRequest, workflow *ApprovalWorkflow) {
	request.WorkflowState.CurrentStage++
	nextIdx := request.WorkflowState.CurrentStage
	if nextIdx < len(workflow.Approvers) {
		_ = jam.sendApprovalNotifications(ctx, request, workflow.Approvers[nextIdx].Approvers)
	}
}

// activateAccess sets the grant active and persists it to the SessionStore.
// On nil grantStore, operates memory-only with no panic.
func (jam *JITAccessManager) activateAccess(ctx context.Context, grant *JITAccessGrant) error {
	now := time.Now()
	grant.Status = JITAccessGrantStatusActive
	grant.ActivatedAt = &now

	if jam.grantStore == nil {
		return nil
	}

	session := &business.Session{
		SessionID:    grant.ID,
		UserID:       grant.RequesterID, // required by Session.Validate()
		TenantID:     grant.TenantID,
		SessionType:  business.SessionTypeJIT,
		CreatedAt:    grant.GrantedAt,
		LastActivity: grant.GrantedAt,
		ExpiresAt:    grant.ExpiresAt,
		Status:       business.SessionStatusActive,
		Persistent:   true,
		SessionData: &business.JITSessionData{
			RequestID:      grant.RequestID,
			TargetID:       grant.TargetID,
			Permissions:    grant.Permissions,
			Roles:          grant.Roles,
			ResourceIDs:    grant.ResourceIDs,
			ApprovedBy:     grant.ApprovedBy,
			ApprovalReason: grant.ApprovalReason,
			GrantedAt:      grant.GrantedAt,
			ExtensionsUsed: grant.ExtensionsUsed,
			MaxExtensions:  grant.MaxExtensions,
		},
	}

	if err := jam.grantStore.CreateSession(ctx, session); err != nil {
		return fmt.Errorf("failed to persist JIT grant to session store: %w", err)
	}

	return nil
}

// deactivateAccess updates the grant's in-memory state and sets the store session to
// SessionStatusTerminated. On nil store, operates memory-only.
// Store errors are best-effort: a connectivity failure is logged but does not fail the
// in-memory revocation. The caller (RevokeAccess) remains authoritative; a subsequent
// restart will reload the session from the store — callers requiring strict durability
// should layer their own retry or saga logic.
func (jam *JITAccessManager) deactivateAccess(ctx context.Context, grant *JITAccessGrant) error {
	now := time.Now()
	grant.Status = JITAccessGrantStatusDeactivated
	grant.DeactivatedAt = &now

	if jam.grantStore == nil {
		return nil
	}

	session, err := jam.grantStore.GetSession(ctx, grant.ID)
	if err != nil {
		slog.Warn("failed to get session for deactivation", "grant_id", grant.ID, "error", err)
		return nil
	}

	session.Status = business.SessionStatusTerminated
	modAt := time.Now()
	session.ModifiedAt = &modAt

	if err := jam.grantStore.UpdateSession(ctx, grant.ID, session); err != nil {
		slog.Warn("failed to update session to terminated", "grant_id", grant.ID, "error", err)
	}

	return nil
}

// scheduleDeactivation is intentionally a no-op. The central ticker loop (started via Start)
// calls CleanupExpiredGrants on a configurable interval to handle expiry for all grants.
func (jam *JITAccessManager) scheduleDeactivation(_ context.Context, _ *JITAccessGrant) {}

func (jam *JITAccessManager) sendNotifications(ctx context.Context, request *JITAccessRequest, eventType string) error {
	if jam.notificationService != nil {
		return jam.notificationService.SendRequestNotification(ctx, request, eventType)
	}
	return nil
}

func (jam *JITAccessManager) sendApprovalNotifications(ctx context.Context, request *JITAccessRequest, approvers []string) error {
	if jam.notificationService != nil {
		return jam.notificationService.SendApprovalNotification(ctx, request, approvers)
	}
	return nil
}

func (jam *JITAccessManager) sendExtensionNotifications(ctx context.Context, grant *JITAccessGrant, duration time.Duration, reason string) error {
	if jam.notificationService != nil {
		return jam.notificationService.SendGrantNotification(ctx, grant, "access_extended")
	}
	return nil
}

func (jam *JITAccessManager) sendRevocationNotifications(ctx context.Context, grant *JITAccessGrant, reason string) error {
	if jam.notificationService != nil {
		return jam.notificationService.SendRevocationNotification(ctx, grant, reason)
	}
	return nil
}

// extractJITSessionData converts session.SessionData to *business.JITSessionData.
// Returns the extracted data and true on success, or an empty struct and false on failure.
// Handles both direct pointer and the map[string]interface{} form produced by JSON round-trips.
func extractJITSessionData(session *business.Session) (*business.JITSessionData, bool) {
	if session.SessionData == nil {
		return &business.JITSessionData{}, false
	}
	switch v := session.SessionData.(type) {
	case *business.JITSessionData:
		return v, true
	case map[string]interface{}:
		b, err := json.Marshal(v)
		if err != nil {
			return &business.JITSessionData{}, false
		}
		var jd business.JITSessionData
		if err := json.Unmarshal(b, &jd); err != nil {
			return &business.JITSessionData{}, false
		}
		return &jd, true
	default:
		return &business.JITSessionData{}, false
	}
}
