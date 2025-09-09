package jit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
	"github.com/google/uuid"
)

// JITAccessManager manages Just-In-Time access requests and grants with zero-trust policy integration
type JITAccessManager struct {
	rbacManager         rbac.RBACManager
	requests            map[string]*JITAccessRequest
	activeGrants        map[string]*JITAccessGrant
	approvalWorkflows   map[string]*ApprovalWorkflow
	auditLogger         *JITAuditLogger
	notificationService NotificationService
	
	// Zero-trust policy integration
	zeroTrustEngine     *zerotrust.ZeroTrustPolicyEngine
	zeroTrustEnabled    bool
	zeroTrustMode       ZeroTrustJITMode
	mutex               sync.RWMutex
}

// ZeroTrustJITMode defines how zero-trust policies are applied to JIT access
type ZeroTrustJITMode string

const (
	// ZeroTrustJITModeDisabled disables zero-trust policy evaluation for JIT access
	ZeroTrustJITModeDisabled ZeroTrustJITMode = "disabled"
	
	// ZeroTrustJITModeRequestValidation evaluates zero-trust policies during JIT request creation
	ZeroTrustJITModeRequestValidation ZeroTrustJITMode = "request_validation"
	
	// ZeroTrustJITModeApprovalGating requires zero-trust policy approval before JIT approval
	ZeroTrustJITModeApprovalGating ZeroTrustJITMode = "approval_gating"
	
	// ZeroTrustJITModeGrantValidation evaluates zero-trust policies when JIT access is activated
	ZeroTrustJITModeGrantValidation ZeroTrustJITMode = "grant_validation"
	
	// ZeroTrustJITModeComprehensive applies zero-trust validation at all JIT lifecycle stages
	ZeroTrustJITModeComprehensive ZeroTrustJITMode = "comprehensive"
)

// NewJITAccessManager creates a new JIT access manager
func NewJITAccessManager(rbacManager rbac.RBACManager, notificationService NotificationService) *JITAccessManager {
	return &JITAccessManager{
		rbacManager:         rbacManager,
		requests:            make(map[string]*JITAccessRequest),
		activeGrants:        make(map[string]*JITAccessGrant),
		approvalWorkflows:   make(map[string]*ApprovalWorkflow),
		auditLogger:         NewJITAuditLogger(),
		notificationService: notificationService,
		
		// Zero-trust defaults
		zeroTrustEngine:  nil,
		zeroTrustEnabled: false,
		zeroTrustMode:    ZeroTrustJITModeDisabled,
		mutex:           sync.RWMutex{},
	}
}

// EnableZeroTrustPolicies enables zero-trust policy evaluation with specified mode
func (jam *JITAccessManager) EnableZeroTrustPolicies(engine *zerotrust.ZeroTrustPolicyEngine, mode ZeroTrustJITMode) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()
	
	jam.zeroTrustEngine = engine
	jam.zeroTrustMode = mode
	jam.zeroTrustEnabled = (mode != ZeroTrustJITModeDisabled && engine != nil)
}

// SetZeroTrustMode updates the zero-trust JIT mode
func (jam *JITAccessManager) SetZeroTrustMode(mode ZeroTrustJITMode) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()
	
	jam.zeroTrustMode = mode
	jam.zeroTrustEnabled = (mode != ZeroTrustJITModeDisabled && jam.zeroTrustEngine != nil)
}

// GetZeroTrustMode returns the current zero-trust JIT mode
func (jam *JITAccessManager) GetZeroTrustMode() ZeroTrustJITMode {
	jam.mutex.RLock()
	defer jam.mutex.RUnlock()
	return jam.zeroTrustMode
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

	// Zero-trust policy validation for request creation
	if jam.shouldEvaluateZeroTrustForRequest() {
		ztValidationResult, err := jam.evaluateZeroTrustForJITRequest(ctx, req)
		if err != nil {
			return nil, fmt.Errorf("zero-trust policy validation failed: %w", err)
		}
		if !ztValidationResult.Granted {
			return nil, fmt.Errorf("JIT access request denied by zero-trust policies: %s", ztValidationResult.Reason)
		}
	}

	// Create the access request
	request := &JITAccessRequest{
		ID:           uuid.New().String(),
		RequesterID:  req.RequesterID,
		TargetID:     req.TargetID,
		TenantID:     req.TenantID,
		Permissions:  req.Permissions,
		Roles:        req.Roles,
		ResourceIDs:  req.ResourceIDs,
		RequestedFor: req.RequestedFor,
		Duration:     req.Duration,
		MaxDuration:  req.MaxDuration,
		Priority:     req.Priority,
		Justification: req.Justification,
		AutoApprove:  req.AutoApprove,
		EmergencyAccess: req.EmergencyAccess,
		RequesterMetadata: req.RequesterMetadata,
		Status:       JITAccessRequestStatusPending,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(req.Duration),
		RequestTTL:   time.Now().Add(24 * time.Hour), // Request expires in 24 hours if not processed
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
	_ = jam.auditLogger.LogAccessRequest(ctx, request, "created")

	// Send notifications
	_ = jam.sendNotifications(ctx, request, "request_created")

	return request, nil
}

// ApproveRequest approves a JIT access request
func (jam *JITAccessManager) ApproveRequest(ctx context.Context, requestID, approverID, reason string) (*JITAccessGrant, error) {
	jam.mutex.Lock()
	defer jam.mutex.Unlock()

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

	// Zero-trust policy validation for approval gating
	if jam.shouldEvaluateZeroTrustForApproval() {
		ztValidationResult, err := jam.evaluateZeroTrustForJITApproval(ctx, request, approverID)
		if err != nil {
			return nil, fmt.Errorf("zero-trust policy validation for approval failed: %w", err)
		}
		if !ztValidationResult.Granted {
			return nil, fmt.Errorf("JIT access approval denied by zero-trust policies: %s", ztValidationResult.Reason)
		}
	}

	// Create the access grant
	grant := &JITAccessGrant{
		ID:               uuid.New().String(),
		RequestID:        requestID,
		RequesterID:      request.RequesterID,
		TargetID:         request.TargetID,
		TenantID:         request.TenantID,
		Permissions:      request.Permissions,
		Roles:            request.Roles,
		ResourceIDs:      request.ResourceIDs,
		ApprovedBy:       approverID,
		ApprovalReason:   reason,
		GrantedAt:        time.Now(),
		ExpiresAt:        request.ExpiresAt,
		Status:           JITAccessGrantStatusActive,
		MaxExtensions:    3, // Allow up to 3 extensions
		ExtensionsUsed:   0,
		ActivationMethod: ActivationMethodImmediate,
		DeactivationMethod: DeactivationMethodAutomatic,
		Conditions:       jam.generateAccessConditions(ctx, request),
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
	_ = jam.auditLogger.LogAccessApproval(ctx, request, grant, approverID)

	// Send notifications
	_ = jam.sendNotifications(ctx, request, "request_approved")

	// Schedule automatic deactivation
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
	_ = jam.auditLogger.LogAccessDenial(ctx, request, reviewerID, reason)

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

	// Extend the grant
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

	// Audit the extension
	_ = jam.auditLogger.LogAccessExtension(ctx, grant, requesterID, duration, reason)

	// Send notifications
	_ = jam.sendExtensionNotifications(ctx, grant, duration, reason)

	// Reschedule deactivation
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

	// Deactivate the access
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
	_ = jam.auditLogger.LogAccessRevocation(ctx, grant, revokerID, reason)

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
	// Default workflow - single approver
	workflow := &ApprovalWorkflow{
		ID:   "default-approval",
		Name: "Default Approval Workflow",
		Type: ApprovalTypeSequential,
		Approvers: []ApprovalStage{
			{
				ID:          "stage-1",
				Type:        ApprovalStageTypeRole,
				Approvers:   []string{"admin", "security_officer"},
				MinApprovals: 1,
				TimeoutHours: 2,
			},
		},
	}

	// Emergency access gets expedited workflow
	if request.EmergencyAccess {
		workflow.Approvers[0].TimeoutHours = 0.5 // 30 minutes
	}

	// High-privilege requests require multiple approvers
	if jam.isHighPrivilegeRequest(request) {
		workflow.Approvers[0].MinApprovals = 2
	}

	return workflow, nil
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
	// Implementation would integrate with workflow engine
	// For now, simulate by notifying first stage approvers
	if len(workflow.Approvers) > 0 {
		firstStage := workflow.Approvers[0]
		return jam.sendApprovalNotifications(ctx, request, firstStage.Approvers)
	}
	return nil
}

func (jam *JITAccessManager) activateAccess(ctx context.Context, grant *JITAccessGrant) error {
	// Zero-trust policy validation for grant activation
	if jam.shouldEvaluateZeroTrustForGrant() {
		ztValidationResult, err := jam.evaluateZeroTrustForJITGrant(ctx, grant)
		if err != nil {
			return fmt.Errorf("zero-trust policy validation for grant activation failed: %w", err)
		}
		if !ztValidationResult.Granted {
			return fmt.Errorf("JIT access grant activation denied by zero-trust policies: %s", ztValidationResult.Reason)
		}
	}

	// Update grant status
	now := time.Now()
	grant.Status = JITAccessGrantStatusActive
	grant.ActivatedAt = &now

	// Note: In a full implementation, this would create temporary role assignments
	// or integrate with the delegation system once it's exposed via the RBACManager interface
	// For now, the grant is tracked internally and can be checked via GetActiveGrants

	return nil
}

func (jam *JITAccessManager) deactivateAccess(ctx context.Context, grant *JITAccessGrant) error {
	// Note: In a full implementation, this would revoke temporary role assignments
	// or revoke delegations once the delegation system is exposed via RBACManager interface

	// Update grant status
	now := time.Now()
	grant.Status = JITAccessGrantStatusDeactivated
	grant.DeactivatedAt = &now

	return nil
}

func (jam *JITAccessManager) scheduleDeactivation(ctx context.Context, grant *JITAccessGrant) {
	// In a real implementation, this would schedule a background job
	// For now, we'll implement a simple goroutine
	go func() {
		// Read ExpiresAt under mutex protection to avoid race condition
		jam.mutex.RLock()
		expiresAt := grant.ExpiresAt
		jam.mutex.RUnlock()
		
		duration := time.Until(expiresAt)
		if duration > 0 {
			time.Sleep(duration)
			
			// Check if grant is still active
			jam.mutex.Lock()
			currentGrant, exists := jam.activeGrants[grant.ID]
			if exists && currentGrant.Status == JITAccessGrantStatusActive {
				_ = jam.deactivateAccess(context.Background(), currentGrant)
				currentGrant.Status = JITAccessGrantStatusExpired
			}
			jam.mutex.Unlock()
		}
	}()
}

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

// Zero-trust policy evaluation methods

// shouldEvaluateZeroTrustForRequest determines if zero-trust evaluation is needed for request creation
func (jam *JITAccessManager) shouldEvaluateZeroTrustForRequest() bool {
	return jam.zeroTrustEnabled && jam.zeroTrustEngine != nil && 
		(jam.zeroTrustMode == ZeroTrustJITModeRequestValidation || jam.zeroTrustMode == ZeroTrustJITModeComprehensive)
}

// shouldEvaluateZeroTrustForApproval determines if zero-trust evaluation is needed for approval gating
func (jam *JITAccessManager) shouldEvaluateZeroTrustForApproval() bool {
	return jam.zeroTrustEnabled && jam.zeroTrustEngine != nil && 
		(jam.zeroTrustMode == ZeroTrustJITModeApprovalGating || jam.zeroTrustMode == ZeroTrustJITModeComprehensive)
}

// shouldEvaluateZeroTrustForGrant determines if zero-trust evaluation is needed for grant activation
func (jam *JITAccessManager) shouldEvaluateZeroTrustForGrant() bool {
	return jam.zeroTrustEnabled && jam.zeroTrustEngine != nil && 
		(jam.zeroTrustMode == ZeroTrustJITModeGrantValidation || jam.zeroTrustMode == ZeroTrustJITModeComprehensive)
}

// evaluateZeroTrustForJITRequest evaluates zero-trust policies for JIT access request creation
func (jam *JITAccessManager) evaluateZeroTrustForJITRequest(ctx context.Context, req *JITAccessRequestSpec) (*zerotrust.ZeroTrustAccessResponse, error) {
	// Convert JIT request to access request for zero-trust evaluation
	accessRequest := jam.convertJITRequestToAccessRequest(req)
	
	// Create zero-trust request with JIT-specific context
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		AccessRequest:    accessRequest,
		RequestID:        fmt.Sprintf("jit-request-%d", time.Now().UnixNano()),
		RequestTime:      time.Now(),
		SubjectType:      zerotrust.SubjectTypeUser,
		ResourceType:     "jit_access",
		SourceSystem:     "jit-access-manager",
		RequestSource:    zerotrust.RequestSourceUI,
		Priority:         jam.determineZeroTrustPriority(req),
	}
	
	// Set JIT-specific context in subject attributes
	zeroTrustRequest.SubjectAttributes = map[string]interface{}{
		"request_type":     "jit_access_request",
		"requested_for":    req.RequestedFor,
		"duration":         req.Duration.String(),
		"justification":    req.Justification,
		"emergency_access": req.EmergencyAccess,
		"auto_approve":     req.AutoApprove,
	}
	
	// Evaluate with zero-trust engine
	return jam.zeroTrustEngine.EvaluateAccess(ctx, zeroTrustRequest)
}

// evaluateZeroTrustForJITApproval evaluates zero-trust policies for JIT access approval
func (jam *JITAccessManager) evaluateZeroTrustForJITApproval(ctx context.Context, request *JITAccessRequest, approverID string) (*zerotrust.ZeroTrustAccessResponse, error) {
	// Convert JIT request to access request for zero-trust evaluation
	accessRequest := jam.convertJITRequestToAccessRequestFromRequest(request)
	
	// Create zero-trust request with approval-specific context
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		AccessRequest:    accessRequest,
		RequestID:        fmt.Sprintf("jit-approval-%s", request.ID),
		RequestTime:      time.Now(),
		SubjectType:      zerotrust.SubjectTypeUser,
		ResourceType:     "jit_access",
		SourceSystem:     "jit-access-manager",
		RequestSource:    zerotrust.RequestSourceSystem, // Approval is system-initiated
		Priority:         jam.determineZeroTrustPriorityFromRequest(request),
	}
	
	// Set JIT approval-specific context in subject attributes
	zeroTrustRequest.SubjectAttributes = map[string]interface{}{
		"request_type":     "jit_access_approval",
		"requested_for":    request.RequestedFor,
		"duration":         request.Duration.String(),
		"justification":    request.Justification,
		"emergency_access": request.EmergencyAccess,
		"auto_approve":     request.AutoApprove,
		"approver_id":      approverID,
	}
	
	// Evaluate with zero-trust engine
	return jam.zeroTrustEngine.EvaluateAccess(ctx, zeroTrustRequest)
}

// evaluateZeroTrustForJITGrant evaluates zero-trust policies for JIT access grant activation
func (jam *JITAccessManager) evaluateZeroTrustForJITGrant(ctx context.Context, grant *JITAccessGrant) (*zerotrust.ZeroTrustAccessResponse, error) {
	// Get the original request to extract context
	originalRequest := jam.requests[grant.RequestID]
	if originalRequest == nil {
		return nil, fmt.Errorf("original request %s not found for grant %s", grant.RequestID, grant.ID)
	}
	
	// Convert grant to access request for zero-trust evaluation
	accessRequest := jam.convertJITGrantToAccessRequest(grant)
	
	// Create zero-trust request with grant-specific context
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		AccessRequest:    accessRequest,
		RequestID:        fmt.Sprintf("jit-grant-%s", grant.ID),
		RequestTime:      time.Now(),
		SubjectType:      zerotrust.SubjectTypeUser,
		ResourceType:     "jit_access",
		SourceSystem:     "jit-access-manager",
		RequestSource:    zerotrust.RequestSourceSystem, // Grant activation is system-initiated
		Priority:         jam.determineZeroTrustPriorityFromRequest(originalRequest),
	}
	
	// Set JIT grant-specific context in subject attributes
	zeroTrustRequest.SubjectAttributes = map[string]interface{}{
		"request_type":     "jit_access_grant",
		"requested_for":    originalRequest.RequestedFor, // Use from original request
		"duration":         time.Until(grant.ExpiresAt).String(),
		"justification":    originalRequest.Justification,
		"emergency_access": originalRequest.EmergencyAccess,
		"auto_approve":     originalRequest.AutoApprove,
		"approver_id":      grant.ApprovedBy,
		"grant_id":         grant.ID,
	}
	
	// Evaluate with zero-trust engine
	return jam.zeroTrustEngine.EvaluateAccess(ctx, zeroTrustRequest)
}

// Helper methods for zero-trust request conversion

func (jam *JITAccessManager) convertJITRequestToAccessRequest(req *JITAccessRequestSpec) *common.AccessRequest {
	// Convert the first permission as the primary permission
	permissionID := ""
	if len(req.Permissions) > 0 {
		permissionID = req.Permissions[0]
	}
	
	// Convert resource IDs to a single resource (take first or empty)
	resourceID := ""
	if len(req.ResourceIDs) > 0 {
		resourceID = req.ResourceIDs[0]
	}
	
	return &common.AccessRequest{
		SubjectId:    req.RequesterID,
		PermissionId: permissionID,
		ResourceId:   resourceID,
		TenantId:     req.TenantID,
		Context: map[string]string{
			"access_type":    "jit",
			"target_id":      req.TargetID,
			"duration":       req.Duration.String(),
			"justification":  req.Justification,
			"emergency":      fmt.Sprintf("%v", req.EmergencyAccess),
		},
	}
}

func (jam *JITAccessManager) convertJITRequestToAccessRequestFromRequest(request *JITAccessRequest) *common.AccessRequest {
	// Convert the first permission as the primary permission
	permissionID := ""
	if len(request.Permissions) > 0 {
		permissionID = request.Permissions[0]
	}
	
	// Convert resource IDs to a single resource (take first or empty)
	resourceID := ""
	if len(request.ResourceIDs) > 0 {
		resourceID = request.ResourceIDs[0]
	}
	
	return &common.AccessRequest{
		SubjectId:    request.RequesterID,
		PermissionId: permissionID,
		ResourceId:   resourceID,
		TenantId:     request.TenantID,
		Context: map[string]string{
			"access_type":    "jit",
			"target_id":      request.TargetID,
			"duration":       request.Duration.String(),
			"justification":  request.Justification,
			"emergency":      fmt.Sprintf("%v", request.EmergencyAccess),
			"request_id":     request.ID,
		},
	}
}

func (jam *JITAccessManager) convertJITGrantToAccessRequest(grant *JITAccessGrant) *common.AccessRequest {
	// Convert the first permission as the primary permission
	permissionID := ""
	if len(grant.Permissions) > 0 {
		permissionID = grant.Permissions[0]
	}
	
	// Convert resource IDs to a single resource (take first or empty)
	resourceID := ""
	if len(grant.ResourceIDs) > 0 {
		resourceID = grant.ResourceIDs[0]
	}
	
	return &common.AccessRequest{
		SubjectId:    grant.RequesterID,
		PermissionId: permissionID,
		ResourceId:   resourceID,
		TenantId:     grant.TenantID,
		Context: map[string]string{
			"access_type":      "jit",
			"target_id":        grant.TargetID,
			"duration":         time.Until(grant.ExpiresAt).String(),
			"approval_reason":  grant.ApprovalReason,
			"approved_by":      grant.ApprovedBy,
			"grant_id":         grant.ID,
		},
	}
}

func (jam *JITAccessManager) determineZeroTrustPriority(req *JITAccessRequestSpec) zerotrust.RequestPriority {
	if req.EmergencyAccess {
		return zerotrust.RequestPriorityHigh
	}
	if req.Duration > 4*time.Hour {
		return zerotrust.RequestPriorityNormal
	}
	return zerotrust.RequestPriorityLow
}

func (jam *JITAccessManager) determineZeroTrustPriorityFromRequest(request *JITAccessRequest) zerotrust.RequestPriority {
	if request.EmergencyAccess {
		return zerotrust.RequestPriorityHigh
	}
	if request.Duration > 4*time.Hour {
		return zerotrust.RequestPriorityNormal
	}
	return zerotrust.RequestPriorityLow
}