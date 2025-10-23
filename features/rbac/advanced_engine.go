// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package rbac

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/zerotrust"
)

// ZeroTrustMode defines how zero-trust policies are applied with RBAC
type ZeroTrustMode string

const (
	// ZeroTrustModeDisabled disables zero-trust policy evaluation
	ZeroTrustModeDisabled ZeroTrustMode = "disabled"

	// ZeroTrustModeAugmented uses zero-trust policies to augment RBAC decisions
	// RBAC must pass AND zero-trust policies must pass
	ZeroTrustModeAugmented ZeroTrustMode = "augmented"

	// ZeroTrustModeEnforced uses zero-trust policies as the primary authorization
	// Zero-trust policies override RBAC decisions
	ZeroTrustModeEnforced ZeroTrustMode = "enforced"

	// ZeroTrustModeAuditing logs zero-trust policy decisions but doesn't enforce them
	ZeroTrustModeAuditing ZeroTrustMode = "auditing"
)

// AdvancedAuthEngine provides enhanced authorization with conditional permissions,
// delegation, zero-trust policy validation, and comprehensive audit logging
type AdvancedAuthEngine struct {
	baseEngine        *AuthEngine
	conditionEngine   *ConditionEngine
	scopeEngine       *ScopeEngine
	delegationManager *DelegationManager
	auditLogger       *AuditLogger

	// Zero-trust policy integration
	zeroTrustEngine  *zerotrust.ZeroTrustPolicyEngine
	zeroTrustEnabled bool
	zeroTrustMode    ZeroTrustMode
}

// NewAdvancedAuthEngine creates a new advanced authorization engine
func NewAdvancedAuthEngine(
	permStore PermissionStore,
	roleStore RoleStore,
	subjectStore SubjectStore,
	assignmentStore RoleAssignmentStore,
) *AdvancedAuthEngine {
	baseEngine := NewAuthEngine(permStore, roleStore, subjectStore, assignmentStore)

	return &AdvancedAuthEngine{
		baseEngine:        baseEngine,
		conditionEngine:   NewConditionEngine(),
		scopeEngine:       NewScopeEngine(),
		delegationManager: NewDelegationManager(nil), // Will be set via SetRBACManager
		auditLogger:       NewAuditLogger(),

		// Zero-trust defaults
		zeroTrustEngine:  nil, // Will be set via SetZeroTrustEngine
		zeroTrustEnabled: false,
		zeroTrustMode:    ZeroTrustModeDisabled,
	}
}

// SetRBACManager sets the RBAC manager reference for delegation operations
func (a *AdvancedAuthEngine) SetRBACManager(rbacManager RBACManager) {
	a.delegationManager = NewDelegationManager(rbacManager)
}

// SetDelegationManager sets a specific delegation manager instance
func (a *AdvancedAuthEngine) SetDelegationManager(delegationManager *DelegationManager) {
	a.delegationManager = delegationManager
}

// SetAuditLogger sets a specific audit logger instance
func (a *AdvancedAuthEngine) SetAuditLogger(auditLogger *AuditLogger) {
	a.auditLogger = auditLogger
}

// SetZeroTrustEngine configures zero-trust policy integration
func (a *AdvancedAuthEngine) SetZeroTrustEngine(engine *zerotrust.ZeroTrustPolicyEngine, mode ZeroTrustMode) {
	a.zeroTrustEngine = engine
	a.zeroTrustMode = mode
	a.zeroTrustEnabled = (mode != ZeroTrustModeDisabled && engine != nil)
}

// EnableZeroTrust enables zero-trust policy evaluation with the specified mode
func (a *AdvancedAuthEngine) EnableZeroTrust(mode ZeroTrustMode) {
	if a.zeroTrustEngine != nil {
		a.zeroTrustMode = mode
		a.zeroTrustEnabled = (mode != ZeroTrustModeDisabled)
	}
}

// DisableZeroTrust disables zero-trust policy evaluation
func (a *AdvancedAuthEngine) DisableZeroTrust() {
	a.zeroTrustEnabled = false
	a.zeroTrustMode = ZeroTrustModeDisabled
}

// GetZeroTrustMode returns the current zero-trust mode
func (a *AdvancedAuthEngine) GetZeroTrustMode() ZeroTrustMode {
	return a.zeroTrustMode
}

// CheckPermission performs comprehensive permission checking with all advanced features including zero-trust policies
func (a *AdvancedAuthEngine) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	// Extract context information for audit logging
	sourceIP := ""
	userAgent := ""
	if request.Context != nil {
		sourceIP = request.Context["source_ip"]
		userAgent = request.Context["user_agent"]
	}

	// Step 1: Check base RBAC permissions
	baseResponse, err := a.baseEngine.CheckPermission(ctx, request)
	if err != nil {
		errorResponse := &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Error checking base permissions: %v", err),
		}
		_ = a.auditLogger.LogPermissionCheck(ctx, request, errorResponse, sourceIP, userAgent)
		return errorResponse, err
	}

	// Step 2: Check for delegated permissions if base RBAC failed
	var delegatedGranted bool
	var delegatedReason string
	if !baseResponse.Granted {
		delegatedGranted, delegatedReason, err = a.delegationManager.CheckDelegatedPermission(
			ctx, request.SubjectId, request.PermissionId, request.ResourceId, request.TenantId, nil)
		if err != nil {
			errorResponse := &common.AccessResponse{
				Granted: false,
				Reason:  fmt.Sprintf("Error checking delegated permissions: %v", err),
			}
			_ = a.auditLogger.LogPermissionCheck(ctx, request, errorResponse, sourceIP, userAgent)
			return errorResponse, err
		}
	}

	// Determine if RBAC (base + delegation) grants access
	rbacGranted := baseResponse.Granted || delegatedGranted
	var rbacReason string
	if baseResponse.Granted {
		rbacReason = baseResponse.Reason
	} else if delegatedGranted {
		rbacReason = delegatedReason
	} else {
		rbacReason = fmt.Sprintf("Base: %s. Delegation: %s", baseResponse.Reason, delegatedReason)
	}

	// Step 3: Evaluate zero-trust policies if enabled
	var finalResponse *common.AccessResponse
	if a.zeroTrustEnabled && a.zeroTrustEngine != nil {
		zeroTrustResponse, err := a.evaluateZeroTrustPolicies(ctx, request, rbacGranted, rbacReason)
		if err != nil {
			errorResponse := &common.AccessResponse{
				Granted: false,
				Reason:  fmt.Sprintf("Error evaluating zero-trust policies: %v", err),
			}
			_ = a.auditLogger.LogPermissionCheck(ctx, request, errorResponse, sourceIP, userAgent)
			return errorResponse, err
		}
		finalResponse = zeroTrustResponse
	} else {
		// No zero-trust evaluation - use RBAC result
		finalResponse = &common.AccessResponse{
			Granted:            rbacGranted,
			Reason:             rbacReason,
			AppliedRoles:       baseResponse.AppliedRoles,
			AppliedPermissions: baseResponse.AppliedPermissions,
		}
		if delegatedGranted && !baseResponse.Granted {
			finalResponse.AppliedPermissions = []string{request.PermissionId}
		}
	}

	// Step 4: Log the final decision
	_ = a.auditLogger.LogPermissionCheck(ctx, request, finalResponse, sourceIP, userAgent)
	return finalResponse, nil
}

// CheckConditionalPermission checks a conditional permission with context evaluation
func (a *AdvancedAuthEngine) CheckConditionalPermission(ctx context.Context, request *common.AccessRequest, conditionalPerm *common.ConditionalPermission, authContext *common.AuthorizationContext) (*common.AccessResponse, error) {
	// First check if user has the base permission
	baseRequest := &common.AccessRequest{
		SubjectId:    request.SubjectId,
		PermissionId: conditionalPerm.PermissionId,
		TenantId:     request.TenantId,
		Context:      request.Context,
	}

	baseResponse, err := a.baseEngine.CheckPermission(ctx, baseRequest)
	if err != nil {
		return nil, err
	}

	if !baseResponse.Granted {
		return &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Base permission not granted: %s", baseResponse.Reason),
		}, nil
	}

	// Check conditions
	evaluationContext := a.conditionEngine.BuildEvaluationContext(authContext)
	conditionsPass, conditionReason := a.conditionEngine.EvaluateConditions(ctx, conditionalPerm.Conditions, evaluationContext)
	if !conditionsPass {
		return &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Conditional permission conditions not met: %s", conditionReason),
		}, nil
	}

	// Check scope if specified
	if conditionalPerm.Scope != nil && request.ResourceId != "" {
		resourceAttributes := make(map[string]string)
		if authContext.ResourceAttributes != nil {
			resourceAttributes = authContext.ResourceAttributes
		}

		scopeAllowed, scopeReason := a.scopeEngine.EvaluateScope(ctx, conditionalPerm.Scope, request.ResourceId, resourceAttributes)
		if !scopeAllowed {
			return &common.AccessResponse{
				Granted: false,
				Reason:  fmt.Sprintf("Resource not in permitted scope: %s", scopeReason),
			}, nil
		}
	}

	// All checks passed
	return &common.AccessResponse{
		Granted:            true,
		Reason:             fmt.Sprintf("Conditional permission granted. Conditions: %s", conditionReason),
		AppliedPermissions: []string{conditionalPerm.PermissionId},
	}, nil
}

// ValidateAccess performs comprehensive access validation with full context
func (a *AdvancedAuthEngine) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	request := &common.AccessRequest{
		SubjectId:    authContext.SubjectId,
		PermissionId: requiredPermission,
		TenantId:     authContext.TenantId,
		Context:      authContext.Environment,
	}

	return a.CheckPermission(ctx, request)
}

// GetSubjectPermissions retrieves all effective permissions for a subject including delegated permissions
func (a *AdvancedAuthEngine) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	// Get base permissions
	basePermissions, err := a.baseEngine.GetSubjectPermissions(ctx, subjectID, tenantID)
	if err != nil {
		return nil, err
	}

	// Get delegated permissions
	delegations, err := a.delegationManager.GetActiveDelegations(ctx, subjectID, tenantID)
	if err != nil {
		return nil, err
	}

	// Create a map to avoid duplicates
	permissionMap := make(map[string]*common.Permission)

	// Add base permissions
	for _, perm := range basePermissions {
		permissionMap[perm.Id] = perm
	}

	// Add delegated permissions
	for _, delegation := range delegations {
		for _, permID := range delegation.PermissionIds {
			if _, exists := permissionMap[permID]; !exists {
				// Get the permission details
				// Note: This would require access to the permission store
				// For now, create a placeholder permission
				permissionMap[permID] = &common.Permission{
					Id:          permID,
					Name:        fmt.Sprintf("Delegated: %s", permID),
					Description: fmt.Sprintf("Permission delegated by %s", delegation.DelegatorId),
				}
			}
		}
	}

	// Convert map back to slice
	var result []*common.Permission
	for _, perm := range permissionMap {
		result = append(result, perm)
	}

	return result, nil
}

// GetEffectivePermissions gets all effective permissions including conditional and delegated
func (a *AdvancedAuthEngine) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return a.GetSubjectPermissions(ctx, subjectID, tenantID)
}

// GetAuditLogger returns the audit logger for external access
func (a *AdvancedAuthEngine) GetAuditLogger() *AuditLogger {
	return a.auditLogger
}

// GetDelegationManager returns the delegation manager for external access
func (a *AdvancedAuthEngine) GetDelegationManager() *DelegationManager {
	return a.delegationManager
}

// GetConditionEngine returns the condition engine for external access
func (a *AdvancedAuthEngine) GetConditionEngine() *ConditionEngine {
	return a.conditionEngine
}

// GetScopeEngine returns the scope engine for external access
func (a *AdvancedAuthEngine) GetScopeEngine() *ScopeEngine {
	return a.scopeEngine
}

// CreateTemporaryPermission creates a temporary permission grant with conditions
func (a *AdvancedAuthEngine) CreateTemporaryPermission(ctx context.Context, req *TemporaryPermissionRequest) (*common.ConditionalPermission, error) {
	// Validate the request
	if err := a.validateTemporaryPermissionRequest(ctx, req); err != nil {
		return nil, fmt.Errorf("invalid temporary permission request: %w", err)
	}

	conditionalPerm := &common.ConditionalPermission{
		Id:           fmt.Sprintf("temp_%s_%s", req.SubjectID, req.PermissionID),
		PermissionId: req.PermissionID,
		Conditions:   req.Conditions,
		Scope:        req.Scope,
		ExpiresAt:    req.ExpiresAt,
		GrantedBy:    req.GrantedBy,
		GrantedAt:    req.GrantedAt,
	}

	// Log the temporary permission grant
	context := map[string]string{
		"type":       "temporary",
		"expires_at": fmt.Sprintf("%d", req.ExpiresAt),
		"granted_by": req.GrantedBy,
	}

	_ = a.auditLogger.LogPermissionGrant(ctx, req.SubjectID, req.PermissionID, req.ResourceID, req.TenantID, req.GrantedBy, context)

	return conditionalPerm, nil
}

// validateTemporaryPermissionRequest validates a temporary permission request
func (a *AdvancedAuthEngine) validateTemporaryPermissionRequest(ctx context.Context, req *TemporaryPermissionRequest) error {
	if req.SubjectID == "" {
		return fmt.Errorf("subject ID cannot be empty")
	}

	if req.PermissionID == "" {
		return fmt.Errorf("permission ID cannot be empty")
	}

	if req.GrantedBy == "" {
		return fmt.Errorf("granted by cannot be empty")
	}

	if req.ExpiresAt <= req.GrantedAt {
		return fmt.Errorf("expiration time must be after granted time")
	}

	// Validate conditions
	if len(req.Conditions) > 0 {
		for _, condition := range req.Conditions {
			if condition.Type == "" {
				return fmt.Errorf("condition type cannot be empty")
			}
			if len(condition.Values) == 0 {
				return fmt.Errorf("condition must have at least one value")
			}
		}
	}

	// Validate scope
	if req.Scope != nil {
		if err := a.scopeEngine.ValidateScope(ctx, req.Scope); err != nil {
			return fmt.Errorf("invalid scope: %w", err)
		}
	}

	return nil
}

// TemporaryPermissionRequest represents a request for temporary permission
type TemporaryPermissionRequest struct {
	SubjectID    string                  `json:"subject_id"`
	PermissionID string                  `json:"permission_id"`
	ResourceID   string                  `json:"resource_id,omitempty"`
	TenantID     string                  `json:"tenant_id"`
	Conditions   []*common.Condition     `json:"conditions,omitempty"`
	Scope        *common.PermissionScope `json:"scope,omitempty"`
	ExpiresAt    int64                   `json:"expires_at"`
	GrantedBy    string                  `json:"granted_by"`
	GrantedAt    int64                   `json:"granted_at"`
}

// evaluateZeroTrustPolicies evaluates zero-trust policies and combines them with RBAC decisions
func (a *AdvancedAuthEngine) evaluateZeroTrustPolicies(ctx context.Context, request *common.AccessRequest, rbacGranted bool, rbacReason string) (*common.AccessResponse, error) {
	// Convert common.AccessRequest to zerotrust.ZeroTrustAccessRequest
	zeroTrustRequest := a.convertToZeroTrustRequest(request)

	// Evaluate zero-trust policies
	zeroTrustResponse, err := a.zeroTrustEngine.EvaluateAccess(ctx, zeroTrustRequest)
	if err != nil {
		return nil, fmt.Errorf("zero-trust policy evaluation failed: %w", err)
	}

	// Combine RBAC and zero-trust decisions based on the configured mode
	finalResponse := a.combineAuthorizationDecisions(rbacGranted, rbacReason, zeroTrustResponse)
	return finalResponse, nil
}

// convertToZeroTrustRequest converts a common AccessRequest to a ZeroTrustAccessRequest
func (a *AdvancedAuthEngine) convertToZeroTrustRequest(request *common.AccessRequest) *zerotrust.ZeroTrustAccessRequest {
	zeroTrustRequest := &zerotrust.ZeroTrustAccessRequest{
		AccessRequest: request,
		RequestID:     fmt.Sprintf("rbac-%d", time.Now().UnixNano()),
		RequestTime:   time.Now(),
		SubjectType:   zerotrust.SubjectTypeUser, // Default to user
		ResourceType:  extractResourceType(request.ResourceId),
		SourceSystem:  "rbac-engine",
		RequestSource: zerotrust.RequestSourceSystem,
		Priority:      zerotrust.RequestPriorityNormal,
	}

	// Extract environmental context from request context
	if request.Context != nil {
		zeroTrustRequest.EnvironmentContext = &zerotrust.EnvironmentContext{
			IPAddress: request.Context["source_ip"],
		}

		zeroTrustRequest.SecurityContext = &zerotrust.SecurityContext{
			AuthenticationMethod: request.Context["auth_method"],
			TrustLevel:           zerotrust.TrustLevelMedium, // Default trust level
		}

		// Set MFA verified if available
		if mfaStr := request.Context["mfa_verified"]; mfaStr == "true" {
			zeroTrustRequest.SecurityContext.MFAVerified = true
		}
	}

	return zeroTrustRequest
}

// combineAuthorizationDecisions combines RBAC and zero-trust decisions based on the configured mode
func (a *AdvancedAuthEngine) combineAuthorizationDecisions(rbacGranted bool, rbacReason string, ztResponse *zerotrust.ZeroTrustAccessResponse) *common.AccessResponse {
	response := &common.AccessResponse{
		AppliedRoles:       make([]string, 0),
		AppliedPermissions: make([]string, 0),
	}

	switch a.zeroTrustMode {
	case ZeroTrustModeAugmented:
		// Both RBAC and zero-trust must grant access
		response.Granted = rbacGranted && ztResponse.Granted
		if response.Granted {
			response.Reason = fmt.Sprintf("Access granted by RBAC (%s) and zero-trust policies", rbacReason)
		} else if !rbacGranted {
			response.Reason = fmt.Sprintf("Access denied by RBAC: %s", rbacReason)
		} else {
			response.Reason = fmt.Sprintf("Access denied by zero-trust policies: %s", ztResponse.Reason)
		}

	case ZeroTrustModeEnforced:
		// Zero-trust policies override RBAC decisions
		response.Granted = ztResponse.Granted
		if response.Granted {
			response.Reason = fmt.Sprintf("Access granted by zero-trust policies (RBAC: %s)", rbacReason)
		} else {
			response.Reason = fmt.Sprintf("Access denied by zero-trust policies: %s (RBAC: %s)", ztResponse.Reason, rbacReason)
		}

	case ZeroTrustModeAuditing:
		// Use RBAC decision but log zero-trust result
		response.Granted = rbacGranted
		response.Reason = fmt.Sprintf("%s (ZT audit: %s)", rbacReason, ztResponse.Reason)

	default: // ZeroTrustModeDisabled
		// Should never reach here, but fallback to RBAC
		response.Granted = rbacGranted
		response.Reason = rbacReason
	}

	// Note: Zero-trust metadata would be logged separately since AccessResponse doesn't support context

	return response
}

// extractResourceType extracts the resource type from a resource ID
func extractResourceType(resourceID string) string {
	if resourceID == "" {
		return "unknown"
	}

	// Simple heuristic: take the first part before a dot or slash
	for _, sep := range []string{".", "/", ":"} {
		if idx := strings.Index(resourceID, sep); idx != -1 {
			return resourceID[:idx]
		}
	}

	return resourceID
}

// GetZeroTrustEngine returns the zero-trust engine for external access
func (a *AdvancedAuthEngine) GetZeroTrustEngine() *zerotrust.ZeroTrustPolicyEngine {
	return a.zeroTrustEngine
}
