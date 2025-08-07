package rbac

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/api/proto/common"
)

// AdvancedAuthEngine provides enhanced authorization with conditional permissions, 
// delegation, and comprehensive audit logging
type AdvancedAuthEngine struct {
	baseEngine        *AuthEngine
	conditionEngine   *ConditionEngine
	scopeEngine       *ScopeEngine
	delegationManager *DelegationManager
	auditLogger       *AuditLogger
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

// CheckPermission performs comprehensive permission checking with all advanced features
func (a *AdvancedAuthEngine) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	// Extract context information for audit logging
	sourceIP := ""
	userAgent := ""
	if request.Context != nil {
		sourceIP = request.Context["source_ip"]
		userAgent = request.Context["user_agent"]
	}

	// First check base permissions
	baseResponse, err := a.baseEngine.CheckPermission(ctx, request)
	if err != nil {
		// Log the error in audit
		errorResponse := &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Error checking base permissions: %v", err),
		}
		_ = a.auditLogger.LogPermissionCheck(ctx, request, errorResponse, sourceIP, userAgent)
		return errorResponse, err
	}

	// If base permission is granted, log and return
	if baseResponse.Granted {
		_ = a.auditLogger.LogPermissionCheck(ctx, request, baseResponse, sourceIP, userAgent)
		return baseResponse, nil
	}

	// Check for delegated permissions
	delegatedGranted, delegatedReason, err := a.delegationManager.CheckDelegatedPermission(
		ctx, request.SubjectId, request.PermissionId, request.ResourceId, request.TenantId, nil)
	if err != nil {
		// Log delegation check error
		errorResponse := &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Error checking delegated permissions: %v", err),
		}
		_ = a.auditLogger.LogPermissionCheck(ctx, request, errorResponse, sourceIP, userAgent)
		return errorResponse, err
	}

	if delegatedGranted {
		response := &common.AccessResponse{
			Granted: true,
			Reason:  delegatedReason,
			AppliedPermissions: []string{request.PermissionId},
		}
		_ = a.auditLogger.LogPermissionCheck(ctx, request, response, sourceIP, userAgent)
		return response, nil
	}

	// No permission granted through standard or delegated means
	finalResponse := &common.AccessResponse{
		Granted: false,
		Reason:  fmt.Sprintf("Access denied. Base: %s. Delegation: %s", baseResponse.Reason, delegatedReason),
	}
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
		Granted: true,
		Reason:  fmt.Sprintf("Conditional permission granted. Conditions: %s", conditionReason),
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