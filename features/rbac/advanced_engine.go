// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package rbac

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/pkg/audit"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// AdvancedAuthEngine provides enhanced authorization with conditional permissions
// and comprehensive audit logging.
type AdvancedAuthEngine struct {
	baseEngine      *AuthEngine
	conditionEngine *ConditionEngine
	scopeEngine     *ScopeEngine
	auditManager    *audit.Manager
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
		baseEngine:      baseEngine,
		conditionEngine: NewConditionEngine(),
		scopeEngine:     NewScopeEngine(),
		auditManager:    nil, // Set via SetAuditManager from parent Manager
	}
}

// SetAuditManager sets the audit manager for recording permission events to durable storage.
func (a *AdvancedAuthEngine) SetAuditManager(am *audit.Manager) {
	a.auditManager = am
}

// SetHierarchyEngine wires a HierarchyEngine into the base AuthEngine so that
// GetEffectivePermissions traverses role inheritance chains through the production
// call path (Manager → advancedEngine → baseEngine with hierarchy).
func (a *AdvancedAuthEngine) SetHierarchyEngine(he *HierarchyEngine) {
	a.baseEngine.SetHierarchyEngine(he)
}

// CheckPermission performs comprehensive permission checking with RBAC and audit logging.
func (a *AdvancedAuthEngine) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	// Extract context information for audit logging
	sourceIP := ""
	userAgent := ""
	if request.Context != nil {
		sourceIP = request.Context["source_ip"]
		userAgent = request.Context["user_agent"]
	}

	baseResponse, err := a.baseEngine.CheckPermission(ctx, request)
	if err != nil {
		errorResponse := &common.AccessResponse{
			Granted: false,
			Reason:  fmt.Sprintf("Error checking base permissions: %v", err),
		}
		a.recordPermissionCheck(ctx, request, business.AuditResultError, errorResponse.Reason, sourceIP, userAgent)
		return errorResponse, err
	}

	// Log the decision to durable audit store
	result := business.AuditResultDenied
	if baseResponse.Granted {
		result = business.AuditResultSuccess
	}
	a.recordPermissionCheck(ctx, request, result, baseResponse.Reason, sourceIP, userAgent)
	return baseResponse, nil
}

// recordPermissionCheck emits a check_permission audit event to the durable store.
// It is a no-op when auditManager is nil.
func (a *AdvancedAuthEngine) recordPermissionCheck(ctx context.Context, request *common.AccessRequest, result business.AuditResult, reason, sourceIP, userAgent string) {
	if a.auditManager == nil {
		return
	}
	if err := a.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
		request.TenantId, request.SubjectId, "permission", request.PermissionId,
		"check_permission", result,
	).Request("", "", "", sourceIP, userAgent).Detail("reason", reason)); err != nil {
		slog.Warn("failed to record permission check audit event", "error", err)
	}
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

// GetSubjectPermissions retrieves all effective permissions for a subject
func (a *AdvancedAuthEngine) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return a.baseEngine.GetSubjectPermissions(ctx, subjectID, tenantID)
}

// GetEffectivePermissions returns all effective permissions considering role hierarchy.
// Delegates to baseEngine.GetEffectivePermissions so the hierarchy traversal wired via
// SetHierarchyEngine is exercised through the production call path
// (Manager.GetEffectivePermissions → advancedEngine → baseEngine with hierarchy).
func (a *AdvancedAuthEngine) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return a.baseEngine.GetEffectivePermissions(ctx, subjectID, tenantID)
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

	// Record the temporary permission grant in the durable audit store
	if a.auditManager != nil {
		if err := a.auditManager.RecordEvent(ctx, audit.AuthorizationEvent(
			req.TenantID, req.SubjectID, "permission", req.PermissionID,
			"grant_permission", business.AuditResultSuccess,
		).
			// permission grant is a sensitive admin action
			Severity(business.AuditSeverityHigh).
			Detail("granted_by", req.GrantedBy).
			Detail("type", "temporary").
			Detail("expires_at", fmt.Sprintf("%d", req.ExpiresAt))); err != nil {
			slog.Warn("failed to record permission grant audit event", "error", err)
		}
	}

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
