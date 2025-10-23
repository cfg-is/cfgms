// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package security

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
)

// TenantSecurityMiddleware integrates tenant security with RBAC system
type TenantSecurityMiddleware struct {
	rbacManager     *rbac.Manager
	isolationEngine *TenantIsolationEngine
	policyEngine    *TenantSecurityPolicyEngine
	auditLogger     *TenantSecurityAuditLogger
}

// NewTenantSecurityMiddleware creates a new tenant security middleware
func NewTenantSecurityMiddleware(
	rbacManager *rbac.Manager,
	isolationEngine *TenantIsolationEngine,
	policyEngine *TenantSecurityPolicyEngine,
	auditLogger *TenantSecurityAuditLogger,
) *TenantSecurityMiddleware {
	return &TenantSecurityMiddleware{
		rbacManager:     rbacManager,
		isolationEngine: isolationEngine,
		policyEngine:    policyEngine,
		auditLogger:     auditLogger,
	}
}

// EnhancedPermissionCheck performs comprehensive permission checking with tenant security
func (tsm *TenantSecurityMiddleware) EnhancedPermissionCheck(ctx context.Context, request *common.AccessRequest) (*EnhancedAccessResponse, error) {
	startTime := time.Now()

	response := &EnhancedAccessResponse{
		StandardResponse: &common.AccessResponse{
			Granted: false,
		},
		TenantSecurityValidation: &TenantSecurityValidationResult{},
		ValidationLatency:        0,
	}

	// 1. Perform standard RBAC check
	rbacResponse, err := tsm.rbacManager.CheckPermission(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("RBAC check failed: %w", err)
	}

	response.StandardResponse = rbacResponse

	// If RBAC denies access, no need to continue with tenant security checks
	if !rbacResponse.Granted {
		response.TenantSecurityValidation.Decision = "rbac_denied"
		response.TenantSecurityValidation.Reason = rbacResponse.Reason
		response.ValidationLatency = time.Since(startTime)
		return response, nil
	}

	// 2. Perform tenant isolation validation
	tenantAccessRequest := &TenantAccessRequest{
		SubjectID:       request.SubjectId,
		SubjectTenantID: request.TenantId, // Assuming subject's tenant
		TargetTenantID:  request.TenantId,
		ResourceID:      request.ResourceId,
		AccessLevel:     tsm.mapPermissionToAccessLevel(request.PermissionId),
		Context:         request.Context,
	}

	isolationResponse, err := tsm.isolationEngine.ValidateTenantAccess(ctx, tenantAccessRequest)
	if err != nil {
		return nil, fmt.Errorf("tenant isolation check failed: %w", err)
	}

	response.TenantSecurityValidation.IsolationValidation = isolationResponse

	if !isolationResponse.Granted {
		response.StandardResponse.Granted = false
		response.StandardResponse.Reason = fmt.Sprintf("Tenant isolation check failed: %s", isolationResponse.Reason)
		response.TenantSecurityValidation.Decision = "isolation_denied"
		response.ValidationLatency = time.Since(startTime)
		return response, nil
	}

	// 3. Perform security policy evaluation
	policyRequest := &SecurityEvaluationRequest{
		TenantID:     request.TenantId,
		SubjectID:    request.SubjectId,
		Action:       tsm.mapPermissionToAction(request.PermissionId),
		ResourceType: tsm.getResourceType(request.ResourceId),
		ResourceID:   request.ResourceId,
		Context:      request.Context,
		Permissions:  rbacResponse.AppliedPermissions,
	}

	policyResult, err := tsm.policyEngine.EvaluateSecurityPolicy(ctx, policyRequest)
	if err != nil {
		return nil, fmt.Errorf("security policy evaluation failed: %w", err)
	}

	response.TenantSecurityValidation.PolicyEvaluation = policyResult

	if !policyResult.Allowed {
		response.StandardResponse.Granted = false
		response.StandardResponse.Reason = fmt.Sprintf("Security policy violation: %s", policyResult.BlockReason)
		response.TenantSecurityValidation.Decision = "policy_denied"
		response.ValidationLatency = time.Since(startTime)
		return response, nil
	}

	// 4. All checks passed
	response.TenantSecurityValidation.Decision = "allowed"
	response.TenantSecurityValidation.Reason = "All security validations passed"
	response.ValidationLatency = time.Since(startTime)

	// 5. Audit the complete validation
	err = tsm.auditCompleteValidation(ctx, request, response)
	if err != nil {
		// Log error but don't fail the request
		fmt.Printf("Failed to audit complete validation: %v\n", err)
	}

	return response, nil
}

// ValidateCrossTenantAccess validates cross-tenant access with full security context
func (tsm *TenantSecurityMiddleware) ValidateCrossTenantAccess(ctx context.Context, sourceTenantID, targetTenantID, subjectID, resourceID string, accessLevel CrossTenantLevel, context map[string]string) (*CrossTenantValidationResult, error) {
	result := &CrossTenantValidationResult{
		SourceTenantID: sourceTenantID,
		TargetTenantID: targetTenantID,
		SubjectID:      subjectID,
		ResourceID:     resourceID,
		AccessLevel:    accessLevel,
		ValidationTime: time.Now(),
		Allowed:        false,
	}

	// 1. Check if cross-tenant access is allowed by isolation rules
	tenantAccessRequest := &TenantAccessRequest{
		SubjectID:       subjectID,
		SubjectTenantID: sourceTenantID,
		TargetTenantID:  targetTenantID,
		ResourceID:      resourceID,
		AccessLevel:     accessLevel,
		Context:         context,
	}

	isolationResponse, err := tsm.isolationEngine.ValidateTenantAccess(ctx, tenantAccessRequest)
	if err != nil {
		return nil, fmt.Errorf("isolation validation failed: %w", err)
	}

	result.IsolationValidation = isolationResponse

	if !isolationResponse.Granted {
		result.Reason = fmt.Sprintf("Isolation check failed: %s", isolationResponse.Reason)
		_ = tsm.auditLogger.LogAccessAttempt(ctx, tenantAccessRequest, &TenantAccessResponse{
			Granted:   false,
			TenantID:  targetTenantID,
			SubjectID: subjectID,
			Reason:    result.Reason,
		})
		return result, nil
	}

	// 2. Check RBAC permissions for cross-tenant access
	rbacRequest := &common.AccessRequest{
		SubjectId:    subjectID,
		PermissionId: fmt.Sprintf("cross_tenant.%s", accessLevel),
		TenantId:     sourceTenantID,
		ResourceId:   fmt.Sprintf("tenant:%s/%s", targetTenantID, resourceID),
		Context:      context,
	}

	rbacResponse, err := tsm.rbacManager.CheckPermission(ctx, rbacRequest)
	if err != nil {
		return nil, fmt.Errorf("RBAC check failed: %w", err)
	}

	result.RBACValidation = rbacResponse

	if !rbacResponse.Granted {
		result.Reason = fmt.Sprintf("RBAC check failed: %s", rbacResponse.Reason)
		return result, nil
	}

	// 3. Evaluate security policies for cross-tenant access
	policyRequest := &SecurityEvaluationRequest{
		TenantID:     targetTenantID,
		SubjectID:    subjectID,
		Action:       string(accessLevel),
		ResourceType: "cross_tenant_resource",
		ResourceID:   resourceID,
		Context:      context,
		Permissions:  rbacResponse.AppliedPermissions,
	}

	policyResult, err := tsm.policyEngine.EvaluateSecurityPolicy(ctx, policyRequest)
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	result.PolicyEvaluation = policyResult

	if !policyResult.Allowed {
		result.Reason = fmt.Sprintf("Policy evaluation failed: %s", policyResult.BlockReason)
		return result, nil
	}

	// 4. All validations passed
	result.Allowed = true
	result.Reason = "Cross-tenant access granted - all validations passed"

	return result, nil
}

// CreateTenantSecuritySubject creates RBAC subjects with tenant security context
func (tsm *TenantSecurityMiddleware) CreateTenantSecuritySubject(ctx context.Context, request *TenantSecuritySubjectRequest) (*common.Subject, error) {
	// Create standard RBAC subject
	subject := &common.Subject{
		Id:          request.SubjectID,
		Type:        request.SubjectType,
		DisplayName: request.DisplayName,
		TenantId:    request.TenantID,
		IsActive:    true,
	}

	err := tsm.rbacManager.CreateSubject(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("failed to create RBAC subject: %w", err)
	}

	// Apply tenant-specific security attributes
	if request.SecurityAttributes != nil {
		err = tsm.applyTenantSecurityAttributes(ctx, subject, request.SecurityAttributes)
		if err != nil {
			// Rollback subject creation
			_ = tsm.rbacManager.DeleteSubject(ctx, subject.Id)
			return nil, fmt.Errorf("failed to apply security attributes: %w", err)
		}
	}

	// Audit subject creation with security context
	_ = tsm.auditLogger.LogSecuritySubjectCreation(ctx, subject, request.SecurityAttributes)

	return subject, nil
}

// Helper methods

func (tsm *TenantSecurityMiddleware) mapPermissionToAccessLevel(permissionID string) CrossTenantLevel {
	// Map RBAC permissions to cross-tenant access levels
	switch permissionID {
	case "read", "config.read", "status.read":
		return CrossTenantLevelRead
	case "write", "config.write":
		return CrossTenantLevelWrite
	case "admin", "config.admin":
		return CrossTenantLevelFull
	case "delegate":
		return CrossTenantLevelDelegate
	default:
		return CrossTenantLevelRead
	}
}

func (tsm *TenantSecurityMiddleware) mapPermissionToAction(permissionID string) string {
	// Extract action from permission ID
	switch permissionID {
	case "read", "config.read":
		return "read"
	case "write", "config.write":
		return "write"
	case "delete", "config.delete":
		return "delete"
	default:
		return "access"
	}
}

func (tsm *TenantSecurityMiddleware) getResourceType(resourceID string) string {
	// Determine resource type from resource ID
	switch resourceID {
	case "config", "configuration":
		return "configuration"
	case "script":
		return "script"
	case "user", "subject":
		return "user_data"
	default:
		return "generic"
	}
}

func (tsm *TenantSecurityMiddleware) applyTenantSecurityAttributes(ctx context.Context, subject *common.Subject, attributes *TenantSecurityAttributes) error {
	// Apply security attributes like compliance requirements, access restrictions, etc.
	// This would integrate with the tenant security system to set up appropriate restrictions
	return nil // Simplified implementation
}

func (tsm *TenantSecurityMiddleware) auditCompleteValidation(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) error {
	return tsm.auditLogger.LogEnhancedAccessValidation(ctx, request, response)
}

// Supporting types

type EnhancedAccessResponse struct {
	StandardResponse         *common.AccessResponse          `json:"standard_response"`
	TenantSecurityValidation *TenantSecurityValidationResult `json:"tenant_security_validation"`
	ValidationLatency        time.Duration                   `json:"validation_latency"`
}

type TenantSecurityValidationResult struct {
	Decision            string                    `json:"decision"`
	Reason              string                    `json:"reason"`
	IsolationValidation *TenantAccessResponse     `json:"isolation_validation,omitempty"`
	PolicyEvaluation    *SecurityEvaluationResult `json:"policy_evaluation,omitempty"`
}

type CrossTenantValidationResult struct {
	SourceTenantID      string                    `json:"source_tenant_id"`
	TargetTenantID      string                    `json:"target_tenant_id"`
	SubjectID           string                    `json:"subject_id"`
	ResourceID          string                    `json:"resource_id"`
	AccessLevel         CrossTenantLevel          `json:"access_level"`
	ValidationTime      time.Time                 `json:"validation_time"`
	Allowed             bool                      `json:"allowed"`
	Reason              string                    `json:"reason"`
	IsolationValidation *TenantAccessResponse     `json:"isolation_validation,omitempty"`
	RBACValidation      *common.AccessResponse    `json:"rbac_validation,omitempty"`
	PolicyEvaluation    *SecurityEvaluationResult `json:"policy_evaluation,omitempty"`
}

type TenantSecuritySubjectRequest struct {
	SubjectID          string                    `json:"subject_id"`
	SubjectType        common.SubjectType        `json:"subject_type"`
	DisplayName        string                    `json:"display_name"`
	TenantID           string                    `json:"tenant_id"`
	SecurityAttributes *TenantSecurityAttributes `json:"security_attributes,omitempty"`
}

type TenantSecurityAttributes struct {
	ComplianceRequirements []string           `json:"compliance_requirements,omitempty"`
	AccessRestrictions     []string           `json:"access_restrictions,omitempty"`
	DataClassification     DataClassification `json:"data_classification,omitempty"`
	MaxSessionDuration     time.Duration      `json:"max_session_duration,omitempty"`
	RequiredMFA            bool               `json:"required_mfa,omitempty"`
}

// Additional audit logger method for enhanced validation
func (tsal *TenantSecurityAuditLogger) LogEnhancedAccessValidation(ctx context.Context, request *common.AccessRequest, response *EnhancedAccessResponse) error {
	severity := AuditSeverityInfo
	if !response.StandardResponse.Granted {
		severity = AuditSeverityWarning
	}

	entry := TenantSecurityAuditEntry{
		ID:         fmt.Sprintf("enhanced-%d", time.Now().UnixNano()),
		Timestamp:  time.Now(),
		EventType:  TenantSecurityEventAccessAttempt,
		TenantID:   request.TenantId,
		SubjectID:  request.SubjectId,
		ResourceID: request.ResourceId,
		Action:     "enhanced_access_validation",
		Result:     response.TenantSecurityValidation.Decision,
		Severity:   severity,
		Details: map[string]interface{}{
			"rbac_granted":       response.StandardResponse.Granted,
			"rbac_reason":        response.StandardResponse.Reason,
			"validation_latency": response.ValidationLatency.Milliseconds(),
			"security_decision":  response.TenantSecurityValidation.Decision,
			"security_reason":    response.TenantSecurityValidation.Reason,
		},
	}

	if request.Context != nil {
		entry.SourceIP = request.Context["source_ip"]
		entry.UserAgent = request.Context["user_agent"]
		entry.SessionID = request.Context["session_id"]
	}

	return tsal.addEntry(entry)
}

func (tsal *TenantSecurityAuditLogger) LogSecuritySubjectCreation(ctx context.Context, subject *common.Subject, attributes *TenantSecurityAttributes) error {
	entry := TenantSecurityAuditEntry{
		ID:        fmt.Sprintf("subject-%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		EventType: TenantSecurityEventAccessAttempt, // Could create a new event type
		TenantID:  subject.TenantId,
		SubjectID: subject.Id,
		Action:    "create_security_subject",
		Result:    "success",
		Severity:  AuditSeverityInfo,
		Details: map[string]interface{}{
			"subject_type":   subject.Type.String(),
			"display_name":   subject.DisplayName,
			"security_attrs": attributes,
		},
	}

	return tsal.addEntry(entry)
}
