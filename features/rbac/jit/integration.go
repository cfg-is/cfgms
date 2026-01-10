// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/tenant/security"
)

// JITIntegrationManager handles integration between JIT access and existing RBAC/tenant security
type JITIntegrationManager struct {
	rbacManager      rbac.RBACManager
	tenantManager    *tenant.Manager
	tenantSecurity   *security.TenantSecurityMiddleware
	jitAccessManager *JITAccessManager
	elevationManager *PrivilegeElevationManager
	timeController   *TimeBasedAccessController
	monitor          *JITAccessMonitor
}

// NewJITIntegrationManager creates a new JIT integration manager
func NewJITIntegrationManager(
	rbacManager rbac.RBACManager,
	tenantManager *tenant.Manager,
	tenantSecurity *security.TenantSecurityMiddleware,
) *JITIntegrationManager {
	notificationService := NewSimpleNotificationService()

	// Initialize JIT components
	jitAccessManager := NewJITAccessManager(rbacManager, notificationService)
	elevationManager := NewPrivilegeElevationManager(rbacManager, jitAccessManager)
	timeController := NewTimeBasedAccessController(jitAccessManager)
	monitor := NewJITAccessMonitor(jitAccessManager, elevationManager, timeController, notificationService)

	return &JITIntegrationManager{
		rbacManager:      rbacManager,
		tenantManager:    tenantManager,
		tenantSecurity:   tenantSecurity,
		jitAccessManager: jitAccessManager,
		elevationManager: elevationManager,
		timeController:   timeController,
		monitor:          monitor,
	}
}

// Initialize initializes the JIT access framework integration
func (jim *JITIntegrationManager) Initialize(ctx context.Context) error {
	// Initialize JIT-specific permissions
	if err := jim.initializeJITPermissions(ctx); err != nil {
		return fmt.Errorf("failed to initialize JIT permissions: %w", err)
	}

	// Initialize JIT-specific roles
	if err := jim.initializeJITRoles(ctx); err != nil {
		return fmt.Errorf("failed to initialize JIT roles: %w", err)
	}

	// Start time-based controller
	go func() {
		if err := jim.timeController.Start(ctx); err != nil {
			// In production, this would log the error
			_ = err
		}
	}()

	// Start monitoring
	go func() {
		if err := jim.monitor.Start(ctx); err != nil {
			// In production, this would log the error
			_ = err
		}
	}()

	return nil
}

// EnhancedAccessCheck performs access checks that consider JIT access grants
func (jim *JITIntegrationManager) EnhancedAccessCheck(ctx context.Context, request *common.AccessRequest) (*EnhancedJITAccessResponse, error) {
	// First perform standard RBAC + tenant security check
	enhancedResponse, err := jim.tenantSecurity.EnhancedPermissionCheck(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("enhanced permission check failed: %w", err)
	}

	// Create JIT-enhanced response
	jitResponse := &EnhancedJITAccessResponse{
		StandardResponse:  enhancedResponse.StandardResponse,
		TenantSecurity:    enhancedResponse.TenantSecurityValidation,
		ValidationLatency: enhancedResponse.ValidationLatency,
		JITAccess:         &JITAccessValidationResult{},
	}

	// If standard access is granted, no need to check JIT
	if enhancedResponse.StandardResponse.Granted {
		jitResponse.JITAccess.HasJITAccess = false
		jitResponse.JITAccess.ValidationTime = time.Now()
		return jitResponse, nil
	}

	// Check for active JIT grants that provide the requested permission
	jitValidation, err := jim.checkJITAccess(ctx, request)
	if err != nil {
		return jitResponse, nil // Don't fail on JIT check errors
	}

	jitResponse.JITAccess = jitValidation

	// If JIT access grants the permission, update the response
	if jitValidation.HasJITAccess {
		jitResponse.StandardResponse.Granted = true
		jitResponse.StandardResponse.Reason = "Access granted via JIT access"
		jitResponse.StandardResponse.AppliedPermissions = append(
			jitResponse.StandardResponse.AppliedPermissions,
			jitValidation.GrantedPermissions...,
		)
	}

	return jitResponse, nil
}

// checkJITAccess checks if the subject has JIT access for the requested permission
func (jim *JITIntegrationManager) checkJITAccess(ctx context.Context, request *common.AccessRequest) (*JITAccessValidationResult, error) {
	result := &JITAccessValidationResult{
		HasJITAccess:    false,
		ValidationTime:  time.Now(),
		ActiveGrants:    []string{},
		ExpirationTimes: []time.Time{},
		Conditions:      []AccessCondition{},
	}

	// Get active grants for the subject
	activeGrants, err := jim.jitAccessManager.GetActiveGrants(ctx, request.SubjectId, request.TenantId)
	if err != nil {
		return result, err
	}

	// Check if any grant provides the requested permission
	for _, grant := range activeGrants {
		for _, permission := range grant.Permissions {
			if permission == request.PermissionId {
				result.HasJITAccess = true
				result.ActiveGrants = append(result.ActiveGrants, grant.ID)
				result.ExpirationTimes = append(result.ExpirationTimes, grant.ExpiresAt)
				result.Conditions = append(result.Conditions, grant.Conditions...)
				result.GrantedPermissions = append(result.GrantedPermissions, permission)

				// Log the JIT access usage
				go func(g *JITAccessGrant) {
					_ = jim.elevationManager.LogElevatedActivity(
						ctx,
						g.ID,
						"jit_access_used",
						request.ResourceId,
						"granted",
						map[string]interface{}{
							"permission": request.PermissionId,
							"resource":   request.ResourceId,
							"tenant":     request.TenantId,
							"context":    request.Context,
						},
					)
				}(grant)
			}
		}
	}

	// Also check for elevated sessions that might provide access
	if jim.elevationManager != nil {
		elevatedSessions, err := jim.elevationManager.GetElevatedSessions(ctx, &ElevationFilter{
			SubjectID: request.SubjectId,
			TenantID:  request.TenantId,
		})
		if err == nil {
			for _, session := range elevatedSessions {
				if session.Status == ElevationStatusActive {
					for _, permission := range session.ElevatedPermissions {
						if permission == request.PermissionId {
							result.HasJITAccess = true
							result.ElevatedSessions = append(result.ElevatedSessions, session.ID)
							result.ExpirationTimes = append(result.ExpirationTimes, session.ExpiresAt)
							// Convert ElevationConditions to AccessConditions
							for _, elevationCondition := range session.Conditions {
								accessCondition := AccessCondition{
									Type:        elevationCondition.Type,
									Value:       elevationCondition.Value,
									Description: elevationCondition.Description,
								}
								result.Conditions = append(result.Conditions, accessCondition)
							}
							result.GrantedPermissions = append(result.GrantedPermissions, permission)
						}
					}
				}
			}
		}
	}

	return result, nil
}

// RequestJITAccess creates a JIT access request with tenant security integration
func (jim *JITIntegrationManager) RequestJITAccess(ctx context.Context, request *JITAccessRequestSpec) (*JITAccessRequest, error) {
	// Validate request against tenant security policies
	securityValidation, err := jim.validateJITRequestSecurity(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}

	if !securityValidation.Valid {
		return nil, fmt.Errorf("JIT access request violates security policies: %v", securityValidation.Violations)
	}

	// Apply any security-mandated modifications to the request
	if err := jim.applySecurityConstraints(ctx, request, securityValidation); err != nil {
		return nil, fmt.Errorf("failed to apply security constraints: %w", err)
	}

	// Create the JIT access request
	jitRequest, err := jim.jitAccessManager.RequestAccess(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create JIT access request: %w", err)
	}

	// Integrate with tenant security audit logging
	if jim.tenantSecurity != nil {
		_ = jim.logTenantSecurityEvent(ctx, jitRequest, "jit_access_requested")
	}

	return jitRequest, nil
}

// RequestPrivilegeElevation creates a privilege elevation request with security integration
func (jim *JITIntegrationManager) RequestPrivilegeElevation(ctx context.Context, request *ElevationRequest) (*ElevatedSession, error) {
	// Validate elevation request against tenant security policies
	if err := jim.validateElevationSecurity(ctx, request); err != nil {
		return nil, fmt.Errorf("elevation security validation failed: %w", err)
	}

	// Create the privilege elevation
	session, err := jim.elevationManager.RequestPrivilegeElevation(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create privilege elevation: %w", err)
	}

	// Integrate with time-based controls
	if jim.timeController != nil && session.GrantID != "" {
		grant, err := jim.jitAccessManager.GetRequest(ctx, session.GrantID)
		if err == nil && grant.GrantedAccess != nil {
			_ = jim.timeController.ScheduleAccessExpiration(ctx, grant.GrantedAccess)
		}
	}

	// Log security event
	if jim.tenantSecurity != nil {
		_ = jim.logTenantSecurityEvent(ctx, &JITAccessRequest{
			ID:            session.ID,
			RequesterID:   session.SubjectID,
			TenantID:      session.TenantID,
			Permissions:   session.ElevatedPermissions,
			Justification: session.Justification,
		}, "privilege_elevation_requested")
	}

	return session, nil
}

// validateJITRequestSecurity validates JIT access requests against tenant security policies
func (jim *JITIntegrationManager) validateJITRequestSecurity(ctx context.Context, request *JITAccessRequestSpec) (*SecurityValidationResult, error) {
	result := &SecurityValidationResult{
		Valid:           true,
		SecurityLevel:   "standard",
		Violations:      []string{},
		Recommendations: []string{},
		RequiresReview:  false,
	}

	// Check if tenant has isolation rules that might affect JIT access
	if jim.tenantSecurity != nil {
		// This would integrate with the tenant security isolation engine
		// For now, we'll do basic validation

		// Check for high-privilege permissions
		highPrivilegePermissions := []string{"admin", "system_config", "user_management", "security_config"}
		for _, reqPerm := range request.Permissions {
			for _, highPerm := range highPrivilegePermissions {
				if reqPerm == highPerm {
					result.SecurityLevel = "high"
					result.RequiresReview = true
					result.Recommendations = append(result.Recommendations,
						fmt.Sprintf("High-privilege permission '%s' requires additional review", reqPerm))
				}
			}
		}

		// Check duration against security policies
		if request.Duration > 8*time.Hour {
			result.Recommendations = append(result.Recommendations,
				"Consider reducing access duration to 8 hours or less")
		}

		// Emergency access requires special handling
		if request.EmergencyAccess {
			result.SecurityLevel = "critical"
			result.RequiresReview = true
			result.Recommendations = append(result.Recommendations,
				"Emergency access requires enhanced monitoring and audit logging")
		}
	}

	return result, nil
}

// validateElevationSecurity validates privilege elevation requests
func (jim *JITIntegrationManager) validateElevationSecurity(ctx context.Context, request *ElevationRequest) error {
	// Check if elevation is allowed by tenant security policies
	if jim.tenantSecurity != nil {
		// Validate against tenant isolation rules
		// This would check if the tenant allows privilege elevation

		// For break-glass access, additional validation
		if request.BreakGlass {
			// Ensure break-glass access is properly justified and logged
			if request.Justification == "" {
				return fmt.Errorf("break-glass access requires detailed justification")
			}
		}
	}

	return nil
}

// applySecurityConstraints applies security constraints to JIT access requests
func (jim *JITIntegrationManager) applySecurityConstraints(ctx context.Context, request *JITAccessRequestSpec, validation *SecurityValidationResult) error {
	// Apply security-mandated constraints
	if validation.SecurityLevel == "high" || validation.SecurityLevel == "critical" {
		// Reduce maximum duration for high-security requests
		maxSecureDuration := 4 * time.Hour
		if request.Duration > maxSecureDuration {
			request.Duration = maxSecureDuration
		}

		// Force approval requirement for high-security requests
		request.AutoApprove = false
	}

	// For emergency access, apply additional constraints
	if request.EmergencyAccess {
		// Force enhanced monitoring
		request.RequesterMetadata["enhanced_monitoring"] = "true"
		request.RequesterMetadata["security_level"] = validation.SecurityLevel
	}

	return nil
}

// logTenantSecurityEvent logs JIT access events to tenant security audit
func (jim *JITIntegrationManager) logTenantSecurityEvent(ctx context.Context, request *JITAccessRequest, eventType string) error {
	// This would integrate with the tenant security audit system
	// For now, we'll use the JIT audit logger
	return jim.jitAccessManager.auditLogger.LogAccessRequest(ctx, request, eventType)
}

// initializeJITPermissions creates JIT-specific permissions
func (jim *JITIntegrationManager) initializeJITPermissions(ctx context.Context) error {
	jitPermissions := []*common.Permission{
		{
			Id:           "jit_access.request",
			Name:         "Request JIT Access",
			Description:  "Permission to request just-in-time access",
			ResourceType: "jit_access",
		},
		{
			Id:           "jit_access.approve",
			Name:         "Approve JIT Access",
			Description:  "Permission to approve just-in-time access requests",
			ResourceType: "jit_access",
		},
		{
			Id:           "jit_access.revoke",
			Name:         "Revoke JIT Access",
			Description:  "Permission to revoke active just-in-time access",
			ResourceType: "jit_access",
		},
		{
			Id:           "jit_access.extend",
			Name:         "Extend JIT Access",
			Description:  "Permission to extend just-in-time access duration",
			ResourceType: "jit_access",
		},
		{
			Id:           "privilege_elevation.request",
			Name:         "Request Privilege Elevation",
			Description:  "Permission to request privilege elevation",
			ResourceType: "privilege_elevation",
		},
		{
			Id:           "privilege_elevation.approve",
			Name:         "Approve Privilege Elevation",
			Description:  "Permission to approve privilege elevation requests",
			ResourceType: "privilege_elevation",
		},
		{
			Id:           "privilege_elevation.revoke",
			Name:         "Revoke Privilege Elevation",
			Description:  "Permission to revoke active privilege elevation",
			ResourceType: "privilege_elevation",
		},
		{
			Id:           "jit_access.monitor",
			Name:         "Monitor JIT Access",
			Description:  "Permission to monitor and view JIT access activity",
			ResourceType: "jit_access",
		},
		{
			Id:           "jit_access.audit",
			Name:         "Audit JIT Access",
			Description:  "Permission to access JIT access audit logs and reports",
			ResourceType: "jit_access",
		},
	}

	for _, permission := range jitPermissions {
		if err := jim.rbacManager.CreatePermission(ctx, permission); err != nil {
			// Permission might already exist, which is okay
			continue
		}
	}

	return nil
}

// initializeJITRoles creates JIT-specific roles
func (jim *JITIntegrationManager) initializeJITRoles(ctx context.Context) error {
	jitRoles := []*common.Role{
		{
			Id:            "jit_user",
			Name:          "JIT Access User",
			Description:   "Can request just-in-time access",
			PermissionIds: []string{"jit_access.request"},
		},
		{
			Id:            "jit_approver",
			Name:          "JIT Access Approver",
			Description:   "Can approve just-in-time access requests",
			PermissionIds: []string{"jit_access.approve", "jit_access.monitor"},
		},
		{
			Id:          "jit_administrator",
			Name:        "JIT Access Administrator",
			Description: "Full administrative access to JIT access system",
			PermissionIds: []string{
				"jit_access.request", "jit_access.approve", "jit_access.revoke",
				"jit_access.extend", "privilege_elevation.request",
				"privilege_elevation.approve", "privilege_elevation.revoke",
				"jit_access.monitor", "jit_access.audit",
			},
		},
		{
			Id:          "security_officer",
			Name:        "Security Officer",
			Description: "Security oversight for JIT access",
			PermissionIds: []string{
				"jit_access.monitor", "jit_access.audit", "jit_access.revoke",
				"privilege_elevation.revoke",
			},
		},
	}

	for _, role := range jitRoles {
		if err := jim.rbacManager.CreateRole(ctx, role); err != nil {
			// Role might already exist, which is okay
			continue
		}
	}

	return nil
}

// GetJITAccessManager returns the JIT access manager for external access
func (jim *JITIntegrationManager) GetJITAccessManager() *JITAccessManager {
	return jim.jitAccessManager
}

// GetPrivilegeElevationManager returns the privilege elevation manager
func (jim *JITIntegrationManager) GetPrivilegeElevationManager() *PrivilegeElevationManager {
	return jim.elevationManager
}

// GetTimeBasedAccessController returns the time-based access controller
func (jim *JITIntegrationManager) GetTimeBasedAccessController() *TimeBasedAccessController {
	return jim.timeController
}

// GetJITAccessMonitor returns the JIT access monitor
func (jim *JITIntegrationManager) GetJITAccessMonitor() *JITAccessMonitor {
	return jim.monitor
}

// Shutdown gracefully shuts down JIT access components
func (jim *JITIntegrationManager) Shutdown(ctx context.Context) error {
	// Stop time controller
	if jim.timeController != nil {
		jim.timeController.Stop()
	}

	// Stop monitor
	if jim.monitor != nil {
		jim.monitor.Stop()
	}

	return nil
}

// Supporting types for integration

// EnhancedJITAccessResponse extends the enhanced access response with JIT access information
type EnhancedJITAccessResponse struct {
	StandardResponse  *common.AccessResponse                   `json:"standard_response"`
	TenantSecurity    *security.TenantSecurityValidationResult `json:"tenant_security"`
	JITAccess         *JITAccessValidationResult               `json:"jit_access"`
	ValidationLatency time.Duration                            `json:"validation_latency"`
}

// JITAccessValidationResult contains the result of JIT access validation
type JITAccessValidationResult struct {
	HasJITAccess       bool              `json:"has_jit_access"`
	ActiveGrants       []string          `json:"active_grants"`
	ElevatedSessions   []string          `json:"elevated_sessions,omitempty"`
	ExpirationTimes    []time.Time       `json:"expiration_times"`
	Conditions         []AccessCondition `json:"conditions"`
	GrantedPermissions []string          `json:"granted_permissions"`
	ValidationTime     time.Time         `json:"validation_time"`
}
