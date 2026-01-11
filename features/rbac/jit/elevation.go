// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package jit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/features/tenant/security"
)

// PrivilegeElevationManager handles privilege elevation and de-elevation
type PrivilegeElevationManager struct {
	rbacManager       rbac.RBACManager
	jitAccessManager  *JITAccessManager
	elevatedSessions  map[string]*ElevatedSession
	elevationPolicies map[string]*ElevationPolicy
	auditLogger       *JITAuditLogger
	mutex             sync.RWMutex
}

// NewPrivilegeElevationManager creates a new privilege elevation manager
func NewPrivilegeElevationManager(rbacManager rbac.RBACManager, jitAccessManager *JITAccessManager) *PrivilegeElevationManager {
	return &PrivilegeElevationManager{
		rbacManager:       rbacManager,
		jitAccessManager:  jitAccessManager,
		elevatedSessions:  make(map[string]*ElevatedSession),
		elevationPolicies: make(map[string]*ElevationPolicy),
		auditLogger:       NewJITAuditLogger(),
		mutex:             sync.RWMutex{},
	}
}

// ElevatedSession represents an active privilege elevation session
type ElevatedSession struct {
	ID                    string               `json:"id"`
	SubjectID             string               `json:"subject_id"`
	TenantID              string               `json:"tenant_id"`
	OriginalPermissions   []string             `json:"original_permissions"`
	ElevatedPermissions   []string             `json:"elevated_permissions"`
	OriginalRoles         []string             `json:"original_roles"`
	ElevatedRoles         []string             `json:"elevated_roles"`
	ElevationType         ElevationType        `json:"elevation_type"`
	ElevationLevel        ElevationLevel       `json:"elevation_level"`
	JustificationRequired bool                 `json:"justification_required"`
	Justification         string               `json:"justification"`
	RequestedBy           string               `json:"requested_by"`
	ApprovedBy            string               `json:"approved_by,omitempty"`
	ElevatedAt            time.Time            `json:"elevated_at"`
	ExpiresAt             time.Time            `json:"expires_at"`
	Status                ElevationStatus      `json:"status"`
	Conditions            []ElevationCondition `json:"conditions,omitempty"`
	ActivityLog           []ElevationActivity  `json:"activity_log,omitempty"`
	MaxInactivity         time.Duration        `json:"max_inactivity"`
	LastActivity          time.Time            `json:"last_activity"`
	MonitoringLevel       MonitoringLevel      `json:"monitoring_level"`
	GrantID               string               `json:"grant_id,omitempty"` // Associated JIT grant if any
	DelegationIDs         []string             `json:"delegation_ids,omitempty"`
}

// ElevationType defines the type of privilege elevation
type ElevationType string

const (
	ElevationTypeTemporary  ElevationType = "temporary"    // Temporary elevation with auto-revert
	ElevationTypeJustInTime ElevationType = "just_in_time" // JIT-based elevation
	ElevationTypeBreakGlass ElevationType = "break_glass"  // Emergency break-glass access
	ElevationTypeScheduled  ElevationType = "scheduled"    // Pre-scheduled elevation
)

// ElevationLevel defines the level of privilege elevation
type ElevationLevel string

const (
	ElevationLevelMinimal    ElevationLevel = "minimal"     // Least additional privileges
	ElevationLevelModerate   ElevationLevel = "moderate"    // Standard elevation
	ElevationLevelElevated   ElevationLevel = "elevated"    // High-level privileges
	ElevationLevelMaximum    ElevationLevel = "maximum"     // Maximum available privileges
	ElevationLevelBreakGlass ElevationLevel = "break_glass" // Emergency access level
)

// ElevationStatus defines the status of privilege elevation
type ElevationStatus string

const (
	ElevationStatusActive    ElevationStatus = "active"
	ElevationStatusExpired   ElevationStatus = "expired"
	ElevationStatusRevoked   ElevationStatus = "revoked"
	ElevationStatusSuspended ElevationStatus = "suspended"
)

// MonitoringLevel defines the level of monitoring for elevated sessions
type MonitoringLevel string

const (
	MonitoringLevelStandard   MonitoringLevel = "standard"
	MonitoringLevelEnhanced   MonitoringLevel = "enhanced"
	MonitoringLevelReal_time  MonitoringLevel = "real_time"
	MonitoringLevelContinuous MonitoringLevel = "continuous"
)

// ElevationCondition defines conditions that must be maintained during elevation
type ElevationCondition struct {
	Type        ConditionType `json:"type"`
	Value       string        `json:"value"`
	Description string        `json:"description"`
	Required    bool          `json:"required"`
	Monitored   bool          `json:"monitored"`
}

// ElevationActivity represents an activity performed during elevation
type ElevationActivity struct {
	Timestamp  time.Time              `json:"timestamp"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id,omitempty"`
	Result     string                 `json:"result"`
	Details    map[string]interface{} `json:"details,omitempty"`
	RiskLevel  RiskLevel              `json:"risk_level"`
}

// RiskLevel defines risk levels for activities
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// ElevationPolicy defines policies for privilege elevation
type ElevationPolicy struct {
	ID                    string                    `json:"id"`
	Name                  string                    `json:"name"`
	TenantID              string                    `json:"tenant_id"`
	ElevationType         ElevationType             `json:"elevation_type"`
	MaxElevationLevel     ElevationLevel            `json:"max_elevation_level"`
	RequireJustification  bool                      `json:"require_justification"`
	RequireApproval       bool                      `json:"require_approval"`
	ApprovalWorkflow      string                    `json:"approval_workflow,omitempty"`
	MaxDuration           time.Duration             `json:"max_duration"`
	MaxInactivity         time.Duration             `json:"max_inactivity"`
	AllowedPermissions    []string                  `json:"allowed_permissions"`
	ProhibitedPermissions []string                  `json:"prohibited_permissions"`
	AllowedRoles          []string                  `json:"allowed_roles"`
	ProhibitedRoles       []string                  `json:"prohibited_roles"`
	ResourceRestrictions  []ResourceRestriction     `json:"resource_restrictions,omitempty"`
	TimeRestrictions      *security.TimeRestriction `json:"time_restrictions,omitempty"`
	MonitoringLevel       MonitoringLevel           `json:"monitoring_level"`
	RequiredConditions    []ElevationCondition      `json:"required_conditions,omitempty"`
	AutoRevert            bool                      `json:"auto_revert"`
	BreakGlassEnabled     bool                      `json:"break_glass_enabled"`
	Priority              int                       `json:"priority"`
	Status                string                    `json:"status"`
	CreatedAt             time.Time                 `json:"created_at"`
	UpdatedAt             time.Time                 `json:"updated_at"`
}

// ResourceRestriction defines restrictions on resource access during elevation
type ResourceRestriction struct {
	ResourceType  string   `json:"resource_type"`
	AllowedIDs    []string `json:"allowed_ids,omitempty"`
	ProhibitedIDs []string `json:"prohibited_ids,omitempty"`
	Scope         string   `json:"scope"` // "read", "write", "delete", "all"
}

// ElevationRequest represents a request for privilege elevation
type ElevationRequest struct {
	SubjectID            string            `json:"subject_id"`
	TenantID             string            `json:"tenant_id"`
	ElevationType        ElevationType     `json:"elevation_type"`
	RequestedLevel       ElevationLevel    `json:"requested_level"`
	RequestedPermissions []string          `json:"requested_permissions,omitempty"`
	RequestedRoles       []string          `json:"requested_roles,omitempty"`
	Duration             time.Duration     `json:"duration"`
	Justification        string            `json:"justification"`
	ResourceTargets      []string          `json:"resource_targets,omitempty"`
	EmergencyAccess      bool              `json:"emergency_access,omitempty"`
	BreakGlass           bool              `json:"break_glass,omitempty"`
	Context              map[string]string `json:"context,omitempty"`
}

// RequestPrivilegeElevation requests privilege elevation for a subject
func (pem *PrivilegeElevationManager) RequestPrivilegeElevation(ctx context.Context, request *ElevationRequest) (*ElevatedSession, error) {
	pem.mutex.Lock()
	defer pem.mutex.Unlock()

	// Validate the elevation request
	if err := pem.validateElevationRequest(ctx, request); err != nil {
		return nil, fmt.Errorf("invalid elevation request: %w", err)
	}

	// Get applicable elevation policy
	policy, err := pem.getApplicablePolicy(ctx, request)
	if err != nil {
		return nil, fmt.Errorf("failed to get elevation policy: %w", err)
	}

	// Check if elevation is allowed by policy
	if err := pem.validateElevationAgainstPolicy(ctx, request, policy); err != nil {
		return nil, fmt.Errorf("elevation not allowed by policy: %w", err)
	}

	// Get current permissions and roles
	currentPermissions, err := pem.rbacManager.GetEffectivePermissions(ctx, request.SubjectID, request.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current permissions: %w", err)
	}

	currentRoles, err := pem.rbacManager.GetSubjectRoles(ctx, request.SubjectID, request.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current roles: %w", err)
	}

	// Determine what permissions and roles to elevate to
	elevatedPermissions, err := pem.calculateElevatedPermissions(ctx, currentPermissions, request, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate elevated permissions: %w", err)
	}

	elevatedRoles, err := pem.calculateElevatedRoles(ctx, currentRoles, request, policy)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate elevated roles: %w", err)
	}

	// Create the elevated session
	session := &ElevatedSession{
		ID:                    fmt.Sprintf("elevation-%d", time.Now().UnixNano()),
		SubjectID:             request.SubjectID,
		TenantID:              request.TenantID,
		OriginalPermissions:   pem.permissionsToStrings(currentPermissions),
		ElevatedPermissions:   elevatedPermissions,
		OriginalRoles:         pem.rolesToStrings(currentRoles),
		ElevatedRoles:         elevatedRoles,
		ElevationType:         request.ElevationType,
		ElevationLevel:        request.RequestedLevel,
		JustificationRequired: policy.RequireJustification,
		Justification:         request.Justification,
		RequestedBy:           request.SubjectID,
		ElevatedAt:            time.Now(),
		ExpiresAt:             time.Now().Add(request.Duration),
		Status:                ElevationStatusActive,
		MaxInactivity:         policy.MaxInactivity,
		LastActivity:          time.Now(),
		MonitoringLevel:       policy.MonitoringLevel,
		Conditions:            policy.RequiredConditions,
		ActivityLog:           make([]ElevationActivity, 0),
	}

	// Handle break-glass access
	if request.BreakGlass {
		session.ElevationType = ElevationTypeBreakGlass
		session.ElevationLevel = ElevationLevelBreakGlass
		session.MonitoringLevel = MonitoringLevelContinuous
		session.Conditions = append(session.Conditions, ElevationCondition{
			Type:        ConditionTypeAuditEnhanced,
			Value:       "true",
			Description: "Enhanced audit logging for break-glass access",
			Required:    true,
			Monitored:   true,
		})
	}

	// Apply the elevation
	err = pem.applyElevation(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to apply elevation: %w", err)
	}

	// Store the session
	pem.elevatedSessions[session.ID] = session

	// Audit the elevation
	_ = pem.auditLogger.LogAccessRequest(ctx, &JITAccessRequest{
		ID:              session.ID,
		RequesterID:     session.SubjectID,
		TenantID:        session.TenantID,
		Permissions:     session.ElevatedPermissions,
		Duration:        request.Duration,
		Justification:   request.Justification,
		EmergencyAccess: request.BreakGlass,
	}, "privilege_elevated")

	return session, nil
}

// RevokePrivilegeElevation revokes privilege elevation
func (pem *PrivilegeElevationManager) RevokePrivilegeElevation(ctx context.Context, sessionID, revokerID, reason string) error {
	pem.mutex.Lock()
	defer pem.mutex.Unlock()

	session, exists := pem.elevatedSessions[sessionID]
	if !exists {
		return fmt.Errorf("elevation session %s not found", sessionID)
	}

	if session.Status != ElevationStatusActive {
		return fmt.Errorf("elevation session %s is not active", sessionID)
	}

	// Validate revoker authority
	if err := pem.validateRevoker(ctx, session, revokerID); err != nil {
		return fmt.Errorf("revoker validation failed: %w", err)
	}

	// Revert the elevation
	err := pem.revertElevation(ctx, session)
	if err != nil {
		return fmt.Errorf("failed to revert elevation: %w", err)
	}

	// Update session status
	session.Status = ElevationStatusRevoked

	// Log the activity
	activity := ElevationActivity{
		Timestamp: time.Now(),
		Action:    "privilege_revoked",
		Result:    "success",
		RiskLevel: RiskLevelHigh,
		Details: map[string]interface{}{
			"revoked_by": revokerID,
			"reason":     reason,
		},
	}
	session.ActivityLog = append(session.ActivityLog, activity)

	return nil
}

// LogElevatedActivity logs an activity performed during privilege elevation
func (pem *PrivilegeElevationManager) LogElevatedActivity(ctx context.Context, sessionID, action, resourceID, result string, details map[string]interface{}) error {
	pem.mutex.Lock()
	defer pem.mutex.Unlock()

	session, exists := pem.elevatedSessions[sessionID]
	if !exists || session.Status != ElevationStatusActive {
		return fmt.Errorf("active elevation session %s not found", sessionID)
	}

	// Determine risk level based on action and resource
	riskLevel := pem.assessActivityRisk(action, resourceID, details)

	activity := ElevationActivity{
		Timestamp:  time.Now(),
		Action:     action,
		ResourceID: resourceID,
		Result:     result,
		Details:    details,
		RiskLevel:  riskLevel,
	}

	session.ActivityLog = append(session.ActivityLog, activity)
	session.LastActivity = time.Now()

	// Enhanced audit logging for high-risk activities
	if riskLevel == RiskLevelHigh || riskLevel == RiskLevelCritical ||
		session.MonitoringLevel == MonitoringLevelContinuous {
		_ = pem.auditLogger.LogAccessUsage(ctx, &JITAccessGrant{
			ID:          session.ID,
			RequesterID: session.SubjectID,
			TenantID:    session.TenantID,
			Permissions: session.ElevatedPermissions,
		}, action, resourceID, details)
	}

	return nil
}

// GetElevatedSessions returns elevated sessions with optional filtering
func (pem *PrivilegeElevationManager) GetElevatedSessions(ctx context.Context, filter *ElevationFilter) ([]*ElevatedSession, error) {
	pem.mutex.RLock()
	defer pem.mutex.RUnlock()

	var results []*ElevatedSession

	for _, session := range pem.elevatedSessions {
		if pem.matchesElevationFilter(session, filter) {
			results = append(results, session)
		}
	}

	return results, nil
}

// Helper methods

func (pem *PrivilegeElevationManager) validateElevationRequest(ctx context.Context, request *ElevationRequest) error {
	if request.SubjectID == "" {
		return fmt.Errorf("subject ID is required")
	}
	if request.TenantID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if request.Duration <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	if request.Duration > 24*time.Hour {
		return fmt.Errorf("duration cannot exceed 24 hours")
	}
	if len(request.RequestedPermissions) == 0 && len(request.RequestedRoles) == 0 {
		return fmt.Errorf("at least one permission or role must be requested")
	}

	return nil
}

func (pem *PrivilegeElevationManager) getApplicablePolicy(ctx context.Context, request *ElevationRequest) (*ElevationPolicy, error) {
	// Find the highest priority policy that matches the request
	var applicablePolicy *ElevationPolicy

	for _, policy := range pem.elevationPolicies {
		if policy.TenantID == request.TenantID && policy.Status == "active" {
			if applicablePolicy == nil || policy.Priority > applicablePolicy.Priority {
				applicablePolicy = policy
			}
		}
	}

	if applicablePolicy == nil {
		// Return default policy
		return &ElevationPolicy{
			ID:                   "default",
			Name:                 "Default Elevation Policy",
			TenantID:             request.TenantID,
			MaxElevationLevel:    ElevationLevelModerate,
			RequireJustification: true,
			RequireApproval:      false,
			MaxDuration:          4 * time.Hour,
			MaxInactivity:        30 * time.Minute,
			MonitoringLevel:      MonitoringLevelStandard,
			AutoRevert:           true,
			BreakGlassEnabled:    false,
		}, nil
	}

	return applicablePolicy, nil
}

func (pem *PrivilegeElevationManager) validateElevationAgainstPolicy(ctx context.Context, request *ElevationRequest, policy *ElevationPolicy) error {
	// Check if break-glass is requested but not enabled
	if request.BreakGlass && !policy.BreakGlassEnabled {
		return fmt.Errorf("break-glass access is not enabled for this tenant")
	}

	// Check duration limits
	if request.Duration > policy.MaxDuration {
		return fmt.Errorf("requested duration %v exceeds policy limit %v", request.Duration, policy.MaxDuration)
	}

	// Check elevation level
	if !pem.isElevationLevelAllowed(request.RequestedLevel, policy.MaxElevationLevel) {
		return fmt.Errorf("requested elevation level %s exceeds policy limit %s", request.RequestedLevel, policy.MaxElevationLevel)
	}

	// Check prohibited permissions
	for _, reqPerm := range request.RequestedPermissions {
		for _, prohibitedPerm := range policy.ProhibitedPermissions {
			if reqPerm == prohibitedPerm {
				return fmt.Errorf("permission %s is prohibited by policy", reqPerm)
			}
		}
	}

	return nil
}

func (pem *PrivilegeElevationManager) applyElevation(ctx context.Context, session *ElevatedSession) error {
	// Create JIT access grant for the elevation
	jitRequest := &JITAccessRequestSpec{
		RequesterID:     session.SubjectID,
		TenantID:        session.TenantID,
		Permissions:     session.ElevatedPermissions,
		Roles:           session.ElevatedRoles,
		Duration:        time.Until(session.ExpiresAt),
		Priority:        AccessPriorityHigh,
		Justification:   session.Justification,
		AutoApprove:     true, // Elevation requests are pre-approved
		EmergencyAccess: session.ElevationType == ElevationTypeBreakGlass,
	}

	jitAccessRequest, err := pem.jitAccessManager.RequestAccess(ctx, jitRequest)
	if err != nil {
		return fmt.Errorf("failed to create JIT access for elevation: %w", err)
	}

	session.GrantID = jitAccessRequest.ID
	return nil
}

func (pem *PrivilegeElevationManager) revertElevation(ctx context.Context, session *ElevatedSession) error {
	if session.GrantID != "" {
		return pem.jitAccessManager.RevokeAccess(ctx, session.GrantID, "system", "privilege elevation revoked")
	}
	return nil
}

func (pem *PrivilegeElevationManager) calculateElevatedPermissions(ctx context.Context, current []*common.Permission, request *ElevationRequest, policy *ElevationPolicy) ([]string, error) {
	var elevated []string

	// Add requested permissions that are allowed by policy
	for _, reqPerm := range request.RequestedPermissions {
		// Check if permission is allowed
		allowed := len(policy.AllowedPermissions) == 0 // If no restrictions, allow all
		for _, allowedPerm := range policy.AllowedPermissions {
			if reqPerm == allowedPerm {
				allowed = true
				break
			}
		}

		if allowed {
			elevated = append(elevated, reqPerm)
		}
	}

	return elevated, nil
}

func (pem *PrivilegeElevationManager) calculateElevatedRoles(ctx context.Context, current []*common.Role, request *ElevationRequest, policy *ElevationPolicy) ([]string, error) {
	var elevated []string

	// Add requested roles that are allowed by policy
	for _, reqRole := range request.RequestedRoles {
		// Check if role is allowed
		allowed := len(policy.AllowedRoles) == 0 // If no restrictions, allow all
		for _, allowedRole := range policy.AllowedRoles {
			if reqRole == allowedRole {
				allowed = true
				break
			}
		}

		if allowed {
			elevated = append(elevated, reqRole)
		}
	}

	return elevated, nil
}

func (pem *PrivilegeElevationManager) assessActivityRisk(action, resourceID string, details map[string]interface{}) RiskLevel {
	// Assess risk based on action type
	highRiskActions := []string{"delete", "modify", "create_user", "grant_permission", "escalate"}
	criticalRiskActions := []string{"delete_system", "modify_security", "break_glass"}

	for _, criticalAction := range criticalRiskActions {
		if action == criticalAction {
			return RiskLevelCritical
		}
	}

	for _, highAction := range highRiskActions {
		if action == highAction {
			return RiskLevelHigh
		}
	}

	return RiskLevelMedium
}

func (pem *PrivilegeElevationManager) validateRevoker(ctx context.Context, session *ElevatedSession, revokerID string) error {
	// Allow subject to revoke their own elevation
	if session.SubjectID == revokerID {
		return nil
	}

	// Check if revoker has permission to revoke elevations
	accessRequest := &common.AccessRequest{
		SubjectId:    revokerID,
		PermissionId: "privilege_elevation.revoke",
		TenantId:     session.TenantID,
	}

	response, err := pem.rbacManager.CheckPermission(ctx, accessRequest)
	if err != nil {
		return fmt.Errorf("failed to check revoker permission: %w", err)
	}
	if !response.Granted {
		return fmt.Errorf("revoker %s does not have permission to revoke privilege elevation", revokerID)
	}

	return nil
}

// Utility helper methods

func (pem *PrivilegeElevationManager) permissionsToStrings(permissions []*common.Permission) []string {
	var result []string
	for _, perm := range permissions {
		result = append(result, perm.Id)
	}
	return result
}

func (pem *PrivilegeElevationManager) rolesToStrings(roles []*common.Role) []string {
	var result []string
	for _, role := range roles {
		result = append(result, role.Id)
	}
	return result
}

func (pem *PrivilegeElevationManager) isElevationLevelAllowed(requested, maxAllowed ElevationLevel) bool {
	levels := map[ElevationLevel]int{
		ElevationLevelMinimal:    1,
		ElevationLevelModerate:   2,
		ElevationLevelElevated:   3,
		ElevationLevelMaximum:    4,
		ElevationLevelBreakGlass: 5,
	}

	return levels[requested] <= levels[maxAllowed]
}

func (pem *PrivilegeElevationManager) matchesElevationFilter(session *ElevatedSession, filter *ElevationFilter) bool {
	if filter == nil {
		return true
	}

	if filter.SubjectID != "" && session.SubjectID != filter.SubjectID {
		return false
	}
	if filter.TenantID != "" && session.TenantID != filter.TenantID {
		return false
	}
	if filter.Status != "" && session.Status != ElevationStatus(filter.Status) {
		return false
	}

	return true
}

// Supporting types

// ElevationFilter for filtering elevated sessions
type ElevationFilter struct {
	SubjectID string     `json:"subject_id,omitempty"`
	TenantID  string     `json:"tenant_id,omitempty"`
	Status    string     `json:"status,omitempty"`
	DateFrom  *time.Time `json:"date_from,omitempty"`
	DateTo    *time.Time `json:"date_to,omitempty"`
}
