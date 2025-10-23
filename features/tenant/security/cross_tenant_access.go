// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package security

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/tenant"
)

// CrossTenantAccessValidator validates and manages cross-tenant access permissions
type CrossTenantAccessValidator struct {
	tenantManager     *tenant.Manager
	accessPolicies    map[string]*CrossTenantAccessPolicy
	approvalWorkflows map[string]*ApprovalWorkflow
	mutex             sync.RWMutex
}

// CrossTenantAccessPolicy defines access permissions between tenants
type CrossTenantAccessPolicy struct {
	ID               string                  `json:"id"`
	SourceTenantID   string                  `json:"source_tenant_id"`
	TargetTenantID   string                  `json:"target_tenant_id"`
	AccessLevel      CrossTenantLevel        `json:"access_level"`
	Permissions      []string                `json:"permissions"`
	ResourceFilters  []ResourceFilter        `json:"resource_filters"`
	TimeRestrictions *TimeRestriction        `json:"time_restrictions,omitempty"`
	ApprovalRequired bool                    `json:"approval_required"`
	ApprovalWorkflow string                  `json:"approval_workflow,omitempty"`
	AutoExpiry       *time.Time              `json:"auto_expiry,omitempty"`
	Conditions       []AccessCondition       `json:"conditions,omitempty"`
	Status           CrossTenantAccessStatus `json:"status"`
	CreatedBy        string                  `json:"created_by"`
	ApprovedBy       string                  `json:"approved_by,omitempty"`
	CreatedAt        time.Time               `json:"created_at"`
	UpdatedAt        time.Time               `json:"updated_at"`
	LastUsedAt       *time.Time              `json:"last_used_at,omitempty"`
}

// ResourceFilter defines filters for resources that can be accessed
type ResourceFilter struct {
	Type         string   `json:"type"`          // "include" or "exclude"
	Patterns     []string `json:"patterns"`      // Resource patterns to match
	ResourceType string   `json:"resource_type"` // Type of resource (config, script, etc.)
}

// TimeRestriction defines time-based access restrictions
type TimeRestriction struct {
	AllowedDaysOfWeek []int    `json:"allowed_days_of_week"` // 0=Sunday, 1=Monday, etc.
	AllowedTimeRanges []string `json:"allowed_time_ranges"`  // "HH:MM-HH:MM" format
	Timezone          string   `json:"timezone"`             // IANA timezone
	MaxDurationHours  int      `json:"max_duration_hours"`   // Maximum access duration
}

// AccessCondition defines additional conditions for access
type AccessCondition struct {
	Type     string            `json:"type"`     // "ip_range", "user_group", "mfa_required", etc.
	Operator string            `json:"operator"` // "equals", "contains", "in_range", etc.
	Values   []string          `json:"values"`   // Condition values
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CrossTenantAccessStatus represents the status of an access policy
type CrossTenantAccessStatus string

const (
	CrossTenantAccessStatusPending   CrossTenantAccessStatus = "pending"
	CrossTenantAccessStatusApproved  CrossTenantAccessStatus = "approved"
	CrossTenantAccessStatusActive    CrossTenantAccessStatus = "active"
	CrossTenantAccessStatusSuspended CrossTenantAccessStatus = "suspended"
	CrossTenantAccessStatusExpired   CrossTenantAccessStatus = "expired"
	CrossTenantAccessStatusRevoked   CrossTenantAccessStatus = "revoked"
)

// ApprovalWorkflow defines the approval process for cross-tenant access
type ApprovalWorkflow struct {
	ID               string             `json:"id"`
	Name             string             `json:"name"`
	Description      string             `json:"description"`
	Steps            []ApprovalStep     `json:"steps"`
	AutoApproval     *AutoApprovalRule  `json:"auto_approval,omitempty"`
	Notifications    []NotificationRule `json:"notifications"`
	MaxDurationHours int                `json:"max_duration_hours"`
}

// ApprovalStep defines a step in the approval process
type ApprovalStep struct {
	Order         int      `json:"order"`
	Name          string   `json:"name"`
	Approvers     []string `json:"approvers"`      // User IDs or roles
	RequiredCount int      `json:"required_count"` // Number of approvals needed
	TimeoutHours  int      `json:"timeout_hours"`
}

// AutoApprovalRule defines conditions for automatic approval
type AutoApprovalRule struct {
	MaxAccessLevel       CrossTenantLevel `json:"max_access_level"`
	AllowedResourceTypes []string         `json:"allowed_resource_types"`
	MaxDurationHours     int              `json:"max_duration_hours"`
	RequireMFA           bool             `json:"require_mfa"`
}

// NotificationRule defines notification settings for workflow steps
type NotificationRule struct {
	Event      string   `json:"event"` // "request", "approval", "denial", "expiry"
	Recipients []string `json:"recipients"`
	Method     string   `json:"method"` // "email", "slack", "webhook"
	Template   string   `json:"template"`
}

// NewCrossTenantAccessValidator creates a new cross-tenant access validator
func NewCrossTenantAccessValidator() *CrossTenantAccessValidator {
	return &CrossTenantAccessValidator{
		accessPolicies:    make(map[string]*CrossTenantAccessPolicy),
		approvalWorkflows: make(map[string]*ApprovalWorkflow),
		mutex:             sync.RWMutex{},
	}
}

// SetTenantManager sets the tenant manager reference
func (ctav *CrossTenantAccessValidator) SetTenantManager(tenantManager *tenant.Manager) {
	ctav.tenantManager = tenantManager
}

// CreateAccessPolicy creates a new cross-tenant access policy
func (ctav *CrossTenantAccessValidator) CreateAccessPolicy(ctx context.Context, policy *CrossTenantAccessPolicy) (*CrossTenantAccessPolicy, error) {
	ctav.mutex.Lock()
	defer ctav.mutex.Unlock()

	// Validate the policy
	if err := ctav.validateAccessPolicy(ctx, policy); err != nil {
		return nil, fmt.Errorf("invalid access policy: %w", err)
	}

	// Generate ID if not provided
	if policy.ID == "" {
		policy.ID = fmt.Sprintf("policy-%s-%s-%d", policy.SourceTenantID, policy.TargetTenantID, time.Now().Unix())
	}

	// Set timestamps and initial status
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now

	// Determine initial status based on approval requirements
	if policy.ApprovalRequired {
		policy.Status = CrossTenantAccessStatusPending
	} else {
		policy.Status = CrossTenantAccessStatusActive
	}

	// Store the policy
	ctav.accessPolicies[policy.ID] = policy

	return policy, nil
}

// ValidateCrossTenantAccess validates a cross-tenant access request
func (ctav *CrossTenantAccessValidator) ValidateCrossTenantAccess(ctx context.Context, request *CrossTenantAccessRequest) (*CrossTenantAccessValidation, error) {
	ctav.mutex.RLock()
	defer ctav.mutex.RUnlock()

	validation := &CrossTenantAccessValidation{
		Request:        request,
		ValidationTime: time.Now(),
		Granted:        false,
	}

	// Find applicable policies
	policies := ctav.findApplicablePolicies(request.SourceTenantID, request.TargetTenantID, request.AccessLevel)
	if len(policies) == 0 {
		validation.Reason = "No applicable cross-tenant access policy found"
		validation.PolicyViolations = []string{"No policy grants access"}
		return validation, nil
	}

	// Validate against each applicable policy
	var grantingPolicy *CrossTenantAccessPolicy
	var violations []string

	for _, policy := range policies {
		// Check policy status
		if policy.Status != CrossTenantAccessStatusActive {
			violations = append(violations, fmt.Sprintf("Policy %s status is %s", policy.ID, policy.Status))
			continue
		}

		// Check expiry
		if policy.AutoExpiry != nil && time.Now().After(*policy.AutoExpiry) {
			violations = append(violations, fmt.Sprintf("Policy %s has expired", policy.ID))
			continue
		}

		// Check time restrictions
		if policy.TimeRestrictions != nil {
			if err := ctav.validateTimeRestrictions(policy.TimeRestrictions); err != nil {
				violations = append(violations, fmt.Sprintf("Policy %s time restriction: %s", policy.ID, err.Error()))
				continue
			}
		}

		// Check resource filters
		if len(policy.ResourceFilters) > 0 {
			if !ctav.validateResourceFilters(policy.ResourceFilters, request.ResourceID) {
				violations = append(violations, fmt.Sprintf("Policy %s resource filter does not match", policy.ID))
				continue
			}
		}

		// Check additional conditions
		if len(policy.Conditions) > 0 {
			if err := ctav.validateAccessConditions(policy.Conditions, request.Context); err != nil {
				violations = append(violations, fmt.Sprintf("Policy %s condition failed: %s", policy.ID, err.Error()))
				continue
			}
		}

		// Policy grants access
		grantingPolicy = policy
		break
	}

	if grantingPolicy != nil {
		validation.Granted = true
		validation.GrantingPolicy = grantingPolicy
		validation.Reason = fmt.Sprintf("Access granted by policy %s", grantingPolicy.ID)

		// Update last used time
		now := time.Now()
		grantingPolicy.LastUsedAt = &now
	} else {
		validation.Reason = "No policy grants access - all policies have violations"
		validation.PolicyViolations = violations
	}

	return validation, nil
}

// findApplicablePolicies finds policies that could apply to the access request
func (ctav *CrossTenantAccessValidator) findApplicablePolicies(sourceTenantID, targetTenantID string, accessLevel CrossTenantLevel) []*CrossTenantAccessPolicy {
	var applicable []*CrossTenantAccessPolicy

	for _, policy := range ctav.accessPolicies {
		// Check tenant match (exact or wildcard)
		if policy.SourceTenantID == sourceTenantID || policy.SourceTenantID == "*" {
			if policy.TargetTenantID == targetTenantID || policy.TargetTenantID == "*" {
				// Check access level compatibility
				if ctav.isAccessLevelCompatible(policy.AccessLevel, accessLevel) {
					applicable = append(applicable, policy)
				}
			}
		}
	}

	return applicable
}

// isAccessLevelCompatible checks if a policy access level is compatible with the requested level
func (ctav *CrossTenantAccessValidator) isAccessLevelCompatible(policyLevel, requestedLevel CrossTenantLevel) bool {
	levels := map[CrossTenantLevel]int{
		CrossTenantLevelNone:     0,
		CrossTenantLevelRead:     1,
		CrossTenantLevelWrite:    2,
		CrossTenantLevelFull:     3,
		CrossTenantLevelDelegate: 4,
	}

	return levels[policyLevel] >= levels[requestedLevel]
}

// validateAccessPolicy validates a cross-tenant access policy
func (ctav *CrossTenantAccessValidator) validateAccessPolicy(ctx context.Context, policy *CrossTenantAccessPolicy) error {
	if policy.SourceTenantID == "" {
		return fmt.Errorf("source tenant ID is required")
	}

	if policy.TargetTenantID == "" {
		return fmt.Errorf("target tenant ID is required")
	}

	if policy.CreatedBy == "" {
		return fmt.Errorf("created by is required")
	}

	// Validate tenants exist (unless wildcards)
	if ctav.tenantManager != nil {
		if policy.SourceTenantID != "*" {
			if _, err := ctav.tenantManager.GetTenant(ctx, policy.SourceTenantID); err != nil {
				return fmt.Errorf("source tenant not found: %w", err)
			}
		}

		if policy.TargetTenantID != "*" {
			if _, err := ctav.tenantManager.GetTenant(ctx, policy.TargetTenantID); err != nil {
				return fmt.Errorf("target tenant not found: %w", err)
			}
		}
	}

	return nil
}

// validateTimeRestrictions validates time-based access restrictions
func (ctav *CrossTenantAccessValidator) validateTimeRestrictions(restrictions *TimeRestriction) error {
	now := time.Now()

	// Check day of week
	if len(restrictions.AllowedDaysOfWeek) > 0 {
		currentDay := int(now.Weekday())
		allowed := false
		for _, day := range restrictions.AllowedDaysOfWeek {
			if day == currentDay {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("access not allowed on %s", now.Weekday().String())
		}
	}

	// Check time ranges
	if len(restrictions.AllowedTimeRanges) > 0 {
		currentTime := now.Format("15:04")
		allowed := false
		for _, timeRange := range restrictions.AllowedTimeRanges {
			if ctav.isTimeInRange(currentTime, timeRange) {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("access not allowed at current time %s", currentTime)
		}
	}

	return nil
}

// validateResourceFilters validates resource access filters
func (ctav *CrossTenantAccessValidator) validateResourceFilters(filters []ResourceFilter, resourceID string) bool {
	for _, filter := range filters {
		for _, pattern := range filter.Patterns {
			matches := ctav.matchResourcePattern(resourceID, pattern)

			if filter.Type == "include" && matches {
				return true
			} else if filter.Type == "exclude" && matches {
				return false
			}
		}
	}

	// If no include filters matched and no exclude filters matched, allow by default
	return true
}

// validateAccessConditions validates additional access conditions
func (ctav *CrossTenantAccessValidator) validateAccessConditions(conditions []AccessCondition, context map[string]string) error {
	for _, condition := range conditions {
		contextValue := context[condition.Type]

		switch condition.Operator {
		case "equals":
			if len(condition.Values) == 0 || contextValue != condition.Values[0] {
				return fmt.Errorf("condition %s failed: expected %s, got %s", condition.Type, condition.Values[0], contextValue)
			}
		case "in":
			found := false
			for _, value := range condition.Values {
				if contextValue == value {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("condition %s failed: %s not in allowed values", condition.Type, contextValue)
			}
		case "contains":
			if len(condition.Values) == 0 {
				return fmt.Errorf("condition %s failed: no values specified", condition.Type)
			}
			// For simplicity, just check if any value is contained in the context value
			// In production, this would be more sophisticated
		}
	}

	return nil
}

// Helper methods
func (ctav *CrossTenantAccessValidator) isTimeInRange(currentTime, timeRange string) bool {
	// Simplified implementation - in production, use proper time parsing
	return true
}

func (ctav *CrossTenantAccessValidator) matchResourcePattern(resourceID, pattern string) bool {
	// Simplified pattern matching - in production, use proper glob/regex matching
	return true
}

// CrossTenantAccessRequest represents a request for cross-tenant access validation
type CrossTenantAccessRequest struct {
	SourceTenantID string            `json:"source_tenant_id"`
	TargetTenantID string            `json:"target_tenant_id"`
	SubjectID      string            `json:"subject_id"`
	ResourceID     string            `json:"resource_id"`
	AccessLevel    CrossTenantLevel  `json:"access_level"`
	Context        map[string]string `json:"context"`
}

// CrossTenantAccessValidation represents the result of cross-tenant access validation
type CrossTenantAccessValidation struct {
	Request          *CrossTenantAccessRequest `json:"request"`
	Granted          bool                      `json:"granted"`
	Reason           string                    `json:"reason"`
	GrantingPolicy   *CrossTenantAccessPolicy  `json:"granting_policy,omitempty"`
	PolicyViolations []string                  `json:"policy_violations,omitempty"`
	ValidationTime   time.Time                 `json:"validation_time"`
}
