// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package jit

import (
	"time"
)

// JITAccessRequestSpec defines the specification for requesting JIT access
type JITAccessRequestSpec struct {
	RequesterID       string            `json:"requester_id"`
	TargetID          string            `json:"target_id,omitempty"` // If different from requester
	TenantID          string            `json:"tenant_id"`
	Permissions       []string          `json:"permissions"`
	Roles             []string          `json:"roles"`
	ResourceIDs       []string          `json:"resource_ids,omitempty"`
	RequestedFor      string            `json:"requested_for,omitempty"` // Business purpose
	Duration          time.Duration     `json:"duration"`
	MaxDuration       time.Duration     `json:"max_duration,omitempty"`
	Priority          AccessPriority    `json:"priority"`
	Justification     string            `json:"justification"`
	AutoApprove       bool              `json:"auto_approve,omitempty"`
	EmergencyAccess   bool              `json:"emergency_access,omitempty"`
	RequesterMetadata map[string]string `json:"requester_metadata,omitempty"`
}

// JITAccessRequest represents a JIT access request
type JITAccessRequest struct {
	ID                string            `json:"id"`
	RequesterID       string            `json:"requester_id"`
	TargetID          string            `json:"target_id,omitempty"`
	TenantID          string            `json:"tenant_id"`
	Permissions       []string          `json:"permissions"`
	Roles             []string          `json:"roles"`
	ResourceIDs       []string          `json:"resource_ids,omitempty"`
	RequestedFor      string            `json:"requested_for,omitempty"`
	Duration          time.Duration     `json:"duration"`
	MaxDuration       time.Duration     `json:"max_duration,omitempty"`
	Priority          AccessPriority    `json:"priority"`
	Justification     string            `json:"justification"`
	AutoApprove       bool              `json:"auto_approve,omitempty"`
	EmergencyAccess   bool              `json:"emergency_access,omitempty"`
	RequesterMetadata map[string]string `json:"requester_metadata,omitempty"`

	// Request lifecycle
	Status           JITAccessRequestStatus `json:"status"`
	ApprovalWorkflow string                 `json:"approval_workflow"`
	ApprovedBy       string                 `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time             `json:"approved_at,omitempty"`
	ApprovalReason   string                 `json:"approval_reason,omitempty"`
	ReviewedBy       string                 `json:"reviewed_by,omitempty"`
	ReviewedAt       *time.Time             `json:"reviewed_at,omitempty"`
	DenialReason     string                 `json:"denial_reason,omitempty"`

	// Timestamps
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`
	RequestTTL time.Time `json:"request_ttl"`

	// Grant reference
	GrantedAccess *JITAccessGrant `json:"granted_access,omitempty"`
}

// JITAccessGrant represents an active JIT access grant
type JITAccessGrant struct {
	ID          string   `json:"id"`
	RequestID   string   `json:"request_id"`
	RequesterID string   `json:"requester_id"`
	TargetID    string   `json:"target_id,omitempty"`
	TenantID    string   `json:"tenant_id"`
	Permissions []string `json:"permissions"`
	Roles       []string `json:"roles"`
	ResourceIDs []string `json:"resource_ids,omitempty"`

	// Approval details
	ApprovedBy     string    `json:"approved_by"`
	ApprovalReason string    `json:"approval_reason"`
	GrantedAt      time.Time `json:"granted_at"`
	ExpiresAt      time.Time `json:"expires_at"`

	// Status and lifecycle
	Status           JITAccessGrantStatus `json:"status"`
	ActivatedAt      *time.Time           `json:"activated_at,omitempty"`
	DeactivatedAt    *time.Time           `json:"deactivated_at,omitempty"`
	RevokedAt        *time.Time           `json:"revoked_at,omitempty"`
	RevokedBy        string               `json:"revoked_by,omitempty"`
	RevocationReason string               `json:"revocation_reason,omitempty"`

	// Extensions
	MaxExtensions    int               `json:"max_extensions"`
	ExtensionsUsed   int               `json:"extensions_used"`
	LastExtensionAt  *time.Time        `json:"last_extension_at,omitempty"`
	LastExtensionBy  string            `json:"last_extension_by,omitempty"`
	ExtensionReasons []ExtensionRecord `json:"extension_reasons,omitempty"`

	// Activation/Deactivation
	ActivationMethod   ActivationMethod   `json:"activation_method"`
	DeactivationMethod DeactivationMethod `json:"deactivation_method"`

	// Conditions and constraints
	Conditions []AccessCondition `json:"conditions,omitempty"`

	// RBAC integration
	DelegationID             string   `json:"delegation_id,omitempty"`
	TemporaryRoleAssignments []string `json:"temporary_role_assignments,omitempty"`
}

// ExtensionRecord tracks access grant extensions
type ExtensionRecord struct {
	ExtendedBy string        `json:"extended_by"`
	ExtendedAt time.Time     `json:"extended_at"`
	Duration   time.Duration `json:"duration"`
	Reason     string        `json:"reason"`
}

// AccessCondition defines conditions that must be met during access
type AccessCondition struct {
	Type        ConditionType `json:"type"`
	Value       string        `json:"value"`
	Description string        `json:"description,omitempty"`
}

// ApprovalWorkflow defines the approval process for JIT access requests
type ApprovalWorkflow struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Description     string           `json:"description,omitempty"`
	Type            ApprovalType     `json:"type"`
	Approvers       []ApprovalStage  `json:"approvers"`
	TimeoutHours    float64          `json:"timeout_hours,omitempty"`
	EscalationRules []EscalationRule `json:"escalation_rules,omitempty"`
}

// ApprovalStage represents a stage in the approval workflow
type ApprovalStage struct {
	ID           string            `json:"id"`
	Name         string            `json:"name,omitempty"`
	Type         ApprovalStageType `json:"type"`
	Approvers    []string          `json:"approvers"` // User IDs or role names
	MinApprovals int               `json:"min_approvals"`
	TimeoutHours float64           `json:"timeout_hours"`
	Conditions   map[string]string `json:"conditions,omitempty"`
}

// EscalationRule defines escalation behavior for approval workflows
type EscalationRule struct {
	TriggerCondition string   `json:"trigger_condition"`
	DelayHours       float64  `json:"delay_hours"`
	EscalateTo       []string `json:"escalate_to"`
	Action           string   `json:"action"`
}

// JITAccessRequestFilter for filtering access requests
type JITAccessRequestFilter struct {
	RequesterID string     `json:"requester_id,omitempty"`
	TenantID    string     `json:"tenant_id,omitempty"`
	Status      string     `json:"status,omitempty"`
	DateFrom    *time.Time `json:"date_from,omitempty"`
	DateTo      *time.Time `json:"date_to,omitempty"`
}

// Enumerations

// JITAccessRequestStatus represents the status of a JIT access request
type JITAccessRequestStatus string

const (
	JITAccessRequestStatusPending  JITAccessRequestStatus = "pending"
	JITAccessRequestStatusApproved JITAccessRequestStatus = "approved"
	JITAccessRequestStatusDenied   JITAccessRequestStatus = "denied"
	JITAccessRequestStatusExpired  JITAccessRequestStatus = "expired"
	JITAccessRequestStatusCanceled JITAccessRequestStatus = "canceled"
)

// JITAccessGrantStatus represents the status of a JIT access grant
type JITAccessGrantStatus string

const (
	JITAccessGrantStatusActive      JITAccessGrantStatus = "active"
	JITAccessGrantStatusExpired     JITAccessGrantStatus = "expired"
	JITAccessGrantStatusRevoked     JITAccessGrantStatus = "revoked"
	JITAccessGrantStatusDeactivated JITAccessGrantStatus = "deactivated"
)

// AccessPriority defines the priority level of access requests
type AccessPriority string

const (
	AccessPriorityLow       AccessPriority = "low"
	AccessPriorityMedium    AccessPriority = "medium"
	AccessPriorityHigh      AccessPriority = "high"
	AccessPriorityCritical  AccessPriority = "critical"
	AccessPriorityEmergency AccessPriority = "emergency"
)

// ApprovalType defines how approvals are processed
type ApprovalType string

const (
	ApprovalTypeSequential ApprovalType = "sequential" // Approvers must approve in order
	ApprovalTypeParallel   ApprovalType = "parallel"   // All approvers can approve simultaneously
	ApprovalTypeQuorum     ApprovalType = "quorum"     // Only need a minimum number of approvals
)

// ApprovalStageType defines the type of approvers in a stage
type ApprovalStageType string

const (
	ApprovalStageTypeUser  ApprovalStageType = "user"  // Specific users
	ApprovalStageTypeRole  ApprovalStageType = "role"  // Users with specific roles
	ApprovalStageTypeGroup ApprovalStageType = "group" // Members of specific groups
)

// ActivationMethod defines how access is activated
type ActivationMethod string

const (
	ActivationMethodImmediate ActivationMethod = "immediate" // Activate immediately upon approval
	ActivationMethodManual    ActivationMethod = "manual"    // Requires manual activation
	ActivationMethodScheduled ActivationMethod = "scheduled" // Activate at scheduled time
)

// DeactivationMethod defines how access is deactivated
type DeactivationMethod string

const (
	DeactivationMethodAutomatic DeactivationMethod = "automatic" // Automatic upon expiration
	DeactivationMethodManual    DeactivationMethod = "manual"    // Requires manual deactivation
)

// ConditionType defines types of access conditions
type ConditionType string

const (
	ConditionTypeTimeWindow      ConditionType = "time_window"      // Access limited to time window
	ConditionTypeIPRestriction   ConditionType = "ip_restriction"   // IP-based restrictions
	ConditionTypeLocationLimit   ConditionType = "location_limit"   // Geographic restrictions
	ConditionTypeMFARequired     ConditionType = "mfa_required"     // MFA required for access
	ConditionTypeAuditEnhanced   ConditionType = "audit_enhanced"   // Enhanced audit logging
	ConditionTypeResourceScope   ConditionType = "resource_scope"   // Limited to specific resources
	ConditionTypeEmergencyAccess ConditionType = "emergency_access" // Emergency access controls
	ConditionTypeFailsafeMode    ConditionType = "failsafe_mode"    // Failsafe mode restrictions
)
