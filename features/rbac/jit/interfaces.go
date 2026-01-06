// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package jit

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/features/tenant/security"
)

// JITAccessService defines the main interface for JIT access management
type JITAccessService interface {
	// Request Management
	RequestAccess(ctx context.Context, req *JITAccessRequestSpec) (*JITAccessRequest, error)
	GetRequest(ctx context.Context, requestID string) (*JITAccessRequest, error)
	ListRequests(ctx context.Context, filter *JITAccessRequestFilter) ([]*JITAccessRequest, error)
	CancelRequest(ctx context.Context, requestID, requesterID string) error

	// Approval Management
	ApproveRequest(ctx context.Context, requestID, approverID, reason string) (*JITAccessGrant, error)
	DenyRequest(ctx context.Context, requestID, reviewerID, reason string) error
	GetPendingApprovals(ctx context.Context, approverID, tenantID string) ([]*JITAccessRequest, error)

	// Grant Management
	GetActiveGrants(ctx context.Context, subjectID, tenantID string) ([]*JITAccessGrant, error)
	ExtendAccess(ctx context.Context, grantID string, duration time.Duration, requesterID, reason string) error
	RevokeAccess(ctx context.Context, grantID, revokerID, reason string) error

	// Status and Monitoring
	CheckJITAccess(ctx context.Context, subjectID, permissionID, tenantID string) (*JITAccessValidation, error)
	GetAccessHistory(ctx context.Context, subjectID, tenantID string) (*JITAccessHistory, error)

	// Cleanup and Maintenance
	CleanupExpiredRequests(ctx context.Context) error
	CleanupExpiredGrants(ctx context.Context) error
}

// NotificationService defines the interface for sending notifications
type NotificationService interface {
	// Request notifications
	SendRequestNotification(ctx context.Context, request *JITAccessRequest, eventType string) error
	SendApprovalNotification(ctx context.Context, request *JITAccessRequest, approvers []string) error
	SendReminderNotification(ctx context.Context, request *JITAccessRequest, recipient string) error

	// Grant notifications
	SendGrantNotification(ctx context.Context, grant *JITAccessGrant, eventType string) error
	SendExpirationWarning(ctx context.Context, grant *JITAccessGrant, timeUntilExpiry time.Duration) error
	SendRevocationNotification(ctx context.Context, grant *JITAccessGrant, reason string) error

	// Escalation notifications
	SendEscalationNotification(ctx context.Context, request *JITAccessRequest, escalationLevel int) error
}

// JITAccessValidator provides validation and security checks for JIT access
type JITAccessValidator interface {
	// Request validation
	ValidateAccessRequest(ctx context.Context, req *JITAccessRequestSpec) error
	ValidateRequestSecurity(ctx context.Context, req *JITAccessRequestSpec) (*SecurityValidationResult, error)

	// Permission validation
	ValidatePermissions(ctx context.Context, permissions []string, tenantID string) error
	ValidateResourceAccess(ctx context.Context, resourceIDs []string, permissions []string, tenantID string) error

	// Approval validation
	ValidateApprover(ctx context.Context, approverID string, request *JITAccessRequest) error
	ValidateWorkflowCompliance(ctx context.Context, request *JITAccessRequest, workflow *ApprovalWorkflow) error

	// Risk assessment
	AssessRequestRisk(ctx context.Context, req *JITAccessRequestSpec) (*RiskAssessment, error)
	CheckComplianceRequirements(ctx context.Context, req *JITAccessRequestSpec) (*ComplianceCheck, error)
}

// JITAccessIntegrator handles integration with existing RBAC and tenant security systems
type JITAccessIntegrator interface {
	// RBAC Integration
	CreateTemporaryRoleAssignment(ctx context.Context, grant *JITAccessGrant) error
	RemoveTemporaryRoleAssignment(ctx context.Context, grant *JITAccessGrant) error
	CreatePermissionDelegation(ctx context.Context, grant *JITAccessGrant) (string, error)
	RemovePermissionDelegation(ctx context.Context, delegationID string) error

	// Tenant Security Integration
	ApplyTenantSecurityPolicies(ctx context.Context, grant *JITAccessGrant) error
	ValidateAccessWithTenantPolicies(ctx context.Context, grant *JITAccessGrant) error
	CreateSecurityAuditEntry(ctx context.Context, grant *JITAccessGrant, action string) error

	// Monitoring Integration
	RegisterAccessMonitoring(ctx context.Context, grant *JITAccessGrant) error
	UnregisterAccessMonitoring(ctx context.Context, grant *JITAccessGrant) error
}

// WorkflowEngine handles approval workflow execution
type WorkflowEngine interface {
	// Workflow execution
	StartWorkflow(ctx context.Context, request *JITAccessRequest, workflow *ApprovalWorkflow) error
	ProcessApproval(ctx context.Context, requestID, approverID, decision, reason string) error
	CheckWorkflowStatus(ctx context.Context, requestID string) (*WorkflowStatus, error)

	// Workflow management
	RegisterWorkflow(ctx context.Context, workflow *ApprovalWorkflow) error
	GetWorkflow(ctx context.Context, workflowID string) (*ApprovalWorkflow, error)
	ListWorkflows(ctx context.Context, tenantID string) ([]*ApprovalWorkflow, error)

	// Escalation handling
	ProcessEscalation(ctx context.Context, requestID string, escalationRule *EscalationRule) error
	ScheduleEscalation(ctx context.Context, requestID string, delayHours float64) error
}

// JITAccessPolicyEngine defines policies for JIT access
type JITAccessPolicyEngine interface {
	// Policy evaluation
	EvaluateRequestPolicy(ctx context.Context, req *JITAccessRequestSpec) (*PolicyEvaluationResult, error)
	EvaluateApprovalPolicy(ctx context.Context, request *JITAccessRequest, approverID string) (*PolicyEvaluationResult, error)
	EvaluateGrantPolicy(ctx context.Context, grant *JITAccessGrant) (*PolicyEvaluationResult, error)

	// Policy management
	CreateJITPolicy(ctx context.Context, policy *JITAccessPolicy) error
	UpdateJITPolicy(ctx context.Context, policy *JITAccessPolicy) error
	GetJITPolicies(ctx context.Context, tenantID string) ([]*JITAccessPolicy, error)

	// Auto-approval rules
	CheckAutoApprovalRules(ctx context.Context, req *JITAccessRequestSpec) (bool, string, error)
	RegisterAutoApprovalRule(ctx context.Context, rule *AutoApprovalRule) error
}

// Supporting types for interface contracts

// JITAccessValidation represents the result of JIT access validation
type JITAccessValidation struct {
	HasJITAccess    bool              `json:"has_jit_access"`
	ActiveGrants    []string          `json:"active_grants"`
	ExpirationTimes []time.Time       `json:"expiration_times"`
	Conditions      []AccessCondition `json:"conditions"`
	ValidationTime  time.Time         `json:"validation_time"`
}

// JITAccessHistory represents historical JIT access for a subject
type JITAccessHistory struct {
	SubjectID     string              `json:"subject_id"`
	TenantID      string              `json:"tenant_id"`
	TotalRequests int                 `json:"total_requests"`
	Requests      []*JITAccessRequest `json:"requests"`
	TotalGrants   int                 `json:"total_grants"`
	Grants        []*JITAccessGrant   `json:"grants"`
	GeneratedAt   time.Time           `json:"generated_at"`
}

// SecurityValidationResult represents security validation results
type SecurityValidationResult struct {
	Valid           bool     `json:"valid"`
	SecurityLevel   string   `json:"security_level"`
	Violations      []string `json:"violations"`
	Recommendations []string `json:"recommendations"`
	RequiresReview  bool     `json:"requires_review"`
}

// RiskAssessment represents risk assessment results
type RiskAssessment struct {
	RiskLevel         string        `json:"risk_level"`
	RiskScore         int           `json:"risk_score"`
	RiskFactors       []string      `json:"risk_factors"`
	MitigationActions []string      `json:"mitigation_actions"`
	RequiresApproval  bool          `json:"requires_approval"`
	RecommendedTTL    time.Duration `json:"recommended_ttl"`
}

// ComplianceCheck represents compliance validation results
type ComplianceCheck struct {
	Compliant         bool     `json:"compliant"`
	Frameworks        []string `json:"frameworks"`
	Violations        []string `json:"violations"`
	RequiredControls  []string `json:"required_controls"`
	AdditionalLogging bool     `json:"additional_logging"`
}

// WorkflowStatus represents the status of an approval workflow
type WorkflowStatus struct {
	RequestID       string                    `json:"request_id"`
	WorkflowID      string                    `json:"workflow_id"`
	Status          string                    `json:"status"`
	CurrentStage    int                       `json:"current_stage"`
	CompletedStages []WorkflowStageCompletion `json:"completed_stages"`
	PendingStages   []WorkflowStagePending    `json:"pending_stages"`
	LastActivity    time.Time                 `json:"last_activity"`
}

// WorkflowStageCompletion represents a completed workflow stage
type WorkflowStageCompletion struct {
	StageID     string    `json:"stage_id"`
	ApproverID  string    `json:"approver_id"`
	Decision    string    `json:"decision"`
	Reason      string    `json:"reason"`
	CompletedAt time.Time `json:"completed_at"`
}

// WorkflowStagePending represents a pending workflow stage
type WorkflowStagePending struct {
	StageID          string    `json:"stage_id"`
	PendingApprovers []string  `json:"pending_approvers"`
	TimeoutAt        time.Time `json:"timeout_at"`
}

// PolicyEvaluationResult represents policy evaluation results
type PolicyEvaluationResult struct {
	Allowed      bool                   `json:"allowed"`
	PolicyID     string                 `json:"policy_id"`
	Decision     string                 `json:"decision"`
	Reason       string                 `json:"reason"`
	Conditions   []AccessCondition      `json:"conditions"`
	Restrictions map[string]interface{} `json:"restrictions"`
	EvaluatedAt  time.Time              `json:"evaluated_at"`
}

// JITAccessPolicy defines policies for JIT access
type JITAccessPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	TenantID    string            `json:"tenant_id"`
	Description string            `json:"description"`
	Rules       []PolicyRule      `json:"rules"`
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	Priority    int               `json:"priority"`
	Status      string            `json:"status"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// PolicyRule defines a rule within a JIT access policy
type PolicyRule struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	Conditions  map[string]string `json:"conditions"`
	Actions     []string          `json:"actions"`
	Priority    int               `json:"priority"`
	Description string            `json:"description"`
}

// PolicyCondition defines conditions for policy evaluation
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// PolicyAction defines actions to take when policy conditions are met
type PolicyAction struct {
	Type       string            `json:"type"`
	Parameters map[string]string `json:"parameters"`
}

// AutoApprovalRule defines rules for automatic approval
type AutoApprovalRule struct {
	ID                  string                    `json:"id"`
	Name                string                    `json:"name"`
	TenantID            string                    `json:"tenant_id"`
	Conditions          []PolicyCondition         `json:"conditions"`
	MaxDuration         time.Duration             `json:"max_duration"`
	AllowedPermissions  []string                  `json:"allowed_permissions"`
	ExcludedPermissions []string                  `json:"excluded_permissions"`
	TimeRestrictions    *security.TimeRestriction `json:"time_restrictions,omitempty"`
	Priority            int                       `json:"priority"`
	Status              string                    `json:"status"`
	CreatedAt           time.Time                 `json:"created_at"`
}
