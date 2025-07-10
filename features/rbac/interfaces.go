package rbac

import (
	"context"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// PermissionStore defines the interface for managing permissions
type PermissionStore interface {
	// CreatePermission creates a new permission
	CreatePermission(ctx context.Context, permission *common.Permission) error
	
	// GetPermission retrieves a permission by ID
	GetPermission(ctx context.Context, id string) (*common.Permission, error)
	
	// ListPermissions lists all permissions, optionally filtered by resource type
	ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error)
	
	// UpdatePermission updates an existing permission
	UpdatePermission(ctx context.Context, permission *common.Permission) error
	
	// DeletePermission deletes a permission by ID
	DeletePermission(ctx context.Context, id string) error
}

// RoleStore defines the interface for managing roles
type RoleStore interface {
	// CreateRole creates a new role
	CreateRole(ctx context.Context, role *common.Role) error
	
	// GetRole retrieves a role by ID
	GetRole(ctx context.Context, id string) (*common.Role, error)
	
	// ListRoles lists roles, optionally filtered by tenant
	ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error)
	
	// UpdateRole updates an existing role
	UpdateRole(ctx context.Context, role *common.Role) error
	
	// DeleteRole deletes a role by ID
	DeleteRole(ctx context.Context, id string) error
	
	// GetRolePermissions retrieves all permissions for a role
	GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error)
}

// SubjectStore defines the interface for managing subjects
type SubjectStore interface {
	// CreateSubject creates a new subject
	CreateSubject(ctx context.Context, subject *common.Subject) error
	
	// GetSubject retrieves a subject by ID
	GetSubject(ctx context.Context, id string) (*common.Subject, error)
	
	// ListSubjects lists subjects, optionally filtered by tenant and type
	ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error)
	
	// UpdateSubject updates an existing subject
	UpdateSubject(ctx context.Context, subject *common.Subject) error
	
	// DeleteSubject deletes a subject by ID
	DeleteSubject(ctx context.Context, id string) error
	
	// GetSubjectRoles retrieves all roles assigned to a subject
	GetSubjectRoles(ctx context.Context, subjectID string, tenantID string) ([]*common.Role, error)
}

// RoleAssignmentStore defines the interface for managing role assignments
type RoleAssignmentStore interface {
	// AssignRole assigns a role to a subject
	AssignRole(ctx context.Context, assignment *common.RoleAssignment) error
	
	// RevokeRole revokes a role from a subject
	RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error
	
	// GetAssignment retrieves a specific role assignment
	GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error)
	
	// ListAssignments lists role assignments for a subject or role
	ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error)
	
	// GetSubjectAssignments retrieves all active role assignments for a subject
	GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error)
}

// AuthorizationEngine defines the interface for making authorization decisions
type AuthorizationEngine interface {
	// CheckPermission checks if a subject has a specific permission
	CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error)
	
	// GetSubjectPermissions retrieves all permissions for a subject in a tenant context
	GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error)
	
	// ValidateAccess performs comprehensive access validation with context
	ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error)
}

// PolicyEngine defines the interface for policy-based authorization (ABAC support)
type PolicyEngine interface {
	// EvaluatePolicy evaluates policies against an access request
	EvaluatePolicy(ctx context.Context, request *common.AccessRequest, policies []Policy) (bool, string)
	
	// CreatePolicy creates a new policy
	CreatePolicy(ctx context.Context, policy Policy) error
	
	// GetPolicies retrieves policies for a tenant/resource combination
	GetPolicies(ctx context.Context, tenantID, resourceType string) ([]Policy, error)
}

// Policy represents an ABAC policy
type Policy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	TenantID    string            `json:"tenant_id"`
	ResourceType string           `json:"resource_type"`
	Effect      PolicyEffect      `json:"effect"`
	Conditions  []PolicyCondition `json:"conditions"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// PolicyEffect defines whether a policy allows or denies access
type PolicyEffect string

const (
	PolicyEffectAllow PolicyEffect = "allow"
	PolicyEffectDeny  PolicyEffect = "deny"
)

// PolicyCondition represents a condition in a policy
type PolicyCondition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"`
	Value     interface{} `json:"value"`
}

// RBACManager provides a high-level interface for RBAC operations
type RBACManager interface {
	PermissionStore
	RoleStore
	SubjectStore
	RoleAssignmentStore
	AuthorizationEngine
	
	// Initialize sets up the RBAC system with default roles and permissions
	Initialize(ctx context.Context) error
	
	// CreateTenantDefaultRoles creates default roles for a new tenant
	CreateTenantDefaultRoles(ctx context.Context, tenantID string) error
	
	// GetEffectivePermissions gets all effective permissions for a subject considering role hierarchy
	GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error)
}