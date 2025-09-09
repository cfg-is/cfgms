package rbac

import (
	"context"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
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
	
	// Hierarchy operations
	
	// GetRoleHierarchy retrieves the complete role hierarchy for a role
	GetRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error)
	
	// GetChildRoles retrieves all direct child roles
	GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error)
	
	// GetParentRole retrieves the parent role if it exists
	GetParentRole(ctx context.Context, roleID string) (*common.Role, error)
	
	// SetRoleParent sets or updates the parent role for a role
	SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error
	
	// RemoveRoleParent removes the parent relationship for a role
	RemoveRoleParent(ctx context.Context, roleID string) error
	
	// ValidateRoleHierarchy checks for circular dependencies and validates hierarchy
	ValidateRoleHierarchy(ctx context.Context, roleID string) error
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
	EvaluatePolicy(ctx context.Context, request *common.AccessRequest, policies []memory.Policy) (bool, string)
	
	// CreatePolicy creates a new policy
	CreatePolicy(ctx context.Context, policy memory.Policy) error
	
	// GetPolicies retrieves policies for a tenant/resource combination
	GetPolicies(ctx context.Context, tenantID, resourceType string) ([]memory.Policy, error)
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
	
	// Hierarchy management operations
	
	// ComputeRolePermissions computes effective permissions for a role considering inheritance
	ComputeRolePermissions(ctx context.Context, roleID string) (*memory.EffectivePermissions, error)
	
	// CreateRoleWithParent creates a new role with optional parent relationship
	CreateRoleWithParent(ctx context.Context, role *common.Role, parentRoleID string, inheritanceType common.RoleInheritanceType) error
	
	// GetRoleHierarchyTree retrieves the complete hierarchy tree starting from a role
	GetRoleHierarchyTree(ctx context.Context, rootRoleID string, maxDepth int) (*memory.RoleHierarchy, error)
	
	// ValidateHierarchyOperation validates that a hierarchy operation won't create cycles
	ValidateHierarchyOperation(ctx context.Context, childRoleID, parentRoleID string) error
	
	// ResolvePermissionConflicts resolves conflicts when multiple inherited permissions exist
	ResolvePermissionConflicts(ctx context.Context, roleID string, conflictingPermissions map[string][]*common.Permission) (map[string]*common.Permission, error)
}