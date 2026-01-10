// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/api/proto/common"
)

// Import the actual protobuf types
type RoleInheritanceType = common.RoleInheritanceType

// RoleHierarchy represents a role and its position in the hierarchy
type RoleHierarchy struct {
	Role     *common.Role
	Parent   *RoleHierarchy
	Children []*RoleHierarchy
	Depth    int // 0 for requested role, positive for ancestors, negative for descendants
}

// EffectivePermissions represents the computed permissions for a role considering hierarchy
type EffectivePermissions struct {
	RoleID               string                          `json:"role_id"`
	DirectPermissions    []*common.Permission            `json:"direct_permissions"`
	InheritedPermissions map[string][]*common.Permission `json:"inherited_permissions"` // roleID -> permissions
	ConflictResolution   map[string]ConflictResult       `json:"conflict_resolution,omitempty"`
	ComputedAt           time.Time                       `json:"computed_at"`
}

// ConflictResult represents how a permission conflict was resolved
type ConflictResult struct {
	Permission     *common.Permission `json:"permission"`
	SourceRoleID   string             `json:"source_role_id"`
	Resolution     string             `json:"resolution"` // "override", "merge", "restrict"
	ConflictedWith []string           `json:"conflicted_with"`
}

// Policy represents an ABAC policy
type Policy struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Description  string            `json:"description"`
	TenantID     string            `json:"tenant_id"`
	ResourceType string            `json:"resource_type"`
	Effect       PolicyEffect      `json:"effect"`
	Conditions   []PolicyCondition `json:"conditions"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
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

const (
	RoleInheritanceNone        = common.RoleInheritanceType_ROLE_INHERITANCE_NONE
	RoleInheritanceAdditive    = common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE
	RoleInheritanceOverride    = common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE
	RoleInheritanceRestrictive = common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE
)

// Store provides an in-memory implementation of all RBAC stores
type Store struct {
	mu          sync.RWMutex
	permissions map[string]*common.Permission
	roles       map[string]*common.Role
	subjects    map[string]*common.Subject
	assignments map[string]*common.RoleAssignment
	initialized bool
}

// NewStore creates a new in-memory RBAC store
func NewStore() *Store {
	return &Store{
		permissions: make(map[string]*common.Permission),
		roles:       make(map[string]*common.Role),
		subjects:    make(map[string]*common.Subject),
		assignments: make(map[string]*common.RoleAssignment),
	}
}

// Initialize sets up the store with default permissions and roles
func (s *Store) Initialize(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.initialized {
		return nil
	}

	// Load default permissions (moved to caller)
	// Load default system roles (moved to caller)

	s.initialized = true
	return nil
}

// LoadPermissions loads permissions into the store
func (s *Store) LoadPermissions(permissions []*common.Permission) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, perm := range permissions {
		s.permissions[perm.Id] = perm
	}
}

// LoadRoles loads roles into the store
func (s *Store) LoadRoles(roles []*common.Role) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	for _, role := range roles {
		// Create a copy to avoid race conditions on shared role objects
		roleCopy := &common.Role{
			Id:              role.Id,
			Name:            role.Name,
			Description:     role.Description,
			PermissionIds:   append([]string{}, role.PermissionIds...),
			TenantId:        role.TenantId,
			ParentRoleId:    role.ParentRoleId,
			ChildRoleIds:    append([]string{}, role.ChildRoleIds...),
			InheritanceType: role.InheritanceType,
			IsSystemRole:    role.IsSystemRole,
			CreatedAt:       now,
			UpdatedAt:       now,
		}
		s.roles[roleCopy.Id] = roleCopy
	}

	// Second pass: establish bidirectional parent-child relationships
	for _, inputRole := range roles {
		if inputRole.ParentRoleId != "" {
			if parent, exists := s.roles[inputRole.ParentRoleId]; exists {
				// Add this role to parent's children if not already present
				if !contains(parent.ChildRoleIds, inputRole.Id) {
					parent.ChildRoleIds = append(parent.ChildRoleIds, inputRole.Id)
				}
			}
		}
	}
}

// Permission Store Implementation

func (s *Store) CreatePermission(ctx context.Context, permission *common.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.permissions[permission.Id]; exists {
		return fmt.Errorf("permission %s already exists", permission.Id)
	}

	s.permissions[permission.Id] = permission
	return nil
}

func (s *Store) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	perm, exists := s.permissions[id]
	if !exists {
		return nil, fmt.Errorf("permission %s not found", id)
	}

	return perm, nil
}

func (s *Store) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var permissions []*common.Permission
	for _, perm := range s.permissions {
		if resourceType == "" || perm.ResourceType == resourceType {
			permissions = append(permissions, perm)
		}
	}

	return permissions, nil
}

func (s *Store) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.permissions[permission.Id]; !exists {
		return fmt.Errorf("permission %s not found", permission.Id)
	}

	s.permissions[permission.Id] = permission
	return nil
}

func (s *Store) DeletePermission(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.permissions[id]; !exists {
		return fmt.Errorf("permission %s not found", id)
	}

	delete(s.permissions, id)
	return nil
}

// Role Store Implementation

func (s *Store) CreateRole(ctx context.Context, role *common.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.Id]; exists {
		return fmt.Errorf("role %s already exists", role.Id)
	}

	now := time.Now().Unix()
	role.CreatedAt = now
	role.UpdatedAt = now
	s.roles[role.Id] = role
	return nil
}

func (s *Store) GetRole(ctx context.Context, id string) (*common.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[id]
	if !exists {
		return nil, fmt.Errorf("role %s not found", id)
	}

	return role, nil
}

func (s *Store) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var roles []*common.Role
	for _, role := range s.roles {
		// Include system roles and tenant-specific roles
		if role.IsSystemRole || role.TenantId == tenantID {
			roles = append(roles, role)
		}
	}

	return roles, nil
}

func (s *Store) UpdateRole(ctx context.Context, role *common.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.roles[role.Id]; !exists {
		return fmt.Errorf("role %s not found", role.Id)
	}

	role.UpdatedAt = time.Now().Unix()
	s.roles[role.Id] = role
	return nil
}

func (s *Store) DeleteRole(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	role, exists := s.roles[id]
	if !exists {
		return fmt.Errorf("role %s not found", id)
	}

	if role.IsSystemRole {
		return fmt.Errorf("cannot delete system role %s", id)
	}

	delete(s.roles, id)
	return nil
}

func (s *Store) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}

	var permissions []*common.Permission
	for _, permID := range role.PermissionIds {
		if perm, exists := s.permissions[permID]; exists {
			permissions = append(permissions, perm)
		}
	}

	return permissions, nil
}

// Subject Store Implementation

func (s *Store) CreateSubject(ctx context.Context, subject *common.Subject) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.subjects[subject.Id]; exists {
		return fmt.Errorf("subject %s already exists", subject.Id)
	}

	now := time.Now().Unix()
	subject.CreatedAt = now
	subject.UpdatedAt = now
	s.subjects[subject.Id] = subject
	return nil
}

func (s *Store) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	subject, exists := s.subjects[id]
	if !exists {
		return nil, fmt.Errorf("subject %s not found", id)
	}

	return subject, nil
}

func (s *Store) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var subjects []*common.Subject
	for _, subject := range s.subjects {
		if (tenantID == "" || subject.TenantId == tenantID) &&
			(subjectType == common.SubjectType_SUBJECT_TYPE_UNSPECIFIED || subject.Type == subjectType) {
			subjects = append(subjects, subject)
		}
	}

	return subjects, nil
}

func (s *Store) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.subjects[subject.Id]; !exists {
		return fmt.Errorf("subject %s not found", subject.Id)
	}

	subject.UpdatedAt = time.Now().Unix()
	s.subjects[subject.Id] = subject
	return nil
}

func (s *Store) DeleteSubject(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.subjects[id]; !exists {
		return fmt.Errorf("subject %s not found", id)
	}

	delete(s.subjects, id)
	return nil
}

func (s *Store) GetSubjectRoles(ctx context.Context, subjectID string, tenantID string) ([]*common.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	subject, exists := s.subjects[subjectID]
	if !exists {
		return nil, fmt.Errorf("subject %s not found", subjectID)
	}

	var roles []*common.Role
	for _, roleID := range subject.RoleIds {
		if role, exists := s.roles[roleID]; exists {
			// Include if it's a system role or matches tenant
			if role.IsSystemRole || role.TenantId == tenantID {
				roles = append(roles, role)
			}
		}
	}

	return roles, nil
}

// Role Assignment Store Implementation

func (s *Store) AssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate subject exists
	if _, exists := s.subjects[assignment.SubjectId]; !exists {
		return fmt.Errorf("subject %s not found", assignment.SubjectId)
	}

	// Validate role exists
	if _, exists := s.roles[assignment.RoleId]; !exists {
		return fmt.Errorf("role %s not found", assignment.RoleId)
	}

	// Generate assignment ID if not provided
	if assignment.Id == "" {
		assignment.Id = uuid.New().String()
	}

	assignment.AssignedAt = time.Now().Unix()
	s.assignments[assignment.Id] = assignment

	// Update subject's role list
	subject := s.subjects[assignment.SubjectId]
	subject.RoleIds = append(subject.RoleIds, assignment.RoleId)
	subject.UpdatedAt = time.Now().Unix()

	return nil
}

func (s *Store) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Find and remove assignment
	var assignmentID string
	for id, assignment := range s.assignments {
		if assignment.SubjectId == subjectID && assignment.RoleId == roleID && assignment.TenantId == tenantID {
			assignmentID = id
			break
		}
	}

	if assignmentID == "" {
		return fmt.Errorf("role assignment not found")
	}

	delete(s.assignments, assignmentID)

	// Update subject's role list
	if subject, exists := s.subjects[subjectID]; exists {
		var newRoleIds []string
		for _, id := range subject.RoleIds {
			if id != roleID {
				newRoleIds = append(newRoleIds, id)
			}
		}
		subject.RoleIds = newRoleIds
		subject.UpdatedAt = time.Now().Unix()
	}

	return nil
}

func (s *Store) GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	assignment, exists := s.assignments[id]
	if !exists {
		return nil, fmt.Errorf("assignment %s not found", id)
	}

	return assignment, nil
}

func (s *Store) ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var assignments []*common.RoleAssignment
	for _, assignment := range s.assignments {
		if (subjectID == "" || assignment.SubjectId == subjectID) &&
			(roleID == "" || assignment.RoleId == roleID) &&
			(tenantID == "" || assignment.TenantId == tenantID) {
			assignments = append(assignments, assignment)
		}
	}

	return assignments, nil
}

func (s *Store) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var assignments []*common.RoleAssignment
	now := time.Now().Unix()

	for _, assignment := range s.assignments {
		if assignment.SubjectId == subjectID && assignment.TenantId == tenantID {
			// Check if assignment is still valid (not expired)
			if assignment.ExpiresAt == 0 || assignment.ExpiresAt > now {
				assignments = append(assignments, assignment)
			}
		}
	}

	return assignments, nil
}

// Role Hierarchy Operations

func (s *Store) GetRoleHierarchy(ctx context.Context, roleID string) (*RoleHierarchy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}

	hierarchy := &RoleHierarchy{
		Role:  role,
		Depth: 0,
	}

	// Get parent if exists
	if role.ParentRoleId != "" {
		if parentRole, exists := s.roles[role.ParentRoleId]; exists {
			parentHierarchy := &RoleHierarchy{
				Role:  parentRole,
				Depth: 1,
			}
			hierarchy.Parent = parentHierarchy
		}
	}

	// Get children
	var children []*RoleHierarchy
	for _, childRoleID := range role.ChildRoleIds {
		if childRole, exists := s.roles[childRoleID]; exists {
			childHierarchy := &RoleHierarchy{
				Role:  childRole,
				Depth: -1,
			}
			children = append(children, childHierarchy)
		}
	}
	hierarchy.Children = children

	return hierarchy, nil
}

func (s *Store) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}

	var children []*common.Role
	for _, childRoleID := range role.ChildRoleIds {
		if childRole, exists := s.roles[childRoleID]; exists {
			children = append(children, childRole)
		}
	}

	return children, nil
}

func (s *Store) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return nil, fmt.Errorf("role %s not found", roleID)
	}

	if role.ParentRoleId == "" {
		return nil, fmt.Errorf("role %s has no parent", roleID)
	}

	parentRole, exists := s.roles[role.ParentRoleId]
	if !exists {
		return nil, fmt.Errorf("parent role %s not found", role.ParentRoleId)
	}

	return parentRole, nil
}

func (s *Store) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate both roles exist
	role, exists := s.roles[roleID]
	if !exists {
		return fmt.Errorf("role %s not found", roleID)
	}

	var parentRole *common.Role
	if parentRoleID != "" {
		parentRole, exists = s.roles[parentRoleID]
		if !exists {
			return fmt.Errorf("parent role %s not found", parentRoleID)
		}
	}

	// Remove from old parent's children list if changing parent
	if role.ParentRoleId != "" && role.ParentRoleId != parentRoleID {
		if oldParent, exists := s.roles[role.ParentRoleId]; exists {
			oldParent.ChildRoleIds = removeFromSlice(oldParent.ChildRoleIds, roleID)
			oldParent.UpdatedAt = time.Now().Unix()
		}
	}

	// Update parent's children list
	if parentRole != nil {
		if !contains(parentRole.ChildRoleIds, roleID) {
			parentRole.ChildRoleIds = append(parentRole.ChildRoleIds, roleID)
			parentRole.UpdatedAt = time.Now().Unix()
		}
	}

	// Update role relationships
	role.ParentRoleId = parentRoleID
	role.InheritanceType = inheritanceType
	role.UpdatedAt = time.Now().Unix()

	return nil
}

func (s *Store) RemoveRoleParent(ctx context.Context, roleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	role, exists := s.roles[roleID]
	if !exists {
		return fmt.Errorf("role %s not found", roleID)
	}

	if role.ParentRoleId == "" {
		return nil // Already has no parent
	}

	// Remove from parent's children list
	if parent, exists := s.roles[role.ParentRoleId]; exists {
		parent.ChildRoleIds = removeFromSlice(parent.ChildRoleIds, roleID)
		parent.UpdatedAt = time.Now().Unix()
	}

	// Clear parent relationship
	role.ParentRoleId = ""
	role.InheritanceType = common.RoleInheritanceType_ROLE_INHERITANCE_NONE
	role.UpdatedAt = time.Now().Unix()

	return nil
}

func (s *Store) ValidateRoleHierarchy(ctx context.Context, roleID string) error {
	// This will be implemented by the HierarchyEngine
	// The store provides basic validation here
	s.mu.RLock()
	defer s.mu.RUnlock()

	role, exists := s.roles[roleID]
	if !exists {
		return fmt.Errorf("role %s not found", roleID)
	}

	// Basic cycle detection - check if role is its own ancestor
	visited := make(map[string]bool)
	return s.detectCycle(role, visited)
}

func (s *Store) detectCycle(role *common.Role, visited map[string]bool) error {
	if visited[role.Id] {
		return fmt.Errorf("circular dependency detected in role hierarchy for role %s", role.Id)
	}

	if role.ParentRoleId == "" {
		return nil
	}

	parentRole, exists := s.roles[role.ParentRoleId]
	if !exists {
		return nil
	}

	visited[role.Id] = true
	err := s.detectCycle(parentRole, visited)
	delete(visited, role.Id)

	return err
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func removeFromSlice(slice []string, item string) []string {
	var result []string
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}

// Interfaces are verified in the manager.go file to avoid import cycles
