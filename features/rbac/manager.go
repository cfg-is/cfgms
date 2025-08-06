package rbac

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// Manager provides a complete RBAC implementation
type Manager struct {
	store           *memory.Store
	engine          *AuthEngine
	hierarchyEngine *HierarchyEngine
}

// NewManager creates a new RBAC manager with in-memory storage
func NewManager() *Manager {
	store := memory.NewStore()
	engine := NewAuthEngine(store, store, store, store)
	hierarchyEngine := NewHierarchyEngine(store, store)
	
	return &Manager{
		store:           store,
		engine:          engine,
		hierarchyEngine: hierarchyEngine,
	}
}

// Initialize sets up the RBAC system with default roles and permissions
func (m *Manager) Initialize(ctx context.Context) error {
	if err := m.store.Initialize(ctx); err != nil {
		return err
	}

	// Load default permissions
	m.store.LoadPermissions(DefaultPermissions)
	
	// Load default system roles
	m.store.LoadRoles(GetSystemRoles())
	
	return nil
}

// CreateTenantDefaultRoles creates default roles for a new tenant
func (m *Manager) CreateTenantDefaultRoles(ctx context.Context, tenantID string) error {
	tenantRoles := make([]*common.Role, 0)
	for _, template := range GetTenantRoleTemplates() {
		tenantRole := CreateTenantRole(template, tenantID)
		tenantRoles = append(tenantRoles, tenantRole)
	}
	
	m.store.LoadRoles(tenantRoles)
	return nil
}

// Permission Store Methods
func (m *Manager) CreatePermission(ctx context.Context, permission *common.Permission) error {
	return m.store.CreatePermission(ctx, permission)
}

func (m *Manager) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	return m.store.GetPermission(ctx, id)
}

func (m *Manager) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	return m.store.ListPermissions(ctx, resourceType)
}

func (m *Manager) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	return m.store.UpdatePermission(ctx, permission)
}

func (m *Manager) DeletePermission(ctx context.Context, id string) error {
	return m.store.DeletePermission(ctx, id)
}

// Role Store Methods
func (m *Manager) CreateRole(ctx context.Context, role *common.Role) error {
	return m.store.CreateRole(ctx, role)
}

func (m *Manager) GetRole(ctx context.Context, id string) (*common.Role, error) {
	return m.store.GetRole(ctx, id)
}

func (m *Manager) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	return m.store.ListRoles(ctx, tenantID)
}

func (m *Manager) UpdateRole(ctx context.Context, role *common.Role) error {
	return m.store.UpdateRole(ctx, role)
}

func (m *Manager) DeleteRole(ctx context.Context, id string) error {
	return m.store.DeleteRole(ctx, id)
}

func (m *Manager) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	return m.store.GetRolePermissions(ctx, roleID)
}

// Subject Store Methods
func (m *Manager) CreateSubject(ctx context.Context, subject *common.Subject) error {
	return m.store.CreateSubject(ctx, subject)
}

func (m *Manager) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	return m.store.GetSubject(ctx, id)
}

func (m *Manager) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	return m.store.ListSubjects(ctx, tenantID, subjectType)
}

func (m *Manager) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	return m.store.UpdateSubject(ctx, subject)
}

func (m *Manager) DeleteSubject(ctx context.Context, id string) error {
	return m.store.DeleteSubject(ctx, id)
}

func (m *Manager) GetSubjectRoles(ctx context.Context, subjectID string, tenantID string) ([]*common.Role, error) {
	return m.store.GetSubjectRoles(ctx, subjectID, tenantID)
}

// Role Assignment Store Methods
func (m *Manager) AssignRole(ctx context.Context, assignment *common.RoleAssignment) error {
	return m.store.AssignRole(ctx, assignment)
}

func (m *Manager) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	return m.store.RevokeRole(ctx, subjectID, roleID, tenantID)
}

func (m *Manager) GetAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	return m.store.GetAssignment(ctx, id)
}

func (m *Manager) ListAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	return m.store.ListAssignments(ctx, subjectID, roleID, tenantID)
}

func (m *Manager) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return m.store.GetSubjectAssignments(ctx, subjectID, tenantID)
}

// Authorization Engine Methods
func (m *Manager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return m.engine.CheckPermission(ctx, request)
}

func (m *Manager) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return m.engine.GetSubjectPermissions(ctx, subjectID, tenantID)
}

func (m *Manager) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	return m.engine.ValidateAccess(ctx, authContext, requiredPermission)
}

func (m *Manager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return m.engine.GetEffectivePermissions(ctx, subjectID, tenantID)
}

// Helper methods for common operations

// CreateStewardSubject creates a subject for a steward instance
func (m *Manager) CreateStewardSubject(ctx context.Context, stewardID, tenantID string) error {
	subject := &common.Subject{
		Id:          stewardID,
		Type:        common.SubjectType_SUBJECT_TYPE_STEWARD,
		DisplayName: "Steward " + stewardID,
		TenantId:    tenantID,
		IsActive:    true,
		Attributes:  map[string]string{
			"steward_id": stewardID,
		},
	}

	if err := m.CreateSubject(ctx, subject); err != nil {
		return err
	}

	// Assign steward service role
	assignment := &common.RoleAssignment{
		SubjectId: stewardID,
		RoleId:    "steward.service",
		TenantId:  tenantID,
	}

	return m.AssignRole(ctx, assignment)
}

// CreateServiceSubject creates a subject for a service account
func (m *Manager) CreateServiceSubject(ctx context.Context, serviceID, serviceName, tenantID string, roleIDs []string) error {
	subject := &common.Subject{
		Id:          serviceID,
		Type:        common.SubjectType_SUBJECT_TYPE_SERVICE,
		DisplayName: serviceName,
		TenantId:    tenantID,
		RoleIds:     roleIDs,
		IsActive:    true,
		Attributes:  map[string]string{
			"service_name": serviceName,
		},
	}

	if err := m.CreateSubject(ctx, subject); err != nil {
		return err
	}

	// Assign requested roles
	for _, roleID := range roleIDs {
		assignment := &common.RoleAssignment{
			SubjectId: serviceID,
			RoleId:    roleID,
			TenantId:  tenantID,
		}

		if err := m.AssignRole(ctx, assignment); err != nil {
			return err
		}
	}

	return nil
}

// Hierarchy Management Operations

func (m *Manager) ComputeRolePermissions(ctx context.Context, roleID string) (*memory.EffectivePermissions, error) {
	return m.hierarchyEngine.ComputeEffectivePermissions(ctx, roleID)
}

func (m *Manager) CreateRoleWithParent(ctx context.Context, role *common.Role, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	// Validate hierarchy operation first
	if parentRoleID != "" {
		if err := m.ValidateHierarchyOperation(ctx, role.Id, parentRoleID); err != nil {
			return fmt.Errorf("invalid hierarchy operation: %w", err)
		}
	}

	// Set parent relationship
	role.ParentRoleId = parentRoleID
	role.InheritanceType = inheritanceType

	// Create the role
	if err := m.CreateRole(ctx, role); err != nil {
		return err
	}

	// Set the parent relationship in store
	if parentRoleID != "" {
		return m.store.SetRoleParent(ctx, role.Id, parentRoleID, inheritanceType)
	}

	return nil
}

func (m *Manager) GetRoleHierarchyTree(ctx context.Context, rootRoleID string, maxDepth int) (*memory.RoleHierarchy, error) {
	return m.hierarchyEngine.buildRoleHierarchy(ctx, rootRoleID)
}

func (m *Manager) ValidateHierarchyOperation(ctx context.Context, childRoleID, parentRoleID string) error {
	if childRoleID == parentRoleID {
		return fmt.Errorf("role cannot be its own parent")
	}

	// Check if parent exists
	if parentRoleID != "" {
		_, err := m.store.GetRole(ctx, parentRoleID)
		if err != nil {
			return fmt.Errorf("failed to get role %s: %w", parentRoleID, err)
		}
		
		// Check if adding this relationship would create a cycle
		// We need to check if parentRoleID is already a descendant of childRoleID
		// Only do this check if the child role already exists
		if childExists, _ := m.roleExists(ctx, childRoleID); childExists {
			return m.hierarchyEngine.ValidateHierarchy(ctx, childRoleID)
		}
	}

	return nil
}

func (m *Manager) roleExists(ctx context.Context, roleID string) (bool, error) {
	_, err := m.store.GetRole(ctx, roleID)
	if err != nil {
		// Check if it's a "not found" error vs other errors
		if err.Error() == "role "+roleID+" not found" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (m *Manager) ResolvePermissionConflicts(ctx context.Context, roleID string, conflictingPermissions map[string][]*common.Permission) (map[string]*common.Permission, error) {
	hierarchy, err := m.hierarchyEngine.buildRoleHierarchy(ctx, roleID)
	if err != nil {
		return nil, err
	}

	resolution, err := m.hierarchyEngine.resolveConflicts(ctx, roleID, conflictingPermissions, hierarchy)
	if err != nil {
		return nil, err
	}

	// Convert ConflictResult map to Permission map
	result := make(map[string]*common.Permission)
	for permID, conflict := range resolution {
		result[permID] = conflict.Permission
	}

	return result, nil
}

// Override GetRoleHierarchy to convert between types
func (m *Manager) GetRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error) {
	memoryHierarchy, err := m.store.GetRoleHierarchy(ctx, roleID)
	if err != nil {
		return nil, err
	}

	return memoryHierarchy, nil
}

// Helper to convert between hierarchy types
func (m *Manager) convertToRBACHierarchy(memHierarchy *memory.RoleHierarchy) *memory.RoleHierarchy {
	if memHierarchy == nil {
		return nil
	}

	hierarchy := &memory.RoleHierarchy{
		Role:  memHierarchy.Role,
		Depth: memHierarchy.Depth,
	}

	if memHierarchy.Parent != nil {
		hierarchy.Parent = m.convertToRBACHierarchy(memHierarchy.Parent)
	}

	for _, child := range memHierarchy.Children {
		hierarchy.Children = append(hierarchy.Children, m.convertToRBACHierarchy(child))
	}

	return hierarchy
}

// Delegate hierarchy store operations
func (m *Manager) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	return m.store.GetChildRoles(ctx, roleID)
}

func (m *Manager) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	return m.store.GetParentRole(ctx, roleID)
}

func (m *Manager) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	// Validate first
	if err := m.ValidateHierarchyOperation(ctx, roleID, parentRoleID); err != nil {
		return err
	}
	return m.store.SetRoleParent(ctx, roleID, parentRoleID, inheritanceType)
}

func (m *Manager) RemoveRoleParent(ctx context.Context, roleID string) error {
	return m.store.RemoveRoleParent(ctx, roleID)
}

func (m *Manager) ValidateRoleHierarchy(ctx context.Context, roleID string) error {
	return m.hierarchyEngine.ValidateHierarchy(ctx, roleID)
}

// Verify that Manager implements the RBACManager interface
var _ RBACManager = (*Manager)(nil)