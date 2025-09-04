package rbac

import (
	"context"
	"fmt"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// Manager provides a complete RBAC implementation with advanced features
type Manager struct {
	store                    *memory.Store
	
	// Pluggable storage interfaces (when using NewManagerWithStorage)
	auditStore               interfaces.AuditStore
	clientTenantStore        interfaces.ClientTenantStore
	rbacStore                interfaces.RBACStore
	usePluggableStorage      bool
	auditManager             *audit.Manager
	
	engine                   *AuthEngine
	advancedEngine           *AdvancedAuthEngine
	hierarchyEngine          *HierarchyEngine
	delegationManager        *DelegationManager
	auditLogger              *AuditLogger
	templateManager          *TemplateManager
	escalationPreventionMgr  *EscalationPreventionManager
}

// NewManager is DEPRECATED and removed in Epic 6: Complete Storage Migration
// Use NewManagerWithStorage() with pluggable storage providers instead
// Minimum storage requirement: git provider with local repository
// 
// BREAKING CHANGE: This function has been removed to eliminate package-level 
// storage mechanisms. All RBAC operations now require durable storage.
//
// Migration example:
//   // OLD: manager := rbac.NewManager()  
//   // NEW: 
//   storageManager := interfaces.CreateAllStoresFromConfig("git", config)
//   manager := rbac.NewManagerWithStorage(storageManager.GetAuditStore(), storageManager.GetClientTenantStore())
//
// For testing, use: pkg/testing.SetupTestRBACManager(t)
//
// This change ensures Epic 6 goal: Zero package-level storage mechanisms

// NewManagerWithStorage creates a new RBAC manager with pluggable storage interfaces
// This is the recommended constructor for production deployments with configurable storage backends
func NewManagerWithStorage(auditStore interfaces.AuditStore, clientTenantStore interfaces.ClientTenantStore, rbacStore interfaces.RBACStore) *Manager {
	if auditStore == nil || clientTenantStore == nil || rbacStore == nil {
		panic("NewManagerWithStorage requires non-nil storage interfaces")
	}
	
	// Epic 6: Create ephemeral memory store (not package-level persistent)
	// This store exists only for the lifetime of this manager instance
	// All persistent data flows through global storage interfaces (auditStore, clientTenantStore)
	ephemeralStore := memory.NewStore()
	engine := NewAuthEngine(ephemeralStore, ephemeralStore, ephemeralStore, ephemeralStore)
	hierarchyEngine := NewHierarchyEngine(ephemeralStore, ephemeralStore)
	
	// Create audit manager for RBAC operations
	auditManager := audit.NewManager(auditStore, "rbac")
	
	// Create manager instance with pluggable storage
	manager := &Manager{
		store:               ephemeralStore, // Epic 6: Ephemeral store - not persistent
		auditStore:          auditStore,
		clientTenantStore:   clientTenantStore,
		rbacStore:           rbacStore,      // Write-through persistent RBAC storage
		usePluggableStorage: true,
		auditManager:        auditManager,
		engine:              engine,
		hierarchyEngine:     hierarchyEngine,
	}
	
	// Initialize advanced components
	advancedEngine := NewAdvancedAuthEngine(ephemeralStore, ephemeralStore, ephemeralStore, ephemeralStore)
	delegationManager := NewDelegationManager(manager) // Pass manager for RBAC operations
	auditLogger := NewAuditLogger()
	templateManager := NewTemplateManager(manager) // Pass manager for template operations
	escalationPreventionMgr := NewEscalationPreventionManager(manager) // Pass manager for privilege escalation protection
	
	// Set circular references
	advancedEngine.SetRBACManager(manager)
	
	// Update manager with advanced components
	manager.advancedEngine = advancedEngine
	manager.delegationManager = delegationManager
	manager.auditLogger = auditLogger
	manager.templateManager = templateManager
	manager.escalationPreventionMgr = escalationPreventionMgr
	
	// Share the same delegation manager and audit logger instances
	advancedEngine.SetDelegationManager(delegationManager)
	advancedEngine.SetAuditLogger(auditLogger)
	
	return manager
}

// Initialize sets up the RBAC system with default roles and permissions
func (m *Manager) Initialize(ctx context.Context) error {
	if err := m.store.Initialize(ctx); err != nil {
		return err
	}

	// Initialize persistent storage
	if m.rbacStore != nil {
		if err := m.rbacStore.Initialize(ctx); err != nil {
			return fmt.Errorf("failed to initialize RBAC store: %w", err)
		}
		
		// Load existing data from persistent storage into ephemeral store
		if err := m.loadFromPersistentStorage(ctx); err != nil {
			return fmt.Errorf("failed to load data from persistent storage: %w", err)
		}
	}

	// Load default permissions (both in ephemeral and persistent storage)
	if err := m.loadDefaultPermissions(ctx); err != nil {
		return fmt.Errorf("failed to load default permissions: %w", err)
	}
	
	// Load default system roles (both in ephemeral and persistent storage)
	if err := m.loadDefaultRoles(ctx); err != nil {
		return fmt.Errorf("failed to load default roles: %w", err)
	}
	
	// Initialize template manager with system templates
	if err := m.templateManager.Initialize(ctx); err != nil {
		return fmt.Errorf("failed to initialize template manager: %w", err)
	}
	
	return nil
}

// loadFromPersistentStorage loads existing RBAC data from persistent storage into ephemeral store
func (m *Manager) loadFromPersistentStorage(ctx context.Context) error {
	if m.rbacStore == nil {
		return nil
	}
	
	// Load all permissions
	permissions, err := m.rbacStore.ListPermissions(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to load permissions: %w", err)
	}
	if len(permissions) > 0 {
		m.store.LoadPermissions(permissions)
	}
	
	// Load all roles
	roles, err := m.rbacStore.ListRoles(ctx, "")
	if err != nil {
		return fmt.Errorf("failed to load roles: %w", err)
	}
	if len(roles) > 0 {
		m.store.LoadRoles(roles)
	}
	
	// Load all subjects
	subjects, err := m.rbacStore.ListSubjects(ctx, "", common.SubjectType_SUBJECT_TYPE_UNSPECIFIED)
	if err != nil {
		return fmt.Errorf("failed to load subjects: %w", err)
	}
	for _, subject := range subjects {
		_ = m.store.CreateSubject(ctx, subject)
	}
	
	// Load all role assignments
	assignments, err := m.rbacStore.ListRoleAssignments(ctx, "", "", "")
	if err != nil {
		return fmt.Errorf("failed to load role assignments: %w", err)
	}
	for _, assignment := range assignments {
		_ = m.store.AssignRole(ctx, assignment)
	}
	
	return nil
}

// loadDefaultPermissions ensures default permissions exist in both stores
func (m *Manager) loadDefaultPermissions(ctx context.Context) error {
	// Load into ephemeral store
	m.store.LoadPermissions(DefaultPermissions)
	
	// Persist to storage provider if available
	if m.rbacStore != nil {
		if err := m.rbacStore.StoreBulkPermissions(ctx, DefaultPermissions); err != nil {
			return fmt.Errorf("failed to persist default permissions: %w", err)
		}
	}
	
	return nil
}

// loadDefaultRoles ensures default roles exist in both stores
func (m *Manager) loadDefaultRoles(ctx context.Context) error {
	systemRoles := GetSystemRoles()
	
	// Load into ephemeral store
	m.store.LoadRoles(systemRoles)
	
	// Persist to storage provider if available
	if m.rbacStore != nil {
		if err := m.rbacStore.StoreBulkRoles(ctx, systemRoles); err != nil {
			return fmt.Errorf("failed to persist default roles: %w", err)
		}
	}
	
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
	// Write-through: persist to both ephemeral and persistent storage
	if err := m.store.CreatePermission(ctx, permission); err != nil {
		return err
	}
	
	// Persist to storage provider
	if m.rbacStore != nil {
		if err := m.rbacStore.StorePermission(ctx, permission); err != nil {
			// Try to rollback ephemeral store change
			_ = m.store.DeletePermission(ctx, permission.Id)
			return fmt.Errorf("failed to persist permission: %w", err)
		}
	}
	
	return nil
}

func (m *Manager) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	return m.store.GetPermission(ctx, id)
}

func (m *Manager) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	return m.store.ListPermissions(ctx, resourceType)
}

func (m *Manager) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	// Write-through: persist to both ephemeral and persistent storage
	if err := m.store.UpdatePermission(ctx, permission); err != nil {
		return err
	}
	
	// Persist to storage provider
	if m.rbacStore != nil {
		if err := m.rbacStore.UpdatePermission(ctx, permission); err != nil {
			return fmt.Errorf("failed to persist permission update: %w", err)
		}
	}
	
	return nil
}

func (m *Manager) DeletePermission(ctx context.Context, id string) error {
	// Write-through: remove from both ephemeral and persistent storage
	if err := m.store.DeletePermission(ctx, id); err != nil {
		return err
	}
	
	// Remove from storage provider
	if m.rbacStore != nil {
		if err := m.rbacStore.DeletePermission(ctx, id); err != nil {
			return fmt.Errorf("failed to persist permission deletion: %w", err)
		}
	}
	
	return nil
}

// Role Store Methods
func (m *Manager) CreateRole(ctx context.Context, role *common.Role) error {
	// Write-through: persist to both ephemeral and persistent storage
	err := m.store.CreateRole(ctx, role)
	if err != nil {
		// Record audit failure
		if m.auditManager != nil {
			event := audit.UserManagementEvent(role.TenantId, "system", role.Id, "create_role").
				Resource("role", role.Id, role.Name).
				Result(interfaces.AuditResultError).
				Error("RBAC_CREATE_ROLE_FAILED", err.Error()).
				Severity(interfaces.AuditSeverityHigh)
			_ = m.auditManager.RecordEvent(ctx, event)
		}
		return err
	}
	
	// Persist to storage provider
	if m.rbacStore != nil {
		if persistErr := m.rbacStore.StoreRole(ctx, role); persistErr != nil {
			// Try to rollback ephemeral store change
			_ = m.store.DeleteRole(ctx, role.Id)
			
			// Record audit failure
			if m.auditManager != nil {
				event := audit.UserManagementEvent(role.TenantId, "system", role.Id, "create_role").
					Resource("role", role.Id, role.Name).
					Result(interfaces.AuditResultError).
					Error("RBAC_CREATE_ROLE_PERSISTENCE_FAILED", persistErr.Error()).
					Severity(interfaces.AuditSeverityHigh)
				_ = m.auditManager.RecordEvent(ctx, event)
			}
			return fmt.Errorf("failed to persist role: %w", persistErr)
		}
	}
	
	// Record successful audit event
	if m.auditManager != nil {
		event := audit.UserManagementEvent(role.TenantId, "system", role.Id, "create_role").
			Resource("role", role.Id, role.Name).
			Result(interfaces.AuditResultSuccess).
			Detail("role_permissions", len(role.PermissionIds)).
			Detail("role_description", role.Description).
			Severity(interfaces.AuditSeverityHigh)
		_ = m.auditManager.RecordEvent(ctx, event)
	}
	
	return nil
}

func (m *Manager) GetRole(ctx context.Context, id string) (*common.Role, error) {
	return m.store.GetRole(ctx, id)
}

func (m *Manager) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	return m.store.ListRoles(ctx, tenantID)
}

func (m *Manager) UpdateRole(ctx context.Context, role *common.Role) error {
	// Get the old role for change tracking
	var oldRole *common.Role
	if m.auditManager != nil {
		oldRole, _ = m.store.GetRole(ctx, role.Id) // Ignore error for audit purposes
	}
	
	// Write-through: persist to both ephemeral and persistent storage
	err := m.store.UpdateRole(ctx, role)
	if err != nil {
		// Record audit failure
		if m.auditManager != nil {
			event := audit.UserManagementEvent(role.TenantId, "system", role.Id, "update_role").
				Resource("role", role.Id, role.Name).
				Result(interfaces.AuditResultError).
				Error("RBAC_UPDATE_ROLE_FAILED", err.Error()).
				Severity(interfaces.AuditSeverityHigh)
			_ = m.auditManager.RecordEvent(ctx, event)
		}
		return err
	}
	
	// Persist to storage provider
	if m.rbacStore != nil {
		if persistErr := m.rbacStore.UpdateRole(ctx, role); persistErr != nil {
			// Record audit failure
			if m.auditManager != nil {
				event := audit.UserManagementEvent(role.TenantId, "system", role.Id, "update_role").
					Resource("role", role.Id, role.Name).
					Result(interfaces.AuditResultError).
					Error("RBAC_UPDATE_ROLE_PERSISTENCE_FAILED", persistErr.Error()).
					Severity(interfaces.AuditSeverityHigh)
				_ = m.auditManager.RecordEvent(ctx, event)
			}
			return fmt.Errorf("failed to persist role update: %w", persistErr)
		}
	}
	
	// Record successful audit event with change tracking
	if m.auditManager != nil {
		event := audit.UserManagementEvent(role.TenantId, "system", role.Id, "update_role").
			Resource("role", role.Id, role.Name).
			Result(interfaces.AuditResultSuccess).
			Detail("role_permissions", len(role.PermissionIds)).
			Severity(interfaces.AuditSeverityHigh)
		
		// Add change tracking if we have the old role
		if oldRole != nil {
			changes := make(map[string]interface{})
			after := make(map[string]interface{})
			before := make(map[string]interface{})
			
			if oldRole.Name != role.Name {
				before["name"] = oldRole.Name
				after["name"] = role.Name
				changes["name"] = true
			}
			if oldRole.Description != role.Description {
				before["description"] = oldRole.Description
				after["description"] = role.Description
				changes["description"] = true
			}
			if len(oldRole.PermissionIds) != len(role.PermissionIds) {
				before["permission_count"] = len(oldRole.PermissionIds)
				after["permission_count"] = len(role.PermissionIds)
				changes["permissions"] = true
			}
			
			if len(changes) > 0 {
				fields := make([]string, 0, len(changes))
				for field := range changes {
					fields = append(fields, field)
				}
				event = event.Changes(before, after, fields)
			}
		}
		
		_ = m.auditManager.RecordEvent(ctx, event)
	}
	
	return nil
}

func (m *Manager) DeleteRole(ctx context.Context, id string) error {
	// Get the role before deletion for audit purposes
	var deletedRole *common.Role
	if m.auditManager != nil {
		deletedRole, _ = m.store.GetRole(ctx, id) // Ignore error for audit purposes
	}
	
	// Write-through: remove from both ephemeral and persistent storage
	err := m.store.DeleteRole(ctx, id)
	if err != nil {
		// Record audit failure
		if m.auditManager != nil {
			tenantID := "system" // Default for system-level operations
			roleName := id
			if deletedRole != nil {
				tenantID = deletedRole.TenantId
				roleName = deletedRole.Name
			}
			
			event := audit.UserManagementEvent(tenantID, "system", id, "delete_role").
				Resource("role", id, roleName).
				Result(interfaces.AuditResultError).
				Error("RBAC_DELETE_ROLE_FAILED", err.Error()).
				Severity(interfaces.AuditSeverityCritical)
			_ = m.auditManager.RecordEvent(ctx, event)
		}
		return err
	}
	
	// Remove from storage provider
	if m.rbacStore != nil {
		if persistErr := m.rbacStore.DeleteRole(ctx, id); persistErr != nil {
			// Record audit failure
			if m.auditManager != nil {
				tenantID := "system"
				roleName := id
				if deletedRole != nil {
					tenantID = deletedRole.TenantId
					roleName = deletedRole.Name
				}
				
				event := audit.UserManagementEvent(tenantID, "system", id, "delete_role").
					Resource("role", id, roleName).
					Result(interfaces.AuditResultError).
					Error("RBAC_DELETE_ROLE_PERSISTENCE_FAILED", persistErr.Error()).
					Severity(interfaces.AuditSeverityCritical)
				_ = m.auditManager.RecordEvent(ctx, event)
			}
			return fmt.Errorf("failed to persist role deletion: %w", persistErr)
		}
	}
	
	// Record successful audit event
	if m.auditManager != nil {
		tenantID := "system" // Default for system-level operations
		roleName := id
		
		if deletedRole != nil {
			tenantID = deletedRole.TenantId
			roleName = deletedRole.Name
		}
		
		event := audit.UserManagementEvent(tenantID, "system", id, "delete_role").
			Resource("role", id, roleName).
			Result(interfaces.AuditResultSuccess).
			Severity(interfaces.AuditSeverityCritical) // Role deletion is critical
		
		if deletedRole != nil {
			event = event.Detail("deleted_permissions", len(deletedRole.PermissionIds)).
				Detail("role_description", deletedRole.Description)
		}
		
		_ = m.auditManager.RecordEvent(ctx, event)
	}
	
	return nil
}

func (m *Manager) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	return m.store.GetRolePermissions(ctx, roleID)
}

// Subject Store Methods
func (m *Manager) CreateSubject(ctx context.Context, subject *common.Subject) error {
	// Write-through: persist to both ephemeral and persistent storage
	if err := m.store.CreateSubject(ctx, subject); err != nil {
		return err
	}
	
	// Persist to storage provider
	if m.rbacStore != nil {
		if err := m.rbacStore.StoreSubject(ctx, subject); err != nil {
			// Try to rollback ephemeral store change
			_ = m.store.DeleteSubject(ctx, subject.Id)
			return fmt.Errorf("failed to persist subject: %w", err)
		}
	}
	
	return nil
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
	// Use escalation prevention manager for enhanced security
	return m.escalationPreventionMgr.ValidateAndAssignRole(ctx, assignment)
}

func (m *Manager) RevokeRole(ctx context.Context, subjectID, roleID, tenantID string) error {
	// Write-through: remove from both ephemeral and persistent storage
	err := m.store.RevokeRole(ctx, subjectID, roleID, tenantID)
	if err != nil {
		// Record audit failure
		if m.auditManager != nil {
			event := audit.UserManagementEvent(tenantID, subjectID, subjectID, "revoke_role").
				Resource("role_assignment", roleID, "").
				Result(interfaces.AuditResultError).
				Error("RBAC_REVOKE_ROLE_FAILED", err.Error()).
				Detail("revoked_role", roleID).
				Detail("subject_id", subjectID).
				Severity(interfaces.AuditSeverityHigh)
			_ = m.auditManager.RecordEvent(ctx, event)
		}
		return err
	}
	
	// Remove from storage provider
	if m.rbacStore != nil {
		if persistErr := m.rbacStore.DeleteRoleAssignment(ctx, subjectID, roleID, tenantID); persistErr != nil {
			// Record audit failure
			if m.auditManager != nil {
				event := audit.UserManagementEvent(tenantID, subjectID, subjectID, "revoke_role").
					Resource("role_assignment", roleID, "").
					Result(interfaces.AuditResultError).
					Error("RBAC_REVOKE_ROLE_PERSISTENCE_FAILED", persistErr.Error()).
					Detail("revoked_role", roleID).
					Detail("subject_id", subjectID).
					Severity(interfaces.AuditSeverityHigh)
				_ = m.auditManager.RecordEvent(ctx, event)
			}
			return fmt.Errorf("failed to persist role revocation: %w", persistErr)
		}
	}
	
	// Record successful audit event
	if m.auditManager != nil {
		event := audit.UserManagementEvent(tenantID, subjectID, subjectID, "revoke_role").
			Resource("role_assignment", roleID, "").
			Result(interfaces.AuditResultSuccess).
			Detail("revoked_role", roleID).
			Detail("subject_id", subjectID).
			Severity(interfaces.AuditSeverityHigh)
		_ = m.auditManager.RecordEvent(ctx, event)
	}
	
	return nil
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

// Authorization Engine Methods (delegated to advanced engine)
func (m *Manager) ValidateAccess(ctx context.Context, authContext *common.AuthorizationContext, requiredPermission string) (*common.AccessResponse, error) {
	return m.advancedEngine.ValidateAccess(ctx, authContext, requiredPermission)
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
			// Check if the proposed parent is already an ancestor of the child
			// This would create a circular dependency
			if err := m.checkForCircularDependency(ctx, childRoleID, parentRoleID); err != nil {
				return err
			}
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

// checkForCircularDependency checks if setting parentRoleID as parent of childRoleID would create a cycle
func (m *Manager) checkForCircularDependency(ctx context.Context, childRoleID, parentRoleID string) error {
	// Traverse up the hierarchy from parentRoleID
	// If we find childRoleID, then setting childRoleID -> parentRoleID would create a cycle
	visited := make(map[string]bool)
	return m.checkAncestorsForRole(ctx, parentRoleID, childRoleID, visited)
}

// checkAncestorsForRole recursively checks if targetRoleID appears in the ancestor chain of startRoleID
func (m *Manager) checkAncestorsForRole(ctx context.Context, startRoleID, targetRoleID string, visited map[string]bool) error {
	if visited[startRoleID] {
		return nil // Already checked this branch
	}
	visited[startRoleID] = true
	
	if startRoleID == targetRoleID {
		return fmt.Errorf("circular dependency detected: role %s is already an ancestor of role %s", targetRoleID, startRoleID)
	}
	
	// Get the current role to check its parent
	role, err := m.store.GetRole(ctx, startRoleID)
	if err != nil {
		return err
	}
	
	// If this role has a parent, recursively check the parent chain
	if role.ParentRoleId != "" {
		return m.checkAncestorsForRole(ctx, role.ParentRoleId, targetRoleID, visited)
	}
	
	return nil
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


// Delegate hierarchy store operations
func (m *Manager) GetChildRoles(ctx context.Context, roleID string) ([]*common.Role, error) {
	return m.store.GetChildRoles(ctx, roleID)
}

func (m *Manager) GetParentRole(ctx context.Context, roleID string) (*common.Role, error) {
	return m.store.GetParentRole(ctx, roleID)
}

func (m *Manager) SetRoleParent(ctx context.Context, roleID, parentRoleID string, inheritanceType common.RoleInheritanceType) error {
	// Use escalation prevention manager for enhanced security
	return m.escalationPreventionMgr.ValidateAndSetRoleParent(ctx, roleID, parentRoleID, inheritanceType, "system")
}

func (m *Manager) RemoveRoleParent(ctx context.Context, roleID string) error {
	return m.store.RemoveRoleParent(ctx, roleID)
}

func (m *Manager) ValidateRoleHierarchy(ctx context.Context, roleID string) error {
	return m.hierarchyEngine.ValidateHierarchy(ctx, roleID)
}

// Advanced Permission Management Methods

// CheckPermissionWithContext performs advanced permission checking with context
func (m *Manager) CheckPermissionWithContext(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return m.advancedEngine.CheckPermission(ctx, request)
}

// CheckConditionalPermission checks a conditional permission with full context evaluation
func (m *Manager) CheckConditionalPermission(ctx context.Context, request *common.AccessRequest, conditionalPerm *common.ConditionalPermission, authContext *common.AuthorizationContext) (*common.AccessResponse, error) {
	return m.advancedEngine.CheckConditionalPermission(ctx, request, conditionalPerm, authContext)
}

// CreateDelegation creates a new permission delegation
func (m *Manager) CreateDelegation(ctx context.Context, req *DelegationRequest) (*common.PermissionDelegation, error) {
	return m.delegationManager.CreateDelegation(ctx, req)
}

// RevokeDelegation revokes an existing permission delegation
func (m *Manager) RevokeDelegation(ctx context.Context, delegationID string, revokerID string) error {
	return m.delegationManager.RevokeDelegation(ctx, delegationID, revokerID)
}

// GetActiveDelegations returns active delegations for a delegatee
func (m *Manager) GetActiveDelegations(ctx context.Context, delegateeID string, tenantID string) ([]*common.PermissionDelegation, error) {
	return m.delegationManager.GetActiveDelegations(ctx, delegateeID, tenantID)
}

// CreateTemporaryPermission creates a temporary permission grant with conditions
func (m *Manager) CreateTemporaryPermission(ctx context.Context, req *TemporaryPermissionRequest) (*common.ConditionalPermission, error) {
	return m.advancedEngine.CreateTemporaryPermission(ctx, req)
}

// GetAuditEntries retrieves audit entries with filtering
func (m *Manager) GetAuditEntries(ctx context.Context, filter *AuditFilter) ([]*common.PermissionAuditEntry, error) {
	return m.auditLogger.GetAuditEntries(ctx, filter)
}

// GetComplianceReport generates a compliance report
func (m *Manager) GetComplianceReport(ctx context.Context, filter *AuditFilter) (*ComplianceReport, error) {
	return m.auditLogger.GetComplianceReport(ctx, filter)
}

// GetSecurityAlerts identifies potential security issues
func (m *Manager) GetSecurityAlerts(ctx context.Context, lookbackHours int) ([]*SecurityAlert, error) {
	return m.auditLogger.GetSecurityAlerts(ctx, lookbackHours)
}

// CreateTemplate creates a new permission template
func (m *Manager) CreateTemplate(ctx context.Context, req *TemplateCreateRequest) (*common.PermissionTemplate, error) {
	return m.templateManager.CreateTemplate(ctx, req)
}

// ApplyTemplate applies a template to create roles and assign permissions
func (m *Manager) ApplyTemplate(ctx context.Context, templateID, subjectID, tenantID string, customizations map[string]string) error {
	return m.templateManager.ApplyTemplate(ctx, templateID, subjectID, tenantID, customizations)
}

// ListTemplates lists available permission templates
func (m *Manager) ListTemplates(ctx context.Context, tenantID, category string) ([]*common.PermissionTemplate, error) {
	return m.templateManager.ListTemplates(ctx, tenantID, category)
}

// GetTemplatesByCategory returns templates grouped by category
func (m *Manager) GetTemplatesByCategory(ctx context.Context, tenantID string) (map[string][]*common.PermissionTemplate, error) {
	return m.templateManager.GetTemplatesByCategory(ctx, tenantID)
}

// GetDelegationStats returns delegation statistics for a tenant
func (m *Manager) GetDelegationStats(ctx context.Context, tenantID string) (*DelegationStats, error) {
	return m.delegationManager.GetDelegationStats(ctx, tenantID)
}

// ExportAuditLog exports audit entries in various formats
func (m *Manager) ExportAuditLog(ctx context.Context, filter *AuditFilter, format string) ([]byte, error) {
	return m.auditLogger.ExportAuditLog(ctx, filter, format)
}

// CleanupExpiredDelegations removes expired delegations
func (m *Manager) CleanupExpiredDelegations(ctx context.Context) error {
	return m.delegationManager.CleanupExpiredDelegations(ctx)
}

// Privilege Escalation Prevention Methods

// GetEscalationAlerts returns recent privilege escalation alerts
func (m *Manager) GetEscalationAlerts() []EscalationAlert {
	return m.escalationPreventionMgr.GetEscalationAlerts()
}

// GetEscalationPreventionMetrics returns comprehensive metrics about escalation prevention
func (m *Manager) GetEscalationPreventionMetrics() map[string]interface{} {
	return m.escalationPreventionMgr.GetMetrics()
}

// GetOperationLog returns recent RBAC operations for audit purposes
func (m *Manager) GetOperationLog() []OperationRecord {
	return m.escalationPreventionMgr.GetOperationLog()
}

// GetStore returns the internal store (for testing purposes)
func (m *Manager) GetStore() *memory.Store {
	return m.store
}

func (m *Manager) GetRBACStore() interfaces.RBACStore {
	return m.rbacStore
}

// Override CheckPermission to use advanced engine by default
func (m *Manager) CheckPermission(ctx context.Context, request *common.AccessRequest) (*common.AccessResponse, error) {
	return m.advancedEngine.CheckPermission(ctx, request)
}

// Override GetSubjectPermissions to include delegated permissions
func (m *Manager) GetSubjectPermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return m.advancedEngine.GetSubjectPermissions(ctx, subjectID, tenantID)
}

// Override GetEffectivePermissions to include advanced features
func (m *Manager) GetEffectivePermissions(ctx context.Context, subjectID, tenantID string) ([]*common.Permission, error) {
	return m.advancedEngine.GetEffectivePermissions(ctx, subjectID, tenantID)
}

// Verify that Manager implements the RBACManager interface
var _ RBACManager = (*Manager)(nil)