package rbac

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/rbac/memory"
)

// HierarchyEngine handles role hierarchy operations and permission inheritance
type HierarchyEngine struct {
	roleStore       RoleStore
	permissionStore PermissionStore
}

// NewHierarchyEngine creates a new hierarchy engine
func NewHierarchyEngine(roleStore RoleStore, permissionStore PermissionStore) *HierarchyEngine {
	return &HierarchyEngine{
		roleStore:       roleStore,
		permissionStore: permissionStore,
	}
}

// ComputeEffectivePermissions computes all effective permissions for a role considering inheritance
func (h *HierarchyEngine) ComputeEffectivePermissions(ctx context.Context, roleID string) (*memory.EffectivePermissions, error) {
	// Get the role hierarchy
	hierarchy, err := h.buildRoleHierarchy(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to build role hierarchy: %w", err)
	}

	// Collect permissions from the hierarchy
	directPermissions, inheritedPermissions, err := h.collectHierarchyPermissions(ctx, hierarchy)
	if err != nil {
		return nil, fmt.Errorf("failed to collect hierarchy permissions: %w", err)
	}

	// Resolve conflicts
	conflicts, err := h.detectPermissionConflicts(directPermissions, inheritedPermissions)
	if err != nil {
		return nil, fmt.Errorf("failed to detect conflicts: %w", err)
	}

	conflictResolution, err := h.resolveConflicts(ctx, roleID, conflicts, hierarchy)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve conflicts: %w", err)
	}

	return &memory.EffectivePermissions{
		RoleID:             roleID,
		DirectPermissions:  directPermissions,
		InheritedPermissions: inheritedPermissions,
		ConflictResolution: conflictResolution,
		ComputedAt:         time.Now(),
	}, nil
}

// buildRoleHierarchy builds the complete hierarchy tree for a role
func (h *HierarchyEngine) buildRoleHierarchy(ctx context.Context, roleID string) (*memory.RoleHierarchy, error) {
	visited := make(map[string]bool)
	return h.buildRoleHierarchyWithVisited(ctx, roleID, 0, visited)
}

// buildRoleHierarchyWithVisited builds hierarchy with cycle detection
// For permission computation, we only build parent chain to avoid circular issues
func (h *HierarchyEngine) buildRoleHierarchyWithVisited(ctx context.Context, roleID string, depth int, visited map[string]bool) (*memory.RoleHierarchy, error) {
	// Cycle detection
	if visited[roleID] {
		return nil, fmt.Errorf("circular dependency detected in role hierarchy for role %s", roleID)
	}
	visited[roleID] = true
	defer func() { delete(visited, roleID) }()

	role, err := h.roleStore.GetRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role %s: %w", roleID, err)
	}

	hierarchy := &memory.RoleHierarchy{
		Role:  role,
		Depth: depth,
	}

	// Build parent chain only (inheritance flows down from parents)
	if role.ParentRoleId != "" && depth < 10 {
		parent, err := h.buildRoleHierarchyWithVisited(ctx, role.ParentRoleId, depth+1, visited)
		if err != nil {
			return nil, fmt.Errorf("failed to build parent hierarchy: %w", err)
		}
		hierarchy.Parent = parent
	}

	// Don't build children for permission computation to avoid cycles
	// Children can be retrieved separately if needed via GetChildRoles

	return hierarchy, nil
}

// collectHierarchyPermissions collects permissions from the role hierarchy
func (h *HierarchyEngine) collectHierarchyPermissions(ctx context.Context, hierarchy *memory.RoleHierarchy) (
	[]*common.Permission, 
	map[string][]*common.Permission, 
	error,
) {
	// Get direct permissions for this role
	directPermissions, err := h.roleStore.GetRolePermissions(ctx, hierarchy.Role.Id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get role permissions: %w", err)
	}

	inheritedPermissions := make(map[string][]*common.Permission)

	// Collect inherited permissions based on inheritance type
	if hierarchy.Parent != nil {
		parentPermissions, err := h.roleStore.GetRolePermissions(ctx, hierarchy.Parent.Role.Id)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get parent permissions: %w", err)
		}

		switch hierarchy.Role.InheritanceType {
		case common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE:
			// Inherit all parent permissions
			inheritedPermissions[hierarchy.Parent.Role.Id] = parentPermissions
			
			// Recursively collect from grandparents
			if hierarchy.Parent.Parent != nil {
				_, grandparentInherited, err := h.collectHierarchyPermissions(ctx, hierarchy.Parent)
				if err != nil {
					return nil, nil, err
				}
				for roleID, perms := range grandparentInherited {
					inheritedPermissions[roleID] = perms
				}
			}

		case common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE:
			// Inherit parent permissions, but own permissions take precedence
			inheritedPermissions[hierarchy.Parent.Role.Id] = parentPermissions

		case common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE:
			// Only permissions present in both parent and child
			restrictedPermissions := h.intersectPermissions(directPermissions, parentPermissions)
			inheritedPermissions[hierarchy.Parent.Role.Id] = restrictedPermissions

		case common.RoleInheritanceType_ROLE_INHERITANCE_NONE:
			// No inheritance - use only direct permissions
		}
	}

	return directPermissions, inheritedPermissions, nil
}

// intersectPermissions returns permissions that exist in both sets
func (h *HierarchyEngine) intersectPermissions(set1, set2 []*common.Permission) []*common.Permission {
	permissionMap := make(map[string]*common.Permission)
	
	// Create map of first set
	for _, perm := range set1 {
		permissionMap[perm.Id] = perm
	}

	var intersection []*common.Permission
	for _, perm := range set2 {
		if _, exists := permissionMap[perm.Id]; exists {
			intersection = append(intersection, perm)
		}
	}

	return intersection
}

// detectPermissionConflicts identifies conflicting permissions across the hierarchy
func (h *HierarchyEngine) detectPermissionConflicts(
	direct []*common.Permission,
	inherited map[string][]*common.Permission,
) (map[string][]*common.Permission, error) {
	conflicts := make(map[string][]*common.Permission)
	
	// Build map of direct permissions
	directMap := make(map[string]*common.Permission)
	for _, perm := range direct {
		directMap[perm.Id] = perm
	}

	// Check for conflicts with inherited permissions
	for _, permissions := range inherited {
		for _, perm := range permissions {
			if directPerm, exists := directMap[perm.Id]; exists {
				// Same permission ID exists in both direct and inherited
				if h.permissionsConflict(directPerm, perm) {
					conflictKey := perm.Id
					if conflicts[conflictKey] == nil {
						conflicts[conflictKey] = make([]*common.Permission, 0)
					}
					conflicts[conflictKey] = append(conflicts[conflictKey], perm)
				}
			}
		}
	}

	return conflicts, nil
}

// permissionsConflict checks if two permissions with the same ID have conflicting definitions
func (h *HierarchyEngine) permissionsConflict(perm1, perm2 *common.Permission) bool {
	// Permissions conflict if they have different resource types or actions
	if perm1.ResourceType != perm2.ResourceType {
		return true
	}

	// Check if actions differ
	actions1 := make(map[string]bool)
	for _, action := range perm1.Actions {
		actions1[action] = true
	}

	for _, action := range perm2.Actions {
		if !actions1[action] {
			return true
		}
	}

	return len(perm1.Actions) != len(perm2.Actions)
}

// resolveConflicts resolves permission conflicts based on inheritance type and role hierarchy
func (h *HierarchyEngine) resolveConflicts(
	ctx context.Context,
	roleID string,
	conflicts map[string][]*common.Permission,
	hierarchy *memory.RoleHierarchy,
) (map[string]memory.ConflictResult, error) {
	resolution := make(map[string]memory.ConflictResult)

	role := hierarchy.Role
	for permissionID, conflictingPermissions := range conflicts {
		// Get the direct permission for this role
		directPermissions, err := h.roleStore.GetRolePermissions(ctx, roleID)
		if err != nil {
			return nil, fmt.Errorf("failed to get direct permissions: %w", err)
		}

		var directPerm *common.Permission
		for _, perm := range directPermissions {
			if perm.Id == permissionID {
				directPerm = perm
				break
			}
		}

		if directPerm == nil {
			continue
		}

		var resolvedPermission *common.Permission
		var resolutionType string
		var conflictedWith []string

		for _, conflictPerm := range conflictingPermissions {
			conflictedWith = append(conflictedWith, conflictPerm.Id)
		}

		switch role.InheritanceType {
		case common.RoleInheritanceType_ROLE_INHERITANCE_ADDITIVE:
			// Merge permissions - combine all actions
			resolvedPermission = h.mergePermissions(directPerm, conflictingPermissions)
			resolutionType = "merge"

		case common.RoleInheritanceType_ROLE_INHERITANCE_OVERRIDE:
			// Direct permission overrides inherited
			resolvedPermission = directPerm
			resolutionType = "override"

		case common.RoleInheritanceType_ROLE_INHERITANCE_RESTRICTIVE:
			// Use intersection of permissions
			resolvedPermission = h.restrictPermissions(directPerm, conflictingPermissions)
			resolutionType = "restrict"

		default:
			// Default to override behavior
			resolvedPermission = directPerm
			resolutionType = "override"
		}

		resolution[permissionID] = memory.ConflictResult{
			Permission:     resolvedPermission,
			SourceRoleID:   roleID,
			Resolution:     resolutionType,
			ConflictedWith: conflictedWith,
		}
	}

	return resolution, nil
}

// mergePermissions combines permissions by merging their actions
func (h *HierarchyEngine) mergePermissions(direct *common.Permission, inherited []*common.Permission) *common.Permission {
	actionSet := make(map[string]bool)
	
	// Add direct permission actions
	for _, action := range direct.Actions {
		actionSet[action] = true
	}

	// Add inherited permission actions
	for _, perm := range inherited {
		for _, action := range perm.Actions {
			actionSet[action] = true
		}
	}

	// Convert back to slice
	var actions []string
	for action := range actionSet {
		actions = append(actions, action)
	}

	return &common.Permission{
		Id:           direct.Id,
		Name:         direct.Name,
		Description:  direct.Description,
		ResourceType: direct.ResourceType,
		Actions:      actions,
	}
}

// restrictPermissions returns only actions that exist in all permissions
func (h *HierarchyEngine) restrictPermissions(direct *common.Permission, inherited []*common.Permission) *common.Permission {
	if len(inherited) == 0 {
		return direct
	}

	// Start with direct permission actions
	actionSet := make(map[string]bool)
	for _, action := range direct.Actions {
		actionSet[action] = true
	}

	// Intersect with each inherited permission
	for _, perm := range inherited {
		inheritedActions := make(map[string]bool)
		for _, action := range perm.Actions {
			inheritedActions[action] = true
		}

		// Keep only actions that exist in both
		for action := range actionSet {
			if !inheritedActions[action] {
				delete(actionSet, action)
			}
		}
	}

	// Convert back to slice
	var actions []string
	for action := range actionSet {
		actions = append(actions, action)
	}

	return &common.Permission{
		Id:           direct.Id,
		Name:         direct.Name,
		Description:  direct.Description,
		ResourceType: direct.ResourceType,
		Actions:      actions,
	}
}

// ValidateHierarchy validates that a role hierarchy is valid (no cycles, proper inheritance)
func (h *HierarchyEngine) ValidateHierarchy(ctx context.Context, roleID string) error {
	visited := make(map[string]bool)
	return h.detectCycles(ctx, roleID, visited, make(map[string]bool))
}

// detectCycles detects circular dependencies in role hierarchy
func (h *HierarchyEngine) detectCycles(ctx context.Context, roleID string, visited, inPath map[string]bool) error {
	if inPath[roleID] {
		return fmt.Errorf("circular dependency detected involving role %s", roleID)
	}
	
	if visited[roleID] {
		return nil
	}

	visited[roleID] = true
	inPath[roleID] = true

	role, err := h.roleStore.GetRole(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get role %s: %w", roleID, err)
	}

	if role.ParentRoleId != "" {
		if err := h.detectCycles(ctx, role.ParentRoleId, visited, inPath); err != nil {
			return err
		}
	}

	children, err := h.roleStore.GetChildRoles(ctx, roleID)
	if err != nil {
		return fmt.Errorf("failed to get child roles: %w", err)
	}

	for _, child := range children {
		if err := h.detectCycles(ctx, child.Id, visited, inPath); err != nil {
			return err
		}
	}

	inPath[roleID] = false
	return nil
}