package git

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cfgis/cfgms/api/proto/common"
)

// GitRBACStore implements RBACStore using git for persistence
// This is a basic implementation that stores RBAC data in JSON files within a git repository
type GitRBACStore struct {
	repoPath  string
	remoteURL string
}

// NewGitRBACStore creates a new git-based RBAC store
func NewGitRBACStore(repoPath, remoteURL string) (*GitRBACStore, error) {
	store := &GitRBACStore{
		repoPath:  repoPath,
		remoteURL: remoteURL,
	}
	
	// Initialize git repository if it doesn't exist
	if err := store.initializeRepo(); err != nil {
		return nil, fmt.Errorf("failed to initialize git repository: %w", err)
	}
	
	return store, nil
}

// initializeRepo ensures the git repository exists
func (s *GitRBACStore) initializeRepo() error {
	// Check if directory exists
	if _, err := os.Stat(s.repoPath); os.IsNotExist(err) {
		// Create directory
		if err := os.MkdirAll(s.repoPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory: %w", err)
		}
	}
	
	// Create subdirectories for RBAC data
	dirs := []string{"permissions", "roles", "subjects", "assignments"}
	for _, dir := range dirs {
		fullPath := filepath.Join(s.repoPath, dir)
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	
	return nil
}

// Initialize implements RBACStore.Initialize
func (s *GitRBACStore) Initialize(ctx context.Context) error {
	return s.initializeRepo()
}

// Close implements RBACStore.Close
func (s *GitRBACStore) Close() error {
	return nil
}

// Permission management

// StorePermission implements RBACStore.StorePermission
func (s *GitRBACStore) StorePermission(ctx context.Context, permission *common.Permission) error {
	data, err := json.MarshalIndent(permission, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal permission: %w", err)
	}
	
	filePath := filepath.Join(s.repoPath, "permissions", permission.Id+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write permission file: %w", err)
	}
	
	return nil
}

// GetPermission implements RBACStore.GetPermission
func (s *GitRBACStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	filePath := filepath.Join(s.repoPath, "permissions", id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("permission not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read permission file: %w", err)
	}
	
	var permission common.Permission
	if err := json.Unmarshal(data, &permission); err != nil {
		return nil, fmt.Errorf("failed to unmarshal permission: %w", err)
	}
	
	return &permission, nil
}

// ListPermissions implements RBACStore.ListPermissions
func (s *GitRBACStore) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	permissionsDir := filepath.Join(s.repoPath, "permissions")
	files, err := filepath.Glob(filepath.Join(permissionsDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to list permission files: %w", err)
	}
	
	var permissions []*common.Permission
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip files that can't be read
		}
		
		var permission common.Permission
		if err := json.Unmarshal(data, &permission); err != nil {
			continue // Skip files that can't be parsed
		}
		
		// Filter by resource type if specified
		if resourceType == "" || permission.ResourceType == resourceType {
			permissions = append(permissions, &permission)
		}
	}
	
	return permissions, nil
}

// UpdatePermission implements RBACStore.UpdatePermission
func (s *GitRBACStore) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	return s.StorePermission(ctx, permission)
}

// DeletePermission implements RBACStore.DeletePermission
func (s *GitRBACStore) DeletePermission(ctx context.Context, id string) error {
	filePath := filepath.Join(s.repoPath, "permissions", id+".json")
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("permission not found: %s", id)
		}
		return fmt.Errorf("failed to delete permission file: %w", err)
	}
	
	return nil
}

// Role management

// StoreRole implements RBACStore.StoreRole
func (s *GitRBACStore) StoreRole(ctx context.Context, role *common.Role) error {
	data, err := json.MarshalIndent(role, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal role: %w", err)
	}
	
	filePath := filepath.Join(s.repoPath, "roles", role.Id+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write role file: %w", err)
	}
	
	return nil
}

// GetRole implements RBACStore.GetRole
func (s *GitRBACStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	filePath := filepath.Join(s.repoPath, "roles", id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("role not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read role file: %w", err)
	}
	
	var role common.Role
	if err := json.Unmarshal(data, &role); err != nil {
		return nil, fmt.Errorf("failed to unmarshal role: %w", err)
	}
	
	return &role, nil
}

// ListRoles implements RBACStore.ListRoles
func (s *GitRBACStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	rolesDir := filepath.Join(s.repoPath, "roles")
	files, err := filepath.Glob(filepath.Join(rolesDir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to list role files: %w", err)
	}
	
	var roles []*common.Role
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip files that can't be read
		}
		
		var role common.Role
		if err := json.Unmarshal(data, &role); err != nil {
			continue // Skip files that can't be parsed
		}
		
		// Filter by tenant ID if specified
		if tenantID == "" || role.TenantId == tenantID || role.IsSystemRole {
			roles = append(roles, &role)
		}
	}
	
	return roles, nil
}

// UpdateRole implements RBACStore.UpdateRole
func (s *GitRBACStore) UpdateRole(ctx context.Context, role *common.Role) error {
	return s.StoreRole(ctx, role)
}

// DeleteRole implements RBACStore.DeleteRole
func (s *GitRBACStore) DeleteRole(ctx context.Context, id string) error {
	filePath := filepath.Join(s.repoPath, "roles", id+".json")
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("role not found: %s", id)
		}
		return fmt.Errorf("failed to delete role file: %w", err)
	}
	
	return nil
}

// Subject management - basic stubs for interface compliance

// StoreSubject implements RBACStore.StoreSubject
func (s *GitRBACStore) StoreSubject(ctx context.Context, subject *common.Subject) error {
	data, err := json.MarshalIndent(subject, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal subject: %w", err)
	}
	
	filePath := filepath.Join(s.repoPath, "subjects", subject.Id+".json")
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write subject file: %w", err)
	}
	
	return nil
}

// GetSubject implements RBACStore.GetSubject
func (s *GitRBACStore) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	filePath := filepath.Join(s.repoPath, "subjects", id+".json")
	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("subject not found: %s", id)
		}
		return nil, fmt.Errorf("failed to read subject file: %w", err)
	}
	
	var subject common.Subject
	if err := json.Unmarshal(data, &subject); err != nil {
		return nil, fmt.Errorf("failed to unmarshal subject: %w", err)
	}
	
	return &subject, nil
}

// ListSubjects implements RBACStore.ListSubjects
func (s *GitRBACStore) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	// Basic implementation - return empty list
	return []*common.Subject{}, nil
}

// UpdateSubject implements RBACStore.UpdateSubject
func (s *GitRBACStore) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	return s.StoreSubject(ctx, subject)
}

// DeleteSubject implements RBACStore.DeleteSubject
func (s *GitRBACStore) DeleteSubject(ctx context.Context, id string) error {
	filePath := filepath.Join(s.repoPath, "subjects", id+".json")
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("subject not found: %s", id)
		}
		return fmt.Errorf("failed to delete subject file: %w", err)
	}
	
	return nil
}

// Role assignment management - basic stubs for interface compliance

// StoreRoleAssignment implements RBACStore.StoreRoleAssignment
func (s *GitRBACStore) StoreRoleAssignment(ctx context.Context, assignment *common.RoleAssignment) error {
	data, err := json.MarshalIndent(assignment, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal assignment: %w", err)
	}
	
	fileName := fmt.Sprintf("%s-%s-%s.json", assignment.SubjectId, assignment.RoleId, assignment.TenantId)
	filePath := filepath.Join(s.repoPath, "assignments", fileName)
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write assignment file: %w", err)
	}
	
	return nil
}

// GetRoleAssignment implements RBACStore.GetRoleAssignment
func (s *GitRBACStore) GetRoleAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	// For now, this is not used by the RBAC manager directly
	// The assignment lookups happen via ListRoleAssignments
	return nil, fmt.Errorf("role assignment not found: %s", id)
}

// ListRoleAssignments implements RBACStore.ListRoleAssignments
func (s *GitRBACStore) ListRoleAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	assignmentsDir := filepath.Join(s.repoPath, "assignments")
	
	// Read all assignment files and filter based on parameters
	files, err := os.ReadDir(assignmentsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []*common.RoleAssignment{}, nil
		}
		return nil, fmt.Errorf("failed to read assignments directory: %w", err)
	}
	
	var assignments []*common.RoleAssignment
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		
		filePath := filepath.Join(assignmentsDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue // Skip files that can't be read
		}
		
		var assignment common.RoleAssignment
		if err := json.Unmarshal(data, &assignment); err != nil {
			continue // Skip files that can't be parsed
		}
		
		// Apply filters
		if subjectID != "" && assignment.SubjectId != subjectID {
			continue
		}
		if roleID != "" && assignment.RoleId != roleID {
			continue
		}
		if tenantID != "" && assignment.TenantId != tenantID {
			continue
		}
		
		assignments = append(assignments, &assignment)
	}
	
	return assignments, nil
}

// DeleteRoleAssignment implements RBACStore.DeleteRoleAssignment
func (s *GitRBACStore) DeleteRoleAssignment(ctx context.Context, subjectID, roleID, tenantID string) error {
	fileName := fmt.Sprintf("%s-%s-%s.json", subjectID, roleID, tenantID)
	filePath := filepath.Join(s.repoPath, "assignments", fileName)
	if err := os.Remove(filePath); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("role assignment not found: subject=%s, role=%s, tenant=%s", subjectID, roleID, tenantID)
		}
		return fmt.Errorf("failed to delete assignment file: %w", err)
	}
	
	return nil
}

// Bulk operations - basic stubs for interface compliance

// StoreBulkPermissions implements RBACStore.StoreBulkPermissions
func (s *GitRBACStore) StoreBulkPermissions(ctx context.Context, permissions []*common.Permission) error {
	for _, permission := range permissions {
		if err := s.StorePermission(ctx, permission); err != nil {
			return err
		}
	}
	return nil
}

// StoreBulkRoles implements RBACStore.StoreBulkRoles
func (s *GitRBACStore) StoreBulkRoles(ctx context.Context, roles []*common.Role) error {
	for _, role := range roles {
		if err := s.StoreRole(ctx, role); err != nil {
			return err
		}
	}
	return nil
}

// StoreBulkSubjects implements RBACStore.StoreBulkSubjects
func (s *GitRBACStore) StoreBulkSubjects(ctx context.Context, subjects []*common.Subject) error {
	for _, subject := range subjects {
		if err := s.StoreSubject(ctx, subject); err != nil {
			return err
		}
	}
	return nil
}

// Query operations - basic stubs for interface compliance

// GetSubjectRoles implements RBACStore.GetSubjectRoles
func (s *GitRBACStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	return []*common.Role{}, nil
}

// GetRolePermissions implements RBACStore.GetRolePermissions
func (s *GitRBACStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	
	var permissions []*common.Permission
	for _, permissionID := range role.PermissionIds {
		permission, err := s.GetPermission(ctx, permissionID)
		if err != nil {
			continue // Skip permissions that don't exist
		}
		permissions = append(permissions, permission)
	}
	
	return permissions, nil
}

// GetSubjectAssignments implements RBACStore.GetSubjectAssignments
func (s *GitRBACStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	// Use ListRoleAssignments with subjectID and tenantID filters
	return s.ListRoleAssignments(ctx, subjectID, "", tenantID)
}