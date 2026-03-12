// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cfgis/cfgms/api/proto/common"
)

// Bulk operations

// StoreBulkPermissions implements RBACStore.StoreBulkPermissions
func (s *DatabaseRBACStore) StoreBulkPermissions(ctx context.Context, permissions []*common.Permission) error {
	if len(permissions) == 0 {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Use batch insert for efficiency
	for _, permission := range permissions {
		actionsJSON, err := json.Marshal(permission.Actions)
		if err != nil {
			return fmt.Errorf("failed to serialize actions for permission %s: %w", permission.Id, err)
		}

		query := `
			INSERT INTO rbac_permissions (id, name, description, resource_type, actions)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				resource_type = EXCLUDED.resource_type,
				actions = EXCLUDED.actions,
				updated_at = NOW()
		`

		_, err = tx.ExecContext(ctx, query,
			permission.Id,
			permission.Name,
			permission.Description,
			permission.ResourceType,
			actionsJSON,
		)

		if err != nil {
			return fmt.Errorf("failed to store permission %s: %w", permission.Id, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// StoreBulkRoles implements RBACStore.StoreBulkRoles
func (s *DatabaseRBACStore) StoreBulkRoles(ctx context.Context, roles []*common.Role) error {
	if len(roles) == 0 {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Use batch insert for efficiency
	for _, role := range roles {
		permissionIDsJSON, err := json.Marshal(role.PermissionIds)
		if err != nil {
			return fmt.Errorf("failed to serialize permission IDs for role %s: %w", role.Id, err)
		}

		query := `
			INSERT INTO rbac_roles (id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (id) DO UPDATE SET
				name = EXCLUDED.name,
				description = EXCLUDED.description,
				permission_ids = EXCLUDED.permission_ids,
				is_system_role = EXCLUDED.is_system_role,
				tenant_id = EXCLUDED.tenant_id,
				parent_role_id = EXCLUDED.parent_role_id,
				inheritance_type = EXCLUDED.inheritance_type,
				updated_at = NOW()
		`

		_, err = tx.ExecContext(ctx, query,
			role.Id,
			role.Name,
			role.Description,
			permissionIDsJSON,
			role.IsSystemRole,
			role.TenantId,
			role.ParentRoleId,
			int32(role.InheritanceType),
		)

		if err != nil {
			return fmt.Errorf("failed to store role %s: %w", role.Id, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// StoreBulkSubjects implements RBACStore.StoreBulkSubjects
func (s *DatabaseRBACStore) StoreBulkSubjects(ctx context.Context, subjects []*common.Subject) error {
	if len(subjects) == 0 {
		return nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Use batch insert for efficiency
	for _, subject := range subjects {
		roleIDsJSON, err := json.Marshal(subject.RoleIds)
		if err != nil {
			return fmt.Errorf("failed to serialize role IDs for subject %s: %w", subject.Id, err)
		}

		attributesJSON, err := json.Marshal(subject.Attributes)
		if err != nil {
			return fmt.Errorf("failed to serialize attributes for subject %s: %w", subject.Id, err)
		}

		query := `
			INSERT INTO rbac_subjects (id, type, display_name, tenant_id, role_ids, is_active, attributes)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (id) DO UPDATE SET
				type = EXCLUDED.type,
				display_name = EXCLUDED.display_name,
				tenant_id = EXCLUDED.tenant_id,
				role_ids = EXCLUDED.role_ids,
				is_active = EXCLUDED.is_active,
				attributes = EXCLUDED.attributes,
				updated_at = NOW()
		`

		_, err = tx.ExecContext(ctx, query,
			subject.Id,
			int32(subject.Type),
			subject.DisplayName,
			subject.TenantId,
			roleIDsJSON,
			subject.IsActive,
			attributesJSON,
		)

		if err != nil {
			return fmt.Errorf("failed to store subject %s: %w", subject.Id, err)
		}
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
