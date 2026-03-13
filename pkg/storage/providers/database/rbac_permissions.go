// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/cfgis/cfgms/api/proto/common"
)

// Permission management

// StorePermission implements RBACStore.StorePermission
func (s *DatabaseRBACStore) StorePermission(ctx context.Context, permission *common.Permission) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize actions array to JSON
	actionsJSON, err := json.Marshal(permission.Actions)
	if err != nil {
		return fmt.Errorf("failed to serialize actions: %w", err)
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
		return fmt.Errorf("failed to store permission: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetPermission implements RBACStore.GetPermission
func (s *DatabaseRBACStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, resource_type, actions
		FROM rbac_permissions
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	permission := &common.Permission{}
	var actionsJSON []byte

	err := row.Scan(
		&permission.Id,
		&permission.Name,
		&permission.Description,
		&permission.ResourceType,
		&actionsJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("permission not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get permission: %w", err)
	}

	// Deserialize actions from JSON
	if err := json.Unmarshal(actionsJSON, &permission.Actions); err != nil {
		return nil, fmt.Errorf("failed to deserialize actions: %w", err)
	}

	return permission, nil
}

// ListPermissions implements RBACStore.ListPermissions
func (s *DatabaseRBACStore) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var query string
	var args []interface{}

	if resourceType == "" {
		query = `
			SELECT id, name, description, resource_type, actions
			FROM rbac_permissions
			ORDER BY resource_type, name
		`
	} else {
		query = `
			SELECT id, name, description, resource_type, actions
			FROM rbac_permissions
			WHERE resource_type = $1
			ORDER BY name
		`
		args = []interface{}{resourceType}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list permissions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var permissions []*common.Permission

	for rows.Next() {
		permission := &common.Permission{}
		var actionsJSON []byte

		err := rows.Scan(
			&permission.Id,
			&permission.Name,
			&permission.Description,
			&permission.ResourceType,
			&actionsJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan permission: %w", err)
		}

		// Deserialize actions from JSON
		if err := json.Unmarshal(actionsJSON, &permission.Actions); err != nil {
			return nil, fmt.Errorf("failed to deserialize actions: %w", err)
		}

		permissions = append(permissions, permission)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating permissions: %w", err)
	}

	return permissions, nil
}

// UpdatePermission implements RBACStore.UpdatePermission
func (s *DatabaseRBACStore) UpdatePermission(ctx context.Context, permission *common.Permission) error {
	// Same implementation as StorePermission due to ON CONFLICT DO UPDATE
	return s.StorePermission(ctx, permission)
}

// DeletePermission implements RBACStore.DeletePermission
func (s *DatabaseRBACStore) DeletePermission(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM rbac_permissions WHERE id = $1`

	result, err := tx.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete permission: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("permission not found: %s", id)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

