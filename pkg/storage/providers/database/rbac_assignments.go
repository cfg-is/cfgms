// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
)

// Role assignment management

// StoreRoleAssignment implements RBACStore.StoreRoleAssignment
func (s *DatabaseRBACStore) StoreRoleAssignment(ctx context.Context, assignment *common.RoleAssignment) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Generate ID if not provided
	if assignment.Id == "" {
		assignment.Id = fmt.Sprintf("%s-%s-%s", assignment.SubjectId, assignment.RoleId, assignment.TenantId)
	}

	query := `
		INSERT INTO rbac_role_assignments (id, subject_id, role_id, tenant_id, expires_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (id) DO UPDATE SET
			expires_at = EXCLUDED.expires_at,
			updated_at = NOW()
	`

	var expiresAt sql.NullTime
	if assignment.ExpiresAt != 0 {
		expiresAt = sql.NullTime{Time: time.Unix(assignment.ExpiresAt, 0), Valid: true}
	}

	_, err = tx.ExecContext(ctx, query,
		assignment.Id,
		assignment.SubjectId,
		assignment.RoleId,
		assignment.TenantId,
		expiresAt,
		assignment.AssignedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to store role assignment: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetRoleAssignment implements RBACStore.GetRoleAssignment
func (s *DatabaseRBACStore) GetRoleAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, subject_id, role_id, tenant_id, expires_at, created_by, created_at
		FROM rbac_role_assignments
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	assignment := &common.RoleAssignment{}
	var expiresAt sql.NullTime
	var createdAt time.Time

	err := row.Scan(
		&assignment.Id,
		&assignment.SubjectId,
		&assignment.RoleId,
		&assignment.TenantId,
		&expiresAt,
		&assignment.AssignedBy,
		&createdAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role assignment not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get role assignment: %w", err)
	}

	// Handle nullable expires_at
	if expiresAt.Valid {
		assignment.ExpiresAt = expiresAt.Time.Unix()
	}

	assignment.AssignedAt = createdAt.Unix()

	return assignment, nil
}

// ListRoleAssignments implements RBACStore.ListRoleAssignments
func (s *DatabaseRBACStore) ListRoleAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, subject_id, role_id, tenant_id, expires_at, created_by, created_at
		FROM rbac_role_assignments
		WHERE 1=1
	`

	var args []interface{}
	argCount := 0

	if subjectID != "" {
		argCount++
		query += fmt.Sprintf(" AND subject_id = $%d", argCount)
		args = append(args, subjectID)
	}

	if roleID != "" {
		argCount++
		query += fmt.Sprintf(" AND role_id = $%d", argCount)
		args = append(args, roleID)
	}

	if tenantID != "" {
		argCount++
		query += fmt.Sprintf(" AND tenant_id = $%d", argCount)
		args = append(args, tenantID)
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list role assignments: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var assignments []*common.RoleAssignment

	for rows.Next() {
		assignment := &common.RoleAssignment{}
		var expiresAt sql.NullTime
		var createdAt time.Time

		err := rows.Scan(
			&assignment.Id,
			&assignment.SubjectId,
			&assignment.RoleId,
			&assignment.TenantId,
			&expiresAt,
			&assignment.AssignedBy,
			&createdAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan role assignment: %w", err)
		}

		// Handle nullable expires_at
		if expiresAt.Valid {
			assignment.ExpiresAt = expiresAt.Time.Unix()
		}

		assignment.AssignedAt = createdAt.Unix()

		assignments = append(assignments, assignment)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating role assignments: %w", err)
	}

	return assignments, nil
}

// DeleteRoleAssignment implements RBACStore.DeleteRoleAssignment
func (s *DatabaseRBACStore) DeleteRoleAssignment(ctx context.Context, subjectID, roleID, tenantID string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM rbac_role_assignments WHERE subject_id = $1 AND role_id = $2 AND tenant_id = $3`

	result, err := tx.ExecContext(ctx, query, subjectID, roleID, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete role assignment: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role assignment not found: subject=%s, role=%s, tenant=%s", subjectID, roleID, tenantID)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
