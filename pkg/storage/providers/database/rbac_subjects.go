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

// Subject management

// StoreSubject implements RBACStore.StoreSubject
func (s *DatabaseRBACStore) StoreSubject(ctx context.Context, subject *common.Subject) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// H-TENANT-1: Validate tenant access before storing subject (security audit finding)
	// Subjects are never system-wide, always tenant-specific
	if err := s.validateTenantAccess(ctx, subject.TenantId, false); err != nil {
		return err
	}

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize role IDs and attributes to JSON
	roleIDsJSON, err := json.Marshal(subject.RoleIds)
	if err != nil {
		return fmt.Errorf("failed to serialize role IDs: %w", err)
	}

	attributesJSON, err := json.Marshal(subject.Attributes)
	if err != nil {
		return fmt.Errorf("failed to serialize attributes: %w", err)
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
		return fmt.Errorf("failed to store subject: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetSubject implements RBACStore.GetSubject
func (s *DatabaseRBACStore) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, type, display_name, tenant_id, role_ids, is_active, attributes
		FROM rbac_subjects
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	subject := &common.Subject{}
	var subjectType int32
	var roleIDsJSON, attributesJSON []byte

	err := row.Scan(
		&subject.Id,
		&subjectType,
		&subject.DisplayName,
		&subject.TenantId,
		&roleIDsJSON,
		&subject.IsActive,
		&attributesJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("subject not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get subject: %w", err)
	}

	// H-TENANT-1: Validate tenant access before returning subject (security audit finding)
	// Subjects are never system-wide, always tenant-specific
	if err := s.validateTenantAccess(ctx, subject.TenantId, false); err != nil {
		return nil, err
	}

	subject.Type = common.SubjectType(subjectType)

	// Deserialize role IDs and attributes from JSON
	if err := json.Unmarshal(roleIDsJSON, &subject.RoleIds); err != nil {
		return nil, fmt.Errorf("failed to deserialize role IDs: %w", err)
	}

	if err := json.Unmarshal(attributesJSON, &subject.Attributes); err != nil {
		return nil, fmt.Errorf("failed to deserialize attributes: %w", err)
	}

	return subject, nil
}

// ListSubjects implements RBACStore.ListSubjects
func (s *DatabaseRBACStore) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var query string
	var args []interface{}

	if tenantID == "" && subjectType == common.SubjectType_SUBJECT_TYPE_UNSPECIFIED {
		query = `
			SELECT id, type, display_name, tenant_id, role_ids, is_active, attributes
			FROM rbac_subjects
			ORDER BY tenant_id, type, display_name
		`
	} else if tenantID != "" && subjectType == common.SubjectType_SUBJECT_TYPE_UNSPECIFIED {
		query = `
			SELECT id, type, display_name, tenant_id, role_ids, is_active, attributes
			FROM rbac_subjects
			WHERE tenant_id = $1
			ORDER BY type, display_name
		`
		args = []interface{}{tenantID}
	} else if tenantID == "" && subjectType != common.SubjectType_SUBJECT_TYPE_UNSPECIFIED {
		query = `
			SELECT id, type, display_name, tenant_id, role_ids, is_active, attributes
			FROM rbac_subjects
			WHERE type = $1
			ORDER BY tenant_id, display_name
		`
		args = []interface{}{int32(subjectType)}
	} else {
		query = `
			SELECT id, type, display_name, tenant_id, role_ids, is_active, attributes
			FROM rbac_subjects
			WHERE tenant_id = $1 AND type = $2
			ORDER BY display_name
		`
		args = []interface{}{tenantID, int32(subjectType)}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list subjects: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var subjects []*common.Subject

	for rows.Next() {
		subject := &common.Subject{}
		var subjectTypeInt int32
		var roleIDsJSON, attributesJSON []byte

		err := rows.Scan(
			&subject.Id,
			&subjectTypeInt,
			&subject.DisplayName,
			&subject.TenantId,
			&roleIDsJSON,
			&subject.IsActive,
			&attributesJSON,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan subject: %w", err)
		}

		subject.Type = common.SubjectType(subjectTypeInt)

		// Deserialize role IDs and attributes from JSON
		if err := json.Unmarshal(roleIDsJSON, &subject.RoleIds); err != nil {
			return nil, fmt.Errorf("failed to deserialize role IDs: %w", err)
		}

		if err := json.Unmarshal(attributesJSON, &subject.Attributes); err != nil {
			return nil, fmt.Errorf("failed to deserialize attributes: %w", err)
		}

		subjects = append(subjects, subject)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subjects: %w", err)
	}

	return subjects, nil
}

// UpdateSubject implements RBACStore.UpdateSubject
func (s *DatabaseRBACStore) UpdateSubject(ctx context.Context, subject *common.Subject) error {
	// Same implementation as StoreSubject due to ON CONFLICT DO UPDATE
	return s.StoreSubject(ctx, subject)
}

// DeleteSubject implements RBACStore.DeleteSubject
func (s *DatabaseRBACStore) DeleteSubject(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// H-TENANT-1: Fetch subject first to validate tenant access (security audit finding)
	_, err := s.GetSubject(ctx, id)
	if err != nil {
		return err
	}

	// Tenant validation already performed in GetSubject
	// Proceed with deletion

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM rbac_subjects WHERE id = $1`

	result, err := tx.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete subject: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("subject not found: %s", id)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

