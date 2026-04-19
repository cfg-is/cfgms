// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package sqlite implements RBACStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/api/proto/common"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteRBACStore implements business.RBACStore using SQLite.
type SQLiteRBACStore struct {
	db *sql.DB
}

// Initialize is a no-op; schema is applied in openAndInit.
func (s *SQLiteRBACStore) Initialize(_ context.Context) error { return nil }

// Close closes the database connection.
func (s *SQLiteRBACStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// ---- Permissions ------------------------------------------------------------

func (s *SQLiteRBACStore) StorePermission(ctx context.Context, perm *common.Permission) error {
	if perm == nil {
		return fmt.Errorf("permission cannot be nil")
	}
	actions, err := marshalJSONSlice(perm.Actions)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO rbac_permissions (id, name, description, resource_type, actions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name          = excluded.name,
			description   = excluded.description,
			resource_type = excluded.resource_type,
			actions       = excluded.actions,
			updated_at    = excluded.updated_at`,
		perm.Id, perm.Name, perm.Description, perm.ResourceType, actions, now, now,
	)
	return wrapErr(err, "store permission")
}

func (s *SQLiteRBACStore) GetPermission(ctx context.Context, id string) (*common.Permission, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, resource_type, actions FROM rbac_permissions WHERE id = ?`, id)
	p := &common.Permission{}
	var actionsStr string
	if err := row.Scan(&p.Id, &p.Name, &p.Description, &p.ResourceType, &actionsStr); err == sql.ErrNoRows {
		return nil, fmt.Errorf("permission %s not found", id)
	} else if err != nil {
		return nil, wrapErr(err, "get permission")
	}
	acts, err := unmarshalJSONSlice(actionsStr)
	if err != nil {
		return nil, err
	}
	p.Actions = acts
	return p, nil
}

func (s *SQLiteRBACStore) ListPermissions(ctx context.Context, resourceType string) ([]*common.Permission, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if resourceType == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT id, name, description, resource_type, actions FROM rbac_permissions ORDER BY name`)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT id, name, description, resource_type, actions FROM rbac_permissions WHERE resource_type = ? ORDER BY name`, resourceType)
	}
	if err != nil {
		return nil, wrapErr(err, "list permissions")
	}
	defer func() { _ = rows.Close() }()

	var perms []*common.Permission
	for rows.Next() {
		p := &common.Permission{}
		var actionsStr string
		if err := rows.Scan(&p.Id, &p.Name, &p.Description, &p.ResourceType, &actionsStr); err != nil {
			return nil, wrapErr(err, "scan permission row")
		}
		acts, _ := unmarshalJSONSlice(actionsStr)
		p.Actions = acts
		perms = append(perms, p)
	}
	return perms, rows.Err()
}

func (s *SQLiteRBACStore) UpdatePermission(ctx context.Context, perm *common.Permission) error {
	return s.StorePermission(ctx, perm)
}

func (s *SQLiteRBACStore) DeletePermission(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rbac_permissions WHERE id = ?`, id)
	if err != nil {
		return wrapErr(err, "delete permission")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("permission %s not found", id)
	}
	return nil
}

// ---- Roles ------------------------------------------------------------------

func (s *SQLiteRBACStore) StoreRole(ctx context.Context, role *common.Role) error {
	if role == nil {
		return fmt.Errorf("role cannot be nil")
	}
	permIDs, err := marshalJSONSlice(role.PermissionIds)
	if err != nil {
		return err
	}
	childIDs, err := marshalJSONSlice(role.ChildRoleIds)
	if err != nil {
		return err
	}
	now := time.Now().UTC().UnixNano()
	createdAt := role.CreatedAt
	if createdAt == 0 {
		createdAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO rbac_roles
			(id, name, description, permission_ids, is_system_role, tenant_id,
			 parent_role_id, child_role_ids, inheritance_type, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name             = excluded.name,
			description      = excluded.description,
			permission_ids   = excluded.permission_ids,
			is_system_role   = excluded.is_system_role,
			tenant_id        = excluded.tenant_id,
			parent_role_id   = excluded.parent_role_id,
			child_role_ids   = excluded.child_role_ids,
			inheritance_type = excluded.inheritance_type,
			updated_at       = excluded.updated_at`,
		role.Id, role.Name, role.Description, permIDs,
		boolToInt(role.IsSystemRole), role.TenantId,
		role.ParentRoleId, childIDs, int32(role.InheritanceType),
		createdAt, now,
	)
	return wrapErr(err, "store role")
}

func (s *SQLiteRBACStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, permission_ids, is_system_role, tenant_id,
		       parent_role_id, child_role_ids, inheritance_type, created_at, updated_at
		FROM rbac_roles WHERE id = ?`, id)
	return scanRole(row)
}

func (s *SQLiteRBACStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == "" {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, name, description, permission_ids, is_system_role, tenant_id,
			       parent_role_id, child_role_ids, inheritance_type, created_at, updated_at
			FROM rbac_roles ORDER BY name`)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, name, description, permission_ids, is_system_role, tenant_id,
			       parent_role_id, child_role_ids, inheritance_type, created_at, updated_at
			FROM rbac_roles WHERE tenant_id = ? OR is_system_role = 1 ORDER BY name`, tenantID)
	}
	if err != nil {
		return nil, wrapErr(err, "list roles")
	}
	defer func() { _ = rows.Close() }()

	var roles []*common.Role
	for rows.Next() {
		r, err := scanRoleRow(rows)
		if err != nil {
			return nil, err
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

func (s *SQLiteRBACStore) UpdateRole(ctx context.Context, role *common.Role) error {
	return s.StoreRole(ctx, role)
}

func (s *SQLiteRBACStore) DeleteRole(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rbac_roles WHERE id = ?`, id)
	if err != nil {
		return wrapErr(err, "delete role")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("role %s not found", id)
	}
	return nil
}

// ---- Subjects ---------------------------------------------------------------

func (s *SQLiteRBACStore) StoreSubject(ctx context.Context, subj *common.Subject) error {
	if subj == nil {
		return fmt.Errorf("subject cannot be nil")
	}
	roleIDs, err := marshalJSONSlice(subj.RoleIds)
	if err != nil {
		return err
	}
	attrsJSON, err := json.Marshal(subj.Attributes)
	if err != nil {
		return fmt.Errorf("failed to marshal subject attributes: %w", err)
	}
	now := time.Now().UTC().UnixNano()
	createdAt := subj.CreatedAt
	if createdAt == 0 {
		createdAt = now
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO rbac_subjects
			(id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			type         = excluded.type,
			display_name = excluded.display_name,
			tenant_id    = excluded.tenant_id,
			role_ids     = excluded.role_ids,
			attributes   = excluded.attributes,
			is_active    = excluded.is_active,
			updated_at   = excluded.updated_at`,
		subj.Id, int32(subj.Type), subj.DisplayName, subj.TenantId,
		roleIDs, string(attrsJSON), boolToInt(subj.IsActive),
		createdAt, now,
	)
	return wrapErr(err, "store subject")
}

func (s *SQLiteRBACStore) GetSubject(ctx context.Context, id string) (*common.Subject, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at
		FROM rbac_subjects WHERE id = ?`, id)
	return scanSubject(row)
}

func (s *SQLiteRBACStore) ListSubjects(ctx context.Context, tenantID string, subjectType common.SubjectType) ([]*common.Subject, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch {
	case tenantID != "" && subjectType != common.SubjectType_SUBJECT_TYPE_UNSPECIFIED:
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at
			FROM rbac_subjects WHERE tenant_id = ? AND type = ? ORDER BY display_name`,
			tenantID, int32(subjectType))
	case tenantID != "":
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at
			FROM rbac_subjects WHERE tenant_id = ? ORDER BY display_name`, tenantID)
	case subjectType != common.SubjectType_SUBJECT_TYPE_UNSPECIFIED:
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at
			FROM rbac_subjects WHERE type = ? ORDER BY display_name`, int32(subjectType))
	default:
		rows, err = s.db.QueryContext(ctx, `
			SELECT id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at
			FROM rbac_subjects ORDER BY display_name`)
	}
	if err != nil {
		return nil, wrapErr(err, "list subjects")
	}
	defer func() { _ = rows.Close() }()

	var subjects []*common.Subject
	for rows.Next() {
		subj, err := scanSubjectRow(rows)
		if err != nil {
			return nil, err
		}
		subjects = append(subjects, subj)
	}
	return subjects, rows.Err()
}

func (s *SQLiteRBACStore) UpdateSubject(ctx context.Context, subj *common.Subject) error {
	return s.StoreSubject(ctx, subj)
}

func (s *SQLiteRBACStore) DeleteSubject(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM rbac_subjects WHERE id = ?`, id)
	if err != nil {
		return wrapErr(err, "delete subject")
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("subject %s not found", id)
	}
	return nil
}

// ---- Role Assignments -------------------------------------------------------

func (s *SQLiteRBACStore) StoreRoleAssignment(ctx context.Context, a *common.RoleAssignment) error {
	if a == nil {
		return fmt.Errorf("role assignment cannot be nil")
	}
	conds, err := marshalJSONSlice(a.Conditions)
	if err != nil {
		return err
	}
	now := time.Now().UTC().UnixNano()
	assignedAt := a.AssignedAt
	if assignedAt == 0 {
		assignedAt = now
	}
	var expiresAt sql.NullInt64
	if a.ExpiresAt != 0 {
		expiresAt = sql.NullInt64{Int64: a.ExpiresAt, Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO rbac_role_assignments
			(id, subject_id, role_id, tenant_id, conditions, expires_at, assigned_at, assigned_by)
		VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			subject_id  = excluded.subject_id,
			role_id     = excluded.role_id,
			tenant_id   = excluded.tenant_id,
			conditions  = excluded.conditions,
			expires_at  = excluded.expires_at,
			assigned_at = excluded.assigned_at,
			assigned_by = excluded.assigned_by`,
		a.Id, a.SubjectId, a.RoleId, a.TenantId,
		conds, expiresAt, assignedAt, a.AssignedBy,
	)
	return wrapErr(err, "store role assignment")
}

func (s *SQLiteRBACStore) GetRoleAssignment(ctx context.Context, id string) (*common.RoleAssignment, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, subject_id, role_id, tenant_id, conditions, expires_at, assigned_at, assigned_by
		FROM rbac_role_assignments WHERE id = ?`, id)
	return scanRoleAssignment(row)
}

func (s *SQLiteRBACStore) ListRoleAssignments(ctx context.Context, subjectID, roleID, tenantID string) ([]*common.RoleAssignment, error) {
	conditions := []string{}
	args := []interface{}{}

	if subjectID != "" {
		conditions = append(conditions, "subject_id = ?")
		args = append(args, subjectID)
	}
	if roleID != "" {
		conditions = append(conditions, "role_id = ?")
		args = append(args, roleID)
	}
	if tenantID != "" {
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, tenantID)
	}

	query := `SELECT id, subject_id, role_id, tenant_id, conditions, expires_at, assigned_at, assigned_by FROM rbac_role_assignments`
	if len(conditions) > 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY assigned_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, wrapErr(err, "list role assignments")
	}
	defer func() { _ = rows.Close() }()

	var assignments []*common.RoleAssignment
	for rows.Next() {
		a, err := scanRoleAssignmentRow(rows)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, a)
	}
	return assignments, rows.Err()
}

func (s *SQLiteRBACStore) DeleteRoleAssignment(ctx context.Context, subjectID, roleID, tenantID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM rbac_role_assignments WHERE subject_id = ? AND role_id = ? AND tenant_id = ?`,
		subjectID, roleID, tenantID)
	return wrapErr(err, "delete role assignment")
}

// ---- Bulk operations --------------------------------------------------------

func (s *SQLiteRBACStore) StoreBulkPermissions(ctx context.Context, perms []*common.Permission) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, p := range perms {
		if p == nil {
			continue
		}
		actions, err := marshalJSONSlice(p.Actions)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO rbac_permissions (id, name, description, resource_type, actions, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name          = excluded.name,
				description   = excluded.description,
				resource_type = excluded.resource_type,
				actions       = excluded.actions,
				updated_at    = excluded.updated_at`,
			p.Id, p.Name, p.Description, p.ResourceType, actions, now, now)
		if err != nil {
			return wrapErr(err, "bulk store permission")
		}
	}
	return tx.Commit()
}

func (s *SQLiteRBACStore) StoreBulkRoles(ctx context.Context, roles []*common.Role) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().UnixNano()
	for _, r := range roles {
		if r == nil {
			continue
		}
		permIDs, err := marshalJSONSlice(r.PermissionIds)
		if err != nil {
			return err
		}
		childIDs, err := marshalJSONSlice(r.ChildRoleIds)
		if err != nil {
			return err
		}
		createdAt := r.CreatedAt
		if createdAt == 0 {
			createdAt = now
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO rbac_roles
				(id, name, description, permission_ids, is_system_role, tenant_id,
				 parent_role_id, child_role_ids, inheritance_type, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				name             = excluded.name,
				description      = excluded.description,
				permission_ids   = excluded.permission_ids,
				is_system_role   = excluded.is_system_role,
				tenant_id        = excluded.tenant_id,
				parent_role_id   = excluded.parent_role_id,
				child_role_ids   = excluded.child_role_ids,
				inheritance_type = excluded.inheritance_type,
				updated_at       = excluded.updated_at`,
			r.Id, r.Name, r.Description, permIDs,
			boolToInt(r.IsSystemRole), r.TenantId,
			r.ParentRoleId, childIDs, int32(r.InheritanceType),
			createdAt, now)
		if err != nil {
			return wrapErr(err, "bulk store role")
		}
	}
	return tx.Commit()
}

func (s *SQLiteRBACStore) StoreBulkSubjects(ctx context.Context, subjects []*common.Subject) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC().UnixNano()
	for _, subj := range subjects {
		if subj == nil {
			continue
		}
		roleIDs, err := marshalJSONSlice(subj.RoleIds)
		if err != nil {
			return err
		}
		attrsJSON, err := json.Marshal(subj.Attributes)
		if err != nil {
			return fmt.Errorf("failed to marshal subject attributes: %w", err)
		}
		createdAt := subj.CreatedAt
		if createdAt == 0 {
			createdAt = now
		}
		_, err = tx.ExecContext(ctx, `
			INSERT INTO rbac_subjects
				(id, type, display_name, tenant_id, role_ids, attributes, is_active, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?)
			ON CONFLICT(id) DO UPDATE SET
				type         = excluded.type,
				display_name = excluded.display_name,
				tenant_id    = excluded.tenant_id,
				role_ids     = excluded.role_ids,
				attributes   = excluded.attributes,
				is_active    = excluded.is_active,
				updated_at   = excluded.updated_at`,
			subj.Id, int32(subj.Type), subj.DisplayName, subj.TenantId,
			roleIDs, string(attrsJSON), boolToInt(subj.IsActive),
			createdAt, now)
		if err != nil {
			return wrapErr(err, "bulk store subject")
		}
	}
	return tx.Commit()
}

// ---- Query helpers ----------------------------------------------------------

func (s *SQLiteRBACStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	assignments, err := s.ListRoleAssignments(ctx, subjectID, "", tenantID)
	if err != nil {
		return nil, err
	}
	var roles []*common.Role
	for _, a := range assignments {
		r, err := s.GetRole(ctx, a.RoleId)
		if err != nil {
			continue // role may have been deleted
		}
		roles = append(roles, r)
	}
	return roles, nil
}

func (s *SQLiteRBACStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return nil, err
	}
	var perms []*common.Permission
	for _, pid := range role.PermissionIds {
		p, err := s.GetPermission(ctx, pid)
		if err != nil {
			continue // permission may have been deleted
		}
		perms = append(perms, p)
	}
	return perms, nil
}

func (s *SQLiteRBACStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return s.ListRoleAssignments(ctx, subjectID, "", tenantID)
}

// ---- scan helpers -----------------------------------------------------------

func scanRole(row *sql.Row) (*common.Role, error) {
	r := &common.Role{}
	var permIDsStr, childIDsStr string
	var isSystem int
	var inheritType int32

	err := row.Scan(
		&r.Id, &r.Name, &r.Description, &permIDsStr,
		&isSystem, &r.TenantId, &r.ParentRoleId, &childIDsStr,
		&inheritType, &r.CreatedAt, &r.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role not found")
	}
	if err != nil {
		return nil, wrapErr(err, "scan role")
	}
	r.IsSystemRole = isSystem != 0
	r.InheritanceType = common.RoleInheritanceType(inheritType)
	r.PermissionIds, _ = unmarshalJSONSlice(permIDsStr)
	r.ChildRoleIds, _ = unmarshalJSONSlice(childIDsStr)
	return r, nil
}

func scanRoleRow(rows *sql.Rows) (*common.Role, error) {
	r := &common.Role{}
	var permIDsStr, childIDsStr string
	var isSystem int
	var inheritType int32

	if err := rows.Scan(
		&r.Id, &r.Name, &r.Description, &permIDsStr,
		&isSystem, &r.TenantId, &r.ParentRoleId, &childIDsStr,
		&inheritType, &r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return nil, wrapErr(err, "scan role row")
	}
	r.IsSystemRole = isSystem != 0
	r.InheritanceType = common.RoleInheritanceType(inheritType)
	r.PermissionIds, _ = unmarshalJSONSlice(permIDsStr)
	r.ChildRoleIds, _ = unmarshalJSONSlice(childIDsStr)
	return r, nil
}

func scanSubject(row *sql.Row) (*common.Subject, error) {
	subj := &common.Subject{}
	var roleIDsStr, attrsStr string
	var isActive int
	var subjType int32

	err := row.Scan(
		&subj.Id, &subjType, &subj.DisplayName, &subj.TenantId,
		&roleIDsStr, &attrsStr, &isActive, &subj.CreatedAt, &subj.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("subject not found")
	}
	if err != nil {
		return nil, wrapErr(err, "scan subject")
	}
	subj.Type = common.SubjectType(subjType)
	subj.IsActive = isActive != 0
	subj.RoleIds, _ = unmarshalJSONSlice(roleIDsStr)
	attrs, _ := unmarshalJSONStringMap(attrsStr)
	subj.Attributes = attrs
	return subj, nil
}

func scanSubjectRow(rows *sql.Rows) (*common.Subject, error) {
	subj := &common.Subject{}
	var roleIDsStr, attrsStr string
	var isActive int
	var subjType int32

	if err := rows.Scan(
		&subj.Id, &subjType, &subj.DisplayName, &subj.TenantId,
		&roleIDsStr, &attrsStr, &isActive, &subj.CreatedAt, &subj.UpdatedAt,
	); err != nil {
		return nil, wrapErr(err, "scan subject row")
	}
	subj.Type = common.SubjectType(subjType)
	subj.IsActive = isActive != 0
	subj.RoleIds, _ = unmarshalJSONSlice(roleIDsStr)
	attrs, _ := unmarshalJSONStringMap(attrsStr)
	subj.Attributes = attrs
	return subj, nil
}

func scanRoleAssignment(row *sql.Row) (*common.RoleAssignment, error) {
	a := &common.RoleAssignment{}
	var condsStr string
	var expiresAt sql.NullInt64

	err := row.Scan(
		&a.Id, &a.SubjectId, &a.RoleId, &a.TenantId,
		&condsStr, &expiresAt, &a.AssignedAt, &a.AssignedBy,
	)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("role assignment not found")
	}
	if err != nil {
		return nil, wrapErr(err, "scan role assignment")
	}
	a.Conditions, _ = unmarshalJSONSlice(condsStr)
	if expiresAt.Valid {
		a.ExpiresAt = expiresAt.Int64
	}
	return a, nil
}

func scanRoleAssignmentRow(rows *sql.Rows) (*common.RoleAssignment, error) {
	a := &common.RoleAssignment{}
	var condsStr string
	var expiresAt sql.NullInt64

	if err := rows.Scan(
		&a.Id, &a.SubjectId, &a.RoleId, &a.TenantId,
		&condsStr, &expiresAt, &a.AssignedAt, &a.AssignedBy,
	); err != nil {
		return nil, wrapErr(err, "scan role assignment row")
	}
	a.Conditions, _ = unmarshalJSONSlice(condsStr)
	if expiresAt.Valid {
		a.ExpiresAt = expiresAt.Int64
	}
	return a, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func wrapErr(err error, op string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("sqlite rbac %s: %w", op, err)
}

// ensure SQLiteRBACStore satisfies the interface at compile time
var _ business.RBACStore = (*SQLiteRBACStore)(nil)
