// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/cfgis/cfgms/api/proto/common"
)

// ErrCrossTenantAccessDenied is returned when attempting to access a resource from a different tenant
var ErrCrossTenantAccessDenied = errors.New("cross-tenant access denied")

// DatabaseRBACStore implements RBACStore using PostgreSQL for persistence
type DatabaseRBACStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseRBACStore creates a new PostgreSQL-based RBAC store
func NewDatabaseRBACStore(dsn string, config map[string]interface{}) (*DatabaseRBACStore, error) {
	// Open database connection with connection pooling
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	// Configure connection pool
	maxOpenConns := getIntFromConfig(config, "max_open_connections", 25)
	maxIdleConns := getIntFromConfig(config, "max_idle_connections", 5)
	connMaxLifetime := time.Duration(getIntFromConfig(config, "connection_max_lifetime_minutes", 30)) * time.Minute

	db.SetMaxOpenConns(maxOpenConns)
	db.SetMaxIdleConns(maxIdleConns)
	db.SetConnMaxLifetime(connMaxLifetime)

	// Test connection
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	store := &DatabaseRBACStore{
		db:      db,
		config:  config,
		schemas: NewDatabaseSchemas(),
	}

	// Initialize database schema
	if err := store.initializeSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize database schema: %w", err)
	}

	return store, nil
}

// initializeSchema creates the necessary database tables and indexes for RBAC
func (s *DatabaseRBACStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 13579246 (different from other store locks)
	const schemaLockID = 13579246

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire RBAC schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			// This is non-critical since PostgreSQL will release advisory locks when connection closes
			_ = err // Explicitly ignore error to satisfy linter
		}
	}()

	// Create RBAC tables
	if err := s.schemas.CreateRBACTables(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create RBAC tables: %w", err)
	}

	return nil
}

// Initialize implements RBACStore.Initialize
func (s *DatabaseRBACStore) Initialize(ctx context.Context) error {
	return s.initializeSchema()
}

// Close implements RBACStore.Close
func (s *DatabaseRBACStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// H-TENANT-1: Tenant boundary validation helper (security audit finding)
// validateTenantAccess checks if the authenticated tenant matches the resource's tenant
// System roles are allowed to bypass tenant validation
func (s *DatabaseRBACStore) validateTenantAccess(ctx context.Context, resourceTenantID string, isSystemResource bool) error {
	// System resources (is_system_role=true, etc.) can be accessed by any tenant
	if isSystemResource {
		return nil
	}

	// Extract authenticated tenant ID from context
	authTenantIDValue := ctx.Value("tenant_id")
	if authTenantIDValue == nil {
		// If no tenant_id in context, allow operation (backwards compatibility)
		// This supports operations from internal system components
		return nil
	}

	authTenantID, ok := authTenantIDValue.(string)
	if !ok {
		return fmt.Errorf("invalid tenant_id type in context")
	}

	// H-TENANT-1: Block cross-tenant access (security audit finding)
	if authTenantID != resourceTenantID {
		return fmt.Errorf("%w: authenticated tenant=%s, resource tenant=%s",
			ErrCrossTenantAccessDenied, authTenantID, resourceTenantID)
	}

	return nil
}

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

// Role management

// StoreRole implements RBACStore.StoreRole
func (s *DatabaseRBACStore) StoreRole(ctx context.Context, role *common.Role) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// H-TENANT-1: Validate tenant access before storing role (security audit finding)
	if err := s.validateTenantAccess(ctx, role.TenantId, role.IsSystemRole); err != nil {
		return err
	}

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Serialize permission IDs array to JSON
	permissionIDsJSON, err := json.Marshal(role.PermissionIds)
	if err != nil {
		return fmt.Errorf("failed to serialize permission IDs: %w", err)
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
		return fmt.Errorf("failed to store role: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

// GetRole implements RBACStore.GetRole
func (s *DatabaseRBACStore) GetRole(ctx context.Context, id string) (*common.Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type
		FROM rbac_roles
		WHERE id = $1
	`

	row := s.db.QueryRowContext(ctx, query, id)

	role := &common.Role{}
	var permissionIDsJSON []byte
	var parentRoleID sql.NullString
	var inheritanceType sql.NullInt32

	err := row.Scan(
		&role.Id,
		&role.Name,
		&role.Description,
		&permissionIDsJSON,
		&role.IsSystemRole,
		&role.TenantId,
		&parentRoleID,
		&inheritanceType,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("role not found: %s", id)
		}
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	// H-TENANT-1: Validate tenant access before returning role (security audit finding)
	if err := s.validateTenantAccess(ctx, role.TenantId, role.IsSystemRole); err != nil {
		return nil, err
	}

	// Deserialize permission IDs from JSON
	if err := json.Unmarshal(permissionIDsJSON, &role.PermissionIds); err != nil {
		return nil, fmt.Errorf("failed to deserialize permission IDs: %w", err)
	}

	// Handle nullable fields
	if parentRoleID.Valid {
		role.ParentRoleId = parentRoleID.String
	}
	if inheritanceType.Valid {
		role.InheritanceType = common.RoleInheritanceType(inheritanceType.Int32)
	}

	return role, nil
}

// ListRoles implements RBACStore.ListRoles
func (s *DatabaseRBACStore) ListRoles(ctx context.Context, tenantID string) ([]*common.Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var query string
	var args []interface{}

	if tenantID == "" {
		query = `
			SELECT id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type
			FROM rbac_roles
			ORDER BY is_system_role DESC, tenant_id, name
		`
	} else {
		query = `
			SELECT id, name, description, permission_ids, is_system_role, tenant_id, parent_role_id, inheritance_type
			FROM rbac_roles
			WHERE tenant_id = $1 OR is_system_role = true
			ORDER BY is_system_role DESC, name
		`
		args = []interface{}{tenantID}
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []*common.Role

	for rows.Next() {
		role := &common.Role{}
		var permissionIDsJSON []byte
		var parentRoleID sql.NullString
		var inheritanceType sql.NullInt32

		err := rows.Scan(
			&role.Id,
			&role.Name,
			&role.Description,
			&permissionIDsJSON,
			&role.IsSystemRole,
			&role.TenantId,
			&parentRoleID,
			&inheritanceType,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Deserialize permission IDs from JSON
		if err := json.Unmarshal(permissionIDsJSON, &role.PermissionIds); err != nil {
			return nil, fmt.Errorf("failed to deserialize permission IDs: %w", err)
		}

		// Handle nullable fields
		if parentRoleID.Valid {
			role.ParentRoleId = parentRoleID.String
		}
		if inheritanceType.Valid {
			role.InheritanceType = common.RoleInheritanceType(inheritanceType.Int32)
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating roles: %w", err)
	}

	return roles, nil
}

// UpdateRole implements RBACStore.UpdateRole
func (s *DatabaseRBACStore) UpdateRole(ctx context.Context, role *common.Role) error {
	// Same implementation as StoreRole due to ON CONFLICT DO UPDATE
	return s.StoreRole(ctx, role)
}

// DeleteRole implements RBACStore.DeleteRole
func (s *DatabaseRBACStore) DeleteRole(ctx context.Context, id string) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// H-TENANT-1: Fetch role first to validate tenant access (security audit finding)
	_, err := s.GetRole(ctx, id)
	if err != nil {
		return err
	}

	// Tenant validation already performed in GetRole
	// Proceed with deletion

	// Begin transaction
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	query := `DELETE FROM rbac_roles WHERE id = $1`

	result, err := tx.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete role: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("role not found: %s", id)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

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

// Query operations

// GetSubjectRoles implements RBACStore.GetSubjectRoles
func (s *DatabaseRBACStore) GetSubjectRoles(ctx context.Context, subjectID, tenantID string) ([]*common.Role, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT r.id, r.name, r.description, r.permission_ids, r.is_system_role, r.tenant_id, r.parent_role_id, r.inheritance_type
		FROM rbac_roles r
		INNER JOIN rbac_role_assignments ra ON r.id = ra.role_id
		WHERE ra.subject_id = $1 AND ra.tenant_id = $2
		  AND (ra.expires_at IS NULL OR ra.expires_at > NOW())
		ORDER BY r.is_system_role DESC, r.name
	`

	rows, err := s.db.QueryContext(ctx, query, subjectID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject roles: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var roles []*common.Role

	for rows.Next() {
		role := &common.Role{}
		var permissionIDsJSON []byte
		var parentRoleID sql.NullString
		var inheritanceType sql.NullInt32

		err := rows.Scan(
			&role.Id,
			&role.Name,
			&role.Description,
			&permissionIDsJSON,
			&role.IsSystemRole,
			&role.TenantId,
			&parentRoleID,
			&inheritanceType,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan role: %w", err)
		}

		// Deserialize permission IDs from JSON
		if err := json.Unmarshal(permissionIDsJSON, &role.PermissionIds); err != nil {
			return nil, fmt.Errorf("failed to deserialize permission IDs: %w", err)
		}

		// Handle nullable fields
		if parentRoleID.Valid {
			role.ParentRoleId = parentRoleID.String
		}
		if inheritanceType.Valid {
			role.InheritanceType = common.RoleInheritanceType(inheritanceType.Int32)
		}

		roles = append(roles, role)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating subject roles: %w", err)
	}

	return roles, nil
}

// GetRolePermissions implements RBACStore.GetRolePermissions
func (s *DatabaseRBACStore) GetRolePermissions(ctx context.Context, roleID string) ([]*common.Permission, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// First get the role to find its permission IDs
	role, err := s.GetRole(ctx, roleID)
	if err != nil {
		return nil, fmt.Errorf("failed to get role: %w", err)
	}

	if len(role.PermissionIds) == 0 {
		return []*common.Permission{}, nil
	}

	// Build query with IN clause for permission IDs
	placeholders := make([]string, len(role.PermissionIds))
	args := make([]interface{}, len(role.PermissionIds))

	for i, permissionID := range role.PermissionIds {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = permissionID
	}

	// #nosec G201 - Using parameterized query with dynamic IN clause - placeholders are $1, $2, etc.
	query := fmt.Sprintf(`
		SELECT id, name, description, resource_type, actions
		FROM rbac_permissions
		WHERE id IN (%s)
		ORDER BY resource_type, name
	`, strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get role permissions: %w", err)
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
		return nil, fmt.Errorf("error iterating role permissions: %w", err)
	}

	return permissions, nil
}

// GetSubjectAssignments implements RBACStore.GetSubjectAssignments
func (s *DatabaseRBACStore) GetSubjectAssignments(ctx context.Context, subjectID, tenantID string) ([]*common.RoleAssignment, error) {
	return s.ListRoleAssignments(ctx, subjectID, "", tenantID)
}

// M-TENANT-1: RLS helper functions
// These functions will be used when integrating RLS into database operations.
// Currently unused but documented in migrations/003_enable_rls.sql
// Example usage:
//   err := s.withTenantContext(ctx, tenantID, func(ctx context.Context, tx *sql.Tx) error {
//       // Perform database operations with RLS enforced
//       return nil
//   })
