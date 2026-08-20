// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/lib/pq" // PostgreSQL driver

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// DatabaseTenantStore implements TenantStore using PostgreSQL for persistence
type DatabaseTenantStore struct {
	db      *sql.DB
	config  map[string]interface{}
	mutex   sync.RWMutex
	schemas DatabaseSchemas
}

// NewDatabaseTenantStore creates a new PostgreSQL-based tenant store
func NewDatabaseTenantStore(dsn string, config map[string]interface{}) (*DatabaseTenantStore, error) {
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

	store := &DatabaseTenantStore{
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

// initializeSchema creates the necessary database tables and indexes for tenants
func (s *DatabaseTenantStore) initializeSchema() error {
	ctx := context.Background()

	// Use PostgreSQL advisory lock to prevent concurrent schema initialization
	// Lock ID: 13579247 (different from RBAC's 13579246)
	const schemaLockID = 13579247

	// Acquire advisory lock - will wait if another instance is initializing
	if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_lock($1)", schemaLockID); err != nil {
		return fmt.Errorf("failed to acquire tenant schema initialization lock: %w", err)
	}

	// Ensure we release the lock when done
	defer func() {
		if _, err := s.db.ExecContext(ctx, "SELECT pg_advisory_unlock($1)", schemaLockID); err != nil {
			// Log but don't fail - lock will be released when connection closes
			_ = err
		}
	}()

	// Create tenant tables
	if err := s.schemas.CreateTenantTables(ctx, s.db); err != nil {
		return fmt.Errorf("failed to create tenant tables: %w", err)
	}

	return nil
}

// Initialize implements TenantStore.Initialize
func (s *DatabaseTenantStore) Initialize(ctx context.Context) error {
	return s.initializeSchema()
}

// Close implements TenantStore.Close
func (s *DatabaseTenantStore) Close() error {
	return s.db.Close()
}

// CreateTenant implements TenantStore.CreateTenant
func (s *DatabaseTenantStore) CreateTenant(ctx context.Context, tenant *business.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Serialize metadata to JSON
	metadataJSON, err := json.Marshal(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO cfgms_tenants (id, name, description, parent_id, metadata, status, directly_suspended, cascade_suspended_from, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = s.db.ExecContext(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Description,
		nullStringOrEmpty(tenant.ParentID),
		metadataJSON,
		string(tenant.Status),
		tenant.DirectlySuspended,
		nullStringOrEmpty(dbStringPtrVal(tenant.CascadeSuspendedFrom)),
		tenant.CreatedAt,
		tenant.UpdatedAt,
	)

	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return fmt.Errorf("create tenant %s: %w", tenant.ID, business.ErrTenantAlreadyExists)
		}
		return fmt.Errorf("failed to create tenant: %w", err)
	}

	return nil
}

// GetTenant implements TenantStore.GetTenant
func (s *DatabaseTenantStore) GetTenant(ctx context.Context, tenantID string) (*business.TenantData, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, parent_id, metadata, status, directly_suspended, cascade_suspended_from, created_at, updated_at
		FROM cfgms_tenants
		WHERE id = $1
	`

	var tenant business.TenantData
	var parentID, cascadeFrom sql.NullString
	var metadataJSON []byte

	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(
		&tenant.ID,
		&tenant.Name,
		&tenant.Description,
		&parentID,
		&metadataJSON,
		&tenant.Status,
		&tenant.DirectlySuspended,
		&cascadeFrom,
		&tenant.CreatedAt,
		&tenant.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("get tenant %s: %w", tenantID, business.ErrTenantDoesNotExist)
		}
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	tenant.ParentID = parentID.String
	if cascadeFrom.Valid && cascadeFrom.String != "" {
		s := cascadeFrom.String
		tenant.CascadeSuspendedFrom = &s
	}

	if err := json.Unmarshal(metadataJSON, &tenant.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &tenant, nil
}

// UpdateTenant implements TenantStore.UpdateTenant
func (s *DatabaseTenantStore) UpdateTenant(ctx context.Context, tenant *business.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Serialize metadata to JSON
	metadataJSON, err := json.Marshal(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE cfgms_tenants
		SET name = $2, description = $3, parent_id = $4, metadata = $5, status = $6,
		    directly_suspended = $7, cascade_suspended_from = $8, updated_at = $9
		WHERE id = $1
	`

	result, err := s.db.ExecContext(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Description,
		nullStringOrEmpty(tenant.ParentID),
		metadataJSON,
		string(tenant.Status),
		tenant.DirectlySuspended,
		nullStringOrEmpty(dbStringPtrVal(tenant.CascadeSuspendedFrom)),
		tenant.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to update tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("update tenant %s: %w", tenant.ID, business.ErrTenantDoesNotExist)
	}

	return nil
}

// DeleteTenant implements TenantStore.DeleteTenant
func (s *DatabaseTenantStore) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	query := `DELETE FROM cfgms_tenants WHERE id = $1`

	result, err := s.db.ExecContext(ctx, query, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete tenant: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("delete tenant %s: %w", tenantID, business.ErrTenantDoesNotExist)
	}

	return nil
}

// ListTenants implements TenantStore.ListTenants
func (s *DatabaseTenantStore) ListTenants(ctx context.Context, filter *business.TenantFilter) ([]*business.TenantData, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	query := `
		SELECT id, name, description, parent_id, metadata, status, directly_suspended, cascade_suspended_from, created_at, updated_at
		FROM cfgms_tenants
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	// Apply filters
	if filter != nil {
		if filter.ParentID != "" {
			query += fmt.Sprintf(" AND parent_id = $%d", argCount)
			args = append(args, filter.ParentID)
			argCount++
		}
		if filter.Status != "" {
			query += fmt.Sprintf(" AND status = $%d", argCount)
			args = append(args, string(filter.Status))
			argCount++
		}
		if filter.Name != "" {
			// #nosec G202 -- only the generated placeholder index is formatted;
			// the wildcarded name remains a bound database argument.
			query += fmt.Sprintf(" AND name ILIKE $%d", argCount)
			args = append(args, "%"+filter.Name+"%")
			// argCount not incremented as it's the last filter condition
		}
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tenants []*business.TenantData
	for rows.Next() {
		var tenant business.TenantData
		var parentID, cascadeFrom sql.NullString
		var metadataJSON []byte

		err := rows.Scan(
			&tenant.ID,
			&tenant.Name,
			&tenant.Description,
			&parentID,
			&metadataJSON,
			&tenant.Status,
			&tenant.DirectlySuspended,
			&cascadeFrom,
			&tenant.CreatedAt,
			&tenant.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan tenant row: %w", err)
		}

		tenant.ParentID = parentID.String
		if cascadeFrom.Valid && cascadeFrom.String != "" {
			s := cascadeFrom.String
			tenant.CascadeSuspendedFrom = &s
		}

		if err := json.Unmarshal(metadataJSON, &tenant.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		tenants = append(tenants, &tenant)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating tenant rows: %w", err)
	}

	return tenants, nil
}

// GetTenantHierarchy implements TenantStore.GetTenantHierarchy
func (s *DatabaseTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*business.TenantHierarchy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	// Get path from root to tenant
	path, err := s.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant path: %w", err)
	}

	// Get direct children
	children, err := s.GetChildTenants(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get child tenants: %w", err)
	}

	childIDs := make([]string, len(children))
	for i, child := range children {
		childIDs[i] = child.ID
	}

	return &business.TenantHierarchy{
		TenantID: tenantID,
		Path:     path,
		Depth:    len(path) - 1,
		Children: childIDs,
	}, nil
}

// GetChildTenants implements TenantStore.GetChildTenants
func (s *DatabaseTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*business.TenantData, error) {
	filter := &business.TenantFilter{
		ParentID: parentID,
	}
	return s.ListTenants(ctx, filter)
}

// GetTenantPath implements TenantStore.GetTenantPath
func (s *DatabaseTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	var path []string
	currentID := tenantID

	// Walk up the parent chain
	for currentID != "" {
		tenant, err := s.GetTenant(ctx, currentID)
		if err != nil {
			return nil, fmt.Errorf("failed to get tenant %s: %w", currentID, err)
		}

		// Prepend to path (building from child to root)
		path = append([]string{currentID}, path...)

		currentID = tenant.ParentID

		// Prevent infinite loops
		if len(path) > 100 {
			return nil, fmt.Errorf("tenant hierarchy depth exceeded (possible circular reference)")
		}
	}

	return path, nil
}

// IsTenantAncestor implements TenantStore.IsTenantAncestor
func (s *DatabaseTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	if ancestorID == "" || descendantID == "" {
		return false, fmt.Errorf("ancestor and descendant IDs cannot be empty")
	}

	// Get the path from descendant to root
	path, err := s.GetTenantPath(ctx, descendantID)
	if err != nil {
		return false, fmt.Errorf("failed to get tenant path: %w", err)
	}

	// Check if ancestorID is in the path
	for _, id := range path {
		if id == ancestorID {
			return true, nil
		}
	}

	return false, nil
}

// RequestDeletion implements TenantStore.RequestDeletion.
func (s *DatabaseTenantStore) RequestDeletion(ctx context.Context, pending *business.PendingDeletion) error {
	if pending == nil {
		return fmt.Errorf("pending deletion cannot be nil")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	pinnedJSON, err := json.Marshal(pending.PinnedMemberIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal pinned member IDs: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO cfgms_tenant_pending_deletions
		  (subtree_root_id, requested_by, requested_at, eligible_at, state, pinned_member_ids)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		pending.SubtreeRootID,
		pending.RequestedBy,
		pending.RequestedAt,
		pending.EligibleAt,
		string(pending.State),
		pinnedJSON,
	)
	if err != nil {
		if pgErr, ok := err.(*pq.Error); ok && pgErr.Code == "23505" {
			return fmt.Errorf("request deletion %s: %w", pending.SubtreeRootID, business.ErrPendingDeletionExists)
		}
		return fmt.Errorf("failed to create pending deletion: %w", err)
	}
	return nil
}

// CancelDeletion implements TenantStore.CancelDeletion.
func (s *DatabaseTenantStore) CancelDeletion(ctx context.Context, subtreeRootID string) error {
	if subtreeRootID == "" {
		return fmt.Errorf("subtree root ID cannot be empty")
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()

	result, err := s.db.ExecContext(ctx,
		`DELETE FROM cfgms_tenant_pending_deletions WHERE subtree_root_id = $1`, subtreeRootID)
	if err != nil {
		return fmt.Errorf("failed to cancel deletion: %w", err)
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("cancel deletion %s: %w", subtreeRootID, business.ErrPendingDeletionNotFound)
	}
	return nil
}

// ApproveDeletion implements TenantStore.ApproveDeletion.
// Executes as a single SQL transaction: row-locks the pending-deletion record,
// checks eligibility + dual-control + subtree membership, then hard-deletes
// every tenant in the pinned member set and removes the pending record.
func (s *DatabaseTenantStore) ApproveDeletion(ctx context.Context, subtreeRootID, approvedBy string, requireDualControl bool, now time.Time) ([]string, error) {
	if subtreeRootID == "" {
		return nil, fmt.Errorf("subtree root ID cannot be empty")
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin approval transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	// Row-lock the pending-deletion record so concurrent approval attempts serialise.
	var (
		requestedBy    string
		eligibleAt     time.Time
		stateStr       string
		pinnedMembersB []byte
	)
	err = tx.QueryRowContext(ctx, `
		SELECT requested_by, eligible_at, state, pinned_member_ids
		FROM cfgms_tenant_pending_deletions
		WHERE subtree_root_id = $1
		FOR UPDATE`, subtreeRootID).Scan(&requestedBy, &eligibleAt, &stateStr, &pinnedMembersB)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrPendingDeletionNotFound)
		}
		return nil, fmt.Errorf("failed to lock pending deletion: %w", err)
	}

	// (a) Hold period must have elapsed.
	if now.Before(eligibleAt) {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrHoldNotElapsed)
	}

	// (c) Dual-control: approver must differ from requester.
	if requireDualControl && approvedBy == requestedBy {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrSameApprover)
	}

	// Deserialise the pinned member set.
	var pinnedMembers []string
	if err := json.Unmarshal(pinnedMembersB, &pinnedMembers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pinned member IDs: %w", err)
	}

	// (b) Subtree membership must match exactly.
	// Use a recursive CTE to collect all current members within the transaction.
	// The CTE also yields each member's depth below the subtree root so the
	// hard-delete below can run leaf-first; see the delete loop for why ordering
	// is load-bearing on PostgreSQL.
	rows, err := tx.QueryContext(ctx, `
		WITH RECURSIVE subtree AS (
		  SELECT id, 0 AS depth FROM cfgms_tenants WHERE id = $1
		  UNION ALL
		  SELECT t.id, s.depth + 1 FROM cfgms_tenants t JOIN subtree s ON t.parent_id = s.id
		)
		SELECT id, depth FROM subtree ORDER BY depth DESC, id`, subtreeRootID)
	if err != nil {
		return nil, fmt.Errorf("failed to query current subtree membership: %w", err)
	}
	// deepestFirst holds the same IDs as currentMembers, ordered children before
	// parents.
	var deepestFirst []string
	for rows.Next() {
		var (
			id    string
			depth int
		)
		if err := rows.Scan(&id, &depth); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan subtree member: %w", err)
		}
		deepestFirst = append(deepestFirst, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("subtree query iteration error: %w", err)
	}
	_ = rows.Close()

	if !stringSlicesEqualSorted(sortedCopy(deepestFirst), sortedCopy(pinnedMembers)) {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrMembershipChanged)
	}

	// Row-lock every pinned tenant and re-verify it is still suspended. The CTE above
	// only compares ID sets, so a tenant concurrently restored to Active (e.g. by a
	// second controller replica calling RestoreTenant/UpdateTenant on another
	// connection) keeps the same ID and would otherwise slip through unchanged. FOR
	// UPDATE here blocks that concurrent UPDATE until this transaction commits or
	// rolls back, closing the cross-connection race between approval and restore.
	statusRows, err := tx.QueryContext(ctx,
		`SELECT id, status FROM cfgms_tenants WHERE id = ANY($1) FOR UPDATE`, pq.Array(pinnedMembers))
	if err != nil {
		return nil, fmt.Errorf("failed to lock pinned tenant rows: %w", err)
	}
	currentStatus := make(map[string]string, len(pinnedMembers))
	for statusRows.Next() {
		var id, status string
		if err := statusRows.Scan(&id, &status); err != nil {
			_ = statusRows.Close()
			return nil, fmt.Errorf("failed to scan pinned tenant status: %w", err)
		}
		currentStatus[id] = status
	}
	if err := statusRows.Err(); err != nil {
		_ = statusRows.Close()
		return nil, fmt.Errorf("pinned tenant status query iteration error: %w", err)
	}
	_ = statusRows.Close()

	if len(currentStatus) != len(pinnedMembers) {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrMembershipChanged)
	}
	for _, id := range pinnedMembers {
		if currentStatus[id] != string(business.TenantStatusSuspended) {
			return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrMembershipChanged)
		}
	}

	// Hard-delete every tenant in the pinned set, deepest member first. Ordering
	// is required: cfgms_tenants declares
	// FOREIGN KEY (parent_id) REFERENCES cfgms_tenants(id) ON DELETE RESTRICT
	// (schemas.go), and RESTRICT is checked without deferral, so removing a
	// parent while any child row still references it raises a foreign-key
	// violation and rolls back the whole approval transaction. pinnedMembers is
	// recorded in BFS order (parents before children) by RequestTenantDeletion,
	// which is exactly the wrong order here; deepestFirst comes from the
	// membership CTE above, whose ID set was just proven identical to
	// pinnedMembers, so every child is removed before its parent.
	for _, tenantID := range deepestFirst {
		if _, err := tx.ExecContext(ctx, `DELETE FROM cfgms_tenants WHERE id = $1`, tenantID); err != nil {
			return nil, fmt.Errorf("failed to delete tenant %s: %w", tenantID, err)
		}
	}

	// Remove the pending-deletion record.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM cfgms_tenant_pending_deletions WHERE subtree_root_id = $1`, subtreeRootID); err != nil {
		return nil, fmt.Errorf("failed to remove pending deletion record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit approval transaction: %w", err)
	}
	committed = true

	return pinnedMembers, nil
}

// GetPendingDeletion implements TenantStore.GetPendingDeletion.
func (s *DatabaseTenantStore) GetPendingDeletion(ctx context.Context, subtreeRootID string) (*business.PendingDeletion, error) {
	if subtreeRootID == "" {
		return nil, fmt.Errorf("subtree root ID cannot be empty")
	}
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var (
		pending        business.PendingDeletion
		stateStr       string
		pinnedMembersB []byte
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT subtree_root_id, requested_by, requested_at, eligible_at, state, pinned_member_ids
		FROM cfgms_tenant_pending_deletions
		WHERE subtree_root_id = $1`, subtreeRootID).Scan(
		&pending.SubtreeRootID,
		&pending.RequestedBy,
		&pending.RequestedAt,
		&pending.EligibleAt,
		&stateStr,
		&pinnedMembersB,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("get pending deletion %s: %w", subtreeRootID, business.ErrPendingDeletionNotFound)
		}
		return nil, fmt.Errorf("failed to get pending deletion: %w", err)
	}
	pending.State = business.DeletionState(stateStr)
	if err := json.Unmarshal(pinnedMembersB, &pending.PinnedMemberIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pinned member IDs: %w", err)
	}
	return &pending, nil
}

// sortedCopy returns a sorted copy of ss without modifying the original.
func sortedCopy(ss []string) []string {
	out := make([]string, len(ss))
	copy(out, ss)
	sortStrings(out)
	return out
}

// stringSlicesEqualSorted reports whether two already-sorted string slices are equal.
func stringSlicesEqualSorted(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sortStrings sorts a string slice in place.
func sortStrings(ss []string) {
	for i := 1; i < len(ss); i++ {
		for j := i; j > 0 && ss[j] < ss[j-1]; j-- {
			ss[j], ss[j-1] = ss[j-1], ss[j]
		}
	}
}

// nullStringOrEmpty returns a sql.NullString that's NULL if the input is empty
func nullStringOrEmpty(s string) sql.NullString {
	if s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: s, Valid: true}
}

// dbStringPtrVal dereferences a string pointer, returning "" when nil.
func dbStringPtrVal(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}
