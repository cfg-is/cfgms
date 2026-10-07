// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements TenantStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteTenantStore implements business.TenantStore using SQLite.
type SQLiteTenantStore struct {
	db *sql.DB
}

// Initialize is a no-op: schema is created in openAndInit before this store is returned.
func (s *SQLiteTenantStore) Initialize(ctx context.Context) error { return nil }

// Close closes the underlying database connection.
func (s *SQLiteTenantStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateTenant persists a new tenant.
func (s *SQLiteTenantStore) CreateTenant(ctx context.Context, tenant *business.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	now := nowUTC()
	if tenant.CreatedAt.IsZero() {
		tenant.CreatedAt = now
	}
	if tenant.UpdatedAt.IsZero() {
		tenant.UpdatedAt = now
	}

	meta, err := marshalJSON(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant metadata: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tenants (id, name, description, parent_id, metadata, status, directly_suspended, cascade_suspended_from, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		tenant.ID,
		tenant.Name,
		tenant.Description,
		nullString(tenant.ParentID),
		meta,
		string(tenant.Status),
		boolToInt(tenant.DirectlySuspended),
		nullString(stringPtrVal(tenant.CascadeSuspendedFrom)),
		formatTime(tenant.CreatedAt),
		formatTime(tenant.UpdatedAt),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return fmt.Errorf("create tenant %s: %w", tenant.ID, business.ErrTenantAlreadyExists)
		}
		return fmt.Errorf("failed to create tenant %s: %w", tenant.ID, err)
	}
	return nil
}

// GetTenant retrieves a tenant by ID.
func (s *SQLiteTenantStore) GetTenant(ctx context.Context, tenantID string) (*business.TenantData, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, description, parent_id, metadata, status, directly_suspended, cascade_suspended_from, created_at, updated_at
		FROM tenants WHERE id = ?`, tenantID)

	return scanTenant(row)
}

// UpdateTenant replaces all mutable fields of an existing tenant.
func (s *SQLiteTenantStore) UpdateTenant(ctx context.Context, tenant *business.TenantData) error {
	if tenant == nil {
		return fmt.Errorf("tenant cannot be nil")
	}
	if tenant.ID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	tenant.UpdatedAt = nowUTC()

	meta, err := marshalJSON(tenant.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal tenant metadata: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		UPDATE tenants
		SET name = ?, description = ?, parent_id = ?, metadata = ?, status = ?, directly_suspended = ?, cascade_suspended_from = ?, updated_at = ?
		WHERE id = ?`,
		tenant.Name,
		tenant.Description,
		nullString(tenant.ParentID),
		meta,
		string(tenant.Status),
		boolToInt(tenant.DirectlySuspended),
		nullString(stringPtrVal(tenant.CascadeSuspendedFrom)),
		formatTime(tenant.UpdatedAt),
		tenant.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update tenant %s: %w", tenant.ID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("update tenant %s: %w", tenant.ID, business.ErrTenantDoesNotExist)
	}
	return nil
}

// DeleteTenant removes a tenant by ID.
func (s *SQLiteTenantStore) DeleteTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	res, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, tenantID)
	if err != nil {
		return fmt.Errorf("failed to delete tenant %s: %w", tenantID, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("delete tenant %s: %w", tenantID, business.ErrTenantDoesNotExist)
	}
	return nil
}

// ListTenants returns tenants matching the optional filter.
func (s *SQLiteTenantStore) ListTenants(ctx context.Context, filter *business.TenantFilter) ([]*business.TenantData, error) {
	query := `SELECT id, name, description, parent_id, metadata, status, directly_suspended, cascade_suspended_from, created_at, updated_at FROM tenants WHERE 1=1`
	args := []interface{}{}

	if filter != nil {
		if filter.ParentID != "" {
			query += ` AND parent_id = ?`
			args = append(args, filter.ParentID)
		}
		if filter.Status != "" {
			query += ` AND status = ?`
			args = append(args, string(filter.Status))
		}
		if filter.Name != "" {
			query += ` AND LOWER(name) LIKE LOWER(?)`
			args = append(args, "%"+filter.Name+"%")
		}
	}

	query += ` ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var tenants []*business.TenantData
	for rows.Next() {
		t, err := scanTenantRow(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}

// GetTenantHierarchy returns the hierarchy (path, depth, direct children) for a tenant.
func (s *SQLiteTenantStore) GetTenantHierarchy(ctx context.Context, tenantID string) (*business.TenantHierarchy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	path, err := s.GetTenantPath(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	children, err := s.GetChildTenants(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	childIDs := make([]string, len(children))
	for i, c := range children {
		childIDs[i] = c.ID
	}

	return &business.TenantHierarchy{
		TenantID: tenantID,
		Path:     path,
		Depth:    len(path) - 1,
		Children: childIDs,
	}, nil
}

// GetChildTenants returns direct children of the given parent.
func (s *SQLiteTenantStore) GetChildTenants(ctx context.Context, parentID string) ([]*business.TenantData, error) {
	return s.ListTenants(ctx, &business.TenantFilter{ParentID: parentID})
}

// GetTenantPath returns the path from root to the specified tenant (root first).
func (s *SQLiteTenantStore) GetTenantPath(ctx context.Context, tenantID string) ([]string, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	var path []string
	current := tenantID

	for current != "" {
		t, err := s.GetTenant(ctx, current)
		if err != nil {
			return nil, err
		}
		path = append([]string{current}, path...)
		current = t.ParentID

		if len(path) > 100 {
			return nil, fmt.Errorf("tenant hierarchy depth exceeded (possible circular reference)")
		}
	}
	return path, nil
}

// IsTenantAncestor returns true if ancestorID is an ancestor of descendantID.
func (s *SQLiteTenantStore) IsTenantAncestor(ctx context.Context, ancestorID, descendantID string) (bool, error) {
	if ancestorID == "" || descendantID == "" {
		return false, fmt.Errorf("ancestor and descendant IDs cannot be empty")
	}
	path, err := s.GetTenantPath(ctx, descendantID)
	if err != nil {
		return false, err
	}
	for _, id := range path {
		if id == ancestorID {
			return true, nil
		}
	}
	return false, nil
}

// scanTenant scans a single Row (QueryRow) into a TenantData.
func scanTenant(row *sql.Row) (*business.TenantData, error) {
	var t business.TenantData
	var parentID, cascadeFrom sql.NullString
	var metaStr, statusStr, createdStr, updatedStr string
	var directlySuspended int

	err := row.Scan(
		&t.ID, &t.Name, &t.Description,
		&parentID, &metaStr, &statusStr,
		&directlySuspended, &cascadeFrom,
		&createdStr, &updatedStr,
	)
	if err == sql.ErrNoRows {
		return nil, business.ErrTenantDoesNotExist
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant: %w", err)
	}

	return populateTenant(&t, parentID, cascadeFrom, directlySuspended, metaStr, statusStr, createdStr, updatedStr)
}

// scanTenantRow scans a Rows (Query) into a TenantData.
func scanTenantRow(rows *sql.Rows) (*business.TenantData, error) {
	var t business.TenantData
	var parentID, cascadeFrom sql.NullString
	var metaStr, statusStr, createdStr, updatedStr string
	var directlySuspended int

	if err := rows.Scan(
		&t.ID, &t.Name, &t.Description,
		&parentID, &metaStr, &statusStr,
		&directlySuspended, &cascadeFrom,
		&createdStr, &updatedStr,
	); err != nil {
		return nil, fmt.Errorf("failed to scan tenant row: %w", err)
	}

	return populateTenant(&t, parentID, cascadeFrom, directlySuspended, metaStr, statusStr, createdStr, updatedStr)
}

func populateTenant(t *business.TenantData, parentID, cascadeFrom sql.NullString, directlySuspended int, metaStr, statusStr, createdStr, updatedStr string) (*business.TenantData, error) {
	if parentID.Valid {
		t.ParentID = parentID.String
	}
	t.Status = business.TenantStatus(statusStr)
	t.DirectlySuspended = directlySuspended != 0
	if cascadeFrom.Valid && cascadeFrom.String != "" {
		s := cascadeFrom.String
		t.CascadeSuspendedFrom = &s
	}
	t.CreatedAt = parseTime(createdStr)
	t.UpdatedAt = parseTime(updatedStr)

	meta, err := unmarshalJSONMap(metaStr)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tenant metadata: %w", err)
	}
	// Convert map[string]interface{} to map[string]string
	t.Metadata = make(map[string]string, len(meta))
	for k, v := range meta {
		if sv, ok := v.(string); ok {
			t.Metadata[k] = sv
		} else {
			t.Metadata[k] = fmt.Sprintf("%v", v)
		}
	}

	return t, nil
}

// isUniqueConstraintError returns true when the error is a SQLite UNIQUE constraint violation.
// The mattn/go-sqlite3 driver embeds the text "UNIQUE constraint failed" in the error message.
func isUniqueConstraintError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// RequestDeletion implements TenantStore.RequestDeletion.
func (s *SQLiteTenantStore) RequestDeletion(ctx context.Context, pending *business.PendingDeletion) error {
	if pending == nil {
		return fmt.Errorf("pending deletion cannot be nil")
	}
	pinnedJSON, err := json.Marshal(pending.PinnedMemberIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal pinned member IDs: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO tenant_pending_deletions
		  (subtree_root_id, requested_by, requested_at, eligible_at, state, pinned_member_ids)
		VALUES (?, ?, ?, ?, ?, ?)`,
		pending.SubtreeRootID,
		pending.RequestedBy,
		formatTime(pending.RequestedAt),
		formatTime(pending.EligibleAt),
		string(pending.State),
		string(pinnedJSON),
	)
	if err != nil {
		if isUniqueConstraintError(err) {
			return fmt.Errorf("request deletion %s: %w", pending.SubtreeRootID, business.ErrPendingDeletionExists)
		}
		return fmt.Errorf("failed to create pending deletion: %w", err)
	}
	return nil
}

// CancelDeletion implements TenantStore.CancelDeletion.
func (s *SQLiteTenantStore) CancelDeletion(ctx context.Context, subtreeRootID string) error {
	if subtreeRootID == "" {
		return fmt.Errorf("subtree root ID cannot be empty")
	}
	result, err := s.db.ExecContext(ctx,
		`DELETE FROM tenant_pending_deletions WHERE subtree_root_id = ?`, subtreeRootID)
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
// The entire transaction is wrapped in retryOnBusy: when two concurrent callers
// race, the loser's write is rejected with SQLITE_BUSY, the deferred rollback
// fires, and retryOnBusy starts a fresh attempt. On the retry the loser reads
// the post-commit state (pending row gone) and returns ErrPendingDeletionNotFound.
func (s *SQLiteTenantStore) ApproveDeletion(ctx context.Context, subtreeRootID, approvedBy string, requireDualControl bool, now time.Time) ([]string, error) {
	if subtreeRootID == "" {
		return nil, fmt.Errorf("subtree root ID cannot be empty")
	}
	var deleted []string
	err := retryOnBusy(ctx, func() error {
		var err error
		deleted, err = s.attemptApproveDeletion(ctx, subtreeRootID, approvedBy, requireDualControl, now)
		return err
	})
	return deleted, err
}

// attemptApproveDeletion executes a single transactional approval attempt.
// Called by ApproveDeletion (which retries on SQLITE_BUSY). Each call starts its
// own transaction; the deferred rollback runs before retryOnBusy retries.
func (s *SQLiteTenantStore) attemptApproveDeletion(ctx context.Context, subtreeRootID, approvedBy string, requireDualControl bool, now time.Time) ([]string, error) {
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

	// SQLite has no row-level locking, and a plain BEGIN is deferred: it does not take
	// the write lock until the first write statement runs. This no-op write forces that
	// escalation immediately, before any pinned-tenant status is read below, so a
	// concurrent writer (e.g. RestoreTenant/UpdateTenant on another connection) either
	// commits first and is visible to the status recheck, or blocks (SQLITE_BUSY, caught
	// by retryOnBusy on its own path) until this transaction commits or rolls back.
	if _, err := tx.ExecContext(ctx,
		`UPDATE tenant_pending_deletions SET state = state WHERE subtree_root_id = ?`, subtreeRootID); err != nil {
		return nil, fmt.Errorf("failed to acquire write lock on pending deletion: %w", err)
	}

	var (
		requestedBy    string
		eligibleAtStr  string
		stateStr       string
		pinnedMembersS string
	)
	err = tx.QueryRowContext(ctx, `
		SELECT requested_by, eligible_at, state, pinned_member_ids
		FROM tenant_pending_deletions
		WHERE subtree_root_id = ?`, subtreeRootID).Scan(
		&requestedBy, &eligibleAtStr, &stateStr, &pinnedMembersS)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrPendingDeletionNotFound)
		}
		return nil, fmt.Errorf("failed to read pending deletion: %w", err)
	}

	eligibleAt := parseTime(eligibleAtStr)

	// (a) Hold period must have elapsed.
	if now.Before(eligibleAt) {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrHoldNotElapsed)
	}

	// (c) Dual-control: approver must differ from requester.
	if requireDualControl && approvedBy == requestedBy {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrSameApprover)
	}

	var pinnedMembers []string
	if err := json.Unmarshal([]byte(pinnedMembersS), &pinnedMembers); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pinned member IDs: %w", err)
	}

	// (b) Subtree membership must match the pinned set exactly.
	// Recursive CTE collects the current subtree within the transaction.
	rows, err := tx.QueryContext(ctx, `
		WITH RECURSIVE subtree(id) AS (
		  SELECT id FROM tenants WHERE id = ?
		  UNION ALL
		  SELECT t.id FROM tenants t JOIN subtree s ON t.parent_id = s.id
		)
		SELECT id FROM subtree ORDER BY id`, subtreeRootID)
	if err != nil {
		return nil, fmt.Errorf("failed to query current subtree membership: %w", err)
	}
	var currentMembers []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("failed to scan subtree member: %w", err)
		}
		currentMembers = append(currentMembers, id)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("subtree query iteration error: %w", err)
	}
	_ = rows.Close()

	sortedPinned := make([]string, len(pinnedMembers))
	copy(sortedPinned, pinnedMembers)
	sort.Strings(sortedPinned)

	if !stringSlicesEqual(currentMembers, sortedPinned) {
		return nil, fmt.Errorf("approve deletion %s: %w", subtreeRootID, business.ErrMembershipChanged)
	}

	// Re-verify every pinned member is still suspended. The CTE above only compares ID
	// sets, so a tenant concurrently restored to Active (e.g. by a second controller
	// replica calling RestoreTenant/UpdateTenant on another connection) keeps the same
	// ID and would otherwise slip through unchanged. The write lock forced above
	// ensures this read observes either a fully-committed restore or none at all.
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(pinnedMembers)), ",")
	statusArgs := make([]interface{}, len(pinnedMembers))
	for i, id := range pinnedMembers {
		statusArgs[i] = id
	}
	statusRows, err := tx.QueryContext(ctx,
		fmt.Sprintf(`SELECT id, status FROM tenants WHERE id IN (%s)`, placeholders), statusArgs...)
	if err != nil {
		return nil, fmt.Errorf("failed to query pinned tenant status: %w", err)
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

	// Hard-delete every tenant in the pinned set.
	for _, tenantID := range pinnedMembers {
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, tenantID); err != nil {
			return nil, fmt.Errorf("failed to delete tenant %s: %w", tenantID, err)
		}
	}

	// Remove the pending-deletion record.
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM tenant_pending_deletions WHERE subtree_root_id = ?`, subtreeRootID); err != nil {
		return nil, fmt.Errorf("failed to remove pending deletion record: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("failed to commit approval transaction: %w", err)
	}
	committed = true

	return pinnedMembers, nil
}

// GetPendingDeletion implements TenantStore.GetPendingDeletion.
func (s *SQLiteTenantStore) GetPendingDeletion(ctx context.Context, subtreeRootID string) (*business.PendingDeletion, error) {
	if subtreeRootID == "" {
		return nil, fmt.Errorf("subtree root ID cannot be empty")
	}
	var (
		pending        business.PendingDeletion
		requestedAtStr string
		eligibleAtStr  string
		stateStr       string
		pinnedMembersS string
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT subtree_root_id, requested_by, requested_at, eligible_at, state, pinned_member_ids
		FROM tenant_pending_deletions
		WHERE subtree_root_id = ?`, subtreeRootID).Scan(
		&pending.SubtreeRootID,
		&pending.RequestedBy,
		&requestedAtStr,
		&eligibleAtStr,
		&stateStr,
		&pinnedMembersS,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("get pending deletion %s: %w", subtreeRootID, business.ErrPendingDeletionNotFound)
		}
		return nil, fmt.Errorf("failed to get pending deletion: %w", err)
	}
	pending.RequestedAt = parseTime(requestedAtStr)
	pending.EligibleAt = parseTime(eligibleAtStr)
	pending.State = business.DeletionState(stateStr)
	if err := json.Unmarshal([]byte(pinnedMembersS), &pending.PinnedMemberIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pinned member IDs: %w", err)
	}
	return &pending, nil
}

// stringSlicesEqual reports whether two sorted string slices are equal.
func stringSlicesEqual(a, b []string) bool {
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

// ensure SQLiteTenantStore satisfies the interface at compile time
var _ business.TenantStore = (*SQLiteTenantStore)(nil)
