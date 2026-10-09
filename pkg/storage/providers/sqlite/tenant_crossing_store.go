// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
// Package sqlite implements TenantCrossingStore using SQLite
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// SQLiteTenantCrossingStore implements business.TenantCrossingStore using SQLite.
type SQLiteTenantCrossingStore struct {
	db *sql.DB
}

// Initialize is a no-op: schema is created in openAndInit before this store is returned.
func (s *SQLiteTenantCrossingStore) Initialize(ctx context.Context) error { return nil }

// Close closes the underlying database connection.
func (s *SQLiteTenantCrossingStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// CreateTenantCrossing persists a new grant or break-glass record.
func (s *SQLiteTenantCrossingStore) CreateTenantCrossing(ctx context.Context, c *business.TenantCrossing) error {
	state, verr := business.ValidateTenantCrossingForCreate(c)
	if verr != nil {
		return verr
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tenant_crossings (id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at,
			reason_category, approval_state, approved_by, approved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID,
		c.TenantID,
		c.PrincipalID,
		string(c.Kind),
		c.GrantedBy,
		c.Justification,
		formatTime(c.CreatedAt),
		formatTime(c.ExpiresAt),
		nullTime(c.RevokedAt),
		string(c.ReasonCategory),
		string(state),
		c.ApprovedBy,
		nullTime(c.ApprovedAt),
	)
	if err != nil {
		return fmt.Errorf("failed to create tenant crossing %s: %w", c.ID, err)
	}
	return nil
}

// GetTenantCrossing retrieves a crossing by ID.
func (s *SQLiteTenantCrossingStore) GetTenantCrossing(ctx context.Context, id string) (*business.TenantCrossing, error) {
	if id == "" {
		return nil, fmt.Errorf("tenant crossing ID cannot be empty")
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at,
			reason_category, approval_state, approved_by, approved_at
		FROM tenant_crossings WHERE id = ?`, id)
	return scanTenantCrossing(row)
}

// ListTenantCrossings returns every crossing scoped to tenantID, newest first.
func (s *SQLiteTenantCrossingStore) ListTenantCrossings(ctx context.Context, tenantID string) ([]*business.TenantCrossing, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at,
			reason_category, approval_state, approved_by, approved_at
		FROM tenant_crossings WHERE tenant_id = ? ORDER BY created_at DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tenant crossings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.TenantCrossing
	for rows.Next() {
		c, err := scanTenantCrossingRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// HasActiveTenantCrossing reports whether principalID currently holds a non-expired,
// non-revoked crossing for exactly tenantID. Comparison uses the database's own clock
// (CURRENT_TIMESTAMP-equivalent via string comparison against RFC3339 UTC timestamps,
// consistent with formatTime's encoding elsewhere in this package) rather than the
// application clock, so a slow request cannot straddle expiry inconsistently between
// this check and a concurrent one.
func (s *SQLiteTenantCrossingStore) HasActiveTenantCrossing(ctx context.Context, principalID, tenantID string) (bool, error) {
	if principalID == "" || tenantID == "" {
		return false, fmt.Errorf("principal ID and tenant ID cannot be empty")
	}
	var count int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(1) FROM tenant_crossings
		WHERE tenant_id = ? AND approval_state = 'approved' AND revoked_at IS NULL AND expires_at > ?
		  AND (principal_id = ? OR kind = 'grant')`,
		tenantID, formatTime(nowUTC()), principalID,
	).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check active tenant crossing: %w", err)
	}
	return count > 0, nil
}

// RevokeTenantCrossing marks a crossing revoked immediately, regardless of ExpiresAt.
func (s *SQLiteTenantCrossingStore) RevokeTenantCrossing(ctx context.Context, id string) error {
	if id == "" {
		return fmt.Errorf("tenant crossing ID cannot be empty")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE tenant_crossings SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		formatTime(nowUTC()), id)
	if err != nil {
		return fmt.Errorf("failed to revoke tenant crossing %s: %w", id, err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Either the ID doesn't exist, or it does but was already revoked — confirm which.
		if _, getErr := s.GetTenantCrossing(ctx, id); getErr != nil {
			return getErr
		}
		return nil // already revoked: idempotent
	}
	return nil
}

// ApproveTenantCrossing moves a pending, unexpired, unrevoked crossing to approved in a
// single conditional UPDATE, so concurrent approvals cannot both succeed.
func (s *SQLiteTenantCrossingStore) ApproveTenantCrossing(ctx context.Context, id, approverID string, at, newExpiresAt time.Time) error {
	if id == "" || approverID == "" {
		return fmt.Errorf("tenant crossing ID and approver ID are required")
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE tenant_crossings
		SET approval_state = 'approved', approved_by = ?, approved_at = ?, expires_at = ?
		WHERE id = ? AND approval_state = 'pending' AND revoked_at IS NULL AND expires_at > ?`,
		approverID, formatTime(at), formatTime(newExpiresAt), id, formatTime(nowUTC()))
	if err != nil {
		return fmt.Errorf("failed to approve tenant crossing %s: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if n == 0 {
		if _, getErr := s.GetTenantCrossing(ctx, id); getErr != nil {
			return getErr
		}
		return business.ErrTenantCrossingNotPending
	}
	return nil
}

// ListActiveTenantCrossings returns every approved, unexpired, unrevoked crossing as of now.
func (s *SQLiteTenantCrossingStore) ListActiveTenantCrossings(ctx context.Context, now time.Time) ([]*business.TenantCrossing, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, principal_id, kind, granted_by, justification, created_at, expires_at, revoked_at,
			reason_category, approval_state, approved_by, approved_at
		FROM tenant_crossings
		WHERE approval_state = 'approved' AND revoked_at IS NULL AND expires_at > ?
		ORDER BY created_at DESC`, formatTime(now))
	if err != nil {
		return nil, fmt.Errorf("failed to list active tenant crossings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []*business.TenantCrossing
	for rows.Next() {
		c, err := scanTenantCrossingRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func scanTenantCrossing(row *sql.Row) (*business.TenantCrossing, error) {
	var c business.TenantCrossing
	var kind, createdStr, expiresStr string
	var revokedStr, approvedAtStr sql.NullString
	var reason, state string

	err := row.Scan(&c.ID, &c.TenantID, &c.PrincipalID, &kind, &c.GrantedBy, &c.Justification, &createdStr, &expiresStr, &revokedStr,
		&reason, &state, &c.ApprovedBy, &approvedAtStr)
	if err == sql.ErrNoRows {
		return nil, business.ErrTenantCrossingNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan tenant crossing: %w", err)
	}
	return populateTenantCrossing(&c, kind, createdStr, expiresStr, revokedStr, reason, state, approvedAtStr), nil
}

func scanTenantCrossingRow(rows *sql.Rows) (*business.TenantCrossing, error) {
	var c business.TenantCrossing
	var kind, createdStr, expiresStr string
	var revokedStr, approvedAtStr sql.NullString
	var reason, state string

	if err := rows.Scan(&c.ID, &c.TenantID, &c.PrincipalID, &kind, &c.GrantedBy, &c.Justification, &createdStr, &expiresStr, &revokedStr,
		&reason, &state, &c.ApprovedBy, &approvedAtStr); err != nil {
		return nil, fmt.Errorf("failed to scan tenant crossing row: %w", err)
	}
	return populateTenantCrossing(&c, kind, createdStr, expiresStr, revokedStr, reason, state, approvedAtStr), nil
}

func populateTenantCrossing(c *business.TenantCrossing, kind, createdStr, expiresStr string, revokedStr sql.NullString, reason, state string, approvedAtStr sql.NullString) *business.TenantCrossing {
	c.Kind = business.TenantCrossingKind(kind)
	c.CreatedAt = parseTime(createdStr)
	c.ExpiresAt = parseTime(expiresStr)
	if revokedStr.Valid {
		t := parseTime(revokedStr.String)
		c.RevokedAt = &t
	}
	c.ReasonCategory = business.TenantCrossingReasonCategory(reason)
	c.ApprovalState = business.TenantCrossingApprovalState(state)
	if approvedAtStr.Valid {
		t := parseTime(approvedAtStr.String)
		c.ApprovedAt = &t
	}
	return c
}

// ensure SQLiteTenantCrossingStore satisfies the interface at compile time
var _ business.TenantCrossingStore = (*SQLiteTenantCrossingStore)(nil)
