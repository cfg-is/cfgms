// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.ApprovalStore = (*SQLiteApprovalStore)(nil)

// SQLiteApprovalStore implements business.ApprovalStore using the
// workflow_approvals table. Every state transition is one conditional UPDATE, so
// concurrent callers cannot both win. Timestamps are stored as UNIX nanoseconds
// (0 means unset) so the expiry and lease comparisons run in SQL on a numeric,
// not a string, ordering. The table holds only the checkpoint reference, never
// checkpoint contents.
type SQLiteApprovalStore struct {
	db *sql.DB
}

// Close closes the underlying database connection.
func (s *SQLiteApprovalStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

const approvalColumns = `approval_id, tenant_id, workflow_name, execution_id, step_id, step_name,
	message, approver_permission, requested_by, status, requested_at, expires_at, decided_by,
	decided_at, justification, checkpoint_ref, resume_claimed_by, resume_claimed_at, resumed_at`

func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}

func scanApproval(row interface{ Scan(...any) error }) (*business.WorkflowApproval, error) {
	a := &business.WorkflowApproval{}
	var requestedAt, expiresAt, decidedAt, claimedAt, resumedAt int64
	if err := row.Scan(&a.ApprovalID, &a.TenantID, &a.WorkflowName, &a.ExecutionID, &a.StepID, &a.StepName,
		&a.Message, &a.ApproverPermission, &a.RequestedBy, &a.Status, &requestedAt, &expiresAt, &a.DecidedBy,
		&decidedAt, &a.Justification, &a.CheckpointRef, &a.ResumeClaimedBy, &claimedAt, &resumedAt); err != nil {
		return nil, err
	}
	a.RequestedAt = fromNanos(requestedAt)
	a.ExpiresAt = fromNanos(expiresAt)
	a.DecidedAt = fromNanos(decidedAt)
	a.ResumeClaimedAt = fromNanos(claimedAt)
	a.ResumedAt = fromNanos(resumedAt)
	return a, nil
}

func collectApprovals(rows *sql.Rows) ([]*business.WorkflowApproval, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*business.WorkflowApproval, 0)
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: failed to scan approval: %w", err)
		}
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: failed to read approvals: %w", err)
	}
	return result, nil
}

// CreateApproval implements business.ApprovalStore.
func (s *SQLiteApprovalStore) CreateApproval(ctx context.Context, a *business.WorkflowApproval) error {
	if a == nil || a.TenantID == "" || a.ApprovalID == "" {
		return fmt.Errorf("sqlite: approval requires a tenant id and an approval id")
	}
	if a.Status != "" && a.Status != business.ApprovalStatusPending {
		return fmt.Errorf("sqlite: a new approval must be pending, got %q", a.Status)
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO workflow_approvals (`+approvalColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, '', 0, '', ?, '', 0, 0)
		ON CONFLICT(tenant_id, approval_id) DO NOTHING`,
		a.ApprovalID, a.TenantID, a.WorkflowName, a.ExecutionID, a.StepID, a.StepName,
		a.Message, a.ApproverPermission, a.RequestedBy, nanos(a.RequestedAt), nanos(a.ExpiresAt),
		a.CheckpointRef)
	if err != nil {
		return fmt.Errorf("sqlite: failed to create approval: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n == 0 {
		return business.ErrApprovalAlreadyExists
	}
	return nil
}

// GetApproval implements business.ApprovalStore.
func (s *SQLiteApprovalStore) GetApproval(ctx context.Context, tenantID, approvalID string) (*business.WorkflowApproval, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+approvalColumns+` FROM workflow_approvals
		WHERE tenant_id = ? AND approval_id = ?`, tenantID, approvalID)
	a, err := scanApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrApprovalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to get approval: %w", err)
	}
	return a, nil
}

// ListPending implements business.ApprovalStore.
func (s *SQLiteApprovalStore) ListPending(ctx context.Context, tenantID string) ([]*business.WorkflowApproval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+approvalColumns+` FROM workflow_approvals
		WHERE tenant_id = ? AND status = 'pending' ORDER BY requested_at, approval_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list pending approvals: %w", err)
	}
	return collectApprovals(rows)
}

// classify explains why a conditional UPDATE on (tenantID, approvalID) matched no
// row: the approval is missing, or exists in a state the caller must interpret.
func (s *SQLiteApprovalStore) classify(ctx context.Context, tenantID, approvalID string) (status string, resumedAt int64, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT status, resumed_at FROM workflow_approvals
		WHERE tenant_id = ? AND approval_id = ?`, tenantID, approvalID).Scan(&status, &resumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, business.ErrApprovalNotFound
	}
	if err != nil {
		return "", 0, fmt.Errorf("sqlite: failed to read approval: %w", err)
	}
	return status, resumedAt, nil
}

// DecideApproval implements business.ApprovalStore.
func (s *SQLiteApprovalStore) DecideApproval(ctx context.Context, tenantID, approvalID, status, principal, justification string, at time.Time) error {
	if status != business.ApprovalStatusApproved && status != business.ApprovalStatusRejected {
		return fmt.Errorf("sqlite: a decision must be %q or %q, got %q",
			business.ApprovalStatusApproved, business.ApprovalStatusRejected, status)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE workflow_approvals
		SET status = ?, decided_by = ?, decided_at = ?, justification = ?
		WHERE tenant_id = ? AND approval_id = ? AND status = 'pending'`,
		status, principal, nanos(at), justification, tenantID, approvalID)
	if err != nil {
		return fmt.Errorf("sqlite: failed to decide approval: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	if _, _, err := s.classify(ctx, tenantID, approvalID); err != nil {
		return err
	}
	return business.ErrApprovalAlreadyDecided
}

// ExpireDue implements business.ApprovalStore.
func (s *SQLiteApprovalStore) ExpireDue(ctx context.Context, now time.Time) ([]*business.WorkflowApproval, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE workflow_approvals
		SET status = 'expired', decided_at = ?
		WHERE status = 'pending' AND expires_at > 0 AND expires_at <= ?
		RETURNING `+approvalColumns, nanos(now), nanos(now))
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to expire approvals: %w", err)
	}
	flipped, err := collectApprovals(rows)
	if err != nil {
		return nil, err
	}
	sortApprovalsOldestFirst(flipped)
	return flipped, nil
}

// ClaimResume implements business.ApprovalStore.
func (s *SQLiteApprovalStore) ClaimResume(ctx context.Context, tenantID, approvalID, node string, now time.Time, lease time.Duration) error {
	res, err := s.db.ExecContext(ctx, `UPDATE workflow_approvals
		SET resume_claimed_by = ?, resume_claimed_at = ?
		WHERE tenant_id = ? AND approval_id = ?
		  AND status IN ('approved', 'rejected') AND resumed_at = 0
		  AND (resume_claimed_by = '' OR resume_claimed_at < ?)`,
		node, nanos(now), tenantID, approvalID, nanos(now.Add(-lease)))
	if err != nil {
		return fmt.Errorf("sqlite: failed to claim approval resume: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	status, _, err := s.classify(ctx, tenantID, approvalID)
	if err != nil {
		return err
	}
	if status != business.ApprovalStatusApproved && status != business.ApprovalStatusRejected {
		return business.ErrApprovalNotDecided
	}
	return business.ErrApprovalAlreadyClaimed
}

// MarkResumed implements business.ApprovalStore.
func (s *SQLiteApprovalStore) MarkResumed(ctx context.Context, tenantID, approvalID string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE workflow_approvals SET resumed_at = ?
		WHERE tenant_id = ? AND approval_id = ?
		  AND status IN ('approved', 'rejected') AND resumed_at = 0`,
		nanos(now), tenantID, approvalID)
	if err != nil {
		return fmt.Errorf("sqlite: failed to mark approval resumed: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	status, _, err := s.classify(ctx, tenantID, approvalID)
	if err != nil {
		return err
	}
	if status != business.ApprovalStatusApproved && status != business.ApprovalStatusRejected {
		return business.ErrApprovalNotDecided
	}
	return nil // already resumed: idempotent
}

// ListUnresumed implements business.ApprovalStore.
func (s *SQLiteApprovalStore) ListUnresumed(ctx context.Context, now time.Time, lease time.Duration) ([]*business.WorkflowApproval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+approvalColumns+` FROM workflow_approvals
		WHERE status IN ('approved', 'rejected') AND resumed_at = 0
		  AND (resume_claimed_by = '' OR resume_claimed_at < ?)
		ORDER BY requested_at, approval_id`, nanos(now.Add(-lease)))
	if err != nil {
		return nil, fmt.Errorf("sqlite: failed to list unresumed approvals: %w", err)
	}
	return collectApprovals(rows)
}

func sortApprovalsOldestFirst(list []*business.WorkflowApproval) {
	sort.SliceStable(list, func(i, j int) bool { return approvalBefore(list[i], list[j]) })
}

func approvalBefore(a, b *business.WorkflowApproval) bool {
	if !a.RequestedAt.Equal(b.RequestedAt) {
		return a.RequestedAt.Before(b.RequestedAt)
	}
	return a.ApprovalID < b.ApprovalID
}
