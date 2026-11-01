// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.ApprovalStore = (*DatabaseApprovalStore)(nil)

// DatabaseApprovalStore implements business.ApprovalStore using PostgreSQL — the
// workflow approvals every controller node sees. Every transition is one
// conditional UPDATE, so concurrent callers on different nodes cannot both win.
// The table holds only the checkpoint reference, never checkpoint contents.
type DatabaseApprovalStore struct {
	db *sql.DB
}

// NewDatabaseApprovalStore creates the store on the shared connection pool db
// (owned by DatabaseProvider; ADR-031 Decision 6) and ensures its table exists.
func NewDatabaseApprovalStore(db *sql.DB, _ map[string]interface{}) (*DatabaseApprovalStore, error) {
	if err := NewDatabaseSchemas().CreateWorkflowApprovalsTable(context.Background(), db); err != nil {
		return nil, err
	}
	return &DatabaseApprovalStore{db: db}, nil
}

// Close is a no-op: the connection pool is owned and closed by DatabaseProvider.
func (s *DatabaseApprovalStore) Close() error { return nil }

const workflowApprovalColumns = `approval_id, tenant_id, workflow_name, execution_id, step_id, step_name,
	message, approver_permission, requested_by, status, requested_at, expires_at, decided_by,
	decided_at, justification, checkpoint_ref, resume_claimed_by, resume_claimed_at, resumed_at`

// approvalNullTime maps the zero time to SQL NULL.
func approvalNullTime(t time.Time) sql.NullTime {
	if t.IsZero() {
		return sql.NullTime{}
	}
	return sql.NullTime{Time: t.UTC(), Valid: true}
}

func approvalTimeOrZero(n sql.NullTime) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return n.Time.UTC()
}

func scanWorkflowApproval(row rowScanner) (*business.WorkflowApproval, error) {
	a := &business.WorkflowApproval{}
	var expiresAt, decidedAt, claimedAt, resumedAt sql.NullTime
	if err := row.Scan(&a.ApprovalID, &a.TenantID, &a.WorkflowName, &a.ExecutionID, &a.StepID, &a.StepName,
		&a.Message, &a.ApproverPermission, &a.RequestedBy, &a.Status, &a.RequestedAt, &expiresAt, &a.DecidedBy,
		&decidedAt, &a.Justification, &a.CheckpointRef, &a.ResumeClaimedBy, &claimedAt, &resumedAt); err != nil {
		return nil, err
	}
	a.RequestedAt = a.RequestedAt.UTC()
	a.ExpiresAt = approvalTimeOrZero(expiresAt)
	a.DecidedAt = approvalTimeOrZero(decidedAt)
	a.ResumeClaimedAt = approvalTimeOrZero(claimedAt)
	a.ResumedAt = approvalTimeOrZero(resumedAt)
	return a, nil
}

func collectWorkflowApprovals(rows *sql.Rows) ([]*business.WorkflowApproval, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*business.WorkflowApproval, 0)
	for rows.Next() {
		a, err := scanWorkflowApproval(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan approval: %w", err)
		}
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to read approvals: %w", err)
	}
	return result, nil
}

// CreateApproval implements business.ApprovalStore.
func (s *DatabaseApprovalStore) CreateApproval(ctx context.Context, a *business.WorkflowApproval) error {
	if a == nil || a.TenantID == "" || a.ApprovalID == "" {
		return fmt.Errorf("approval requires a tenant id and an approval id")
	}
	if a.Status != "" && a.Status != business.ApprovalStatusPending {
		return fmt.Errorf("a new approval must be pending, got %q", a.Status)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO cfgms_workflow_approvals
		(approval_id, tenant_id, workflow_name, execution_id, step_id, step_name, message,
		 approver_permission, requested_by, status, requested_at, expires_at, checkpoint_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', $10, $11, $12)`,
		a.ApprovalID, a.TenantID, a.WorkflowName, a.ExecutionID, a.StepID, a.StepName, a.Message,
		a.ApproverPermission, a.RequestedBy, a.RequestedAt.UTC(), approvalNullTime(a.ExpiresAt), a.CheckpointRef)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return business.ErrApprovalAlreadyExists
	}
	if err != nil {
		return fmt.Errorf("failed to create approval: %w", err)
	}
	return nil
}

// GetApproval implements business.ApprovalStore.
func (s *DatabaseApprovalStore) GetApproval(ctx context.Context, tenantID, approvalID string) (*business.WorkflowApproval, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+workflowApprovalColumns+` FROM cfgms_workflow_approvals
		WHERE tenant_id = $1 AND approval_id = $2`, tenantID, approvalID)
	a, err := scanWorkflowApproval(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, business.ErrApprovalNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get approval: %w", err)
	}
	return a, nil
}

// ListPending implements business.ApprovalStore.
func (s *DatabaseApprovalStore) ListPending(ctx context.Context, tenantID string) ([]*business.WorkflowApproval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+workflowApprovalColumns+` FROM cfgms_workflow_approvals
		WHERE tenant_id = $1 AND status = 'pending' ORDER BY requested_at, approval_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list pending approvals: %w", err)
	}
	return collectWorkflowApprovals(rows)
}

// status reads the current status of one approval; ErrApprovalNotFound when absent.
// It explains why a conditional UPDATE matched no row.
func (s *DatabaseApprovalStore) status(ctx context.Context, tenantID, approvalID string) (string, error) {
	var status string
	err := s.db.QueryRowContext(ctx, `SELECT status FROM cfgms_workflow_approvals
		WHERE tenant_id = $1 AND approval_id = $2`, tenantID, approvalID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return "", business.ErrApprovalNotFound
	}
	if err != nil {
		return "", fmt.Errorf("failed to read approval: %w", err)
	}
	return status, nil
}

func isDecidedStatus(status string) bool {
	return status == business.ApprovalStatusApproved || status == business.ApprovalStatusRejected
}

// DecideApproval implements business.ApprovalStore.
func (s *DatabaseApprovalStore) DecideApproval(ctx context.Context, tenantID, approvalID, status, principal, justification string, at time.Time) error {
	if !isDecidedStatus(status) {
		return fmt.Errorf("a decision must be %q or %q, got %q",
			business.ApprovalStatusApproved, business.ApprovalStatusRejected, status)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_workflow_approvals
		SET status = $1, decided_by = $2, decided_at = $3, justification = $4
		WHERE tenant_id = $5 AND approval_id = $6 AND status = 'pending'`,
		status, principal, at.UTC(), justification, tenantID, approvalID)
	if err != nil {
		return fmt.Errorf("failed to decide approval: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	if _, err := s.status(ctx, tenantID, approvalID); err != nil {
		return err
	}
	return business.ErrApprovalAlreadyDecided
}

// ExpireDue implements business.ApprovalStore.
func (s *DatabaseApprovalStore) ExpireDue(ctx context.Context, now time.Time) ([]*business.WorkflowApproval, error) {
	rows, err := s.db.QueryContext(ctx, `UPDATE cfgms_workflow_approvals
		SET status = 'expired', decided_at = $1
		WHERE status = 'pending' AND expires_at IS NOT NULL AND expires_at <= $1
		RETURNING `+workflowApprovalColumns, now.UTC())
	if err != nil {
		return nil, fmt.Errorf("failed to expire approvals: %w", err)
	}
	return collectWorkflowApprovals(rows)
}

// ClaimResume implements business.ApprovalStore.
func (s *DatabaseApprovalStore) ClaimResume(ctx context.Context, tenantID, approvalID, node string, now time.Time, lease time.Duration) error {
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_workflow_approvals
		SET resume_claimed_by = $1, resume_claimed_at = $2
		WHERE tenant_id = $3 AND approval_id = $4
		  AND status IN ('approved', 'rejected') AND resumed_at IS NULL
		  AND (resume_claimed_by = '' OR resume_claimed_at IS NULL OR resume_claimed_at < $5)`,
		node, now.UTC(), tenantID, approvalID, now.Add(-lease).UTC())
	if err != nil {
		return fmt.Errorf("failed to claim approval resume: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	status, err := s.status(ctx, tenantID, approvalID)
	if err != nil {
		return err
	}
	if !isDecidedStatus(status) {
		return business.ErrApprovalNotDecided
	}
	return business.ErrApprovalAlreadyClaimed
}

// MarkResumed implements business.ApprovalStore.
func (s *DatabaseApprovalStore) MarkResumed(ctx context.Context, tenantID, approvalID string, now time.Time) error {
	res, err := s.db.ExecContext(ctx, `UPDATE cfgms_workflow_approvals SET resumed_at = $1
		WHERE tenant_id = $2 AND approval_id = $3
		  AND status IN ('approved', 'rejected') AND resumed_at IS NULL`,
		now.UTC(), tenantID, approvalID)
	if err != nil {
		return fmt.Errorf("failed to mark approval resumed: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil || n > 0 {
		return err
	}
	status, err := s.status(ctx, tenantID, approvalID)
	if err != nil {
		return err
	}
	if !isDecidedStatus(status) {
		return business.ErrApprovalNotDecided
	}
	return nil // already resumed: idempotent
}

// ListUnresumed implements business.ApprovalStore.
func (s *DatabaseApprovalStore) ListUnresumed(ctx context.Context, now time.Time, lease time.Duration) ([]*business.WorkflowApproval, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+workflowApprovalColumns+` FROM cfgms_workflow_approvals
		WHERE status IN ('approved', 'rejected') AND resumed_at IS NULL
		  AND (resume_claimed_by = '' OR resume_claimed_at IS NULL OR resume_claimed_at < $1)
		ORDER BY requested_at, approval_id`, now.Add(-lease).UTC())
	if err != nil {
		return nil, fmt.Errorf("failed to list unresumed approvals: %w", err)
	}
	return collectWorkflowApprovals(rows)
}
