// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package business

import (
	"context"
	"errors"
	"time"
)

// Approval statuses held in WorkflowApproval.Status.
const (
	ApprovalStatusPending  = "pending"
	ApprovalStatusApproved = "approved"
	ApprovalStatusRejected = "rejected"
	ApprovalStatusExpired  = "expired"
)

var (
	// ErrApprovalNotFound is returned when no approval exists for (tenantID, approvalID).
	ErrApprovalNotFound = errors.New("approval not found")

	// ErrApprovalAlreadyExists is returned by CreateApproval when (tenantID, approvalID) is taken.
	ErrApprovalAlreadyExists = errors.New("approval already exists")

	// ErrApprovalAlreadyDecided is returned by DecideApproval when the approval has left
	// the pending state (decided by another caller, or expired).
	ErrApprovalAlreadyDecided = errors.New("approval already decided")

	// ErrApprovalNotDecided is returned by ClaimResume and MarkResumed for an approval
	// that is still pending or has expired: only approved or rejected approvals resume.
	ErrApprovalNotDecided = errors.New("approval not decided")

	// ErrApprovalAlreadyClaimed is returned by ClaimResume when another node holds a live
	// claim, or when the approval has already been resumed.
	ErrApprovalAlreadyClaimed = errors.New("approval resume already claimed")
)

// WorkflowApproval is one pending-or-decided human approval gate of a workflow run.
//
// The workflow checkpoint (variables, step outputs, possibly credentials) is never
// held here. The engine writes it through the secrets provider and records only the
// reference in CheckpointRef, so this store never sees checkpoint contents.
type WorkflowApproval struct {
	ApprovalID         string
	TenantID           string
	WorkflowName       string
	ExecutionID        string
	StepID             string
	StepName           string
	Message            string
	ApproverPermission string
	// RequestedBy is the principal that started the run.
	RequestedBy string
	// Status is one of the ApprovalStatus* constants.
	Status      string
	RequestedAt time.Time
	// ExpiresAt is the deadline after which ExpireDue flips a pending approval.
	// The zero value means the approval never expires.
	ExpiresAt     time.Time
	DecidedBy     string
	DecidedAt     time.Time
	Justification string
	// CheckpointRef references the checkpoint held in the secrets provider.
	CheckpointRef string
	// ResumeClaimedBy and ResumeClaimedAt record the node that currently holds the
	// right to resume the run, and when it took it.
	ResumeClaimedBy string
	ResumeClaimedAt time.Time
	// ResumedAt is set once the run has been resumed; it ends further claims.
	ResumedAt time.Time
}

// ApprovalStore defines the durable, tenant-scoped storage contract for workflow
// approvals. Every method that addresses one approval takes the tenant ID, and no
// per-tenant method crosses tenants. All state transitions are compare-and-set, so
// concurrent callers on one node or on different controller nodes cannot both win.
type ApprovalStore interface {
	// CreateApproval stores a new approval. TenantID and ApprovalID are required, and
	// Status must be empty (treated as pending) or pending. Returns
	// ErrApprovalAlreadyExists when (TenantID, ApprovalID) is already stored.
	CreateApproval(ctx context.Context, approval *WorkflowApproval) error

	// GetApproval returns the approval for (tenantID, approvalID), or ErrApprovalNotFound.
	GetApproval(ctx context.Context, tenantID, approvalID string) (*WorkflowApproval, error)

	// ListPending returns tenantID's pending approvals, oldest first. Returns an empty
	// (non-nil) slice when there are none.
	ListPending(ctx context.Context, tenantID string) ([]*WorkflowApproval, error)

	// DecideApproval moves a pending approval to status (approved or rejected),
	// recording principal, justification and at. It is a compare-and-set from pending:
	// of any number of concurrent calls exactly one succeeds and the rest get
	// ErrApprovalAlreadyDecided. Returns ErrApprovalNotFound for an unknown approval.
	DecideApproval(ctx context.Context, tenantID, approvalID, status, principal, justification string, at time.Time) error

	// ExpireDue flips every pending approval, across all tenants, whose non-zero
	// ExpiresAt is at or before now to expired, and returns the approvals it flipped so
	// the caller can fail their runs. Decided approvals are never touched.
	ExpireDue(ctx context.Context, now time.Time) ([]*WorkflowApproval, error)

	// ClaimResume records node as the resumer of a decided approval. It is a
	// compare-and-set from decided-and-not-resumed: it succeeds when the approval is
	// unclaimed or when the existing claim is older than lease (a crashed claimer is
	// retried). Otherwise it returns ErrApprovalAlreadyClaimed; for an approval that is
	// pending or expired it returns ErrApprovalNotDecided.
	ClaimResume(ctx context.Context, tenantID, approvalID, node string, now time.Time, lease time.Duration) error

	// MarkResumed records that the run has been resumed, which ends further claims.
	// Idempotent: the first ResumedAt is kept. Returns ErrApprovalNotDecided for an
	// approval that is pending or expired.
	MarkResumed(ctx context.Context, tenantID, approvalID string, now time.Time) error

	// ListUnresumed returns decided approvals, across all tenants, that have not been
	// resumed and are unclaimed or whose claim is older than lease. It exists for
	// engine recovery only.
	ListUnresumed(ctx context.Context, now time.Time, lease time.Duration) ([]*WorkflowApproval, error)
}
