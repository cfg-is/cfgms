// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package flatfile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Compile-time assertion.
var _ business.ApprovalStore = (*FlatFileApprovalStore)(nil)

// FlatFileApprovalStore implements business.ApprovalStore backed by a single JSON file.
//
// File layout: <root>/approvals/workflow_approvals.json
//
// Approvals for all tenants live in one JSON array, always addressed by
// (tenant_id, approval_id). Writes are atomic (temp-file + rename) and sync.Mutex
// serializes every read-modify-write within the process, which makes each state
// transition a compare-and-set. The file holds only the checkpoint reference,
// never checkpoint contents.
type FlatFileApprovalStore struct {
	root string
	mu   sync.Mutex
}

// approvalJSON is the on-disk representation of a workflow approval.
type approvalJSON struct {
	ApprovalID         string     `json:"approval_id"`
	TenantID           string     `json:"tenant_id"`
	WorkflowName       string     `json:"workflow_name"`
	ExecutionID        string     `json:"execution_id"`
	StepID             string     `json:"step_id"`
	StepName           string     `json:"step_name"`
	Message            string     `json:"message,omitempty"`
	ApproverPermission string     `json:"approver_permission,omitempty"`
	RequestedBy        string     `json:"requested_by,omitempty"`
	Status             string     `json:"status"`
	RequestedAt        time.Time  `json:"requested_at"`
	ExpiresAt          *time.Time `json:"expires_at,omitempty"`
	DecidedBy          string     `json:"decided_by,omitempty"`
	DecidedAt          *time.Time `json:"decided_at,omitempty"`
	Justification      string     `json:"justification,omitempty"`
	CheckpointRef      string     `json:"checkpoint_ref,omitempty"`
	ResumeClaimedBy    string     `json:"resume_claimed_by,omitempty"`
	ResumeClaimedAt    *time.Time `json:"resume_claimed_at,omitempty"`
	ResumedAt          *time.Time `json:"resumed_at,omitempty"`
}

// NewFlatFileApprovalStore creates a FlatFileApprovalStore rooted at <root>/approvals.
// The directory is created if it does not exist.
func NewFlatFileApprovalStore(root string) (*FlatFileApprovalStore, error) {
	if err := os.MkdirAll(filepath.Join(root, "approvals"), 0750); err != nil {
		return nil, fmt.Errorf("flatfile: failed to create approvals directory: %w", err)
	}
	return &FlatFileApprovalStore{root: root}, nil
}

func (s *FlatFileApprovalStore) dataFilePath() string {
	return filepath.Join(s.root, "approvals", "workflow_approvals.json")
}

// load reads the approvals file; a missing file is an empty store.
// Must be called with the lock held.
func (s *FlatFileApprovalStore) load() ([]approvalJSON, error) {
	raw, err := readFile(s.dataFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("flatfile: failed to read approvals file: %w", err)
	}
	var approvals []approvalJSON
	if err := json.Unmarshal(raw, &approvals); err != nil {
		return nil, fmt.Errorf("flatfile: failed to parse approvals file: %w", err)
	}
	return approvals, nil
}

// save atomically writes approvals. Must be called with the lock held.
func (s *FlatFileApprovalStore) save(approvals []approvalJSON) error {
	if approvals == nil {
		approvals = []approvalJSON{}
	}
	raw, err := json.MarshalIndent(approvals, "", "  ")
	if err != nil {
		return fmt.Errorf("flatfile: failed to marshal approvals: %w", err)
	}
	return writeAtomic(s.dataFilePath(), raw)
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func timeVal(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func toApprovalJSON(a *business.WorkflowApproval) approvalJSON {
	return approvalJSON{
		ApprovalID: a.ApprovalID, TenantID: a.TenantID, WorkflowName: a.WorkflowName,
		ExecutionID: a.ExecutionID, StepID: a.StepID, StepName: a.StepName, Message: a.Message,
		ApproverPermission: a.ApproverPermission, RequestedBy: a.RequestedBy, Status: a.Status,
		RequestedAt: a.RequestedAt.UTC(), ExpiresAt: timePtr(a.ExpiresAt),
		DecidedBy: a.DecidedBy, DecidedAt: timePtr(a.DecidedAt), Justification: a.Justification,
		CheckpointRef: a.CheckpointRef, ResumeClaimedBy: a.ResumeClaimedBy,
		ResumeClaimedAt: timePtr(a.ResumeClaimedAt), ResumedAt: timePtr(a.ResumedAt),
	}
}

func toWorkflowApproval(a approvalJSON) *business.WorkflowApproval {
	return &business.WorkflowApproval{
		ApprovalID: a.ApprovalID, TenantID: a.TenantID, WorkflowName: a.WorkflowName,
		ExecutionID: a.ExecutionID, StepID: a.StepID, StepName: a.StepName, Message: a.Message,
		ApproverPermission: a.ApproverPermission, RequestedBy: a.RequestedBy, Status: a.Status,
		RequestedAt: a.RequestedAt, ExpiresAt: timeVal(a.ExpiresAt),
		DecidedBy: a.DecidedBy, DecidedAt: timeVal(a.DecidedAt), Justification: a.Justification,
		CheckpointRef: a.CheckpointRef, ResumeClaimedBy: a.ResumeClaimedBy,
		ResumeClaimedAt: timeVal(a.ResumeClaimedAt), ResumedAt: timeVal(a.ResumedAt),
	}
}

func isDecided(a approvalJSON) bool {
	return a.Status == business.ApprovalStatusApproved || a.Status == business.ApprovalStatusRejected
}

// claimable reports whether a decided, unresumed approval is unclaimed or its
// claim is older than lease.
func claimable(a approvalJSON, now time.Time, lease time.Duration) bool {
	return a.ResumedAt == nil && (a.ResumeClaimedBy == "" || a.ResumeClaimedAt == nil ||
		now.Sub(*a.ResumeClaimedAt) > lease)
}

// find returns the index of (tenantID, approvalID) or -1.
func findApproval(approvals []approvalJSON, tenantID, approvalID string) int {
	for i, a := range approvals {
		if a.TenantID == tenantID && a.ApprovalID == approvalID {
			return i
		}
	}
	return -1
}

// CreateApproval implements business.ApprovalStore.
func (s *FlatFileApprovalStore) CreateApproval(_ context.Context, approval *business.WorkflowApproval) error {
	if approval == nil || approval.TenantID == "" || approval.ApprovalID == "" {
		return fmt.Errorf("flatfile: approval requires a tenant id and an approval id")
	}
	if approval.Status != "" && approval.Status != business.ApprovalStatusPending {
		return fmt.Errorf("flatfile: a new approval must be pending, got %q", approval.Status)
	}
	rec := toApprovalJSON(approval)
	rec.Status = business.ApprovalStatusPending

	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return err
	}
	if findApproval(approvals, rec.TenantID, rec.ApprovalID) >= 0 {
		return business.ErrApprovalAlreadyExists
	}
	return s.save(append(approvals, rec))
}

// GetApproval implements business.ApprovalStore.
func (s *FlatFileApprovalStore) GetApproval(_ context.Context, tenantID, approvalID string) (*business.WorkflowApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return nil, err
	}
	i := findApproval(approvals, tenantID, approvalID)
	if i < 0 {
		return nil, business.ErrApprovalNotFound
	}
	return toWorkflowApproval(approvals[i]), nil
}

// ListPending implements business.ApprovalStore.
func (s *FlatFileApprovalStore) ListPending(_ context.Context, tenantID string) ([]*business.WorkflowApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return nil, err
	}
	result := make([]*business.WorkflowApproval, 0)
	for _, a := range approvals {
		if a.TenantID == tenantID && a.Status == business.ApprovalStatusPending {
			result = append(result, toWorkflowApproval(a))
		}
	}
	sortApprovals(result)
	return result, nil
}

// DecideApproval implements business.ApprovalStore.
func (s *FlatFileApprovalStore) DecideApproval(_ context.Context, tenantID, approvalID, status, principal, justification string, at time.Time) error {
	if status != business.ApprovalStatusApproved && status != business.ApprovalStatusRejected {
		return fmt.Errorf("flatfile: a decision must be %q or %q, got %q",
			business.ApprovalStatusApproved, business.ApprovalStatusRejected, status)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return err
	}
	i := findApproval(approvals, tenantID, approvalID)
	if i < 0 {
		return business.ErrApprovalNotFound
	}
	if approvals[i].Status != business.ApprovalStatusPending {
		return business.ErrApprovalAlreadyDecided
	}
	approvals[i].Status = status
	approvals[i].DecidedBy = principal
	approvals[i].DecidedAt = timePtr(at)
	approvals[i].Justification = justification
	return s.save(approvals)
}

// ExpireDue implements business.ApprovalStore.
func (s *FlatFileApprovalStore) ExpireDue(_ context.Context, now time.Time) ([]*business.WorkflowApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return nil, err
	}
	flipped := make([]*business.WorkflowApproval, 0)
	for i, a := range approvals {
		if a.Status != business.ApprovalStatusPending || a.ExpiresAt == nil || a.ExpiresAt.After(now) {
			continue
		}
		approvals[i].Status = business.ApprovalStatusExpired
		approvals[i].DecidedAt = timePtr(now)
		flipped = append(flipped, toWorkflowApproval(approvals[i]))
	}
	if len(flipped) == 0 {
		return flipped, nil
	}
	if err := s.save(approvals); err != nil {
		return nil, err
	}
	sortApprovals(flipped)
	return flipped, nil
}

// ClaimResume implements business.ApprovalStore.
func (s *FlatFileApprovalStore) ClaimResume(_ context.Context, tenantID, approvalID, node string, now time.Time, lease time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return err
	}
	i := findApproval(approvals, tenantID, approvalID)
	if i < 0 {
		return business.ErrApprovalNotFound
	}
	if !isDecided(approvals[i]) {
		return business.ErrApprovalNotDecided
	}
	if !claimable(approvals[i], now, lease) {
		return business.ErrApprovalAlreadyClaimed
	}
	approvals[i].ResumeClaimedBy = node
	approvals[i].ResumeClaimedAt = timePtr(now)
	return s.save(approvals)
}

// MarkResumed implements business.ApprovalStore.
func (s *FlatFileApprovalStore) MarkResumed(_ context.Context, tenantID, approvalID string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return err
	}
	i := findApproval(approvals, tenantID, approvalID)
	if i < 0 {
		return business.ErrApprovalNotFound
	}
	if !isDecided(approvals[i]) {
		return business.ErrApprovalNotDecided
	}
	if approvals[i].ResumedAt != nil {
		return nil
	}
	approvals[i].ResumedAt = timePtr(now)
	return s.save(approvals)
}

// ListUnresumed implements business.ApprovalStore.
func (s *FlatFileApprovalStore) ListUnresumed(_ context.Context, now time.Time, lease time.Duration) ([]*business.WorkflowApproval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	approvals, err := s.load()
	if err != nil {
		return nil, err
	}
	result := make([]*business.WorkflowApproval, 0)
	for _, a := range approvals {
		if isDecided(a) && claimable(a, now, lease) {
			result = append(result, toWorkflowApproval(a))
		}
	}
	sortApprovals(result)
	return result, nil
}

// sortApprovals orders approvals oldest first, with the approval id as tiebreaker.
func sortApprovals(list []*business.WorkflowApproval) {
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].RequestedAt.Equal(list[j].RequestedAt) {
			return list[i].RequestedAt.Before(list[j].RequestedAt)
		}
		return list[i].ApprovalID < list[j].ApprovalID
	})
}
