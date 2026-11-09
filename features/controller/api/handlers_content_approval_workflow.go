// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// workflowApprovalResourceType is the audit resource type of a workflow approval.
const workflowApprovalResourceType = "workflow_approval"

// WorkflowApprovalState is the evaluator state of one workflow version.
type WorkflowApprovalState string

const (
	// WorkflowApprovalApproved means an approval bound to the current approval hash exists.
	WorkflowApprovalApproved WorkflowApprovalState = "approved"
	// WorkflowApprovalPending means no such approval exists.
	WorkflowApprovalPending WorkflowApprovalState = "pending"
)

// ApproveWorkflowRequest is the body of POST /api/v1/automation/approvals/workflows.
// ApprovalHash is the value the presence tap covers (WorkflowApprovalHash, which
// includes the owner tenant). ContentHash is optional; when present it must equal the
// canonical hash of the stored version. A body without ApprovalHash is refused.
type ApproveWorkflowRequest struct {
	WorkflowID   string `json:"workflow_id"`
	Version      string `json:"version"`
	ApprovalHash string `json:"approval_hash"`
	ContentHash  string `json:"content_hash,omitempty"`
}

// WorkflowApprovalInfo is an approval as shown to the UI.
type WorkflowApprovalInfo struct {
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
	Method     string `json:"method"`
}

// WorkflowApprovalEntry is one workflow version with its evaluator state. It carries
// both hashes so the UI can show what is being approved.
type WorkflowApprovalEntry struct {
	WorkflowID   string                `json:"workflow_id"`
	Version      string                `json:"version"`
	ContentHash  string                `json:"content_hash"`
	ApprovalHash string                `json:"approval_hash"`
	State        WorkflowApprovalState `json:"state"`
	Reason       string                `json:"reason"`
	Approval     *WorkflowApprovalInfo `json:"approval,omitempty"`
}

// WorkflowApprovalListResponse is the body of GET /api/v1/automation/approvals/workflows.
type WorkflowApprovalListResponse struct {
	Mode      ApprovalMode            `json:"mode"`
	Workflows []WorkflowApprovalEntry `json:"workflows"`
}

// workflowApprovalHashOf returns the canonical content hash of vw and the approval
// hash an approval of it is bound to, or "" for both when the version cannot be
// hashed. owner is the tenant that holds the stored object.
func workflowApprovalHashOf(owner string, vw *workflow.VersionedWorkflow) (contentHash, approvalHash string) {
	if vw == nil || vw.Name == "" {
		return "", ""
	}
	contentHash, err := workflow.CanonicalWorkflowHash(vw)
	if err != nil {
		return "", ""
	}
	return contentHash, WorkflowApprovalHash(owner, vw.Name, vw.SemanticVersion.String(), contentHash)
}

// evaluateWorkflowApproval is the evaluator state of a workflow version: approved
// only while a record bound to its current approval hash exists. It reads the store
// on every call, so a withdrawn approval reads as pending at once.
func (st *ContentApprovalStore) evaluateWorkflowApproval(ctx context.Context, owner string, vw *workflow.VersionedWorkflow) (WorkflowApprovalState, *ContentApproval, string, string, error) {
	_, hash := workflowApprovalHashOf(owner, vw)
	if hash == "" {
		return WorkflowApprovalPending, nil, "", "the workflow version cannot be hashed and so cannot be approved", nil
	}
	a, err := st.GetApproval(ctx, owner, LibraryKindWorkflow, vw.Name, vw.SemanticVersion.String(), hash)
	if err != nil {
		return "", nil, hash, "", err
	}
	if a == nil {
		return WorkflowApprovalPending, nil, hash, "no approval exists for this exact version and content", nil
	}
	return WorkflowApprovalApproved, a, hash, "an approval is recorded for this exact version and content", nil
}

// workflowApprovalDeps returns the wired approval store, the workflow config store and
// the caller's own tenant, or writes the refusal.
func (s *Server) workflowApprovalDeps(w http.ResponseWriter, r *http.Request) (*ContentApprovalStore, cfgconfig.ConfigStore, string, bool) {
	s.mu.RLock()
	st, h := s.contentApprovalStore, s.workflowHandler
	s.mu.RUnlock()
	if st == nil || h == nil || h.configStore == nil || s.tenantManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Workflow approvals not available", "SERVICE_UNAVAILABLE")
		return nil, nil, "", false
	}
	tenantID, ok := callerOwnTenant(r.Context())
	if !ok {
		s.writeErrorResponse(w, http.StatusForbidden, "No tenant scope", "NO_TENANT_SCOPE")
		return nil, nil, "", false
	}
	return st, h.configStore, tenantID, true
}

// recordWorkflowApprovalAudit writes the audit event and returns its error. The callers
// write it BEFORE changing the approval, so an audit failure changes nothing.
func (s *Server) recordWorkflowApprovalAudit(ctx context.Context, action, owner string, p *Principal, id, version, contentHash, approvalHash string) error {
	if s.auditManager == nil {
		return errors.New("audit manager not configured")
	}
	b := audit.NewEventBuilder().
		Tenant(owner).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(p.ID, business.AuditUserTypeHuman).
		Resource(workflowApprovalResourceType, id, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Detail("id", logging.SanitizeLogValue(id)).
		Detail("version", logging.SanitizeLogValue(version)).
		Detail("content_hash", logging.SanitizeLogValue(contentHash)).
		Detail("approval_hash", logging.SanitizeLogValue(approvalHash)).
		Detail("actor", logging.SanitizeLogValue(p.ID))
	return s.auditManager.RecordEvent(ctx, b)
}

// matchesStored reports whether the body names exactly what the controller holds now.
// The approval hash is required; the content hash is checked when present.
func (r ApproveWorkflowRequest) matchesStored(approvalHash, contentHash string) bool {
	if subtle.ConstantTimeCompare([]byte(r.ApprovalHash), []byte(approvalHash)) != 1 {
		return false
	}
	return r.ContentHash == "" || subtle.ConstantTimeCompare([]byte(r.ContentHash), []byte(contentHash)) == 1
}

// resolveApprovableWorkflow loads the exact version through the inherited resolver with
// the caller's own tenant as both run tenant and ceiling, so only a workflow the caller's
// tenant holds can be approved. It returns the version and its owner tenant.
func (s *Server) resolveApprovableWorkflow(ctx context.Context, cs cfgconfig.ConfigStore, callerTenant, name, version string) (*workflow.VersionedWorkflow, string, error) {
	chain, err := tenant.LibraryChain(ctx, s.tenantManager, callerTenant, callerTenant)
	if err != nil {
		return nil, "", fmt.Errorf("resolve tenant chain: %w", err)
	}
	return workflow.ResolveInherited(ctx, cs, chain, name, version)
}

// approvableWorkflow is the version an approve request names, as the controller holds it.
type approvableWorkflow struct {
	req          ApproveWorkflowRequest
	vw           *workflow.VersionedWorkflow
	owner        string
	contentHash  string
	approvalHash string
}

// decodeApproveWorkflowRequest decodes and validates the approve body. It writes the
// refusal and returns ok=false when the body is unusable.
func (s *Server) decodeApproveWorkflowRequest(w http.ResponseWriter, r *http.Request) (ApproveWorkflowRequest, bool) {
	var req ApproveWorkflowRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return req, false
	}
	if req.WorkflowID == "" || req.Version == "" || req.ApprovalHash == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "workflow_id, version and approval_hash are required", "MISSING_FIELDS")
		return req, false
	}
	return req, true
}

// loadApprovableWorkflow decodes the approve body, loads the version and checks the body
// hashes against what the controller holds now. It writes the refusal and returns
// ok=false on any difference.
func (s *Server) loadApprovableWorkflow(w http.ResponseWriter, r *http.Request, cs cfgconfig.ConfigStore, callerTenant string) (approvableWorkflow, bool) {
	req, ok := s.decodeApproveWorkflowRequest(w, r)
	if !ok {
		return approvableWorkflow{}, false
	}
	vw, owner, err := s.resolveApprovableWorkflow(r.Context(), cs, callerTenant, req.WorkflowID, req.Version)
	if err != nil || vw == nil {
		if err != nil && !errors.Is(err, workflow.ErrWorkflowNotFound) {
			s.logger.Warn("Workflow approval lookup failed", "error", logging.SanitizeLogValue(err.Error()))
		}
		s.writeErrorResponse(w, http.StatusNotFound, "Workflow version not found", "NOT_FOUND")
		return approvableWorkflow{}, false
	}
	contentHash, approvalHash := workflowApprovalHashOf(owner, vw)
	if approvalHash == "" {
		s.writeErrorResponse(w, http.StatusUnprocessableEntity, "Workflow cannot be approved", "NOT_APPROVABLE")
		return approvableWorkflow{}, false
	}
	if !req.matchesStored(approvalHash, contentHash) {
		s.writeErrorResponse(w, http.StatusConflict, "Hash does not match the stored workflow version", "HASH_MISMATCH")
		return approvableWorkflow{}, false
	}
	return approvableWorkflow{req: req, vw: vw, owner: owner, contentHash: contentHash, approvalHash: approvalHash}, true
}

// handleApproveWorkflow handles POST /api/v1/automation/approvals/workflows. The record
// is written under the OWNER tenant of the workflow.
func (s *Server) handleApproveWorkflow(w http.ResponseWriter, r *http.Request) {
	p, ok := s.humanApprover(w, r)
	if !ok {
		return
	}
	st, cs, callerTenant, ok := s.workflowApprovalDeps(w, r)
	if !ok {
		return
	}
	target, ok := s.loadApprovableWorkflow(w, r, cs, callerTenant)
	if !ok {
		return
	}
	vw, owner, contentHash, approvalHash := target.vw, target.owner, target.contentHash, target.approvalHash
	version := vw.SemanticVersion.String()
	if err := s.recordWorkflowApprovalAudit(r.Context(), auditActionContentApprovalApprove, owner, p, vw.Name, version, contentHash, approvalHash); err != nil {
		s.writeAuditFailure(w, auditActionContentApprovalApprove, err)
		return
	}
	rec := ContentApproval{
		TenantID: owner, Kind: LibraryKindWorkflow, ContentID: vw.Name, Version: version,
		ContentHash: approvalHash, ApprovedBy: p.ID, Method: ApprovalMethodApproveTap,
	}
	if err := st.PutApproval(r.Context(), rec); err != nil {
		s.logger.Error("Failed to store workflow approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record approval", "INTERNAL_ERROR")
		return
	}
	s.writeResponse(w, http.StatusCreated, WorkflowApprovalEntry{
		WorkflowID: vw.Name, Version: version, ContentHash: contentHash, ApprovalHash: approvalHash,
		State: WorkflowApprovalApproved, Reason: "an approval is recorded for this exact version and content",
		Approval: &WorkflowApprovalInfo{
			ApprovedBy: p.ID, ApprovedAt: time.Now().UTC().Format(time.RFC3339), Method: string(ApprovalMethodApproveTap),
		},
	})
}

// handleRevokeWorkflowApproval handles
// DELETE /api/v1/automation/approvals/workflows/{id}/{version}/{approval_hash}.
// The approval is found by its stored key, not recomputed from the workflow, so an
// approval of a version that has since changed can still be withdrawn.
func (s *Server) handleRevokeWorkflowApproval(w http.ResponseWriter, r *http.Request) {
	p, ok := s.humanApprover(w, r)
	if !ok {
		return
	}
	//duplication:justified features/controller/api/handlers_content_approval.go -- workflow counterpart of handleRevokeScriptApproval and handleListScriptApprovals; the script handlers are bound to the script resolver and resource type, and that file is outside this story's scope
	st, _, owner, ok := s.workflowApprovalDeps(w, r)
	if !ok {
		return
	}
	vars := mux.Vars(r)
	id, version, hash := vars["id"], vars["version"], vars["approval_hash"]
	existing, err := st.GetApproval(r.Context(), owner, LibraryKindWorkflow, id, version, hash)
	if err != nil {
		s.logger.Error("Failed to read workflow approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read approval", "INTERNAL_ERROR")
		return
	}
	if existing == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Approval not found", "NOT_FOUND")
		return
	}
	if err := s.recordWorkflowApprovalAudit(r.Context(), auditActionContentApprovalRevoke, owner, p, id, version, "", hash); err != nil {
		s.writeAuditFailure(w, auditActionContentApprovalRevoke, err)
		return
	}
	if _, err := st.DeleteApproval(r.Context(), owner, LibraryKindWorkflow, id, version, hash); err != nil {
		s.logger.Error("Failed to delete workflow approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to withdraw approval", "INTERNAL_ERROR")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListWorkflowApprovals handles GET /api/v1/automation/approvals/workflows: the
// caller tenant's workflow library, every version with its evaluator state.
func (s *Server) handleListWorkflowApprovals(w http.ResponseWriter, r *http.Request) {
	st, cs, owner, ok := s.workflowApprovalDeps(w, r)
	if !ok {
		return
	}
	mode, err := st.GetMode(r.Context(), owner, LibraryKindWorkflow)
	if err != nil {
		s.logger.Error("Failed to read library mode", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read library mode", "INTERNAL_ERROR")
		return
	}
	entries, err := workflowApprovalEntries(r.Context(), st, cs, owner)
	if err != nil {
		s.logger.Error("Failed to list workflow approvals", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list approvals", "INTERNAL_ERROR")
		return
	}
	s.writeSuccessResponse(w, WorkflowApprovalListResponse{Mode: mode, Workflows: entries})
}

func workflowApprovalEntries(ctx context.Context, st *ContentApprovalStore, cs cfgconfig.ConfigStore, owner string) ([]WorkflowApprovalEntry, error) {
	ws := workflow.NewWorkflowStore(cs, owner)
	latest, err := ws.ListWorkflows(ctx)
	if err != nil {
		return nil, fmt.Errorf("list library: %w", err)
	}
	out := []WorkflowApprovalEntry{}
	for _, l := range latest {
		versions, err := ws.ListWorkflowVersions(ctx, l.Name)
		if err != nil {
			return nil, fmt.Errorf("list versions: %w", err)
		}
		for _, vw := range versions {
			e, err := workflowApprovalEntry(ctx, st, owner, vw)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].WorkflowID != out[j].WorkflowID {
			return out[i].WorkflowID < out[j].WorkflowID
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// workflowApprovalEntry builds the list entry of one version.
func workflowApprovalEntry(ctx context.Context, st *ContentApprovalStore, owner string, vw *workflow.VersionedWorkflow) (WorkflowApprovalEntry, error) {
	state, a, approvalHash, reason, err := st.evaluateWorkflowApproval(ctx, owner, vw)
	if err != nil {
		return WorkflowApprovalEntry{}, err
	}
	contentHash, _ := workflowApprovalHashOf(owner, vw)
	e := WorkflowApprovalEntry{
		WorkflowID: vw.Name, Version: vw.SemanticVersion.String(), ContentHash: contentHash,
		ApprovalHash: approvalHash, State: state, Reason: reason,
	}
	if a != nil {
		e.Approval = &WorkflowApprovalInfo{ApprovedBy: a.ApprovedBy, ApprovedAt: a.ApprovedAt.Format(time.RFC3339), Method: string(a.Method)}
	}
	return e, nil
}
