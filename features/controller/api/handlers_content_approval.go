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

	"github.com/cfgis/cfgms/features/modules/stdlib/script"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// Audit actions of the script approval routes.
const (
	auditActionContentApprovalApprove = "content_approval.approve"
	auditActionContentApprovalRevoke  = "content_approval.revoke"
)

// ScriptApprovalState is the evaluator state of one script version.
type ScriptApprovalState string

const (
	// ScriptApprovalApproved means an approval bound to the current approval hash exists.
	ScriptApprovalApproved ScriptApprovalState = "approved"
	// ScriptApprovalPending means no such approval exists.
	ScriptApprovalPending ScriptApprovalState = "pending"
)


// ContentApprovalStore returns the wired content approval store, or nil when
// unwired. Exposed so controller startup wiring can be regression-tested.
func (s *Server) ContentApprovalStore() *ContentApprovalStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.contentApprovalStore
}

// ApproveScriptRequest is the body of POST /api/v1/automation/approvals/scripts.
// ApprovalHash is the value the presence tap covers: it spans shell, timeout and
// parameters as well as content. ContentHash is optional; when present it must
// equal the stored content hash. A body without ApprovalHash is refused.
type ApproveScriptRequest struct {
	ScriptID     string `json:"script_id"`
	Version      string `json:"version"`
	ApprovalHash string `json:"approval_hash"`
	ContentHash  string `json:"content_hash,omitempty"`
}

// ScriptApprovalInfo is an approval as shown to the UI.
type ScriptApprovalInfo struct {
	ApprovedBy string `json:"approved_by"`
	ApprovedAt string `json:"approved_at"`
	Method     string `json:"method"`
}

// ScriptApprovalEntry is one script version with its evaluator state. It carries
// both hashes so the UI can show what is being approved.
type ScriptApprovalEntry struct {
	ScriptID     string              `json:"script_id"`
	Version      string              `json:"version"`
	ContentHash  string              `json:"content_hash"`
	ApprovalHash string              `json:"approval_hash"`
	State        ScriptApprovalState `json:"state"`
	Approval     *ScriptApprovalInfo `json:"approval,omitempty"`
}

// ScriptApprovalListResponse is the body of GET /api/v1/automation/approvals/scripts.
type ScriptApprovalListResponse struct {
	Mode    ApprovalMode          `json:"mode"`
	Scripts []ScriptApprovalEntry `json:"scripts"`
}

// scriptVersionLibrary is implemented by a tenant-resolving repository that can
// open one tenant's library to enumerate its versions.
type scriptVersionLibrary interface {
	ForTenant(tenantID string) (*script.GitScriptRepository, error)
}

// evaluateScriptApproval is the evaluator for the approve mode: a version is
// approved only while a record bound to its current approval hash exists. It reads
// the store on every call, so a withdrawn approval reads as pending at once.
func (st *ContentApprovalStore) evaluateScriptApproval(ctx context.Context, owner string, vs *script.VersionedScript) (ScriptApprovalState, *ContentApproval, string, error) {
	hash := script.ScriptApprovalHash(owner, vs)
	if hash == "" {
		return ScriptApprovalPending, nil, "", nil
	}
	a, err := st.GetApproval(ctx, owner, LibraryKindScript, vs.Metadata.ID, vs.Metadata.Version.String(), hash)
	if err != nil {
		return "", nil, hash, err
	}
	if a == nil {
		return ScriptApprovalPending, nil, hash, nil
	}
	return ScriptApprovalApproved, a, hash, nil
}

// approvalDeps returns the wired store and the caller's own tenant, or writes the
// refusal. The caller's tenant must own the library the script is in.
func (s *Server) approvalDeps(w http.ResponseWriter, r *http.Request) (*ContentApprovalStore, script.TenantScriptResolver, string, bool) {
	s.mu.RLock()
	st, repo := s.contentApprovalStore, s.scriptRepo
	s.mu.RUnlock()
	resolver, isResolver := repo.(script.TenantScriptResolver)
	if st == nil || !isResolver {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Script approvals not available", "SERVICE_UNAVAILABLE")
		return nil, nil, "", false
	}
	tenant, ok := callerOwnTenant(r.Context())
	if !ok {
		s.writeErrorResponse(w, http.StatusForbidden, "No tenant scope", "NO_TENANT_SCOPE")
		return nil, nil, "", false
	}
	return st, resolver, tenant, true
}

// humanApprover returns the approving principal. Only a human channel may approve
// or withdraw: an API key, a relay or a grant principal never does, whatever the
// assurance gate in front of the route decided.
func (s *Server) humanApprover(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	p, _ := r.Context().Value(principalContextKey).(*Principal)
	if p == nil || p.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, false
	}
	switch p.Channel {
	case AuthChannelWebCookie, AuthChannelCfgBearer, AuthChannelMTLS:
		return p, true
	}
	s.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions", "INSUFFICIENT_PERMISSIONS")
	return nil, false
}

// recordContentApprovalAudit writes the audit event and returns its error. The
// callers write it BEFORE changing the approval, so an audit failure changes nothing.
func (s *Server) recordContentApprovalAudit(ctx context.Context, action, owner string, p *Principal, id, version, contentHash, approvalHash string) error {
	if s.auditManager == nil {
		return errors.New("audit manager not configured")
	}
	b := audit.NewEventBuilder().
		Tenant(owner).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(p.ID, business.AuditUserTypeHuman).
		Resource("script_approval", id, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Detail("id", logging.SanitizeLogValue(id)).
		Detail("version", logging.SanitizeLogValue(version)).
		Detail("content_hash", logging.SanitizeLogValue(contentHash)).
		Detail("approval_hash", logging.SanitizeLogValue(approvalHash)).
		Detail("actor", logging.SanitizeLogValue(p.ID))
	return s.auditManager.RecordEvent(ctx, b)
}

func (s *Server) writeAuditFailure(w http.ResponseWriter, action string, err error) {
	s.logger.Error("Failed to record content approval audit event",
		"action", action, "error", logging.SanitizeLogValue(err.Error()))
	s.writeErrorResponse(w, http.StatusInternalServerError, "Audit unavailable; nothing was changed", "AUDIT_UNAVAILABLE")
}

// loadApprovableScript decodes the approve body, loads the version from the
// caller tenant's library and checks the body hashes against what the controller
// holds now. It writes the refusal and returns ok=false on any difference.
func (s *Server) loadApprovableScript(w http.ResponseWriter, r *http.Request, resolver script.TenantScriptResolver, owner string) (ApproveScriptRequest, *script.VersionedScript, string, bool) {
	var req ApproveScriptRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return req, nil, "", false
	}
	if req.ScriptID == "" || req.Version == "" || req.ApprovalHash == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "script_id, version and approval_hash are required", "MISSING_FIELDS")
		return req, nil, "", false
	}
	vs, err := resolver.GetForTenant(owner, req.ScriptID, req.Version)
	if err != nil || !hasVersion(vs, req.Version) {
		s.writeErrorResponse(w, http.StatusNotFound, "Script version not found", "NOT_FOUND")
		return req, nil, "", false
	}
	approvalHash := script.ScriptApprovalHash(owner, vs)
	if approvalHash == "" {
		s.writeErrorResponse(w, http.StatusUnprocessableEntity, "Script cannot be approved", "NOT_APPROVABLE")
		return req, nil, "", false
	}
	if !req.matchesStored(approvalHash, vs.Hash) {
		s.writeErrorResponse(w, http.StatusConflict, "Hash does not match the stored script version", "HASH_MISMATCH")
		return req, nil, "", false
	}
	return req, vs, approvalHash, true
}

func hasVersion(vs *script.VersionedScript, version string) bool {
	return vs != nil && vs.Metadata != nil && vs.Metadata.Version != nil && vs.Metadata.Version.String() == version
}

// matchesStored reports whether the body names exactly what the controller holds
// now. The approval hash is required; the content hash is checked when present.
func (r ApproveScriptRequest) matchesStored(approvalHash, contentHash string) bool {
	if subtle.ConstantTimeCompare([]byte(r.ApprovalHash), []byte(approvalHash)) != 1 {
		return false
	}
	return r.ContentHash == "" || subtle.ConstantTimeCompare([]byte(r.ContentHash), []byte(contentHash)) == 1
}

// handleApproveScript handles POST /api/v1/automation/approvals/scripts.
func (s *Server) handleApproveScript(w http.ResponseWriter, r *http.Request) {
	st, resolver, owner, ok := s.approvalDeps(w, r)
	if !ok {
		return
	}
	p, ok := s.humanApprover(w, r)
	if !ok {
		return
	}
	req, vs, approvalHash, ok := s.loadApprovableScript(w, r, resolver, owner)
	if !ok {
		return
	}
	if err := s.recordContentApprovalAudit(r.Context(), auditActionContentApprovalApprove, owner, p, req.ScriptID, req.Version, vs.Hash, approvalHash); err != nil {
		s.writeAuditFailure(w, auditActionContentApprovalApprove, err)
		return
	}
	rec := ContentApproval{
		TenantID: owner, Kind: LibraryKindScript, ContentID: req.ScriptID, Version: req.Version,
		ContentHash: approvalHash, ApprovedBy: p.ID, Method: ApprovalMethodApproveTap,
	}
	if err := st.PutApproval(r.Context(), rec); err != nil {
		s.logger.Error("Failed to store script approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to record approval", "INTERNAL_ERROR")
		return
	}
	s.writeResponse(w, http.StatusCreated, ScriptApprovalEntry{
		ScriptID: req.ScriptID, Version: req.Version, ContentHash: vs.Hash, ApprovalHash: approvalHash,
		State: ScriptApprovalApproved, Approval: &ScriptApprovalInfo{
			ApprovedBy: p.ID, ApprovedAt: time.Now().UTC().Format(time.RFC3339), Method: string(ApprovalMethodApproveTap),
		},
	})
}

// handleRevokeScriptApproval handles
// DELETE /api/v1/automation/approvals/scripts/{id}/{version}/{approval_hash}.
// The approval is found by its stored key, not recomputed from the script, so an
// approval of a version that has since changed can still be withdrawn.
func (s *Server) handleRevokeScriptApproval(w http.ResponseWriter, r *http.Request) {
	st, _, owner, ok := s.approvalDeps(w, r)
	if !ok {
		return
	}
	p, ok := s.humanApprover(w, r)
	if !ok {
		return
	}
	vars := mux.Vars(r)
	id, version, hash := vars["id"], vars["version"], vars["approval_hash"]
	existing, err := st.GetApproval(r.Context(), owner, LibraryKindScript, id, version, hash)
	if err != nil {
		s.logger.Error("Failed to read script approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read approval", "INTERNAL_ERROR")
		return
	}
	if existing == nil {
		s.writeErrorResponse(w, http.StatusNotFound, "Approval not found", "NOT_FOUND")
		return
	}
	if err := s.recordContentApprovalAudit(r.Context(), auditActionContentApprovalRevoke, owner, p, id, version, "", hash); err != nil {
		s.writeAuditFailure(w, auditActionContentApprovalRevoke, err)
		return
	}
	if _, err := st.DeleteApproval(r.Context(), owner, LibraryKindScript, id, version, hash); err != nil {
		s.logger.Error("Failed to delete script approval", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to withdraw approval", "INTERNAL_ERROR")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListScriptApprovals handles GET /api/v1/automation/approvals/scripts: the
// caller tenant's library, every version with its evaluator state.
func (s *Server) handleListScriptApprovals(w http.ResponseWriter, r *http.Request) {
	st, resolver, owner, ok := s.approvalDeps(w, r)
	if !ok {
		return
	}
	mode, err := st.GetMode(r.Context(), owner, LibraryKindScript)
	if err != nil {
		s.logger.Error("Failed to read library mode", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read library mode", "INTERNAL_ERROR")
		return
	}
	entries, err := s.scriptApprovalEntries(r.Context(), st, resolver, owner)
	if err != nil {
		s.logger.Error("Failed to list script approvals", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list approvals", "INTERNAL_ERROR")
		return
	}
	s.writeSuccessResponse(w, ScriptApprovalListResponse{Mode: mode, Scripts: entries})
}

func (s *Server) scriptApprovalEntries(ctx context.Context, st *ContentApprovalStore, resolver script.TenantScriptResolver, owner string) ([]ScriptApprovalEntry, error) {
	metas, err := resolver.ListForTenant(owner, nil)
	if err != nil {
		return nil, fmt.Errorf("list library: %w", err)
	}
	out := []ScriptApprovalEntry{}
	for _, m := range metas {
		for _, version := range s.scriptVersionNames(resolver, owner, m) {
			e, ok, err := scriptApprovalEntry(ctx, st, resolver, owner, m.ID, version)
			if err != nil {
				return nil, err
			}
			if ok {
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ScriptID != out[j].ScriptID {
			return out[i].ScriptID < out[j].ScriptID
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
}

// scriptApprovalEntry builds the list entry of one version. ok is false for a
// version that cannot be loaded, which the list leaves out.
func scriptApprovalEntry(ctx context.Context, st *ContentApprovalStore, resolver script.TenantScriptResolver, owner, id, version string) (ScriptApprovalEntry, bool, error) {
	vs, err := resolver.GetForTenant(owner, id, version)
	if err != nil || vs == nil || vs.Metadata == nil || vs.Metadata.Version == nil {
		return ScriptApprovalEntry{}, false, nil
	}
	state, a, approvalHash, err := st.evaluateScriptApproval(ctx, owner, vs)
	if err != nil {
		return ScriptApprovalEntry{}, false, err
	}
	e := ScriptApprovalEntry{
		ScriptID: id, Version: vs.Metadata.Version.String(), ContentHash: vs.Hash,
		ApprovalHash: approvalHash, State: state,
	}
	if a != nil {
		e.Approval = &ScriptApprovalInfo{ApprovedBy: a.ApprovedBy, ApprovedAt: a.ApprovedAt.Format(time.RFC3339), Method: string(a.Method)}
	}
	return e, true, nil
}

// scriptVersionNames lists the versions of one library script, falling back to
// the listed (latest) version when the repository cannot enumerate versions.
func (s *Server) scriptVersionNames(resolver script.TenantScriptResolver, owner string, m *script.ScriptMetadata) []string {
	fallback := []string{""}
	if m.Version != nil {
		fallback = []string{m.Version.String()}
	}
	lib, ok := resolver.(scriptVersionLibrary)
	if !ok {
		return fallback
	}
	repo, err := lib.ForTenant(owner)
	if err != nil {
		return fallback
	}
	versions, err := repo.ListVersions(m.ID)
	if err != nil || len(versions) == 0 {
		return fallback
	}
	names := make([]string, 0, len(versions))
	for _, v := range versions {
		names = append(names, v.String())
	}
	return names
}
