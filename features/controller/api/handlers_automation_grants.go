// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	automationGrantAuditCreate = "automation_grant.create"
	automationGrantAuditRevoke = "automation_grant.revoke"
	automationGrantMaxBody     = 4 << 10
)

// automationGrantCreateRequest is the POST body. TenantID is optional: it defaults to
// the caller's tenant, and a root-scoped caller must supply it.
type automationGrantCreateRequest struct {
	Name      string    `json:"name"`
	TenantID  string    `json:"tenant_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// automationGrantCreateResponse carries the plaintext credential, returned exactly
// once: no later read can recover it.
type automationGrantCreateResponse struct {
	Grant      *AutomationGrant `json:"grant"`
	Credential string           `json:"credential"`
}

// automationGrantRevokeResponse reports the revoked grant and how many open runs the
// revocation ended.
type automationGrantRevokeResponse struct {
	Grant     *AutomationGrant `json:"grant"`
	RunsEnded int              `json:"runs_ended"`
}

// automationGrantActor returns the authenticated human principal, or writes a 401.
func (s *Server) automationGrantActor(w http.ResponseWriter, r *http.Request) (*Principal, bool) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || principal.ID == "" {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return nil, false
	}
	return principal, true
}

// automationGrantStoreOrUnavailable returns the wired store, or writes a 503. Audit is
// part of the contract of every grant change, so a missing audit manager is a 503 too.
func (s *Server) automationGrantStoreOrUnavailable(w http.ResponseWriter, needAudit bool) (*AutomationGrantStore, bool) {
	store := s.grantStoreOrNil()
	if store == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Automation grants not available", "SERVICE_UNAVAILABLE")
		return nil, false
	}
	if needAudit && s.auditManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail not available", "SERVICE_UNAVAILABLE")
		return nil, false
	}
	return store, true
}

// authorizeGrantTenant applies the tenant boundary to the tenant a grant lives in: a
// tenant outside the caller's subtree is a 404, never a 403, and a root-scoped caller
// without an active crossing receives the crossing challenge. It writes the response
// and returns false when the tenant is refused; notFound names what the 404 reports.
func (s *Server) authorizeGrantTenant(w http.ResponseWriter, r *http.Request, principal *Principal, tenantID, notFound, notFoundCode string) bool {
	if tenantID == "" || s.tenantManager == nil {
		s.writeErrorResponse(w, http.StatusNotFound, notFound, notFoundCode)
		return false
	}
	switch s.authorizeTenantAccess(r.Context(), principal, tenantID) {
	case tenantAuthAllowed:
		return true
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, tenantID)
	default:
		s.writeErrorResponse(w, http.StatusNotFound, notFound, notFoundCode)
	}
	return false
}

// resolveGrantCreateTenant returns the stored ID of the tenant a new grant belongs
// to: the requested tenant, else the caller's own. A root-scoped caller has no tenant
// of its own and must name one. The tenant must exist and pass the tenant boundary.
// It writes the response and returns false when the request is refused.
func (s *Server) resolveGrantCreateTenant(w http.ResponseWriter, r *http.Request, principal *Principal, requested string) (string, bool) {
	tenantID := requested
	if tenantID == "" {
		scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
		if scope.IsRoot() { //architecture:allow-root-scope -- a root caller has no tenant of its own and must name one, which then passes authorizeTenantAccess
			s.writeErrorResponse(w, http.StatusBadRequest, "tenant_id is required for a root-scoped caller", "TENANT_REQUIRED")
			return "", false
		}
		tenantID, _ = r.Context().Value(ctxkeys.TenantID).(string)
		if tenantID == "" {
			s.writeErrorResponse(w, http.StatusBadRequest, "A tenant is required", "TENANT_REQUIRED")
			return "", false
		}
	}
	if !s.authorizeGrantTenant(w, r, principal, tenantID, "Tenant not found", "TENANT_NOT_FOUND") {
		return "", false
	}
	stored, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil || stored == nil || stored.ID == "" {
		s.writeErrorResponse(w, http.StatusNotFound, "Tenant not found", "TENANT_NOT_FOUND")
		return "", false
	}
	return stored.ID, true
}

// handleCreateAutomationGrant handles POST /api/v1/automation/grants.
//
// A grant is a credential that acts without a human, so creating one takes a
// presence tap (enforced by requirePermission). The create event is recorded before
// the response: if it cannot be, the grant is removed again and the credential is
// never returned, so no unaudited grant survives.
func (s *Server) handleCreateAutomationGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.automationGrantActor(w, r)
	if !ok {
		return
	}
	store, ok := s.automationGrantStoreOrUnavailable(w, true)
	if !ok {
		return
	}
	req, ok := s.decodeAutomationGrantCreate(w, r)
	if !ok {
		return
	}

	tenantID, ok := s.resolveGrantCreateTenant(w, r, principal, req.TenantID)
	if !ok {
		return
	}

	grant, credential, err := store.Create(r.Context(), tenantID, req.Name, principal.ID, req.ExpiresAt)
	if err != nil {
		if errors.Is(err, ErrInvalidGrantRequest) {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_GRANT_REQUEST")
			return
		}
		s.logger.Error("Failed to create automation grant", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to create automation grant", "INTERNAL_ERROR")
		return
	}

	if err := s.recordAutomationGrantAudit(r, principal, automationGrantAuditCreate, grant, business.AuditResultSuccess); err != nil {
		s.logger.Error("Automation grant creation refused: audit event not recorded",
			"error", logging.SanitizeLogValue(err.Error()))
		s.discardAutomationGrant(r, store, grant)
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail unavailable; grant not created", "AUDIT_UNAVAILABLE")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	s.writeResponse(w, http.StatusCreated, automationGrantCreateResponse{Grant: grant, Credential: credential})
}

// discardAutomationGrant removes a grant whose create event could not be recorded.
// The secret hash goes first, so even a failure to remove the record leaves a grant
// that can never authenticate.
func (s *Server) discardAutomationGrant(r *http.Request, store *AutomationGrantStore, grant *AutomationGrant) {
	ctx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	if err := store.deleteSecret(ctx, grant.TenantID, grant.ID); err != nil {
		s.logger.Error("Failed to remove the secret of an unaudited automation grant",
			"error", logging.SanitizeLogValue(err.Error()))
	}
	if err := store.configs.DeleteConfig(ctx, grantConfigKey(grant.TenantID, grant.ID)); err != nil {
		s.logger.Error("Failed to remove an unaudited automation grant",
			"error", logging.SanitizeLogValue(err.Error()))
	}
}

// decodeAutomationGrantCreate reads the POST body: exactly one JSON object with no
// unknown fields. It writes the response and returns false when the body is rejected.
func (s *Server) decodeAutomationGrantCreate(w http.ResponseWriter, r *http.Request) (automationGrantCreateRequest, bool) {
	var req automationGrantCreateRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, automationGrantMaxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return req, false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return req, false
	}
	return req, true
}

// handleListAutomationGrants handles GET /api/v1/automation/grants: the grants inside
// the caller's tenant subtree. The credential is never part of a grant record, so a
// list can not return it. A root-scoped caller lists one tenant, ?tenant= (default the
// root tenant), through the tenant-crossing boundary.
func (s *Server) handleListAutomationGrants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.automationGrantActor(w, r); !ok {
		return
	}
	store, ok := s.automationGrantStoreOrUnavailable(w, false)
	if !ok {
		return
	}

	var scopeIDs []string
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if scope.IsRoot() { //architecture:allow-root-scope -- a root caller lists the one tenant it selects, which passes the ADR-025 crossing, never every tenant
		selected := r.URL.Query().Get("tenant")
		if selected == "" {
			selected = s.rootTenantID(r.Context())
		}
		tenantID, ok := s.selectAuthorizedTenant(w, r, selected)
		if !ok {
			return
		}
		scopeIDs = []string{tenantID}
	} else {
		callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
		for id := range s.tenantSubtreeIDs(r.Context(), callerTenant) {
			scopeIDs = append(scopeIDs, id)
		}
	}

	grants, err := store.List(r.Context(), scopeIDs)
	if err != nil {
		s.logger.Error("Failed to list automation grants", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list automation grants", "INTERNAL_ERROR")
		return
	}
	if grants == nil {
		grants = []*AutomationGrant{}
	}
	s.writeSuccessResponse(w, map[string]any{"grants": grants, "count": len(grants)})
}

// handleRevokeAutomationGrant handles DELETE /api/v1/automation/grants/{id}.
//
// Revoking only removes power, so it takes no presence tap, but it is audited before
// it is made: if the event cannot be recorded the grant is left as it was. The grant
// is revoked first and its open runs are ended second, so an interrupted revoke can
// be repeated: revoking a revoked grant keeps its record and ends any run still open.
func (s *Server) handleRevokeAutomationGrant(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.automationGrantActor(w, r)
	if !ok {
		return
	}
	store, ok := s.automationGrantStoreOrUnavailable(w, true)
	if !ok {
		return
	}
	grant, ok := s.loadAuthorizedGrant(w, r, principal, store, mux.Vars(r)["id"])
	if !ok {
		return
	}

	if err := s.recordAutomationGrantAudit(r, principal, automationGrantAuditRevoke, grant, business.AuditResultSuccess); err != nil {
		s.logger.Error("Automation grant revocation refused: audit event not recorded",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Audit trail unavailable; grant not revoked", "AUDIT_UNAVAILABLE")
		return
	}

	revoked, err := store.Revoke(r.Context(), grant.TenantID, grant.ID, principal.ID)
	if err != nil {
		s.failGrantRevoke(w, r, principal, grant, err)
		return
	}
	ended, err := s.endGrantRuns(r.Context(), revoked.ID)
	if err != nil {
		s.logger.Error("Automation grant revoked but its open runs could not all be ended",
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError,
			"Grant revoked but its open runs could not be ended; repeat the request", "INTERNAL_ERROR")
		return
	}
	s.writeSuccessResponse(w, automationGrantRevokeResponse{Grant: revoked, RunsEnded: ended})
}

// endGrantRuns ends every open run of the grant and returns how many it ended.
func (s *Server) endGrantRuns(ctx context.Context, grantID string) (int, error) {
	runs := s.automationRunStore()
	if runs == nil {
		return 0, nil
	}
	return runs.EndRunsForGrant(ctx, grantID)
}

// failGrantRevoke answers a revocation the store refused after its success audit
// event was recorded, and records a failure event correcting it.
func (s *Server) failGrantRevoke(w http.ResponseWriter, r *http.Request, principal *Principal, grant *AutomationGrant, err error) {
	s.logger.Error("Failed to revoke automation grant", "error", logging.SanitizeLogValue(err.Error()))
	if aerr := s.recordAutomationGrantAudit(r, principal, automationGrantAuditRevoke, grant, business.AuditResultFailure); aerr != nil {
		s.logger.Warn("Failed to record automation grant revoke failure audit",
			"error", logging.SanitizeLogValue(aerr.Error()))
	}
	s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to revoke automation grant", "INTERNAL_ERROR")
}

// loadAuthorizedGrant reads the grant with the given id and applies the tenant
// boundary to its tenant. A grant outside the caller's subtree is indistinguishable
// from an unknown one (404). It writes the response and returns false when refused.
func (s *Server) loadAuthorizedGrant(w http.ResponseWriter, r *http.Request, principal *Principal, store *AutomationGrantStore, id string) (*AutomationGrant, bool) {
	grant, err := store.findByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrGrantNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Automation grant not found", "GRANT_NOT_FOUND")
			return nil, false
		}
		s.logger.Error("Failed to read automation grant", "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read automation grant", "INTERNAL_ERROR")
		return nil, false
	}
	if !s.authorizeGrantTenant(w, r, principal, grant.TenantID, "Automation grant not found", "GRANT_NOT_FOUND") {
		return nil, false
	}
	return grant, true
}

// recordAutomationGrantAudit records one automation_grant.create or .revoke event
// naming the grant, its tenant and expiry, and the actor. Unlike emitOperatorAudit it
// returns the error: the caller must not change a grant without the event. The
// credential is never an input, so it can not reach the record.
func (s *Server) recordAutomationGrantAudit(r *http.Request, principal *Principal, action string, grant *AutomationGrant, result business.AuditResult) error {
	b := audit.NewEventBuilder().
		Tenant(grant.TenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(principal.ID, principalAuditUserType(principal)).
		Resource("automation_grant", grant.ID, "").
		Result(result).
		Severity(business.AuditSeverityHigh).
		Detail("grant_id", grant.ID).
		Detail("tenant", grant.TenantID).
		Detail("expires_at", grant.ExpiresAt.UTC().Format(time.RFC3339)).
		Detail("actor", principal.ID)
	auditCtx, cancel := detachedAuditContext(r.Context())
	defer cancel()
	return s.auditManager.RecordEvent(auditCtx, b)
}
