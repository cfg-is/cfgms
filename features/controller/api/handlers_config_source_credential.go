// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	cfgpkg "github.com/cfgis/cfgms/pkg/config"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsiface "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	configSourceCredentialMaxBodyBytes = 64 * 1024
	configSourceCredentialMaxTokenLen  = 4096
	configSourceCredentialAuditAction  = "config_source.credential.set"
)

// configSourceCredentialRequest is the body of PUT /api/v1/tenants/{id}/config-source/credential.
type configSourceCredentialRequest struct {
	URL   string `json:"url"`
	Token string `json:"token"`
}

// configSourceCredentialResponse names the stored credential and the repository it is bound to.
type configSourceCredentialResponse struct {
	CredentialRef      string `json:"credential_ref"`
	BoundRepositoryURL string `json:"bound_repository_url"`
}

func validConfigSourceToken(v string) bool {
	if v == "" || len(v) > configSourceCredentialMaxTokenLen {
		return false
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// handlePutTenantConfigSourceCredential implements
// PUT /api/v1/tenants/{id}/config-source/credential.
//
// The token and its repository binding are written together in one StoreSecret call on
// the server's secret store (the store the git router and ValidateMountPoint read), so a
// binding can never change without a new token. The token is never returned or logged.
func (s *Server) handlePutTenantConfigSourceCredential(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}

	// Same scope check and 404 as handleConfigSourceTest: an unknown and an
	// out-of-scope tenant are indistinguishable.
	scope, _ := r.Context().Value(ctxkeys.TenantScopeKey).(ctxkeys.TenantScope)
	if access := s.tenantAccessForScope(r.Context(), scope, tenantID, "PUT /api/v1/tenants/{id}/config-source/credential"); access != tenantAuthAllowed {
		if !s.writeTenantCrossingIfNeeded(w, access, tenantID) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		}
		return
	}

	s.mu.RLock()
	ss := s.secretStore
	s.mu.RUnlock()
	if ss == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "secret store not available", "SECRET_STORE_UNAVAILABLE")
		return
	}
	if s.tenantManager == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant manager not available", "SERVICE_UNAVAILABLE")
		return
	}
	td, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.logger.Error("config-source credential: failed to load tenant",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	var req configSourceCredentialRequest
	r.Body = http.MaxBytesReader(w, r.Body, configSourceCredentialMaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.URL == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "url is required", "INVALID_URL")
		return
	}
	if err := cfgpkg.ValidateSourceURL(req.URL); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid url: "+err.Error(), "INVALID_URL")
		return
	}
	if !validConfigSourceToken(req.Token) {
		s.writeErrorResponse(w, http.StatusBadRequest, "token is required", "INVALID_TOKEN")
		return
	}

	var actorID string
	if p, _ := r.Context().Value(principalContextKey).(*Principal); p != nil {
		actorID = p.ID
	}
	bound := cfgpkg.NormalizeRepositoryURL(req.URL)
	// The secret is stored as key "config-source-git" in the tenant's namespace; the
	// store resolves the reference "<tenant id>/config-source-git" to it on read.
	ref := td.ID + "/" + cfgpkg.ConfigSourceCredentialKeyName
	if err := ss.StoreSecret(r.Context(), &secretsiface.SecretRequest{
		Key:         cfgpkg.ConfigSourceCredentialKeyName,
		Value:       req.Token,
		Metadata:    map[string]string{cfgpkg.SecretMetaKeyBoundRepositoryURL: bound},
		CreatedBy:   actorID,
		TenantID:    td.ID,
		Description: "git config-source credential",
	}); err != nil {
		s.logger.Error("config-source credential: failed to store secret",
			"tenant_id", logging.SanitizeLogValue(td.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to store credential", "CREDENTIAL_STORE_FAILED")
		return
	}

	s.auditConfigSourceCredential(r, td.ID, actorID, bound)
	s.writeSuccessResponse(w, configSourceCredentialResponse{CredentialRef: ref, BoundRepositoryURL: bound})
}

// auditConfigSourceCredential records who bound a credential to which repository for
// which tenant. The token is never part of the event.
func (s *Server) auditConfigSourceCredential(r *http.Request, tenantID, actorID, boundURL string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(configSourceCredentialAuditAction).
		User(actorID, business.AuditUserTypeHuman).
		Resource("tenant", tenantID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Details(map[string]interface{}{"tenant_id": tenantID, "actor": actorID, "bound_repository_url": boundURL})
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Error("Failed to record config-source credential audit event",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
