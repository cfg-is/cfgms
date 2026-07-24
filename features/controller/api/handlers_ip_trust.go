// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// addIPTrustRequest is the request body for POST /api/v1/registration/ip-trust.
type addIPTrustRequest struct {
	TenantID  string `json:"tenant_id"`
	CIDR      string `json:"cidr"`
	PreSeeded bool   `json:"pre_seeded"`
}

// IPTrustEntryResponse is the per-entry shape for GET /api/v1/registration/ip-trust.
// Mirrors the IPTrustEntry storage model for the response envelope.
type IPTrustEntryResponse struct {
	CIDR         string     `json:"cidr"`
	TenantID     string     `json:"tenant_id"`
	PreSeeded    bool       `json:"pre_seeded"`
	TrustedSince time.Time  `json:"trusted_since"`
	LastActivity time.Time  `json:"last_activity,omitempty"`
	Revoked      bool       `json:"revoked"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// handleAddIPTrust handles POST /api/v1/registration/ip-trust.
// Adds a trusted CIDR range for a tenant; pre_seeded marks the range as operator-seeded.
// Scoped callers may only add ranges for tenants within their own subtree.
func (s *Server) handleAddIPTrust(w http.ResponseWriter, r *http.Request) {
	if s.ipTrustStore == nil {
		http.Error(w, "ip-trust store unavailable", http.StatusServiceUnavailable)
		return
	}

	var req addIPTrustRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.TenantID == "" || req.CIDR == "" {
		http.Error(w, "tenant_id and cidr are required", http.StatusBadRequest)
		return
	}

	// Tenant subtree enforcement: scoped callers may not add ranges for other tenants.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := req.TenantID == callerTenant || strings.HasPrefix(req.TenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "forbidden: target tenant is outside caller's tenant subtree", http.StatusForbidden)
			return
		}
	}

	if err := s.ipTrustStore.AddTrustedRange(r.Context(), req.TenantID, req.CIDR, req.PreSeeded); err != nil {
		s.logger.Error("Failed to add IP trust range",
			"tenant_id", logging.SanitizeLogValue(req.TenantID),
			"cidr", logging.SanitizeLogValue(req.CIDR),
			"error", err)
		http.Error(w, "Failed to add IP trust range", http.StatusInternalServerError)
		return
	}

	s.logger.Info("IP trust range added",
		"tenant_id", logging.SanitizeLogValue(req.TenantID),
		"cidr", logging.SanitizeLogValue(req.CIDR),
		"pre_seeded", req.PreSeeded)
	s.emitIPTrustAudit(r, "ip_trust.added", req.TenantID, req.CIDR)
	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeIPTrust handles DELETE /api/v1/registration/ip-trust/{tenant_id}/{cidr:.+}.
// Revokes a trusted CIDR range for a tenant. The {cidr:.+} pattern allows the CIDR slash
// to appear in the URL path (gorilla/mux decodes %2F before extraction).
// Scoped callers may only revoke ranges for tenants within their own subtree.
func (s *Server) handleRevokeIPTrust(w http.ResponseWriter, r *http.Request) {
	if s.ipTrustStore == nil {
		http.Error(w, "ip-trust store unavailable", http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	tenantID := vars["tenant_id"]
	cidr := vars["cidr"]

	if tenantID == "" || cidr == "" {
		http.Error(w, "tenant_id and cidr are required", http.StatusBadRequest)
		return
	}

	// Tenant subtree enforcement: scoped callers may not revoke ranges for other tenants.
	callerTenant := s.callerTenantID(r)
	if callerTenant != "" {
		inSubtree := tenantID == callerTenant || strings.HasPrefix(tenantID, callerTenant+"/")
		if !inSubtree {
			http.Error(w, "forbidden: target tenant is outside caller's tenant subtree", http.StatusForbidden)
			return
		}
	}

	if err := s.ipTrustStore.RevokeTrustedRange(r.Context(), tenantID, cidr); err != nil {
		if err == business.ErrIPTrustEntryNotFound {
			http.Error(w, "ip trust entry not found", http.StatusNotFound)
			return
		}
		s.logger.Error("Failed to revoke IP trust range",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"cidr", logging.SanitizeLogValue(cidr),
			"error", err)
		http.Error(w, "Failed to revoke IP trust range", http.StatusInternalServerError)
		return
	}

	s.logger.Info("IP trust range revoked",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"cidr", logging.SanitizeLogValue(cidr))
	s.emitIPTrustAudit(r, "ip_trust.revoked", tenantID, cidr)
	w.WriteHeader(http.StatusNoContent)
}

// handleListIPTrust handles GET /api/v1/registration/ip-trust.
// Scoped callers (API-key principals) always see only their own tenant's ranges.
// Unscoped (mTLS admin) callers must supply ?tenant_id= to narrow the result.
func (s *Server) handleListIPTrust(w http.ResponseWriter, r *http.Request) {
	if s.ipTrustStore == nil {
		http.Error(w, "ip-trust store unavailable", http.StatusServiceUnavailable)
		return
	}

	// Scoped callers: always use their own tenant.
	// Unscoped (admin): require tenant_id query param to avoid open-ended scans.
	callerTenant := s.callerTenantID(r)
	tenantID := callerTenant
	if tenantID == "" {
		tenantID = r.URL.Query().Get("tenant_id")
		if tenantID == "" {
			http.Error(w, "tenant_id query parameter is required for unscoped callers", http.StatusBadRequest)
			return
		}
	}

	entries, err := s.ipTrustStore.ListTrustedRanges(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to list IP trust ranges",
			"tenant_id", logging.SanitizeLogValue(tenantID), "error", err)
		http.Error(w, "Failed to list IP trust ranges", http.StatusInternalServerError)
		return
	}

	resp := make([]IPTrustEntryResponse, 0, len(entries))
	for _, e := range entries {
		resp = append(resp, IPTrustEntryResponse{
			CIDR:         e.CIDR,
			TenantID:     e.TenantID,
			PreSeeded:    e.PreSeeded,
			TrustedSince: e.TrustedSince,
			LastActivity: e.LastActivity,
			Revoked:      e.Revoked,
			RevokedAt:    e.RevokedAt,
		})
	}
	s.writeSuccessResponse(w, resp)
}

// emitIPTrustAudit records an audit event for an IP trust mutation (add or revoke).
// It is a no-op when auditManager is nil.
func (s *Server) emitIPTrustAudit(r *http.Request, action, tenantID, cidr string) {
	if s.auditManager == nil {
		return
	}
	auditTenantID := tenantID
	if auditTenantID == "" {
		auditTenantID = audit.SystemTenantID
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	b := audit.NewEventBuilder().
		Tenant(auditTenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(principalID, business.AuditUserTypeHuman).
		Resource("ip_trust", cidr, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Detail("cidr", cidr)
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit ip-trust audit event", "error", err, "action", action)
	}
}
