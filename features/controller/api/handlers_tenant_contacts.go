// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/tenant"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// tenantContactsMaxBodyBytes bounds the PUT body; 20 addresses of at most 254
// bytes fit comfortably.
const tenantContactsMaxBodyBytes = 16 * 1024

// tenantAdminContactsBody is the request and response shape of the
// /tenants/{id}/admin-contacts endpoints.
type tenantAdminContactsBody struct {
	Contacts []string `json:"contacts"`
}

// authorizeTenantContactsAccess resolves the {id} tenant and applies the ordinary
// tenant-scope decision. It writes the response and returns "" when the caller is
// refused (404 for a missing or out-of-scope tenant, the crossing challenge for a
// root-scoped caller lacking a crossing).
func (s *Server) authorizeTenantContactsAccess(w http.ResponseWriter, r *http.Request, principal *Principal) string {
	tenantID := mux.Vars(r)["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return ""
	}
	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return ""
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return ""
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		return existing.ID
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
	default:
		s.logger.Info("Cross-tenant admin contacts access refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenantFilter(r.Context())))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
	}
	return ""
}

// handleGetTenantAdminContacts implements GET /api/v1/tenants/{id}/admin-contacts.
func (s *Server) handleGetTenantAdminContacts(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	tenantID := s.authorizeTenantContactsAccess(w, r, principal)
	if tenantID == "" {
		return
	}
	contacts, err := s.tenantManager.GetAdminContacts(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to read tenant admin contacts",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to read admin contacts", "GET_FAILED")
		return
	}
	s.writeSuccessResponse(w, tenantAdminContactsBody{Contacts: contacts})
}

// handlePutTenantAdminContacts implements PUT /api/v1/tenants/{id}/admin-contacts.
// It replaces the tenant's administrator contact list. A root-scoped caller is
// refused even with an active crossing: the list is where the MSP is told about
// root's own access, so root editing it would defeat that notification.
func (s *Server) handlePutTenantAdminContacts(w http.ResponseWriter, r *http.Request) {
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	tenantID := s.authorizeTenantContactsAccess(w, r, principal)
	if tenantID == "" {
		return
	}
	if subjectToTenantCrossingBoundary(principal) {
		s.writeErrorResponse(w, http.StatusForbidden,
			"root-scoped callers cannot edit administrator contacts", "ROOT_SCOPED_CANNOT_EDIT_CONTACTS")
		return
	}

	var req tenantAdminContactsBody
	r.Body = http.MaxBytesReader(w, r.Body, tenantContactsMaxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Contacts == nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body: contacts array is required", "INVALID_REQUEST")
		return
	}

	saved, err := s.tenantManager.SetAdminContacts(r.Context(), tenantID, req.Contacts)
	if err != nil {
		if errors.Is(err, tenant.ErrInvalidAdminContacts) {
			s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_CONTACTS")
			return
		}
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.logger.Error("Failed to update tenant admin contacts",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to update admin contacts", "UPDATE_FAILED")
		return
	}

	s.recordTenantAdminContactsAudit(r, tenantID, principal, len(saved))
	s.logger.Info("Updated tenant admin contacts",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"contact_count", len(saved))
	s.writeSuccessResponse(w, tenantAdminContactsBody{Contacts: saved})
}

// recordTenantAdminContactsAudit writes the tenant-scoped, high-severity
// tenant.admin_contacts_updated event. The detail carries the address count only:
// contacts are personal data and stay out of the audit trail.
func (s *Server) recordTenantAdminContactsAudit(r *http.Request, tenantID string, principal *Principal, count int) {
	if s.auditManager == nil {
		return
	}
	var actorID string
	if principal != nil {
		actorID = principal.ID
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action("tenant.admin_contacts_updated").
		User(actorID, business.AuditUserTypeHuman).
		Resource("tenant", tenantID, "").
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Detail("contact_count", count)
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Error("Failed to record admin contacts audit event",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
