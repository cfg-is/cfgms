// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/modules/hyperv"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// hypervProfileEnroll is the wire shape of hyperv.EnrollConfig. Defined
// separately (rather than reusing hyperv.EnrollConfig's yaml-only tags)
// so the REST payload uses the project's standard snake_case JSON convention.
type hypervProfileEnroll struct {
	RegistrationTokenSecretKey string `json:"registration_token_secret_key,omitempty"`
	BundleURL                  string `json:"bundle_url,omitempty"`
	CorrelationLabel           string `json:"correlation_label,omitempty"`
}

// hypervProfileRequest is the body for POST /api/v1/hyperv/profiles.
type hypervProfileRequest struct {
	Name         string              `json:"name"`
	OSFamily     string              `json:"os_family"`
	AnswerFormat string              `json:"answer_format"`
	Template     string              `json:"template"`
	Enroll       hypervProfileEnroll `json:"enroll,omitempty"`
}

// hypervProfileResponse is the shape returned by the create/read endpoints.
type hypervProfileResponse struct {
	Name         string              `json:"name"`
	OSFamily     string              `json:"os_family"`
	AnswerFormat string              `json:"answer_format"`
	Template     string              `json:"template"`
	Enroll       hypervProfileEnroll `json:"enroll,omitempty"`
}

// hypervProfileListResponse is the shape returned by GET /api/v1/hyperv/profiles.
type hypervProfileListResponse struct {
	Profiles []string `json:"profiles"`
}

// toUnattendProfile converts a decoded request into the hyperv.UnattendProfile
// the ConfigBackedProfileStore write path validates and persists.
func (req hypervProfileRequest) toUnattendProfile() *hyperv.UnattendProfile {
	return &hyperv.UnattendProfile{
		Name:         req.Name,
		OSFamily:     req.OSFamily,
		AnswerFormat: hyperv.AnswerFormat(req.AnswerFormat),
		Template:     req.Template,
		Enroll: hyperv.EnrollConfig{
			RegistrationTokenSecretKey: req.Enroll.RegistrationTokenSecretKey,
			BundleURL:                  req.Enroll.BundleURL,
			CorrelationLabel:           req.Enroll.CorrelationLabel,
		},
	}
}

// hypervProfileResponseFrom converts a stored profile into its wire response shape.
func hypervProfileResponseFrom(p *hyperv.UnattendProfile) hypervProfileResponse {
	return hypervProfileResponse{
		Name:         p.Name,
		OSFamily:     p.OSFamily,
		AnswerFormat: string(p.AnswerFormat),
		Template:     p.Template,
		Enroll: hypervProfileEnroll{
			RegistrationTokenSecretKey: p.Enroll.RegistrationTokenSecretKey,
			BundleURL:                  p.Enroll.BundleURL,
			CorrelationLabel:           p.Enroll.CorrelationLabel,
		},
	}
}

// hypervProfileTenantFromRequest resolves the target tenant for a hyperv-profile
// request. A tenant-scoped caller is PINNED to its own tenant — the write
// surface is root-code-execution-equivalent (a stored profile is rendered and
// executed as root by cloud-init/preseed at guest first boot), so a caller must
// never be able to redirect a write into another tenant's namespace via a
// mismatched ?tenant= value. A root/global admin (empty principal tenant)
// selects the target tenant explicitly via ?tenant=. Mirrors
// roleTenantFromRequest (Issue #2548) exactly.
func hypervProfileTenantFromRequest(r *http.Request, principal *Principal) string {
	if principal.TenantID != "" {
		return principal.TenantID
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant"))
}

// resolveHypervProfileTenant resolves the target tenant for a hyperv-profile
// request, or writes a 400 TENANT_REQUIRED and returns ok=false when none can
// be determined (a global admin that omitted ?tenant=).
func (s *Server) resolveHypervProfileTenant(w http.ResponseWriter, r *http.Request, principal *Principal) (string, bool) {
	tenantID := hypervProfileTenantFromRequest(r, principal)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"tenant is required: a global admin must pass ?tenant=<id> (hyperv profiles are stored per tenant)", "TENANT_REQUIRED")
		return "", false
	}
	return tenantID, true
}

// handleCreateHypervProfile handles POST /api/v1/hyperv/profiles.
func (s *Server) handleCreateHypervProfile(w http.ResponseWriter, r *http.Request) {
	if s.hypervProfileConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Hyperv profile store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveHypervProfileTenant(w, r, principal)
	if !ok {
		return
	}

	var req hypervProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}

	ps := hyperv.NewConfigBackedProfileStore(s.hypervProfileConfigStore, tenantID)
	profile := req.toUnattendProfile()
	if err := ps.StoreProfile(r.Context(), profile); err != nil {
		s.writeHypervProfileValidationError(w, req.Name, err)
		return
	}

	s.emitHypervProfileAudit(r, "hyperv_profile.created", tenantID, req.Name)
	s.logger.Info("Hyperv profile created", "name", logging.SanitizeLogValue(req.Name), "tenant_id", logging.SanitizeLogValue(tenantID))
	s.writeResponse(w, http.StatusCreated, hypervProfileResponseFrom(profile))
}

// handleGetHypervProfile handles GET /api/v1/hyperv/profiles/{name}.
func (s *Server) handleGetHypervProfile(w http.ResponseWriter, r *http.Request) {
	if s.hypervProfileConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Hyperv profile store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveHypervProfileTenant(w, r, principal)
	if !ok {
		return
	}

	name := mux.Vars(r)["name"]
	ps := hyperv.NewConfigBackedProfileStore(s.hypervProfileConfigStore, tenantID)
	profile, err := ps.GetProfile(r.Context(), name)
	if err != nil {
		if errors.Is(err, hyperv.ErrProfileNotFound) || errors.Is(err, hyperv.ErrInvalidProfileName) {
			s.writeErrorResponse(w, http.StatusNotFound, "Hyperv profile not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get hyperv profile", "name", logging.SanitizeLogValue(name), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get hyperv profile", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, hypervProfileResponseFrom(profile))
}

// handleListHypervProfiles handles GET /api/v1/hyperv/profiles.
func (s *Server) handleListHypervProfiles(w http.ResponseWriter, r *http.Request) {
	if s.hypervProfileConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Hyperv profile store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveHypervProfileTenant(w, r, principal)
	if !ok {
		return
	}

	ps := hyperv.NewConfigBackedProfileStore(s.hypervProfileConfigStore, tenantID)
	names, err := ps.ListProfiles(r.Context())
	if err != nil {
		s.logger.Error("Failed to list hyperv profiles", "tenant_id", logging.SanitizeLogValue(tenantID), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list hyperv profiles", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, hypervProfileListResponse{Profiles: names})
}

// handleDeleteHypervProfile handles DELETE /api/v1/hyperv/profiles/{name}.
func (s *Server) handleDeleteHypervProfile(w http.ResponseWriter, r *http.Request) {
	if s.hypervProfileConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Hyperv profile store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveHypervProfileTenant(w, r, principal)
	if !ok {
		return
	}

	name := mux.Vars(r)["name"]
	ps := hyperv.NewConfigBackedProfileStore(s.hypervProfileConfigStore, tenantID)
	if err := ps.DeleteProfile(r.Context(), name); err != nil {
		if errors.Is(err, hyperv.ErrProfileNotFound) || errors.Is(err, hyperv.ErrInvalidProfileName) {
			s.writeErrorResponse(w, http.StatusNotFound, "Hyperv profile not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to delete hyperv profile", "name", logging.SanitizeLogValue(name), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete hyperv profile", "INTERNAL_ERROR")
		return
	}

	s.emitHypervProfileAudit(r, "hyperv_profile.deleted", tenantID, name)
	s.logger.Info("Hyperv profile deleted", "name", logging.SanitizeLogValue(name), "tenant_id", logging.SanitizeLogValue(tenantID))
	s.writeSuccessResponse(w, map[string]string{"deleted": name})
}

// writeHypervProfileValidationError maps a StoreProfile failure to a response.
// The four sentinel errors are author-time input rejections (AC: name pattern,
// answer_format, unparseable template, size cap) and map to 400; anything else
// is an unexpected backend failure (e.g. StoreConfig I/O) and maps to 500.
func (s *Server) writeHypervProfileValidationError(w http.ResponseWriter, name string, err error) {
	switch {
	case errors.Is(err, hyperv.ErrInvalidProfileName):
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_NAME")
	case errors.Is(err, hyperv.ErrInvalidAnswerFormat):
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_ANSWER_FORMAT")
	case errors.Is(err, hyperv.ErrInvalidProfileTemplate):
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_TEMPLATE")
	case errors.Is(err, hyperv.ErrProfileTooLarge):
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "PROFILE_TOO_LARGE")
	default:
		s.logger.Error("Failed to store hyperv profile", "name", logging.SanitizeLogValue(name), "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store hyperv profile", "INTERNAL_ERROR")
	}
}

// emitHypervProfileAudit records a create/delete audit event keyed on the
// cfg-declared resource id "hyperv-profile:<name>" (Issue #3785). No-op when
// auditManager is unwired.
func (s *Server) emitHypervProfileAudit(r *http.Request, action, tenantID, name string) {
	if s.auditManager == nil {
		return
	}
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	principalID := ""
	if principal != nil {
		principalID = principal.ID
	}
	resourceID := "hyperv-profile:" + name
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(principalID, business.AuditUserTypeHuman).
		Resource("hyperv-profile", resourceID, name).
		Result(business.AuditResultSuccess).
		Severity(business.AuditSeverityHigh).
		Request(s.getRequestID(r), r.Method, r.URL.Path, extractSourceIP(r, s.trustedProxies), r.Header.Get("User-Agent")).
		Detail("name", logging.SanitizeLogValue(name)).
		Detail("tenant_id", logging.SanitizeLogValue(tenantID))

	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Warn("Failed to emit hyperv profile audit event",
			"error", err, "action", action, "resource", logging.SanitizeLogValue(resourceID))
	}
}
