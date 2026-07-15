// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/fleet/selector"
	"github.com/cfgis/cfgms/pkg/logging"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// RoleConfig is the stored + returned shape for a role config object.
// Selector selects matching stewards; Fragment is merged during resolution (S4).
type RoleConfig struct {
	Name      string                     `json:"name"`
	TenantID  string                     `json:"tenant_id"`
	Selector  string                     `json:"selector"`
	Fragment  stewardtypes.StewardConfig `json:"fragment"`
	CreatedAt time.Time                  `json:"created_at,omitempty"`
	CreatedBy string                     `json:"created_by,omitempty"`
}

// createRoleConfigRequest is the body for POST /api/v1/roles.
type createRoleConfigRequest struct {
	Name     string                     `json:"name"`
	Selector string                     `json:"selector"`
	Fragment stewardtypes.StewardConfig `json:"fragment"`
}

// roleTenantFromRequest resolves the target tenant for a role-config request.
// Role configs are stored per tenant (the selector-driven resolver lists
// role-policies under each steward's own tenant), so every role operation needs a
// concrete tenant. A tenant-scoped caller is always pinned to its own tenant
// (the auth middleware sets ctxkeys.TenantID from the authenticated principal). A
// root/global admin — whose principal carries no tenant — selects the target
// tenant explicitly via the ?tenant= query parameter; without it there is no way
// to author into a named tenant and every store call fails "tenant ID is
// required" (Issue #2548).
func roleTenantFromRequest(r *http.Request, principal *Principal) string {
	if principal.TenantID != "" {
		return principal.TenantID
	}
	if q := strings.TrimSpace(r.URL.Query().Get("tenant")); q != "" {
		return q
	}
	ctxTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	return ctxTenant
}

// resolveRoleTenant resolves the target tenant for a role request, or writes a
// 400 TENANT_REQUIRED and returns ok=false when none can be determined (a global
// admin that omitted ?tenant=). Every role operation — create, get, list, delete
// — needs a concrete tenant: role configs are stored per tenant, and an empty
// tenant reaching the store is not harmless. On the default flatfile backend a
// get/delete with an empty tenant 500s (the key validator rejects it, so it never
// surfaces as a clean not-found), and a list with an empty tenant filter omits
// the tenant predicate entirely and returns roles across ALL tenants. Guarding
// here keeps all four handlers consistent and closes that cross-tenant list.
func (s *Server) resolveRoleTenant(w http.ResponseWriter, r *http.Request, principal *Principal) (string, bool) {
	tenantID := roleTenantFromRequest(r, principal)
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest,
			"tenant is required: a global admin must pass ?tenant=<id> (role configs are stored per tenant)", "TENANT_REQUIRED")
		return "", false
	}
	return tenantID, true
}

// handleCreateRoleConfig implements POST /api/v1/roles.
func (s *Server) handleCreateRoleConfig(w http.ResponseWriter, r *http.Request) {
	if s.roleConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Role config store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveRoleTenant(w, r, principal)
	if !ok {
		return
	}

	var req createRoleConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}

	if err := validateRoleConfigName(req.Name); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, err.Error(), "INVALID_NAME")
		return
	}

	safeSelector := strings.ReplaceAll(strings.ReplaceAll(req.Selector, "\n", ""), "\r", "")
	if _, _, err := selector.Parse(req.Selector); err != nil {
		s.logger.Info("Invalid role selector", "selector", safeSelector, "error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid selector: %s", err.Error()), "INVALID_SELECTOR")
		return
	}

	now := time.Now().UTC()
	rc := &RoleConfig{
		Name:      req.Name,
		TenantID:  tenantID,
		Selector:  req.Selector,
		Fragment:  req.Fragment,
		CreatedAt: now,
		CreatedBy: principal.ID,
	}

	data, err := json.Marshal(rc)
	if err != nil {
		s.logger.Error("Failed to marshal role config", "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store role config", "INTERNAL_ERROR")
		return
	}

	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	entry := &cfgconfig.ConfigEntry{
		Key: &cfgconfig.ConfigKey{
			TenantID:  tenantID,
			Namespace: "role-policies",
			Name:      req.Name,
		},
		Data:      data,
		Format:    cfgconfig.ConfigFormatJSON,
		Checksum:  checksum,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: principal.ID,
		UpdatedBy: principal.ID,
		Source:    "role-admin",
	}

	if err := s.roleConfigStore.StoreConfig(r.Context(), entry); err != nil {
		s.logger.Error("Failed to store role config", "name", logging.SanitizeLogValue(req.Name), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store role config", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Role config created", "name", logging.SanitizeLogValue(req.Name), "tenant_id", logging.SanitizeLogValue(tenantID))
	s.writeResponse(w, http.StatusCreated, rc)
}

// handleGetRoleConfig implements GET /api/v1/roles/{name}.
func (s *Server) handleGetRoleConfig(w http.ResponseWriter, r *http.Request) {
	if s.roleConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Role config store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveRoleTenant(w, r, principal)
	if !ok {
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role name is required", "MISSING_NAME")
		return
	}

	entry, err := s.roleConfigStore.GetConfig(r.Context(), &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "role-policies",
		Name:      name,
	})
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Role config not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to get role config", "name", logging.SanitizeLogValue(name), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get role config", "INTERNAL_ERROR")
		return
	}

	rc, err := unmarshalRoleConfig(entry)
	if err != nil {
		s.logger.Error("Failed to decode role config", "name", logging.SanitizeLogValue(name), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to decode role config", "INTERNAL_ERROR")
		return
	}

	s.writeSuccessResponse(w, rc)
}

// handleListRoleConfigs implements GET /api/v1/roles.
func (s *Server) handleListRoleConfigs(w http.ResponseWriter, r *http.Request) {
	if s.roleConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Role config store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveRoleTenant(w, r, principal)
	if !ok {
		return
	}

	entries, err := s.roleConfigStore.ListConfigs(r.Context(), &cfgconfig.ConfigFilter{
		TenantID:  tenantID,
		Namespace: "role-policies",
	})
	if err != nil {
		s.logger.Error("Failed to list role configs", "tenant_id", logging.SanitizeLogValue(tenantID), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to list role configs", "INTERNAL_ERROR")
		return
	}

	roles := make([]*RoleConfig, 0, len(entries))
	for _, entry := range entries {
		rc, err := unmarshalRoleConfig(entry)
		if err != nil {
			s.logger.Warn("Skipping malformed role config entry", "name", logging.SanitizeLogValue(entry.Key.Name), "error", err)
			continue
		}
		roles = append(roles, rc)
	}

	s.writeSuccessResponse(w, roles)
}

// handleDeleteRoleConfig implements DELETE /api/v1/roles/{name}.
func (s *Server) handleDeleteRoleConfig(w http.ResponseWriter, r *http.Request) {
	if s.roleConfigStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Role config store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}
	tenantID, ok := s.resolveRoleTenant(w, r, principal)
	if !ok {
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Role name is required", "MISSING_NAME")
		return
	}

	err := s.roleConfigStore.DeleteConfig(r.Context(), &cfgconfig.ConfigKey{
		TenantID:  tenantID,
		Namespace: "role-policies",
		Name:      name,
	})
	if err != nil {
		if errors.Is(err, cfgconfig.ErrConfigNotFound) {
			s.writeErrorResponse(w, http.StatusNotFound, "Role config not found", "NOT_FOUND")
			return
		}
		s.logger.Error("Failed to delete role config", "name", logging.SanitizeLogValue(name), "error", err)
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to delete role config", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Role config deleted", "name", logging.SanitizeLogValue(name), "tenant_id", logging.SanitizeLogValue(tenantID))
	s.writeSuccessResponse(w, map[string]string{"deleted": name})
}

// unmarshalRoleConfig decodes a ConfigEntry into a RoleConfig.
func unmarshalRoleConfig(entry *cfgconfig.ConfigEntry) (*RoleConfig, error) {
	var rc RoleConfig
	if err := json.Unmarshal(entry.Data, &rc); err != nil {
		return nil, fmt.Errorf("unmarshal role config: %w", err)
	}
	return &rc, nil
}

// validateRoleConfigName returns an error if name is empty or contains illegal characters.
// A valid name contains only alphanumerics, hyphens, underscores, and dots.
func validateRoleConfigName(name string) error {
	if name == "" {
		return fmt.Errorf("role name is required")
	}
	for _, c := range name {
		if !isValidRoleNameChar(c) {
			return fmt.Errorf("role name contains invalid character %q: use alphanumerics, hyphens, underscores, or dots", c)
		}
	}
	return nil
}

func isValidRoleNameChar(c rune) bool {
	return (c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '_' || c == '.'
}
