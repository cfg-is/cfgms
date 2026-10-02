// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/session"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// AssurancePolicyOverrideDTO is the wire representation of a single per-permission
// assurance override. MinOverride, when non-nil, must be "basic" or "strong"
// (never "machine" — an override can only raise the bar, not lower it past the
// global floor, and "machine" would be a downgrade for any non-machine permission).
type AssurancePolicyOverrideDTO struct {
	PermissionID        string  `json:"permission_id"`
	MinOverride         *string `json:"min_override,omitempty"`
	RequireUserPresence bool    `json:"require_user_presence"`
}

// AdminAssurancePolicyRequest is the body for PUT /api/v1/tenants/{tenant_path}/assurance-policy.
type AdminAssurancePolicyRequest struct {
	Overrides []AssurancePolicyOverrideDTO `json:"overrides"`
}

// AdminAssurancePolicyResponse is returned by GET and PUT /api/v1/tenants/{tenant_path}/assurance-policy.
type AdminAssurancePolicyResponse struct {
	TenantID  string                       `json:"tenant_id"`
	Overrides []AssurancePolicyOverrideDTO `json:"overrides"`
}

// minOverrideToLevel converts a "basic" / "strong" string to its session.AssuranceLevel.
// Returns (level, true) on success; (0, false) on unrecognised input.
func minOverrideToLevel(s string) (session.AssuranceLevel, bool) {
	switch s {
	case "basic":
		return session.AssuranceBasic, true
	case "strong":
		return session.AssuranceStrong, true
	default:
		return 0, false
	}
}

// levelToMinOverride converts a session.AssuranceLevel to its string representation
// for the DTO ("basic" or "strong"). AssuranceMachine is not a valid MinOverride value.
func levelToMinOverride(lvl session.AssuranceLevel) string {
	switch lvl {
	case session.AssuranceBasic:
		return "basic"
	case session.AssuranceStrong:
		return "strong"
	default:
		return ""
	}
}

// handleGetAssurancePolicy handles GET /api/v1/tenants/{tenant_path}/assurance-policy.
func (s *Server) handleGetAssurancePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["tenant_path"]

	// Cross-tenant: a scoped caller may only read policy for their own tenant or descendants.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		sameTenant := tenantID == callerTenant
		ancestorTenant := strings.HasPrefix(tenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}

	if s.assurancePolicyStore == nil {
		http.Error(w, "assurance policy store unavailable", http.StatusServiceUnavailable)
		return
	}

	policy, err := s.assurancePolicyStore.GetPolicy(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to get assurance policy",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "failed to get assurance policy", http.StatusInternalServerError)
		return
	}

	resp := AdminAssurancePolicyResponse{
		TenantID:  policy.TenantID,
		Overrides: overridesToDTO(policy.Overrides),
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode assurance policy response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// handleSetAssurancePolicy handles PUT /api/v1/tenants/{tenant_path}/assurance-policy.
func (s *Server) handleSetAssurancePolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["tenant_path"]

	// Cross-tenant: a scoped caller may only write policy for their own tenant or descendants.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" {
		sameTenant := tenantID == callerTenant
		ancestorTenant := strings.HasPrefix(tenantID, callerTenant+"/")
		if !sameTenant && !ancestorTenant {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
	}

	var req AdminAssurancePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if s.assurancePolicyStore == nil {
		http.Error(w, "assurance policy store unavailable", http.StatusServiceUnavailable)
		return
	}

	// Tighten-only validation (ADR-021, Issue #2839): each requested MinOverride must be
	// >= the ancestor-resolved requirement (global floor + ancestor overrides, excluding the
	// tenant being written). This is checked at write time so the store never holds a value
	// that would silently lower the effective bar for any descendant.
	//
	// RequireUserPresence needs no such check: resolution ORs it across the whole chain
	// including ancestors. A leaf tenant structurally cannot lower it by omitting or setting
	// it false — the ancestor's true survives the OR regardless.
	if s.tenantStore != nil {
		path, err := s.tenantStore.GetTenantPath(r.Context(), tenantID)
		if err != nil {
			s.logger.Warn("handleSetAssurancePolicy: failed to get tenant path",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error", logging.SanitizeLogValue(err.Error()),
			)
			http.Error(w, "failed to resolve tenant path", http.StatusInternalServerError)
			return
		}

		// ancestorPath is the path excluding the tenant being written.
		var ancestorPath []string
		if len(path) > 0 {
			ancestorPath = path[:len(path)-1]
		}

		for _, ov := range req.Overrides {
			if ov.MinOverride == nil {
				continue
			}
			requestedLevel, ok := minOverrideToLevel(*ov.MinOverride)
			if !ok {
				http.Error(w, "invalid min_override: must be \"basic\" or \"strong\"", http.StatusBadRequest)
				return
			}

			// Resolve the ancestor-only requirement (global floor + ancestor chain, excluding this tenant).
			ancestorReq, _ := s.resolveAssuranceRequirementForPath(r.Context(), ancestorPath, ov.PermissionID)
			if requestedLevel < ancestorReq.Min {
				http.Error(w, "min_override for "+ov.PermissionID+" is below ancestor-resolved requirement: cannot lower the assurance bar", http.StatusBadRequest)
				return
			}
		}
	}

	// Validate and convert DTOs to store model.
	overrides, err := dtosToOverrides(req.Overrides)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	policy := &business.AssurancePolicy{
		TenantID:  tenantID,
		Overrides: overrides,
	}
	if err := s.assurancePolicyStore.SetPolicy(r.Context(), policy); err != nil {
		s.logger.Error("Failed to set assurance policy",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()),
		)
		http.Error(w, "failed to set assurance policy", http.StatusInternalServerError)
		return
	}

	resp := AdminAssurancePolicyResponse{
		TenantID:  tenantID,
		Overrides: req.Overrides,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		s.logger.Error("Failed to encode assurance policy response", "error", logging.SanitizeLogValue(err.Error()))
	}
}

// resolveAssuranceRequirementForPath resolves the assurance requirement for a given
// permission by walking a pre-computed tenant path (rather than looking up the path
// from the store). Used by handleSetAssurancePolicy to evaluate ancestor requirements
// without including the tenant being written.
func (s *Server) resolveAssuranceRequirementForPath(ctx context.Context, path []string, permissionID string) (Requirement, bool) {
	floor, found := permissionAssurance[permissionID]
	if s.assurancePolicyStore == nil {
		return floor, found
	}

	result := floor
	for _, t := range path {
		policy, err := s.assurancePolicyStore.GetPolicy(ctx, t)
		if err != nil {
			s.logger.Warn("resolveAssuranceRequirementForPath: failed to get assurance policy; using global floor",
				"tenant_id", logging.SanitizeLogValue(t),
				"permission_id", logging.SanitizeLogValue(permissionID),
				"error", logging.SanitizeLogValue(err.Error()),
			)
			return floor, found
		}
		for _, ov := range policy.Overrides {
			// Same alias-aware match as resolveAssuranceRequirement: the ancestor bar used
			// for tighten-only validation must include overrides stored under a pre-rename
			// permission ID (Issue #3574).
			if !overrideAppliesTo(ov.PermissionID, permissionID) {
				continue
			}
			found = true
			if ov.MinOverride != nil {
				if ovMin := session.AssuranceLevel(*ov.MinOverride); ovMin > result.Min {
					result.Min = ovMin
				}
			}
			if ov.RequireUserPresence {
				result.RequireUserPresence = true
			}
		}
	}
	return result, found
}

// overridesToDTO converts business model overrides to their DTO representation.
func overridesToDTO(overrides []business.AssurancePolicyOverride) []AssurancePolicyOverrideDTO {
	if len(overrides) == 0 {
		return nil
	}
	dtos := make([]AssurancePolicyOverrideDTO, 0, len(overrides))
	for _, ov := range overrides {
		dto := AssurancePolicyOverrideDTO{
			PermissionID:        ov.PermissionID,
			RequireUserPresence: ov.RequireUserPresence,
		}
		if ov.MinOverride != nil {
			s := levelToMinOverride(session.AssuranceLevel(*ov.MinOverride))
			if s != "" {
				dto.MinOverride = &s
			}
		}
		dtos = append(dtos, dto)
	}
	return dtos
}

// dtosToOverrides converts DTO overrides to their business model representation,
// validating MinOverride values in the process.
func dtosToOverrides(dtos []AssurancePolicyOverrideDTO) ([]business.AssurancePolicyOverride, error) {
	overrides := make([]business.AssurancePolicyOverride, 0, len(dtos))
	for _, dto := range dtos {
		ov := business.AssurancePolicyOverride{
			PermissionID:        dto.PermissionID,
			RequireUserPresence: dto.RequireUserPresence,
		}
		if dto.MinOverride != nil {
			lvl, ok := minOverrideToLevel(*dto.MinOverride)
			if !ok {
				return nil, errInvalidMinOverride(*dto.MinOverride)
			}
			v := int(lvl)
			ov.MinOverride = &v
		}
		overrides = append(overrides, ov)
	}
	return overrides, nil
}

type invalidMinOverrideError string

func (e invalidMinOverrideError) Error() string {
	return "invalid min_override \"" + string(e) + "\": must be \"basic\" or \"strong\""
}

func errInvalidMinOverride(s string) error { return invalidMinOverrideError(s) }
