// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"

	stewardtypes "github.com/cfgis/cfgms/features/config/stewardtypes"
	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/logging"
	schedule "github.com/cfgis/cfgms/pkg/maintenance/schedule"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
)

// rebootWindowPutRequest is the body for PUT /api/v1/tenants/{id}/reboot-window
// and PUT /api/v1/stewards/{id}/reboot-window.
type rebootWindowPutRequest struct {
	// ScheduleYAML is the raw YAML for the reboot_window block (validated via schedule.Parse).
	ScheduleYAML string `json:"schedule_yaml"`
	// TenantDefaultTimezone sets StewardSettings.TenantDefaultTimezone (tenant PUT only).
	TenantDefaultTimezone string `json:"tenant_default_timezone,omitempty"`
}

// rebootWindowResponse is returned by GET and PUT /api/v1/{tenants|stewards}/{id}/reboot-window.
type rebootWindowResponse struct {
	TenantID              string `json:"tenant_id,omitempty"`
	StewardID             string `json:"steward_id,omitempty"`
	TenantDefaultTimezone string `json:"tenant_default_timezone,omitempty"`
	// DeclaredScheduleYAML is the raw YAML for the declared reboot_window at this level.
	DeclaredScheduleYAML string `json:"declared_schedule_yaml,omitempty"`
	// NextOccurrence is the ISO-8601 timestamp of the next window start.
	// Empty when no window is in effect (see Status field).
	NextOccurrence string `json:"next_occurrence,omitempty"`
	// NextOccurrenceDisplay is a human-readable form of the next occurrence.
	NextOccurrenceDisplay string `json:"next_occurrence_display,omitempty"`
	// Status is "scheduled" when a window is in effect, or "unrestricted" when none is declared.
	Status string `json:"status"`
}

// handlePutTenantRebootWindow implements PUT /api/v1/tenants/{id}/reboot-window.
// Writes TenantDefaultTimezone + a validated RebootWindow into the tenant's config doc.
func (s *Server) handlePutTenantRebootWindow(w http.ResponseWriter, r *http.Request) {
	configStore := s.rebootWindowConfigStore()
	if configStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Config store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	tenantID := mux.Vars(r)["tenant_id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Tenant ID is required", "MISSING_TENANT_ID")
		return
	}

	var req rebootWindowPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}

	if strings.TrimSpace(req.ScheduleYAML) == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "schedule_yaml is required", "MISSING_SCHEDULE")
		return
	}

	// Validate the schedule via schedule.Parse (Issue #2975).
	parsed, _, err := schedule.Parse([]byte(req.ScheduleYAML))
	if err != nil {
		s.logger.Info("Invalid reboot_window schedule submitted",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("invalid schedule: %s", err.Error()), "INVALID_SCHEDULE")
		return
	}

	// Determine config key based on tenant hierarchy level.
	configKey, err := s.rebootWindowTenantConfigKey(r.Context(), tenantID)
	if err != nil {
		s.logger.Error("Failed to resolve tenant config key",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve tenant config", "INTERNAL_ERROR")
		return
	}

	// Read-modify-write: preserve any existing fields in the stored config doc.
	storedCfg := &stewardtypes.StewardConfig{}
	existing, getErr := configStore.GetConfig(r.Context(), configKey)
	if getErr != nil && !errors.Is(getErr, cfgconfig.ErrConfigNotFound) {
		s.logger.Error("Failed to read existing tenant config",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(getErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read existing config", "INTERNAL_ERROR")
		return
	}
	if existing != nil {
		if parseErr := yaml.Unmarshal(existing.Data, storedCfg); parseErr != nil {
			s.logger.Warn("Existing config parse error; starting fresh",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error", logging.SanitizeLogValue(parseErr.Error()))
			storedCfg = &stewardtypes.StewardConfig{}
		}
	}

	storedCfg.Steward.RebootWindow = parsed
	if req.TenantDefaultTimezone != "" {
		storedCfg.Steward.TenantDefaultTimezone = req.TenantDefaultTimezone
	}

	data, marshalErr := yaml.Marshal(storedCfg)
	if marshalErr != nil {
		s.logger.Error("Failed to marshal updated config",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(marshalErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store config", "INTERNAL_ERROR")
		return
	}

	now := time.Now().UTC()
	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	entry := &cfgconfig.ConfigEntry{
		Key:       configKey,
		Data:      data,
		Format:    cfgconfig.ConfigFormatYAML,
		Checksum:  checksum,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: principal.ID,
		UpdatedBy: principal.ID,
		Source:    "reboot-window-admin",
	}
	if existing != nil {
		entry.CreatedAt = existing.CreatedAt
		entry.CreatedBy = existing.CreatedBy
	}

	if storeErr := configStore.StoreConfig(r.Context(), entry); storeErr != nil {
		s.logger.Error("Failed to store reboot_window config",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(storeErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store config", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Reboot window updated for tenant",
		"tenant_id", logging.SanitizeLogValue(tenantID),
		"namespace", logging.SanitizeLogValue(configKey.Namespace))

	s.recordRebootWindowAuditEvent(r.Context(), tenantID, "tenants/"+tenantID, "update", principal.ID)

	resp := buildNextOccurrenceResponse(parsed, storedCfg.Steward.TenantDefaultTimezone)
	resp.TenantID = tenantID
	resp.TenantDefaultTimezone = storedCfg.Steward.TenantDefaultTimezone
	resp.DeclaredScheduleYAML = req.ScheduleYAML
	s.writeSuccessResponse(w, resp)
}

// handleGetTenantRebootWindow implements GET /api/v1/tenants/{id}/reboot-window.
// Returns the declared rule and the resolved next occurrence from the effective cascade.
func (s *Server) handleGetTenantRebootWindow(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["tenant_id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Tenant ID is required", "MISSING_TENANT_ID")
		return
	}

	// Resolve effective config via full cascade (Issue #2976 InheritanceResolver).
	// stewardID="" means no device-level config is applied; only tenant cascade.
	var resolvedWindow *schedule.Config
	var tenantDefaultTZ string

	if s.configService != nil {
		effective, err := s.configService.GetEffectiveConfiguration(r.Context(), tenantID, "")
		if err != nil {
			s.logger.Error("Failed to resolve effective configuration",
				"tenant_id", logging.SanitizeLogValue(tenantID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve configuration", "INTERNAL_ERROR")
			return
		}
		if effective.Config != nil {
			resolvedWindow = effective.Config.Steward.RebootWindow
			tenantDefaultTZ = effective.Config.Steward.TenantDefaultTimezone
		}
	}

	// Read the directly declared config at this tenant's level for the "declared" field.
	var declaredYAML string
	configStore := s.rebootWindowConfigStore()
	if configStore != nil {
		if configKey, keyErr := s.rebootWindowTenantConfigKey(r.Context(), tenantID); keyErr == nil {
			if existingEntry, getErr := configStore.GetConfig(r.Context(), configKey); getErr == nil {
				var storedCfg stewardtypes.StewardConfig
				if unmarshalErr := yaml.Unmarshal(existingEntry.Data, &storedCfg); unmarshalErr == nil && storedCfg.Steward.RebootWindow != nil {
					if rawBytes, marshalErr := yaml.Marshal(storedCfg.Steward.RebootWindow); marshalErr == nil {
						declaredYAML = string(rawBytes)
					}
				}
			}
		}
	}

	resp := buildNextOccurrenceResponse(resolvedWindow, tenantDefaultTZ)
	resp.TenantID = tenantID
	resp.TenantDefaultTimezone = tenantDefaultTZ
	if declaredYAML != "" {
		resp.DeclaredScheduleYAML = declaredYAML
	}
	s.writeSuccessResponse(w, resp)
}

// handlePutStewardRebootWindow implements PUT /api/v1/stewards/{id}/reboot-window.
// Writes a device-level RebootWindow override into the stewards namespace.
func (s *Server) handlePutStewardRebootWindow(w http.ResponseWriter, r *http.Request) {
	configStore := s.rebootWindowConfigStore()
	if configStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Config store not available", "SERVICE_UNAVAILABLE")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.writeErrorResponse(w, http.StatusUnauthorized, "Authentication required", "AUTHENTICATION_REQUIRED")
		return
	}

	stewardID := mux.Vars(r)["id"]
	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Resolve the steward's tenant via the in-memory controller registry and enforce the
	// caller's tenant boundary before touching any config. The permission middleware
	// cannot do this for these routes (see authorizeStewardRebootWindowTenant).
	stewardTenant, tenantOK := s.authorizeStewardRebootWindowTenant(w, r, stewardID)
	if !tenantOK {
		return
	}

	var req rebootWindowPutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body", "INVALID_REQUEST")
		return
	}

	if strings.TrimSpace(req.ScheduleYAML) == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "schedule_yaml is required", "MISSING_SCHEDULE")
		return
	}

	parsed, _, err := schedule.Parse([]byte(req.ScheduleYAML))
	if err != nil {
		s.logger.Info("Invalid reboot_window schedule submitted for steward",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("invalid schedule: %s", err.Error()), "INVALID_SCHEDULE")
		return
	}

	configKey := &cfgconfig.ConfigKey{
		TenantID:  stewardTenant,
		Namespace: "stewards",
		Name:      stewardID,
	}

	// Read-modify-write: preserve any existing steward-level fields.
	storedCfg := &stewardtypes.StewardConfig{}
	existing, getErr := configStore.GetConfig(r.Context(), configKey)
	if getErr != nil && !errors.Is(getErr, cfgconfig.ErrConfigNotFound) {
		s.logger.Error("Failed to read existing steward config",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(getErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to read existing config", "INTERNAL_ERROR")
		return
	}
	if existing != nil {
		if parseErr := yaml.Unmarshal(existing.Data, storedCfg); parseErr != nil {
			s.logger.Warn("Existing steward config parse error; starting fresh",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(parseErr.Error()))
			storedCfg = &stewardtypes.StewardConfig{}
		}
	}

	storedCfg.Steward.RebootWindow = parsed

	data, marshalErr := yaml.Marshal(storedCfg)
	if marshalErr != nil {
		s.logger.Error("Failed to marshal steward config",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(marshalErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store config", "INTERNAL_ERROR")
		return
	}

	now := time.Now().UTC()
	checksum := fmt.Sprintf("%x", sha256.Sum256(data))
	entry := &cfgconfig.ConfigEntry{
		Key:       configKey,
		Data:      data,
		Format:    cfgconfig.ConfigFormatYAML,
		Checksum:  checksum,
		CreatedAt: now,
		UpdatedAt: now,
		CreatedBy: principal.ID,
		UpdatedBy: principal.ID,
		Source:    "reboot-window-admin",
	}
	if existing != nil {
		entry.CreatedAt = existing.CreatedAt
		entry.CreatedBy = existing.CreatedBy
	}

	if storeErr := configStore.StoreConfig(r.Context(), entry); storeErr != nil {
		s.logger.Error("Failed to store steward reboot_window",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"error", logging.SanitizeLogValue(storeErr.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to store config", "INTERNAL_ERROR")
		return
	}

	s.logger.Info("Reboot window updated for steward",
		"steward_id", logging.SanitizeLogValue(stewardID),
		"tenant_id", logging.SanitizeLogValue(stewardTenant))

	s.recordRebootWindowAuditEvent(r.Context(), stewardTenant, "stewards/"+stewardID, "update", principal.ID)

	resp := buildNextOccurrenceResponse(parsed, "")
	resp.StewardID = stewardID
	resp.DeclaredScheduleYAML = req.ScheduleYAML
	s.writeSuccessResponse(w, resp)
}

// handleGetStewardRebootWindow implements GET /api/v1/stewards/{id}/reboot-window.
// Returns the declared rule and resolved next occurrence from the full effective cascade.
func (s *Server) handleGetStewardRebootWindow(w http.ResponseWriter, r *http.Request) {
	stewardID := mux.Vars(r)["id"]
	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// Resolve the steward's tenant and enforce the caller's tenant boundary before any
	// config read (see authorizeStewardRebootWindowTenant).
	stewardTenant, tenantOK := s.authorizeStewardRebootWindowTenant(w, r, stewardID)
	if !tenantOK {
		return
	}

	var resolvedWindow *schedule.Config
	var tenantDefaultTZ string

	if s.configService != nil {
		effective, err := s.configService.GetEffectiveConfiguration(r.Context(), stewardTenant, stewardID)
		if err != nil {
			s.logger.Error("Failed to resolve effective configuration for steward",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to resolve configuration", "INTERNAL_ERROR")
			return
		}
		if effective.Config != nil {
			resolvedWindow = effective.Config.Steward.RebootWindow
			tenantDefaultTZ = effective.Config.Steward.TenantDefaultTimezone
		}
	}

	// Directly declared config at the steward level for the "declared" field.
	var declaredYAML string
	configStore := s.rebootWindowConfigStore()
	if configStore != nil {
		configKey := &cfgconfig.ConfigKey{
			TenantID:  stewardTenant,
			Namespace: "stewards",
			Name:      stewardID,
		}
		if existingEntry, getErr := configStore.GetConfig(r.Context(), configKey); getErr == nil {
			var storedCfg stewardtypes.StewardConfig
			if unmarshalErr := yaml.Unmarshal(existingEntry.Data, &storedCfg); unmarshalErr == nil && storedCfg.Steward.RebootWindow != nil {
				if rawBytes, marshalErr := yaml.Marshal(storedCfg.Steward.RebootWindow); marshalErr == nil {
					declaredYAML = string(rawBytes)
				}
			}
		}
	}

	resp := buildNextOccurrenceResponse(resolvedWindow, tenantDefaultTZ)
	resp.StewardID = stewardID
	resp.TenantDefaultTimezone = tenantDefaultTZ
	if declaredYAML != "" {
		resp.DeclaredScheduleYAML = declaredYAML
	}
	s.writeSuccessResponse(w, resp)
}

// rebootWindowConfigStore returns the ConfigStore used for reboot window operations.
// Re-uses the configService's config store so PUT and GET share the same backend.
func (s *Server) rebootWindowConfigStore() cfgconfig.ConfigStore {
	if s.configService == nil {
		return nil
	}
	return s.configService.GetConfigStore()
}

// rebootWindowTenantConfigKey resolves the ConfigKey for a tenant's policy-level config doc.
// It mirrors the namespace/name selection in pkg/config/inheritance.go:applyConfigurationLevel:
//   - level 0 (MSP)    → msp-policies / global
//   - level 1 (Client) → client-policies / {tenantID}
//   - level ≥2 (Group) → group-policies / {tenantID}-groups
//
// When s.tenantStore is nil (e.g. lightweight test setups without tenant hierarchy),
// it defaults to the client-policies namespace, which is the most common tenant level.
func (s *Server) rebootWindowTenantConfigKey(ctx context.Context, tenantID string) (*cfgconfig.ConfigKey, error) {
	if s.tenantStore != nil {
		path, err := s.tenantStore.GetTenantPath(ctx, tenantID)
		if err != nil {
			return nil, fmt.Errorf("get tenant path: %w", err)
		}
		level := len(path) - 1
		switch level {
		case 0:
			return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "msp-policies", Name: "global"}, nil
		case 1:
			return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "client-policies", Name: tenantID}, nil
		default:
			return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "group-policies", Name: tenantID + "-groups"}, nil
		}
	}
	// Default: client-policies (most common tenant level).
	return &cfgconfig.ConfigKey{TenantID: tenantID, Namespace: "client-policies", Name: tenantID}, nil
}

// resolveStewardTenant looks up the tenant for a steward via the in-memory controller service.
func (s *Server) resolveStewardTenant(stewardID string) (string, bool) {
	if s.controllerService == nil {
		return "", false
	}
	info, ok := s.controllerService.GetStewardInfo(stewardID)
	if !ok {
		return "", false
	}
	return info.TenantID, true
}

// authorizeStewardRebootWindowTenant resolves the steward's tenant and enforces the
// caller's tenant boundary for the steward-scoped reboot_window endpoints. It returns
// the steward's tenant, or writes the refusal response and returns ok=false.
//
// The permission middleware cannot enforce this. requirePermission's isolation-engine
// and ADR-025 boundary checks both derive the target tenant from the request path
// (extractTargetTenantFromRequest / extractBoundaryTenantFromRequest in middleware.go),
// which yields the "tenant_id" var — or "id" only when resourceType is "tenant". These
// routes carry a *steward* ID under {id} with resourceType "reboot_window", so both
// extractors return "" and both checks are skipped. A steward's tenant is only knowable
// after a registry lookup, so the check has to happen here, which is the same stance
// every sibling steward handler takes (handlers_stewards.go).
//
// Refusals:
//   - unknown steward, or a steward outside a tenant-scoped caller's subtree → 404
//     STEWARD_NOT_FOUND. 404 rather than 403 so a cross-tenant caller cannot use the
//     status code as an existence oracle for steward IDs.
//   - root-scoped caller (ADR-025 Amendment 1 A1.3) acting on a tenant below root with
//     no active crossing → tenant-crossing challenge (ADR-025 Decision 3), so a
//     legitimate break-glass invocation still learns its remedy.
func (s *Server) authorizeStewardRebootWindowTenant(w http.ResponseWriter, r *http.Request, stewardID string) (string, bool) {
	stewardTenant, tenantOK := s.resolveStewardTenant(stewardID)
	if !tenantOK {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return "", false
	}

	// API-key, session and relay principals carry a non-empty TenantID; unscoped mTLS
	// admin principals carry "" and isWithinTenantScope allows them through.
	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	var callerTenant string
	if principal != nil {
		callerTenant = principal.TenantID
	} else {
		callerTenant = s.callerTenantID(r)
	}
	if !isWithinTenantScope(callerTenant, stewardTenant) {
		s.logger.Info("Cross-tenant steward reboot_window access refused",
			"steward_id", logging.SanitizeLogValue(stewardID),
			"steward_tenant", logging.SanitizeLogValue(stewardTenant),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return "", false
	}

	if principal != nil && principal.RootScoped {
		if s.tenantManager == nil {
			// No ancestry source wired: fail closed exactly as if no crossing were
			// active, matching authorizeRootScopedTenantAccess's nil-store stance.
			s.writeTenantCrossingChallenge(w, stewardTenant)
			return "", false
		}
		switch s.authorizeTenantAccess(r.Context(), principal, stewardTenant) {
		case tenantAuthAllowed:
			// Root itself, or a tenant covered by an active crossing.
		case tenantAuthNeedsCrossing:
			s.writeTenantCrossingChallenge(w, stewardTenant)
			return "", false
		default:
			s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
			return "", false
		}
	}

	return stewardTenant, true
}

// buildNextOccurrenceResponse computes the resolved next occurrence from a schedule.Config.
// Returns a response with Status "unrestricted" when cfg is nil or has no schedules.
// ADR-026 decision 6: never omit this computation — if no window is in effect, say so explicitly.
func buildNextOccurrenceResponse(cfg *schedule.Config, tenantDefaultTZ string) *rebootWindowResponse {
	if cfg == nil || len(cfg.Schedules) == 0 {
		return &rebootWindowResponse{
			Status:                "unrestricted",
			NextOccurrenceDisplay: "no reboot_window in effect — unrestricted",
		}
	}

	// Resolve timezone: window timezone > tenant default > UTC.
	tz := cfg.Timezone
	if tz == "" {
		tz = tenantDefaultTZ
	}
	if tz == "" || tz == "device" {
		tz = "UTC"
	}

	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
		tz = "UTC"
	}

	now := time.Now().In(loc)
	var earliest time.Time
	for _, sched := range cfg.Schedules {
		next := schedule.NextOccurrence(now, sched)
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}

	if earliest.IsZero() {
		return &rebootWindowResponse{
			Status:                "unrestricted",
			NextOccurrenceDisplay: "no reboot_window in effect — unrestricted",
		}
	}

	return &rebootWindowResponse{
		NextOccurrence:        earliest.UTC().Format(time.RFC3339),
		NextOccurrenceDisplay: formatNextOccurrenceDisplay(earliest, tz),
		Status:                "scheduled",
	}
}

// formatNextOccurrenceDisplay formats a next-occurrence time for human display,
// e.g. "Thu 16 Jan 2026, 02:00 (America/New_York)".
func formatNextOccurrenceDisplay(t time.Time, tz string) string {
	display := t.Format("Mon 02 Jan 2006, 15:04")
	if tz != "" && tz != "UTC" {
		display += " (" + tz + ")"
	}
	return display
}

// recordRebootWindowAuditEvent emits an audit event for a reboot_window write.
// Fire-and-forget: audit failures are logged but do not surface as errors to callers.
func (s *Server) recordRebootWindowAuditEvent(ctx context.Context, tenantID, resourceID, action, actorID string) {
	if s.auditManager == nil {
		return
	}

	actor := actorID
	if actor == "" {
		actor = audit.SystemUserID
	}

	event := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventConfiguration).
		Action(action).
		User(actor, business.AuditUserTypeHuman).
		Resource("reboot_window", resourceID, "").
		Detail("resource_id", resourceID).
		Detail("actor", actor)

	if err := s.auditManager.RecordEvent(ctx, event); err != nil {
		s.logger.Warn("Failed to record reboot_window audit event",
			"resource_id", logging.SanitizeLogValue(resourceID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
