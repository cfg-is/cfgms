// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/audit"
	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// maxTenantCrossingGrantDuration bounds how far into the future an MSP administrator
	// may time-box a client-granted support access record (ADR-025 Decision 2(a)).
	maxTenantCrossingGrantDuration = 24 * time.Hour

	// tenantCrossingBreakGlassDuration is the fixed elevation window for a tenant-crossing
	// break-glass invocation (ADR-025 Decision 2(b)). Shorter than emergency.break-glass's
	// 4h system-resource window (features/rbac/templates.go) because a tenant-crossing
	// elevation reaches a specific MSP client's own configuration and data, not shared
	// platform infrastructure — the tighter default narrows exposure if a token is stolen
	// mid-window. Not yet exposed as a per-invocation parameter; ADR-025's own "Remaining
	// Tunables" list carries the expiry default as still open (see Amendment 2).
	tenantCrossingBreakGlassDuration = 30 * time.Minute

	// Justification bounds mirror features/rbac.ValidateSensitiveOperation's M-AUTH-2
	// convention (10-1000 chars) — not reused directly because that helper's
	// SensitiveOperationType enum is scoped to RBAC role/permission CRUD, not tenant
	// crossing, but the same anti-abuse rationale applies verbatim here.
	tenantCrossingJustificationMinLen = 10
	tenantCrossingJustificationMaxLen = 1000
)

// handleCreateTenantCrossingGrant implements POST /api/v1/tenants/{id}/access-grants.
// An MSP administrator (or unscoped admin) already authorized for tenantID explicitly
// grants a root-scoped support principal time-boxed, revocable access into their own
// tenant subtree (ADR-025 Decision 2(a)). No justification is required — this is
// opt-in, client-initiated trust, not an emergency override. Returns 404 for an unknown
// or out-of-scope target tenant (existence-oracle prevention, matching handleGetTenant).
func (s *Server) handleCreateTenantCrossingGrant(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	// "root" is the SaaS operator's own scope, not an MSP that can consent to being
	// supported (ADR-025 Decision 1). A crossing recorded on "root" would sit on every
	// tenant's ancestry path (hasActiveTenantCrossing walks GetTenantPath, which starts
	// at "root") and act as a fleet-wide skeleton key, so it is never a legitimate grant
	// target — the per-MSP grant (Decision 2(a)) or the justified, 30-minute break-glass
	// (Decision 2(b)) are the only ways across the boundary.
	if tenantID == rootTenantID {
		s.writeErrorResponse(w, http.StatusForbidden,
			"access grants cannot be created on the root tenant", "ROOT_TENANT_NOT_GRANTABLE")
		return
	}
	// A grant is client-initiated consent flowing from an MSP to a root-scoped support
	// principal. A root-scoped caller minting one would be consenting on the MSP's behalf
	// — self-dealing that bypasses Decision 2(b)'s justification, 30-minute cap, and
	// critical-severity audit trail. Break-glass is the root-scoped caller's only path.
	if principal != nil && principal.RootScoped {
		s.writeErrorResponse(w, http.StatusForbidden,
			"root-scoped callers cannot create access grants; use break-glass", "ROOT_SCOPED_CANNOT_GRANT")
		return
	}

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	// The granting caller must itself be authorized for tenantID — an MSP admin can only
	// grant access into a tenant it already controls, never into an arbitrary one. Reuses
	// the same decision as handleGetTenant; a root-scoped caller without its own crossing
	// gets the same step-up challenge here, since it cannot grant access it doesn't hold.
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant crossing-grant creation refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	var req struct {
		PrincipalID     string `json:"principal_id"`
		DurationMinutes int    `json:"duration_minutes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "invalid request body", "INVALID_REQUEST")
		return
	}
	if req.PrincipalID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "principal_id is required", "MISSING_PRINCIPAL_ID")
		return
	}
	duration := time.Duration(req.DurationMinutes) * time.Minute
	if req.DurationMinutes <= 0 || duration > maxTenantCrossingGrantDuration {
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("duration_minutes must be between 1 and %d", int(maxTenantCrossingGrantDuration.Minutes())),
			"INVALID_DURATION")
		return
	}

	var callerID string
	if principal != nil {
		callerID = principal.ID
	}
	// A grant names a *different* principal as its beneficiary: the MSP admin authorises
	// support staff, it never authorises itself. A self-grant is only ever an attempt to
	// convert whatever access the caller already holds into a longer-lived, differently
	// gated crossing record, so it is refused regardless of the caller's scope.
	if callerID != "" && req.PrincipalID == callerID {
		s.writeErrorResponse(w, http.StatusForbidden,
			"an access grant cannot name its own creator as the granted principal", "SELF_GRANT_FORBIDDEN")
		return
	}
	now := time.Now().UTC()
	crossing := &business.TenantCrossing{
		ID:          uuid.New().String(),
		TenantID:    existing.ID,
		PrincipalID: req.PrincipalID,
		Kind:        business.TenantCrossingKindGrant,
		GrantedBy:   callerID,
		CreatedAt:   now,
		ExpiresAt:   now.Add(duration),
	}
	if err := s.tenantCrossingStore.CreateTenantCrossing(r.Context(), crossing); err != nil {
		s.logger.Error("Failed to create tenant crossing grant",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to create grant", "GRANT_FAILED")
		return
	}

	s.recordTenantCrossingAudit(r, existing.ID, callerID, crossing, business.AuditSeverityHigh,
		"tenant.crossing_grant_created", req.PrincipalID)

	s.writeResponse(w, http.StatusCreated, crossing)
}

// handleTenantBreakGlass implements POST /api/v1/tenants/{id}/break-glass.
// A root-scoped SaaS-operator principal (ADR-025 Amendment 1 A1.3) invokes a
// justified, time-boxed, audited elevation into a tenant it does not otherwise have
// access to (ADR-025 Decision 2(b)) — distinct from, and never granted by, the
// system-resource-only emergency.break-glass RBAC template (features/rbac). Requires
// X-Justification (10-1000 chars, mirroring features/rbac's M-AUTH-2 convention).
func (s *Server) handleTenantBreakGlass(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	// Same boundary as the grant path: a crossing recorded on "root" would cover every
	// tenant in the tree via the ancestry walk in hasActiveTenantCrossing. A root-scoped
	// caller already reaches "root" itself without any crossing (ADR-025 Decision 1), so
	// break-glass on "root" can only ever be an escalation attempt.
	if tenantID == rootTenantID {
		s.writeErrorResponse(w, http.StatusForbidden,
			"break-glass cannot be invoked on the root tenant", "ROOT_TENANT_NOT_CROSSABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	if principal == nil || !principal.RootScoped {
		// Only a root-scoped caller can be denied purely by the ADR-025 boundary — anyone
		// else either already has ordinary ancestry-based access or is denied for a reason
		// break-glass cannot remedy (e.g. missing tenant:* permission entirely).
		s.writeErrorResponse(w, http.StatusForbidden, "break-glass is only available to root-scoped callers", "NOT_ROOT_SCOPED")
		return
	}

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}

	justification := strings.TrimSpace(r.Header.Get("X-Justification"))
	if len(justification) < tenantCrossingJustificationMinLen || len(justification) > tenantCrossingJustificationMaxLen {
		s.writeErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("X-Justification header is required (%d-%d characters)", tenantCrossingJustificationMinLen, tenantCrossingJustificationMaxLen),
			"JUSTIFICATION_REQUIRED")
		return
	}

	now := time.Now().UTC()
	crossing := &business.TenantCrossing{
		ID:            uuid.New().String(),
		TenantID:      existing.ID,
		PrincipalID:   principal.ID,
		Kind:          business.TenantCrossingKindBreakGlass,
		GrantedBy:     principal.ID,
		Justification: justification,
		CreatedAt:     now,
		ExpiresAt:     now.Add(tenantCrossingBreakGlassDuration),
	}
	if err := s.tenantCrossingStore.CreateTenantCrossing(r.Context(), crossing); err != nil {
		s.logger.Error("Failed to create tenant crossing break-glass session",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to create break-glass session", "BREAK_GLASS_FAILED")
		return
	}

	s.recordTenantCrossingAudit(r, existing.ID, principal.ID, crossing, business.AuditSeverityCritical,
		"tenant.crossing_break_glass_invoked", justification)

	s.writeResponse(w, http.StatusCreated, crossing)
}

// handleListTenantCrossings implements GET /api/v1/tenants/{id}/access-grants.
// Returns every grant and break-glass record (active, expired, and revoked) for
// tenantID — the MSP's own tenant-crossing activity view (ADR-025 Decision 2: both
// crossing kinds must be visible to the affected MSP, not hidden from it).
func (s *Server) handleListTenantCrossings(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	tenantID := vars["id"]
	if tenantID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "tenant id is required", "MISSING_TENANT_ID")
		return
	}
	if s.tenantCrossingStore == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "tenant crossing store not available", "TENANT_CROSSING_UNAVAILABLE")
		return
	}

	principal, _ := r.Context().Value(principalContextKey).(*Principal)
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	existing, err := s.tenantManager.GetTenant(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, business.ErrTenantDoesNotExist) {
			s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
			return
		}
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to get tenant", "GET_FAILED")
		return
	}
	switch s.authorizeTenantAccess(r.Context(), principal, existing.ID) {
	case tenantAuthAllowed:
		// proceed
	case tenantAuthNeedsCrossing:
		s.writeTenantCrossingChallenge(w, existing.ID)
		return
	default:
		s.logger.Info("Cross-tenant crossing-list refused",
			"resource_tenant", logging.SanitizeLogValue(existing.ID),
			"caller_tenant", logging.SanitizeLogValue(callerTenant))
		s.writeErrorResponse(w, http.StatusNotFound, "tenant not found", "TENANT_NOT_FOUND")
		return
	}

	crossings, err := s.tenantCrossingStore.ListTenantCrossings(r.Context(), existing.ID)
	if err != nil {
		s.logger.Error("Failed to list tenant crossings",
			"tenant_id", logging.SanitizeLogValue(existing.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "failed to list tenant crossings", "LIST_FAILED")
		return
	}

	s.writeSuccessResponse(w, crossings)
}

// recordTenantCrossingAudit records a Decision 2 grant/break-glass event, tenant-scoped
// so it surfaces through the existing GET /api/v1/audit/entries endpoint — which always
// scopes to the caller's own context tenant — giving the affected MSP visibility into
// crossing activity on its tenant without a bespoke activity-view endpoint.
func (s *Server) recordTenantCrossingAudit(r *http.Request, tenantID, actorID string, crossing *business.TenantCrossing, severity business.AuditSeverity, action, detail string) {
	if s.auditManager == nil {
		return
	}
	b := audit.NewEventBuilder().
		Tenant(tenantID).
		Type(business.AuditEventSystemAccess).
		Action(action).
		User(actorID, business.AuditUserTypeHuman).
		Resource("tenant_crossing", crossing.ID, "").
		Result(business.AuditResultSuccess).
		Severity(severity).
		Detail("crossing_kind", string(crossing.Kind)).
		Detail("target_principal_id", logging.SanitizeLogValue(crossing.PrincipalID)).
		Detail("expires_at", crossing.ExpiresAt.Format(time.RFC3339)).
		Detail("detail", logging.SanitizeLogValue(detail))
	if err := s.auditManager.RecordEvent(r.Context(), b); err != nil {
		s.logger.Error("Failed to record tenant crossing audit event",
			"tenant_id", logging.SanitizeLogValue(tenantID),
			"error", logging.SanitizeLogValue(err.Error()))
	}
}
