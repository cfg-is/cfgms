// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

const (
	// unattendedRolloutRefusedAction is the audit action recorded each time the scoped
	// rollout credential is refused by the unattended-rollouts gate (Issue #6067).
	unattendedRolloutRefusedAction = "unattended_rollout_refused"

	// Routes the gate protects. They are fixed strings, never request-derived, so the
	// audited route cannot be shaped by the caller.
	gateRouteStartRollout    = "POST /api/v1/rollout"
	gateRouteDispatchUpgrade = "POST /api/v1/stewards/upgrade"
	gateRoutePublishBinary   = "POST /api/v1/installer/steward-binaries/{version}/{platform}/{arch}"
)

// refuseUnattendedRollout is the gate for the routes that start a rollout, dispatch an
// upgrade or publish a steward binary. It refuses the scoped rollout credential (by its
// explicit key kind, never its permission list) unless the cell's unattended-rollouts
// setting is on, writes the response and returns true. Every other principal passes
// untouched, as does the credential while the setting is on.
//
// It runs after requirePermission and request validation and before any record or blob
// is written. The setting is read from the store on every call with no cache, so turning
// it off takes effect on the next request. A missing store or a read error refuses the
// credential with 503 rather than reading as either value. Each refusal is audited.
// Halt and rollback never call it.
func (s *Server) refuseUnattendedRollout(w http.ResponseWriter, r *http.Request, principal *Principal, tenantID, route string) bool {
	if !isRolloutCredential(principal) {
		return false
	}
	st := s.UnattendedRolloutStore()
	if st == nil {
		s.auditUnattendedRolloutRefused(r, principal, tenantID, route, "setting_store_unavailable")
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Unattended rollout setting not available", "UNATTENDED_ROLLOUTS_UNAVAILABLE")
		return true
	}
	setting, err := st.Get(r.Context())
	if err != nil {
		s.logger.Error("Unattended rollout setting unreadable; refusing rollout credential",
			"error", logging.SanitizeLogValue(err.Error()))
		s.auditUnattendedRolloutRefused(r, principal, tenantID, route, "setting_unreadable")
		s.writeErrorResponse(w, http.StatusServiceUnavailable,
			"Unattended rollout setting not available", "UNATTENDED_ROLLOUTS_UNAVAILABLE")
		return true
	}
	if setting.Enabled {
		return false
	}
	s.auditUnattendedRolloutRefused(r, principal, tenantID, route, "unattended_rollouts_disabled")
	s.writeErrorResponse(w, http.StatusForbidden,
		"Unattended rollouts are disabled for this cell", "UNATTENDED_ROLLOUTS_DISABLED")
	return true
}

// auditUnattendedRolloutRefused records a refusal: the principal, the route and the reason.
func (s *Server) auditUnattendedRolloutRefused(r *http.Request, principal *Principal, tenantID, route, reason string) {
	s.emitOperatorAudit(r, principal, rolloutAuditTenant(tenantID),
		business.AuditEventSecurityEvent, unattendedRolloutRefusedAction, "route", route,
		business.AuditResultDenied, business.AuditSeverityHigh,
		map[string]interface{}{
			"principal": principal.ID,
			"route":     route,
			"reason":    reason,
		})
}
