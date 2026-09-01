// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// CommandRecordResponse is the trackable delivery/command record surfaced by
// GET /api/v1/commands/{id} (Issue #3757, ADR-031 Decision 2). It is the shape
// callers watch a steward-directed write's delivery lifecycle through.
type CommandRecordResponse struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	StewardID      string    `json:"steward_id"`
	TenantID       string    `json:"tenant_id"`
	Status         string    `json:"status"`
	DeliveryStatus string    `json:"delivery_status"`
	DeliveryDetail string    `json:"delivery_detail,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
	IssuedBy       string    `json:"issued_by,omitempty"`
}

// PendingDeliveriesResponse is returned by GET /api/v1/stewards/{id}/pending-deliveries.
type PendingDeliveriesResponse struct {
	StewardID  string                   `json:"steward_id"`
	Deliveries []*CommandRecordResponse `json:"deliveries"`
}

func commandRecordToResponse(rec *business.CommandRecord) *CommandRecordResponse {
	return &CommandRecordResponse{
		ID:             rec.ID,
		Type:           rec.Type,
		StewardID:      rec.StewardID,
		TenantID:       rec.TenantID,
		Status:         string(rec.Status),
		DeliveryStatus: string(rec.DeliveryStatus),
		DeliveryDetail: rec.DeliveryDetail,
		IssuedAt:       rec.IssuedAt,
		IssuedBy:       rec.IssuedBy,
	}
}

// handleGetCommandRecord implements GET /api/v1/commands/{id} (Issue #3757).
//
// Returns the durable delivery/command record referenced by ConfigPushResponse
// and equivalent steward-directed write responses, so a caller can watch a
// write until it lands (ADR-031 Decision 2). Tenant-scoped: returns 404 (not
// 403) on a cross-tenant lookup to avoid disclosing that the command ID exists,
// matching handleGetConfigPush's precedent.
func (s *Server) handleGetCommandRecord(w http.ResponseWriter, r *http.Request) {
	if s.commandStore == nil {
		s.respondError(w, http.StatusServiceUnavailable, "command store not available")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "command id is required")
		return
	}

	record, err := s.commandStore.GetCommandRecord(r.Context(), id)
	if errors.Is(err, business.ErrCommandNotFound) {
		s.respondError(w, http.StatusNotFound, "command record not found")
		return
	}
	if err != nil {
		s.logger.Error("Failed to retrieve command record",
			"command_id", logging.SanitizeLogValue(id), "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusInternalServerError, "failed to retrieve command record")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, record.TenantID) {
		s.respondError(w, http.StatusNotFound, "command record not found")
		return
	}

	s.respondJSON(w, http.StatusOK, commandRecordToResponse(record))
}

// handleListPendingDeliveries implements GET /api/v1/stewards/{id}/pending-deliveries
// (Issue #3757). Returns every command record targeting the given steward whose
// DeliveryStatus is still pending — the set a steward drains on reconnect.
//
// Tenant scope is resolved from the steward's own record via the node-local
// controller service (resolveStewardTenant, shared with the reboot_window
// endpoints), never from a caller-supplied tenant on the request. A caller
// outside the steward's tenant subtree gets 404, not the pending-deliveries
// list, so this read surface cannot be used to probe cross-tenant delivery
// state by steward ID.
//
// Authorizing on the steward is not sufficient on its own, because a steward's
// tenant binding is mutable (POST /api/v1/stewards/{id}/move, Issue #2341):
// records written while the steward lived in a previous tenant keep that
// tenant_id but stay attached to the same steward_id, and CommandRecordResponse
// exposes tenant_id and issued_by. So the read is also scoped by tenant —
// stewardTenant plus its ancestors, the only tenants that can legitimately have
// targeted the steward where it lives now — in the store query, and each returned
// record is re-checked against that same chain below.
func (s *Server) handleListPendingDeliveries(w http.ResponseWriter, r *http.Request) {
	if s.commandStore == nil {
		s.respondError(w, http.StatusServiceUnavailable, "command store not available")
		return
	}

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	stewardID := mux.Vars(r)["id"]
	if stewardID == "" {
		s.respondError(w, http.StatusBadRequest, "steward id is required")
		return
	}

	// A steward whose tenant is unresolvable cannot be tenant-scoped, and the
	// controller service never records one (it skips devices with no resolvable
	// tenant rather than fabricating an empty one, Issue #2008). Refuse rather
	// than fall back to an unscoped read.
	stewardTenant, found := s.resolveStewardTenant(stewardID)
	if !found || stewardTenant == "" {
		s.respondError(w, http.StatusNotFound, "steward not found")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, stewardTenant) {
		s.respondError(w, http.StatusNotFound, "steward not found")
		return
	}

	records, err := s.commandStore.ListPendingDeliveries(r.Context(), stewardID, stewardTenant)
	if err != nil {
		s.logger.Error("Failed to list pending deliveries",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusInternalServerError, "failed to list pending deliveries")
		return
	}

	// Re-check every record against the steward's tenant chain. CommandStore is a
	// pluggable seam, so the query-level filter is the first line of defence, not
	// the only one: a record stamped with any other tenant (e.g. one written
	// before the steward was moved) never reaches the response body.
	allowedTenants := make(map[string]struct{}, 4)
	for _, tenant := range business.TenantPathChain(stewardTenant) {
		allowedTenants[tenant] = struct{}{}
	}

	out := make([]*CommandRecordResponse, 0, len(records))
	for _, rec := range records {
		if _, ok := allowedTenants[rec.TenantID]; !ok {
			s.logger.Warn("Dropping pending delivery outside the steward's tenant chain",
				"steward_id", logging.SanitizeLogValue(stewardID),
				"steward_tenant", logging.SanitizeLogValue(stewardTenant),
				"record_tenant", logging.SanitizeLogValue(rec.TenantID))
			continue
		}
		out = append(out, commandRecordToResponse(rec))
	}

	s.respondJSON(w, http.StatusOK, PendingDeliveriesResponse{
		StewardID:  stewardID,
		Deliveries: out,
	})
}
