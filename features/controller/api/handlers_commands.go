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

	stewardTenant, found := s.resolveStewardTenant(stewardID)
	if !found {
		s.respondError(w, http.StatusNotFound, "steward not found")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if !isWithinTenantScope(callerTenant, stewardTenant) {
		s.respondError(w, http.StatusNotFound, "steward not found")
		return
	}

	records, err := s.commandStore.ListPendingDeliveries(r.Context(), stewardID)
	if err != nil {
		s.logger.Error("Failed to list pending deliveries",
			"steward_id", logging.SanitizeLogValue(stewardID), "error", logging.SanitizeLogValue(err.Error()))
		s.respondError(w, http.StatusInternalServerError, "failed to list pending deliveries")
		return
	}

	out := make([]*CommandRecordResponse, 0, len(records))
	for _, rec := range records {
		out = append(out, commandRecordToResponse(rec))
	}

	s.respondJSON(w, http.StatusOK, PendingDeliveriesResponse{
		StewardID:  stewardID,
		Deliveries: out,
	})
}
