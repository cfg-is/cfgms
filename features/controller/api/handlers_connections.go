// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/logging"
)

// StewardConnectionDetail is the response body for GET /api/v1/stewards/{id}/connection.
type StewardConnectionDetail struct {
	StewardID    string     `json:"steward_id"`
	Connected    bool       `json:"connected"`
	ConnectedAt  *time.Time `json:"connected_at,omitempty"`
	RemoteAddr   string     `json:"remote_addr,omitempty"`
	LastActivity *time.Time `json:"last_activity,omitempty"`
}

// StewardConnectionItem is one entry in the bulk connections list.
type StewardConnectionItem struct {
	StewardID    string    `json:"steward_id"`
	ConnectedAt  time.Time `json:"connected_at"`
	RemoteAddr   string    `json:"remote_addr"`
	LastActivity time.Time `json:"last_activity"`
}

// handleGetStewardConnection handles GET /api/v1/stewards/{id}/connection.
//
// Returns transport-level connection detail (ConnectedAt, RemoteAddr, last-activity)
// for one steward, sourced from the live connection registry. Distinguishes
// "unknown steward" (404) from "known but not currently connected" (200, connected:false).
//
// Tenant isolation is enforced explicitly: requirePermission's path-var tenant check
// does not apply to a steward-ID path variable (only "tenant" resourceType qualifies),
// so the handler compares steward.TenantID against the caller's tenant directly.
// Admin principals (empty TenantID from context) have global access.
func (s *Server) handleGetStewardConnection(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]
	stewardIDForLog := logging.SanitizeLogValue(stewardID)

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "connection registry not available", "REGISTRY_UNAVAILABLE")
		return
	}

	// Confirm the steward exists (mirrors handleGetSteward existence check).
	stewardInfo, exists := s.controllerService.GetStewardInfo(stewardID)
	if !exists {
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	// Tenant isolation: API-key principals carry a non-empty TenantID; admin mTLS
	// principals have TenantID="" meaning no scope restriction.
	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)
	if callerTenant != "" && stewardInfo.TenantID != callerTenant {
		// 404 instead of 403 to avoid disclosing steward existence across tenants.
		s.writeErrorResponse(w, http.StatusNotFound, "Steward not found", "STEWARD_NOT_FOUND")
		return
	}

	conn, connected := reg.Get(stewardID)
	if !connected {
		s.logger.Debug("Steward known but not currently connected", "steward_id", stewardIDForLog)
		s.writeSuccessResponse(w, StewardConnectionDetail{
			StewardID: stewardID,
			Connected: false,
		})
		return
	}

	connectedAt := conn.ConnectedAt
	lastActivity := conn.GetLastActivity()
	s.writeSuccessResponse(w, StewardConnectionDetail{
		StewardID:    stewardID,
		Connected:    true,
		ConnectedAt:  &connectedAt,
		RemoteAddr:   conn.RemoteAddr,
		LastActivity: &lastActivity,
	})
}

// handleListAllConnections handles GET /api/v1/stewards/connections/all.
//
// Returns all currently-connected stewards from the registry, filtered to the
// caller's tenant. Cross-references registry entries against ListFleetStewards() to
// enforce tenant isolation (registry entries carry no TenantID directly).
//
// The path /stewards/connections/all (2 segments under the stewards subrouter) cannot
// collide with the existing /{id} pattern (1 segment) or /{id}/connection (2 segments
// with a different second-segment literal), so registration order does not matter here.
func (s *Server) handleListAllConnections(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	reg := s.registry
	s.mu.RUnlock()
	if reg == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "connection registry not available", "REGISTRY_UNAVAILABLE")
		return
	}

	callerTenant, _ := r.Context().Value(ctxkeys.TenantID).(string)

	// Build the set of steward IDs visible to the caller using the fleet-wide source
	// (ADR-031 Decision 3, Issue #3764) so stewards attached to peer nodes are included
	// in tenant-scoping checks. The actual connection data still comes from this node's
	// registry (reg.GetAll()), which is node-local by design. (Issue #3495: intended
	// behavior change — peer-attached steward IDs now appear in allowedIDs, improving
	// tenant-scoping correctness.)
	clusterCtx := context.Background()
	if callerTenant != "" {
		clusterCtx = context.WithValue(clusterCtx, ctxkeys.TenantID, callerTenant)
	}
	allStewards := s.controllerService.ListFleetStewards(clusterCtx)
	allowedIDs := make(map[string]bool, len(allStewards))
	for _, st := range allStewards {
		allowedIDs[st.ID] = true
	}

	allConns := reg.GetAll()
	items := make([]StewardConnectionItem, 0, len(allConns))
	for _, conn := range allConns {
		if !allowedIDs[conn.StewardID] {
			continue
		}
		lastActivity := conn.GetLastActivity()
		items = append(items, StewardConnectionItem{
			StewardID:    conn.StewardID,
			ConnectedAt:  conn.ConnectedAt,
			RemoteAddr:   conn.RemoteAddr,
			LastActivity: lastActivity,
		})
	}

	s.logger.Info("Listed active connections", "count", len(items))
	s.writeSuccessResponse(w, map[string]interface{}{"connections": items})
}
