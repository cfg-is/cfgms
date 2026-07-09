// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/cluster"
	"github.com/cfgis/cfgms/pkg/logging"
)

// defaultDecommissionTimeout is the maximum time Decommission waits for
// steward sessions to drain before force-marking the node decommissioned.
const defaultDecommissionTimeout = 5 * time.Minute

// clusterNodeDrainResponse is the JSON body for a successful drain request.
type clusterNodeDrainResponse struct {
	NodeID string `json:"node_id"`
	State  string `json:"state"`
}

// handleClusterNodeDrain handles POST /api/v1/cluster/nodes/{id}/drain.
//
// Requires an admin mTLS principal. Non-admin and unauthenticated callers receive
// HTTP 403 before any membership state is touched (defense-in-depth on top of the
// TierMTLSOnly subrouter middleware).
//
// On success returns HTTP 202 Accepted: {"node_id": "...", "state": "draining"}.
// Story 6 will append handleClusterNodeDecommission below this function.
func (s *Server) handleClusterNodeDrain(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusForbidden, "authentication required")
		return
	}
	if !principal.IsAdmin {
		s.respondError(w, http.StatusForbidden, "admin mTLS certificate required")
		return
	}

	nodeID := mux.Vars(r)["id"]

	if s.membershipStore == nil {
		s.respondError(w, http.StatusServiceUnavailable, "cluster membership not configured")
		return
	}

	if err := cluster.Drain(r.Context(), nodeID, s.membershipStore, s); err != nil {
		switch {
		case errors.Is(err, cluster.ErrNodeNotFound):
			s.respondError(w, http.StatusNotFound, "node not found")
		case errors.Is(err, cluster.ErrNodeNotActive):
			s.respondError(w, http.StatusConflict, "node is not active")
		default:
			s.logger.Error("cluster drain failed",
				"node_id", logging.SanitizeLogValue(nodeID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.respondError(w, http.StatusInternalServerError, "drain failed")
		}
		return
	}

	s.logger.Info("cluster node drain initiated",
		"node_id", logging.SanitizeLogValue(nodeID),
		"principal_id", logging.SanitizeLogValue(principal.ID))

	s.respondJSON(w, http.StatusAccepted, clusterNodeDrainResponse{
		NodeID: nodeID,
		State:  string(cluster.StateDraining),
	})
}

// clusterNodeDecommissionResponse is the JSON body for a successful decommission.
type clusterNodeDecommissionResponse struct {
	NodeID string `json:"node_id"`
	State  string `json:"state"`
}

// handleClusterNodeDecommission handles POST /api/v1/cluster/nodes/{id}/decommission.
//
// Requires an admin mTLS principal. Non-admin callers receive HTTP 403 before
// any membership state is touched. The node must be in StateDraining; any
// other state returns HTTP 409.
//
// The handler blocks until all active steward sessions on the local node drain
// or defaultDecommissionTimeout elapses, then marks the node StateDecommissioned
// and returns HTTP 200: {"node_id": "...", "state": "decommissioned"}.
func (s *Server) handleClusterNodeDecommission(w http.ResponseWriter, r *http.Request) {
	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusForbidden, "authentication required")
		return
	}
	if !principal.IsAdmin {
		s.respondError(w, http.StatusForbidden, "admin mTLS certificate required")
		return
	}

	nodeID := mux.Vars(r)["id"]

	if s.membershipStore == nil {
		s.respondError(w, http.StatusServiceUnavailable, "cluster membership not configured")
		return
	}

	if s.registry == nil {
		s.respondError(w, http.StatusServiceUnavailable, "session registry not configured")
		return
	}

	if err := cluster.Decommission(r.Context(), nodeID, s.membershipStore, s.registry, s.logger, defaultDecommissionTimeout); err != nil {
		switch {
		case errors.Is(err, cluster.ErrNodeNotFound):
			s.respondError(w, http.StatusNotFound, "node not found")
		case errors.Is(err, cluster.ErrNodeNotDraining):
			s.respondError(w, http.StatusConflict, "node is not in draining state")
		default:
			s.logger.Error("cluster decommission failed",
				"node_id", logging.SanitizeLogValue(nodeID),
				"error", logging.SanitizeLogValue(err.Error()))
			s.respondError(w, http.StatusInternalServerError, "decommission failed")
		}
		return
	}

	s.logger.Info("cluster node decommissioned",
		"node_id", logging.SanitizeLogValue(nodeID),
		"principal_id", logging.SanitizeLogValue(principal.ID))

	s.respondJSON(w, http.StatusOK, clusterNodeDecommissionResponse{
		NodeID: nodeID,
		State:  string(cluster.StateDecommissioned),
	})
}
