// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/cluster"
	"github.com/cfgis/cfgms/pkg/logging"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// defaultDecommissionTimeout is the maximum time Decommission waits for
// steward sessions to drain before force-marking the node decommissioned.
const defaultDecommissionTimeout = 5 * time.Minute

// clusterLifecycleScopeAllowed reports whether principal may act on controller
// HA-cluster membership (Issue #3303).
//
// Controller cluster nodes are fleet-wide infrastructure: features/controller/cluster
// carries no tenant concept, and /cluster/nodes/{id} exposes no tenant path variable.
// requirePermission therefore resolves an empty target tenant for these routes, so
// middleware.go's tenant-isolation block admits any tenant-scoped principal that holds
// the grant, and the ADR-025 Decision 1 root-scoped block is likewise a no-op. Since
// cluster:drain-node and cluster:decommission-node are grantable permission IDs
// (permissions.go), an account confined to a single tenant could otherwise drain or
// decommission a node serving every tenant. Restrict both operations to principals with
// no tenant confinement — unscoped admins, and root-scoped SaaS operators, whose
// TenantID is "" by construction (middleware.go: RootScoped principals keep the unscoped
// shape) and who own root's own infrastructure.
func clusterLifecycleScopeAllowed(principal *Principal) bool {
	return principal.TenantID == ""
}

// clusterNodeDrainResponse is the JSON body for a successful drain request.
type clusterNodeDrainResponse struct {
	NodeID string `json:"node_id"`
	State  string `json:"state"`
}

// handleClusterNodeDrain handles POST /api/v1/cluster/nodes/{id}/drain.
//
// Authorization is enforced at the router level via requirePermission("cluster", "drain-node"),
// which requires AssuranceStrong (ADR-021, Issue #2780), plus the scope guard below.
//
// On success returns HTTP 202 Accepted: {"node_id": "...", "state": "draining"}.
func (s *Server) handleClusterNodeDrain(w http.ResponseWriter, r *http.Request) {

	principal, ok := r.Context().Value(principalContextKey).(*Principal)
	if !ok || principal == nil {
		s.respondError(w, http.StatusForbidden, "authentication required")
		return
	}
	if !clusterLifecycleScopeAllowed(principal) {
		s.respondError(w, http.StatusForbidden, "cluster node lifecycle requires an unscoped principal")
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

// nodeScopedSessionCounter adapts a business.RoutingStore to
// cluster.SessionCounter, scoped to a single target node ID (Issue #3895).
//
// Under any-node routing (ADR-031 Decision 1), a decommission request for
// node B can land on node A. registry.Registry.Count() only ever reports the
// process it lives in — node A's own local connections — so using it
// directly bases the drain-wait on the wrong node's sessions. RoutingStore is
// the durable, cluster-wide table Issue #3764 introduced to answer exactly
// "how many steward sessions does node X hold," so this adapter closes over
// the decommission target's nodeID and asks the shared store instead.
//
// On a read error, Count returns 1 (non-zero) rather than 0: waitForSessionDrain
// treats 0 as "drained, stop waiting immediately," and a store outage must not
// be misread as an empty node. This fails safe by falling back to the existing
// poll-until-timeout behavior — Decommission still force-completes after
// defaultDecommissionTimeout, same as an honestly non-zero count.
type nodeScopedSessionCounter struct {
	ctx          context.Context
	routingStore business.RoutingStore
	nodeID       string
	logger       logging.Logger
}

func (c *nodeScopedSessionCounter) Count() int {
	n, err := c.routingStore.CountByNode(c.ctx, c.nodeID)
	if err != nil {
		c.logger.Error("failed to count target node sessions for decommission drain-wait",
			"node_id", logging.SanitizeLogValue(c.nodeID),
			"error", logging.SanitizeLogValue(err.Error()))
		return 1
	}
	return n
}

// handleClusterNodeDecommission handles POST /api/v1/cluster/nodes/{id}/decommission.
//
// Authorization is enforced at the router level via requirePermission("cluster", "decommission-node"),
// which requires AssuranceStrong (ADR-021, Issue #2780), plus the scope guard below.
// The node must be in StateDraining; any other state returns HTTP 409.
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
	if !clusterLifecycleScopeAllowed(principal) {
		s.respondError(w, http.StatusForbidden, "cluster node lifecycle requires an unscoped principal")
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

	// Issue #3895: prefer the cluster-wide routing store, scoped to the actual
	// target node, over the local registry — which only ever reports sessions
	// on whichever node happens to receive this request. Fall back to the
	// local registry when no routing store is configured (single-node/test
	// deployments), preserving prior behavior there.
	var counter cluster.SessionCounter = s.registry
	if s.routingStore != nil {
		counter = &nodeScopedSessionCounter{
			ctx:          r.Context(),
			routingStore: s.routingStore,
			nodeID:       nodeID,
			logger:       s.logger,
		}
	}

	timeout := s.decommissionTimeout
	if timeout <= 0 {
		timeout = defaultDecommissionTimeout
	}

	if err := cluster.Decommission(r.Context(), nodeID, s.membershipStore, counter, s.logger, timeout); err != nil {
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
