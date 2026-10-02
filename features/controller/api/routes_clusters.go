// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerClusterRoutes) }

func registerClusterRoutes(s *Server, api *mux.Router) {
	// Cluster registry endpoints (Issue #2424): read-only view of cluster topology
	// derived on demand from steward DNA attributes. Eventually consistent (up to one
	// DNARefreshInterval, default 30 min) — see docs/api/rest-api.md for details.
	// Reconciliation endpoint (Issue #2704): compares declared vs actual cluster state.
	clusters := api.PathPrefix("/clusters").Subrouter()
	clusters.Handle("", s.requirePermission("cluster", "list")(http.HandlerFunc(s.handleListClusters))).Methods("GET")
	clusters.Handle("/{name}", s.requirePermission("cluster", "read")(http.HandlerFunc(s.handleGetCluster))).Methods("GET")
	clusters.Handle("/{name}/reconciliation", s.requirePermission("cluster", "read")(http.HandlerFunc(s.handleClusterReconciliation))).Methods("GET")
}
