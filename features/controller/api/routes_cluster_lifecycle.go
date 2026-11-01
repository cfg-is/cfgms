// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerClusterLifecycleRoutes) }

func registerClusterLifecycleRoutes(s *Server, api *mux.Router) {
	// Cluster node lifecycle endpoints (Issue #2283, #2288, #2780).
	// cluster:drain-node and cluster:decommission-node are in permissionAssurance with
	// Min: AssuranceStrong — requirePermission enforces the assurance gate.
	clusterRouter := api.PathPrefix("/cluster").Subrouter()
	clusterRouter.Handle("/nodes/{id}/drain",
		s.requirePermission("cluster", "drain-node")(http.HandlerFunc(s.handleClusterNodeDrain))).Methods("POST")
	clusterRouter.Handle("/nodes/{id}/decommission",
		s.requirePermission("cluster", "decommission-node")(http.HandlerFunc(s.handleClusterNodeDecommission))).Methods("POST")
}
