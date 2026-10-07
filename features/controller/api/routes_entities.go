// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerEntityRoutes) }

// registerEntityRoutes registers all /api/v1/entities routes via the per-feature
// registrar (Issue #2796). Routes are registered in specificity order: exact paths
// first, then suffix patterns, then the {eid:.+} catch-all last. All endpoints are
// read-only (GET) and apply mandatory tenant-subtree filtering in-handler (ADR-022 §7).
func registerEntityRoutes(s *Server, api *mux.Router) {
	entities := api.PathPrefix("/entities").Subrouter()

	// Collection endpoints (exact paths, no EID variable).
	entities.Handle("",
		s.requirePermission("entity", "list")(http.HandlerFunc(s.handleQueryEntities)),
	).Methods("GET")

	// /drifted, /edges (POST), and /timeline must be registered before {eid:.+} to take priority.
	entities.Handle("/drifted",
		s.requirePermission("entity", "list")(http.HandlerFunc(s.handleListDrifted)),
	).Methods("GET")

	entities.Handle("/timeline",
		s.requirePermission("entity", "list")(http.HandlerFunc(s.handleGetTimeline)),
	).Methods("GET")

	// Operator edge assertion — exact path registered before the {eid:.+} catch-all (Issue #3374).
	entities.Handle("/edges",
		s.requirePermission("entity", "write")(http.HandlerFunc(s.handleAssertEdge)),
	).Methods("POST")

	// Sub-resource routes — registered before the bare {eid:.+} catch-all so that
	// gorilla/mux prefers the more-specific pattern for paths like /entity-id/edges.
	entities.Handle("/{eid:.+}/edges",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleGetEdges)),
	).Methods("GET")

	entities.Handle("/{eid:.+}/neighborhood",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleGetNeighborhood)),
	).Methods("GET")

	entities.Handle("/{eid:.+}/history",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleGetHistory)),
	).Methods("GET")

	entities.Handle("/{eid:.+}/diff",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleDiff)),
	).Methods("GET")

	entities.Handle("/{eid:.+}/drift",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleGetDriftState)),
	).Methods("GET")

	entities.Handle("/{eid:.+}/desired-state",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleGetDesiredState)),
	).Methods("GET")

	// Single-entity catch-all — must be last so more specific routes above win.
	entities.Handle("/{eid:.+}",
		s.requirePermission("entity", "read")(http.HandlerFunc(s.handleGetEntity)),
	).Methods("GET")
}
