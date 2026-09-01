// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerStewardRoutes) }

// registerStewardRoutes registers all routes on the /stewards subrouter.
// Routes come from two scattered regions of the original setupRouter:
// region 1 (core CRUD, config, connections, scripts, tags) and
// region 2 (compliance, module inventory) — both appended to the same variable.
func registerStewardRoutes(s *Server, api *mux.Router) {
	// Steward management endpoints (require API key authentication)
	stewards := api.PathPrefix("/stewards").Subrouter()
	stewards.Handle("", s.requirePermission("steward", "list")(http.HandlerFunc(s.handleListStewards))).Methods("GET")
	stewards.Handle("/{id}", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleGetSteward))).Methods("GET")
	stewards.Handle("/{id}/dna", s.requirePermission("steward", "read-dna")(http.HandlerFunc(s.handleGetStewardDNA))).Methods("GET")
	stewards.Handle("/{id}/logs", s.requirePermission("steward", "read-logs")(http.HandlerFunc(s.handleGetStewardLogs))).Methods("GET")
	stewards.Handle("/{id}/auth/refresh", s.requirePermission("steward", "auth-refresh")(http.HandlerFunc(s.handleStewardAuthRefresh))).Methods("POST")
	stewards.Handle("/{id}/move", s.requirePermission("steward", "move")(http.HandlerFunc(s.handleMoveSteward))).Methods("POST")                       // Issue #2341, #2780: AssuranceStrong via permissionAssurance
	stewards.Handle("/{id}/visibility", s.requirePermission("steward", "visibility")(http.HandlerFunc(s.handleSetStewardVisibility))).Methods("PATCH") // Issue #2918: AssuranceBasic via permissionAssurance
	stewards.Handle("/{id}", s.requirePermission("steward", "decommission")(http.HandlerFunc(s.handleDecommissionSteward))).Methods("DELETE")          // Issue #2408, #2780: AssuranceStrong via permissionAssurance

	// Configuration management endpoints
	stewards.Handle("/{id}/config", s.requirePermission("steward", "read-config")(http.HandlerFunc(s.handleGetStewardConfig))).Methods("GET")
	stewards.Handle("/{id}/config", s.requirePermission("steward", "write-config")(http.HandlerFunc(s.handleUpdateStewardConfig))).Methods("PUT")
	stewards.Handle("/{id}/config", s.requirePermission("steward", "delete-config")(http.HandlerFunc(s.handleDeleteStewardConfig))).Methods("DELETE")
	stewards.Handle("/{id}/config/validate", s.requirePermission("steward", "validate-config")(http.HandlerFunc(s.handleValidateConfig))).Methods("POST")
	stewards.Handle("/{id}/config/effective", s.requirePermission("steward", "read-config")(http.HandlerFunc(s.handleGetEffectiveConfig))).Methods("GET")

	// Connection monitoring endpoints (Issue #2367)
	stewards.Handle("/connections/all", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleListAllConnections))).Methods("GET")
	stewards.Handle("/{id}/connection", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleGetStewardConnection))).Methods("GET")

	// Script management endpoints
	stewards.Handle("/{id}/scripts/executions", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptExecutions))).Methods("GET")
	stewards.Handle("/{id}/scripts/executions/{execution_id}", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptExecution))).Methods("GET")
	stewards.Handle("/{id}/scripts/executions/{execution_id}/retry", s.requirePermission("steward", "execute-scripts")(http.HandlerFunc(s.handlePostScriptRetry))).Methods("POST")
	stewards.Handle("/{id}/scripts/metrics", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptMetrics))).Methods("GET")
	stewards.Handle("/{id}/scripts/status", s.requirePermission("steward", "read-scripts")(http.HandlerFunc(s.handleGetScriptStatus))).Methods("GET")

	// Steward tag management endpoints (Issue #2545)
	stewards.Handle("/{id}/tags", s.requirePermission("steward", "tag:read")(http.HandlerFunc(s.handleListStewardTags))).Methods("GET")
	stewards.Handle("/{id}/tags", s.requirePermission("steward", "tag:write")(http.HandlerFunc(s.handleAddStewardTags))).Methods("POST")
	stewards.Handle("/{id}/tags", s.requirePermission("steward", "tag:write")(http.HandlerFunc(s.handleDeleteStewardTags))).Methods("DELETE")

	// Compliance reporting endpoints (Story #212) — region 2, appended to same stewards var.
	// Steward-specific compliance endpoints
	stewards.Handle("/{id}/compliance", s.requirePermission("steward", "read-compliance")(http.HandlerFunc(s.handleGetStewardCompliance))).Methods("GET")
	stewards.Handle("/{id}/compliance/report", s.requirePermission("steward", "read-compliance")(http.HandlerFunc(s.handleGetStewardComplianceReport))).Methods("GET")

	// Module inventory endpoint (Issue #1949)
	stewards.Handle("/{id}/modules", s.requirePermission("steward", "read-modules")(http.HandlerFunc(s.handleGetStewardModules))).Methods("GET")

	// Device-level reboot_window override endpoints (Issue #2979). reboot_window.override is
	// intentionally distinct from config.update (ADR-026 decision 3) — a holder of
	// config.update alone must receive 403 on the PUT.
	stewards.Handle("/{id}/reboot-window",
		s.requirePermission("reboot_window", "read")(http.HandlerFunc(s.handleGetStewardRebootWindow))).Methods("GET")
	stewards.Handle("/{id}/reboot-window",
		s.requirePermission("reboot_window", "override")(http.HandlerFunc(s.handlePutStewardRebootWindow))).Methods("PUT")

	// Durable delivery-outbox read endpoint (Issue #3757, ADR-031 Decision 2).
	stewards.Handle("/{id}/pending-deliveries", s.requirePermission("steward", "read")(http.HandlerFunc(s.handleListPendingDeliveries))).Methods("GET")
}
