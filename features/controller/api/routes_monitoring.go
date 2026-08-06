// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerMonitoringRoutes) }

func registerMonitoringRoutes(s *Server, api *mux.Router) {
	// Public product monitoring endpoints. Metrics are deliberately absent:
	// they are registered only on the dedicated private metrics router below.
	monitoring := api.PathPrefix("/monitoring").Subrouter()
	monitoring.Handle("/health", s.requirePermission("monitoring", "read-health")(http.HandlerFunc(s.handleSystemHealth))).Methods("GET")
	monitoring.Handle("/config", s.requirePermission("monitoring", "read-config")(http.HandlerFunc(s.handleMonitoringConfig))).Methods("GET")

	// Platform monitoring endpoints
	monitoring.Handle("/anomalies", s.requirePermission("monitoring", "read-anomalies")(http.HandlerFunc(s.handleMonitoringAnomalies))).Methods("GET")
	monitoring.Handle("/components/{component}/health", s.requirePermission("monitoring", "read-component-health")(http.HandlerFunc(s.handleMonitoringComponentHealth))).Methods("GET")
}

// registerPrivateMetricsRoutes preserves authentication and RBAC on the
// metrics surface while keeping the routes off the public product router.
func registerPrivateMetricsRoutes(s *Server, router *mux.Router) {
	api := router.PathPrefix("/api/v1").Subrouter()
	api.Use(s.authenticationMiddleware)
	api.Use(s.validationMiddleware)

	monitoring := api.PathPrefix("/monitoring").Subrouter()
	monitoring.Handle("/metrics", s.requirePermission("monitoring", "read-metrics")(http.HandlerFunc(s.handleSystemMetrics))).Methods("GET")
	monitoring.Handle("/components/{component}/metrics", s.requirePermission("monitoring", "read-component-metrics")(http.HandlerFunc(s.handleMonitoringComponentMetrics))).Methods("GET")
}
