// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"
)

func init() { RegisterRoutes(registerHealthDetailRoutes) }

// registerHealthDetailRoutes wires health.Handler's detailed health, metrics,
// alert and trace endpoints (Issue #4208) onto the authenticated /api/v1
// router, following the same registration and permission-gating pattern as
// registerMonitoringRoutes. These back the `cfg controller status`,
// `cfg controller metrics` and `cfg trace` CLI commands.
func registerHealthDetailRoutes(s *Server, api *mux.Router) {
	health := api.PathPrefix("/health").Subrouter()
	health.Handle("/detailed", s.requirePermission("monitoring", "read-detailed-health")(http.HandlerFunc(s.handleHealthDetailed))).Methods("GET")
	health.Handle("/metrics", s.requirePermission("monitoring", "read-metrics")(http.HandlerFunc(s.handleHealthMetrics))).Methods("GET")
	health.Handle("/metrics/history", s.requirePermission("monitoring", "read-metrics-history")(http.HandlerFunc(s.handleHealthMetricsHistory))).Methods("GET")
	health.Handle("/alerts", s.requirePermission("monitoring", "read-alerts")(http.HandlerFunc(s.handleHealthAlerts))).Methods("GET")
	health.Handle("/alerts/history", s.requirePermission("monitoring", "read-alert-history")(http.HandlerFunc(s.handleHealthAlertHistory))).Methods("GET")
	health.Handle("/trace/{request_id}", s.requirePermission("monitoring", "read-trace")(http.HandlerFunc(s.handleHealthTrace))).Methods("GET")
	health.Handle("/traces", s.requirePermission("monitoring", "read-traces")(http.HandlerFunc(s.handleHealthTraces))).Methods("GET")
}

// handleHealthDetailUnavailable reports 503 when the controller was
// constructed without a health collector, alert manager or trace manager
// (some test servers intentionally omit them) — see healthDetailHandler in
// server.go.
func (s *Server) handleHealthDetailUnavailable(w http.ResponseWriter) {
	s.writeErrorResponse(w, http.StatusServiceUnavailable, "Detailed health reporting is not configured", "HEALTH_DETAIL_UNAVAILABLE")
}

func (s *Server) handleHealthDetailed(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleDetailedHealth(w, r)
}

func (s *Server) handleHealthMetrics(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleMetrics(w, r)
}

func (s *Server) handleHealthMetricsHistory(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleMetricsHistory(w, r)
}

func (s *Server) handleHealthAlerts(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleAlerts(w, r)
}

func (s *Server) handleHealthAlertHistory(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleAlertHistory(w, r)
}

func (s *Server) handleHealthTrace(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleTrace(w, r)
}

func (s *Server) handleHealthTraces(w http.ResponseWriter, r *http.Request) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	s.healthDetailHandler.HandleTraces(w, r)
}
