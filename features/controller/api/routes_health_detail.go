// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/controller/health"
)

func init() { RegisterRoutes(registerHealthDetailRoutes) }

// registerHealthDetailRoutes wires health.Handler's detailed health, alert and
// trace endpoints (Issue #4208) onto the authenticated public /api/v1 router,
// following the same registration and permission-gating pattern as
// registerMonitoringRoutes. These back the `cfg controller status` and
// `cfg trace` CLI commands.
//
// The metrics-bearing routes (/health/metrics, /health/metrics/history) are
// NOT registered here. They serve health.Collector data, which the #3156
// hardening decision keeps off the public listener, so they are registered on
// the private metrics listener by registerPrivateHealthMetricsRoutes below,
// beside /monitoring/metrics. `cfg controller metrics` reaches them with --url
// (or CFGMS_METRICS_URL) pointed at that listener's address.
//
// health.Handler.HandlePrometheusMetrics (/health/metrics/prometheus) is
// registered on that same private metrics listener, never here. It exports the
// collector values plus the service-level signal registry in Prometheus text
// format, so it is metrics-bearing data under the same #3156 rule as the routes
// above, and it is gated by the same monitoring/read-metrics permission as
// /monitoring/metrics. A scraper reaches it at the metrics listener address.
//
// Tenant-crossing classification (Issue #4720): these routes describe the
// controller platform itself — system and component health, alerts and traces —
// which is ADR-025 Decision 4 "system and platform logs and metrics". They are
// platform signals, not client-tenant data, and stay reachable to a root caller
// without a crossing.
func registerHealthDetailRoutes(s *Server, api *mux.Router) {
	health := api.PathPrefix("/health").Subrouter()
	health.Handle("/detailed", s.requirePermission("monitoring", "read-detailed-health")(http.HandlerFunc(s.handleHealthDetailed))).Methods("GET")
	health.Handle("/alerts", s.requirePermission("monitoring", "read-alerts")(http.HandlerFunc(s.handleHealthAlerts))).Methods("GET")
	health.Handle("/alerts/history", s.requirePermission("monitoring", "read-alert-history")(http.HandlerFunc(s.handleHealthAlertHistory))).Methods("GET")
	health.Handle("/trace/{request_id}", s.requirePermission("monitoring", "read-trace")(http.HandlerFunc(s.handleHealthTrace))).Methods("GET")
	health.Handle("/traces", s.requirePermission("monitoring", "read-traces")(http.HandlerFunc(s.handleHealthTraces))).Methods("GET")
}

// handleHealthDetailUnavailable reports 503 when the controller was
// constructed without a health collector, alert manager or trace manager
// (some test servers intentionally omit them) — see healthDetailHandler in
// server.go.
// registerPrivateHealthMetricsRoutes registers the health.Collector metrics
// routes on the private metrics listener only. `api` is that listener's
// authenticated /api/v1 subrouter (registerPrivateMetricsRoutes).
func registerPrivateHealthMetricsRoutes(s *Server, api *mux.Router) {
	health := api.PathPrefix("/health").Subrouter()
	health.Handle("/metrics", s.requirePermission("monitoring", "read-metrics")(http.HandlerFunc(s.handleHealthMetrics))).Methods("GET")
	health.Handle("/metrics/history", s.requirePermission("monitoring", "read-metrics-history")(http.HandlerFunc(s.handleHealthMetricsHistory))).Methods("GET")
	health.Handle("/metrics/prometheus", s.requirePermission("monitoring", "read-metrics")(http.HandlerFunc(s.handleHealthMetricsPrometheus))).Methods("GET")
}

func (s *Server) handleHealthDetailUnavailable(w http.ResponseWriter) {
	s.writeErrorResponse(w, http.StatusServiceUnavailable, "Detailed health reporting is not configured", "HEALTH_DETAIL_UNAVAILABLE")
}

// serveHealthDetail answers 503 when the controller has no health detail
// handler, and otherwise dispatches to serve.
func (s *Server) serveHealthDetail(w http.ResponseWriter, r *http.Request, serve func(*health.Handler, http.ResponseWriter, *http.Request)) {
	if s.healthDetailHandler == nil {
		s.handleHealthDetailUnavailable(w)
		return
	}
	serve(s.healthDetailHandler, w, r)
}

func (s *Server) handleHealthDetailed(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleDetailedHealth)
}

func (s *Server) handleHealthMetrics(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleMetrics)
}

func (s *Server) handleHealthMetricsHistory(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleMetricsHistory)
}

func (s *Server) handleHealthMetricsPrometheus(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandlePrometheusMetrics)
}

func (s *Server) handleHealthAlerts(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleAlerts)
}

func (s *Server) handleHealthAlertHistory(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleAlertHistory)
}

func (s *Server) handleHealthTrace(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleTrace)
}

func (s *Server) handleHealthTraces(w http.ResponseWriter, r *http.Request) {
	s.serveHealthDetail(w, r, (*health.Handler).HandleTraces)
}
