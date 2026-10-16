// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/cfgis/cfgms/pkg/logging"
)

// handleReady handles GET /api/v1/ready — the controller's REAL-STATE readiness
// probe (Issue #2012). Unlike /api/v1/health (object-presence liveness), this
// round-trips the durable DNA fleet store, so it returns 200 only when the
// controller can actually serve. The blue/green cutover smoketester uses it to
// reject a candidate that bound its API port but cannot reach storage.
// Unauthenticated (registered on the base router) so the probe needs no creds.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ready := ReadinessStatus{
		Status: "ready",
	}
	statusCode := http.StatusOK

	if s.controllerService == nil {
		ready.Status = "not_ready"
		statusCode = http.StatusServiceUnavailable
	} else if err := s.controllerService.StorageReady(r.Context()); err != nil {
		// Log the cause server-side for diagnostics; do not leak it in the
		// response body (no information disclosure).
		s.logger.Warn("Readiness probe: storage round-trip failed", "error", logging.SanitizeLogValue(err.Error()))
		ready.Status = "not_ready"
		statusCode = http.StatusServiceUnavailable
	}

	s.writeResponse(w, statusCode, ready)
}

// handleHealth handles GET /api/v1/health. It is unauthenticated, so the body is
// the overall status only (Issue #5022); per-service detail and the build version
// are served by the authenticated GET /api/v1/health/detailed.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := HealthStatus{Status: "healthy"}

	// Issue #2283: drain gate — fails the LB health check as soon as an operator
	// initiates a drain, before any session drains.
	degraded := s.clusterDraining.Load() ||
		s.controllerService == nil ||
		s.configService == nil ||
		s.rbacService == nil ||
		s.tenantManager == nil ||
		s.rbacManager == nil

	statusCode := http.StatusOK
	if degraded {
		health.Status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	s.writeResponse(w, statusCode, health)
}
