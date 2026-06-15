// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"time"

	"github.com/cfgis/cfgms/pkg/version"
)

// handleReady handles GET /api/v1/ready — the controller's REAL-STATE readiness
// probe (Issue #2012). Unlike /api/v1/health (object-presence liveness), this
// round-trips the durable DNA fleet store, so it returns 200 only when the
// controller can actually serve. The blue/green cutover smoketester uses it to
// reject a candidate that bound its API port but cannot reach storage.
// Unauthenticated (registered on the base router) so the probe needs no creds.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ready := ReadinessStatus{
		Status:    "ready",
		Version:   version.ShortWithoutPrefix(),
		Timestamp: time.Now().UTC(),
		Checks:    make(map[string]string),
	}
	statusCode := http.StatusOK

	if s.controllerService == nil {
		ready.Status = "not_ready"
		ready.Checks["controller"] = "unavailable"
		statusCode = http.StatusServiceUnavailable
	} else if err := s.controllerService.StorageReady(r.Context()); err != nil {
		// Log the cause server-side for diagnostics; do not leak it in the
		// response body (no information disclosure).
		s.logger.Warn("Readiness probe: storage round-trip failed", "error", err)
		ready.Status = "not_ready"
		ready.Checks["dna_storage"] = "unavailable"
		statusCode = http.StatusServiceUnavailable
	} else {
		ready.Checks["controller"] = "ok"
		ready.Checks["dna_storage"] = "ok"
	}

	s.writeResponse(w, statusCode, ready)
}

// handleHealth handles GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Create health status
	health := HealthStatus{
		Status:    "healthy",
		Version:   version.ShortWithoutPrefix(),
		Timestamp: time.Now().UTC(),
		Services:  make(map[string]string),
	}

	// Check gRPC services
	if s.controllerService != nil {
		health.Services["controller"] = "healthy"
	} else {
		health.Services["controller"] = "unavailable"
		health.Status = "degraded"
	}

	if s.configService != nil {
		health.Services["configuration"] = "healthy"
	} else {
		health.Services["configuration"] = "unavailable"
		health.Status = "degraded"
	}

	if s.certProvisioningService != nil {
		health.Services["certificate_provisioning"] = "healthy"
	} else {
		health.Services["certificate_provisioning"] = "unavailable"
	}

	if s.rbacService != nil {
		health.Services["rbac"] = "healthy"
	} else {
		health.Services["rbac"] = "unavailable"
		health.Status = "degraded"
	}

	// Certificate manager status
	if s.certManager != nil {
		health.Services["certificate_manager"] = "healthy"
	} else {
		health.Services["certificate_manager"] = "unavailable"
	}

	// Tenant manager status
	if s.tenantManager != nil {
		health.Services["tenant_manager"] = "healthy"
	} else {
		health.Services["tenant_manager"] = "unavailable"
		health.Status = "degraded"
	}

	// RBAC manager status
	if s.rbacManager != nil {
		health.Services["rbac_manager"] = "healthy"
	} else {
		health.Services["rbac_manager"] = "unavailable"
		health.Status = "degraded"
	}

	// Workflow engine status (Issue #414)
	if s.workflowHandler != nil && s.workflowHandler.engine != nil {
		health.Services["workflow_engine"] = "healthy"
	} else {
		health.Services["workflow_engine"] = "unavailable"
	}

	// Return appropriate HTTP status
	statusCode := http.StatusOK
	if health.Status == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeResponse(w, statusCode, health)
}
