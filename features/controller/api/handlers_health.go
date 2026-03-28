// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"

	"github.com/cfgis/cfgms/pkg/version"
)

// handleHealth handles GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Create health status
	health := HealthStatus{
		Status:    "healthy",
		Version:   version.ShortWithoutPrefix(),
		Timestamp: getCurrentTimestamp(),
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
