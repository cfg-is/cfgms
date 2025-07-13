package api

import (
	"net/http"
)

// handleHealth handles GET /api/v1/health
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Create health status
	health := HealthStatus{
		Status:    "healthy",
		Version:   "0.2.0", // TODO: Get from build info
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

	// Return appropriate HTTP status
	statusCode := http.StatusOK
	if health.Status == "degraded" {
		statusCode = http.StatusServiceUnavailable
	}

	s.writeResponse(w, statusCode, health)
}
