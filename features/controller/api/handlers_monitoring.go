// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/pkg/logging"
)

// SystemHealth represents system health information
type SystemHealth struct {
	Status       string            `json:"status"`
	Timestamp    time.Time         `json:"timestamp"`
	Version      string            `json:"version"`
	Uptime       string            `json:"uptime"`
	Components   map[string]string `json:"components"`
	Dependencies map[string]string `json:"dependencies"`
}

// SystemMetrics represents system metrics
type SystemMetrics struct {
	Timestamp      time.Time          `json:"timestamp"`
	CPU            map[string]float64 `json:"cpu"`
	Memory         map[string]int64   `json:"memory"`
	Disk           map[string]int64   `json:"disk"`
	Network        map[string]int64   `json:"network"`
	ActiveStewards int                `json:"active_stewards"`
	TotalStewards  int                `json:"total_stewards"`
	ConfigRequests int64              `json:"config_requests"`
	Errors         map[string]int64   `json:"errors"`
}

// handleSystemHealth handles GET /api/v1/monitoring/health
func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	s.handleBasicSystemHealth(w, r)
}

// handleBasicSystemHealth provides fallback health check when platform monitor is not available
func (s *Server) handleBasicSystemHealth(w http.ResponseWriter, r *http.Request) {
	components := map[string]string{
		"certificate_ca": "healthy",
		"grpc_server":    "healthy",
		"rbac_service":   "healthy",
	}
	dependencies := map[string]string{
		"storage":    "available",
		"networking": "available",
	}

	// Use real health collector metrics if available (Story #417)
	if s.healthCollector != nil {
		if metrics, err := s.healthCollector.GetCurrentMetrics(); err == nil {
			if metrics.Transport != nil {
				if metrics.Transport.ConnectedStewards > 0 {
					components["transport"] = "healthy"
				} else {
					components["transport"] = "no_connections"
				}
			}
			if metrics.Storage != nil && metrics.Storage.Provider != "" {
				components["storage"] = "healthy"
				dependencies["storage"] = metrics.Storage.Provider
			}
			if metrics.System != nil {
				if metrics.System.CPUPercent > 90 || metrics.System.MemoryPercent > 90 {
					components["system_resources"] = "degraded"
				} else {
					components["system_resources"] = "healthy"
				}
			}
		}
	}

	status := "healthy"
	for _, cs := range components {
		if cs == "degraded" || cs == "unhealthy" {
			status = "degraded"
			break
		}
	}

	health := SystemHealth{
		Status:       status,
		Timestamp:    time.Now(),
		Version:      "0.5.0",
		Uptime:       "unknown",
		Components:   components,
		Dependencies: dependencies,
	}

	s.writeSuccessResponse(w, health)
}

// handleSystemMetrics handles GET /api/v1/monitoring/metrics
func (s *Server) handleSystemMetrics(w http.ResponseWriter, r *http.Request) {
	s.handleBasicSystemMetrics(w, r)
}

// handleBasicSystemMetrics provides fallback metrics when platform monitor is not available
func (s *Server) handleBasicSystemMetrics(w http.ResponseWriter, r *http.Request) {
	metrics := SystemMetrics{
		Timestamp:      time.Now(),
		CPU:            map[string]float64{},
		Memory:         map[string]int64{},
		Disk:           map[string]int64{},
		Network:        map[string]int64{},
		ActiveStewards: 0,
		TotalStewards:  0,
		ConfigRequests: 0,
		Errors:         map[string]int64{},
	}

	// Use real health collector metrics if available (Story #417)
	if s.healthCollector != nil {
		if cm, err := s.healthCollector.GetCurrentMetrics(); err == nil {
			if cm.System != nil {
				metrics.CPU["usage_percent"] = cm.System.CPUPercent
				metrics.Memory["used_bytes"] = cm.System.MemoryUsedBytes
				metrics.Memory["heap_bytes"] = cm.System.HeapBytes
				metrics.Memory["rss_bytes"] = cm.System.RSSBytes
			}
			if cm.Transport != nil {
				metrics.ActiveStewards = cm.Transport.ConnectedStewards
				metrics.Network["transport_messages_sent"] = cm.Transport.MessagesSent
				metrics.Network["transport_messages_received"] = cm.Transport.MessagesReceived
				metrics.Errors["transport_stream_errors"] = cm.Transport.StreamErrors
			}
			if cm.Storage != nil {
				metrics.Errors["storage_query_errors"] = cm.Storage.QueryErrors
			}
		}
	}

	s.writeSuccessResponse(w, metrics)
}

// handleMonitoringConfig handles GET /api/v1/monitoring/config
func (s *Server) handleMonitoringConfig(w http.ResponseWriter, r *http.Request) {
	// Return monitoring configuration settings
	config := map[string]interface{}{
		"metrics": map[string]interface{}{
			"enabled":             true,
			"collection_interval": "30s",
			"retention_period":    "7d",
		},
		"logging": map[string]interface{}{
			"level":            "info",
			"structured":       true,
			"output":           "stdout",
			"retention_period": "30d",
		},
		"tracing": map[string]interface{}{
			"enabled":       false,
			"sampling_rate": 0.1,
			"endpoint":      "",
		},
		"health_checks": map[string]interface{}{
			"enabled":        true,
			"check_interval": "10s",
			"timeout":        "5s",
		},
		"alerting": map[string]interface{}{
			"enabled":         false,
			"webhook_url":     "",
			"alert_threshold": 0.8,
		},
	}

	s.writeSuccessResponse(w, config)
}

// handleMonitoringAnomalies handles GET /api/v1/monitoring/anomalies
func (s *Server) handleMonitoringAnomalies(w http.ResponseWriter, r *http.Request) {
	s.writeSuccessResponse(w, map[string]interface{}{
		"anomalies": []interface{}{},
		"total":     0,
		"summary": map[string]interface{}{
			"total_anomalies":  0,
			"active_anomalies": 0,
			"severity_counts":  map[string]int{},
			"type_counts":      map[string]int{},
		},
	})
}

// componentHealthResponse is the only shape the component health endpoint serves.
// It deliberately has no details field: probe details can carry raw error text.
type componentHealthResponse struct {
	Status      string    `json:"status"`
	Message     string    `json:"message"`
	LastChecked time.Time `json:"last_checked"`
}

// controllerCollector resolves the monitor's controller collector, or nil when
// no platform monitor is wired.
func (s *Server) controllerCollector() *monitoring.ControllerCollector {
	if s.systemMonitor == nil {
		return nil
	}
	c, ok := s.systemMonitor.GetCollector("controller")
	if !ok {
		return nil
	}
	cc, _ := c.(*monitoring.ControllerCollector)
	return cc
}

// handleMonitoringComponentHealth handles GET /api/v1/monitoring/components/{component}/health
//
// component is a controller-level infrastructure name (e.g. "grpc_server", "storage"),
// not a tenant-scoped resource; there is no per-tenant component data and no owning
// tenant to check the caller against. It returns the registered service's real status,
// message and last-check time, and 404 for a name with no registered service.
//
//architecture:allow-unscoped-tenant-read -- controller-level infrastructure name, no owning tenant (Issue #4335)
func (s *Server) handleMonitoringComponentHealth(w http.ResponseWriter, r *http.Request) {
	component := mux.Vars(r)["component"]
	if component == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request", "Component name is required")
		return
	}

	cc := s.controllerCollector()
	if cc == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Monitoring not available", "Platform monitor is not running")
		return
	}

	h, err := cc.GetServiceHealth(r.Context(), component)
	if errors.Is(err, monitoring.ErrServiceNotFound) {
		s.writeErrorResponse(w, http.StatusNotFound, "Component not found", "No such monitored component")
		return
	}
	if err != nil {
		s.logger.Warn("Component health lookup failed",
			"component", logging.SanitizeLogValue(component),
			"error", logging.SanitizeLogValue(err.Error()))
		s.writeErrorResponse(w, http.StatusInternalServerError, "Internal error", "Component health unavailable")
		return
	}

	s.writeSuccessResponse(w, componentHealthResponse{
		Status:      h.Status,
		Message:     h.Message,
		LastChecked: h.LastChecked,
	})
}

// handleMonitoringComponentMetrics handles GET /api/v1/monitoring/components/{component}/metrics
//
// component is a controller-level infrastructure name, not a tenant-scoped resource;
// see handleMonitoringComponentHealth (same file) for the full rationale. Registered
// only on the private metrics router.
//
//architecture:allow-unscoped-tenant-read -- controller-level infrastructure name, no owning tenant (Issue #4335)
func (s *Server) handleMonitoringComponentMetrics(w http.ResponseWriter, r *http.Request) {
	component := mux.Vars(r)["component"]
	if component == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request", "Component name is required")
		return
	}

	cc := s.controllerCollector()
	if cc == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Monitoring not available", "Platform monitor is not running")
		return
	}

	metrics, err := cc.GetServiceMetrics(r.Context(), component)
	switch {
	case errors.Is(err, monitoring.ErrServiceNotFound):
		s.writeErrorResponse(w, http.StatusNotFound, "Component not found", "No such monitored component")
		return
	case err != nil:
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Metrics unavailable", "Component metrics are currently unavailable")
		return
	}

	s.writeSuccessResponse(w, metrics)
}
