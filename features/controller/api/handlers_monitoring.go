// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package api

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/monitoring"
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
	ctx := r.Context()

	// Get system health from platform monitor
	if s.platformMonitor == nil {
		// Fallback to basic health check
		s.handleBasicSystemHealth(w, r)
		return
	}

	systemHealth, err := s.platformMonitor.GetSystemHealth(ctx)
	if err != nil {
		s.logger.ErrorCtx(ctx, "Failed to get system health", "error", err.Error())
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system health", err.Error())
		return
	}

	// Convert to API response format
	components := make(map[string]string)
	dependencies := make(map[string]string)

	for name, health := range systemHealth.Components {
		components[name] = string(health.Status)

		// Add dependencies from component health
		for _, dep := range health.Dependencies {
			dependencies[dep.Name] = string(dep.Status)
		}
	}

	response := SystemHealth{
		Status:       string(systemHealth.Status),
		Timestamp:    systemHealth.Timestamp,
		Version:      systemHealth.Version,
		Uptime:       systemHealth.Uptime.String(),
		Components:   components,
		Dependencies: dependencies,
	}

	s.writeSuccessResponse(w, response)
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
	ctx := r.Context()

	// Get system metrics from platform monitor
	if s.platformMonitor == nil {
		// Fallback to basic metrics
		s.handleBasicSystemMetrics(w, r)
		return
	}

	systemMetrics, err := s.platformMonitor.GetSystemMetrics(ctx)
	if err != nil {
		s.logger.ErrorCtx(ctx, "Failed to get system metrics", "error", err.Error())
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get system metrics", err.Error())
		return
	}

	// Convert to API response format
	response := SystemMetrics{
		Timestamp:      systemMetrics.Timestamp,
		ActiveStewards: int(systemMetrics.Performance.ActiveConnections),
		TotalStewards:  int(systemMetrics.Aggregated.TotalRequests), // Approximation
		ConfigRequests: systemMetrics.Aggregated.TotalRequests,
		CPU: map[string]float64{
			"usage_percent": systemMetrics.Aggregated.ResourceUtilization.CPUPercent,
		},
		Memory: map[string]int64{
			"used_bytes": systemMetrics.Aggregated.ResourceUtilization.MemoryBytes,
		},
		Disk: map[string]int64{
			"used_bytes": systemMetrics.Aggregated.ResourceUtilization.DiskBytes,
		},
		Network: map[string]int64{
			"bytes_sent":     systemMetrics.Aggregated.ResourceUtilization.NetworkBytesOut,
			"bytes_received": systemMetrics.Aggregated.ResourceUtilization.NetworkBytesIn,
		},
		Errors: make(map[string]int64),
	}

	// Calculate error counts from component metrics
	for _, componentMetrics := range systemMetrics.Components {
		if componentMetrics.Performance != nil {
			errorCount := int64(float64(componentMetrics.Performance.RequestCount) * componentMetrics.Performance.ErrorRate / 100.0)
			response.Errors[componentMetrics.ComponentName] = errorCount
		}
	}

	s.writeSuccessResponse(w, response)
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
	ctx := r.Context()

	// Get anomalies from platform monitor
	if s.platformMonitor == nil {
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
		return
	}

	anomalies, err := s.platformMonitor.GetAnomalies(ctx)
	if err != nil {
		s.logger.ErrorCtx(ctx, "Failed to get anomalies", "error", err.Error())
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get anomalies", err.Error())
		return
	}

	// Convert to API response format
	anomalyList := make([]map[string]interface{}, len(anomalies))
	severityCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	activeAnomalies := 0

	for i, anomaly := range anomalies {
		resolvedAt := (*string)(nil)
		if anomaly.ResolvedAt != nil {
			resolvedStr := anomaly.ResolvedAt.Format("2006-01-02T15:04:05Z07:00")
			resolvedAt = &resolvedStr
		}

		anomalyList[i] = map[string]interface{}{
			"id":             anomaly.ID,
			"component_name": anomaly.ComponentName,
			"type":           string(anomaly.Type),
			"severity":       string(anomaly.Severity),
			"title":          anomaly.Title,
			"description":    anomaly.Description,
			"detected_at":    anomaly.DetectedAt.Format("2006-01-02T15:04:05Z07:00"),
			"resolved_at":    resolvedAt,
			"status":         string(anomaly.Status),
			"context":        anomaly.Context,
			"actions":        anomaly.Actions,
		}

		severityCounts[string(anomaly.Severity)]++
		typeCounts[string(anomaly.Type)]++

		if anomaly.Status == monitoring.AnomalyStatusActive {
			activeAnomalies++
		}
	}

	response := map[string]interface{}{
		"timestamp": time.Now().Format("2006-01-02T15:04:05Z07:00"),
		"anomalies": anomalyList,
		"total":     len(anomalies),
		"summary": map[string]interface{}{
			"total_anomalies":  len(anomalies),
			"active_anomalies": activeAnomalies,
			"severity_counts":  severityCounts,
			"type_counts":      typeCounts,
		},
	}

	s.writeSuccessResponse(w, response)
}

// handleMonitoringComponentHealth handles GET /api/v1/monitoring/components/{component}/health
func (s *Server) handleMonitoringComponentHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	component := vars["component"]

	if component == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request", "Component name is required")
		return
	}

	// Get component health from platform monitor
	if s.platformMonitor == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Monitoring not available", "Platform monitor not initialized")
		return
	}

	health, err := s.platformMonitor.GetComponentHealth(ctx, component)
	if err != nil {
		s.logger.ErrorCtx(ctx, "Failed to get component health",
			"component", component, "error", err.Error())
		s.writeErrorResponse(w, http.StatusNotFound, "Component not found", err.Error())
		return
	}

	// Convert to response format
	dependencies := make([]map[string]interface{}, len(health.Dependencies))
	for i, dep := range health.Dependencies {
		dependencies[i] = map[string]interface{}{
			"name":      dep.Name,
			"status":    string(dep.Status),
			"message":   dep.Message,
			"timestamp": dep.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	response := map[string]interface{}{
		"status":       string(health.Status),
		"message":      health.Message,
		"last_check":   health.LastCheck.Format("2006-01-02T15:04:05Z07:00"),
		"details":      health.Details,
		"dependencies": dependencies,
	}

	s.writeSuccessResponse(w, response)
}

// handleMonitoringComponentMetrics handles GET /api/v1/monitoring/components/{component}/metrics
func (s *Server) handleMonitoringComponentMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	vars := mux.Vars(r)
	component := vars["component"]

	if component == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Invalid request", "Component name is required")
		return
	}

	// Get component metrics from platform monitor
	if s.platformMonitor == nil {
		s.writeErrorResponse(w, http.StatusServiceUnavailable, "Monitoring not available", "Platform monitor not initialized")
		return
	}

	metrics, err := s.platformMonitor.GetComponentMetrics(ctx, component)
	if err != nil {
		s.logger.ErrorCtx(ctx, "Failed to get component metrics",
			"component", component, "error", err.Error())
		s.writeErrorResponse(w, http.StatusNotFound, "Component not found", err.Error())
		return
	}

	// Convert to response format
	response := map[string]interface{}{
		"component_name": metrics.ComponentName,
		"timestamp":      metrics.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
		"business":       metrics.Business,
		"custom":         metrics.Custom,
	}

	if metrics.Performance != nil {
		response["performance"] = map[string]interface{}{
			"response_time_ms":   metrics.Performance.ResponseTime.Milliseconds(),
			"throughput":         metrics.Performance.Throughput,
			"error_rate":         metrics.Performance.ErrorRate,
			"success_rate":       metrics.Performance.SuccessRate,
			"request_count":      metrics.Performance.RequestCount,
			"active_connections": metrics.Performance.ActiveConnections,
		}
	}

	if metrics.Resource != nil {
		response["resource"] = map[string]interface{}{
			"cpu_percent":       metrics.Resource.CPUPercent,
			"memory_bytes":      metrics.Resource.MemoryBytes,
			"memory_percent":    metrics.Resource.MemoryPercent,
			"disk_bytes":        metrics.Resource.DiskBytes,
			"disk_percent":      metrics.Resource.DiskPercent,
			"network_bytes_in":  metrics.Resource.NetworkBytesIn,
			"network_bytes_out": metrics.Resource.NetworkBytesOut,
			"goroutines":        metrics.Resource.Goroutines,
			"file_descriptors":  metrics.Resource.FileDescriptors,
		}
	}

	s.writeSuccessResponse(w, response)
}
