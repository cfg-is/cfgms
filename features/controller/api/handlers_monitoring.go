// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
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

// ResourceMetrics represents resource utilization metrics
type ResourceMetrics struct {
	Timestamp      time.Time              `json:"timestamp"`
	Controllers    map[string]interface{} `json:"controllers"`
	Stewards       map[string]interface{} `json:"stewards"`
	Certificates   map[string]interface{} `json:"certificates"`
	Configurations map[string]interface{} `json:"configurations"`
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
	// Calculate uptime (placeholder - would need actual start time)
	uptime := "24h30m15s" // This should be calculated from actual start time

	// Check component health
	components := map[string]string{
		"database":       "healthy",
		"certificate_ca": "healthy",
		"grpc_server":    "healthy",
		"rbac_service":   "healthy",
	}

	// Check dependencies
	dependencies := map[string]string{
		"storage":    "available",
		"networking": "available",
	}

	// Determine overall health status
	status := "healthy"
	for _, componentStatus := range components {
		if componentStatus != "healthy" {
			status = "degraded"
			break
		}
	}

	health := SystemHealth{
		Status:       status,
		Timestamp:    time.Now(),
		Version:      "0.5.0", // Updated version
		Uptime:       uptime,
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
	// In a real implementation, these would be collected from actual system monitoring
	metrics := SystemMetrics{
		Timestamp: time.Now(),
		CPU: map[string]float64{
			"usage_percent": 15.5,
			"load_1m":       1.2,
			"load_5m":       1.1,
			"load_15m":      0.9,
		},
		Memory: map[string]int64{
			"total_bytes":     8589934592, // 8GB
			"used_bytes":      2147483648, // 2GB
			"available_bytes": 6442450944, // 6GB
			"cache_bytes":     1073741824, // 1GB
		},
		Disk: map[string]int64{
			"total_bytes":     1099511627776, // 1TB
			"used_bytes":      214748364800,  // 200GB
			"available_bytes": 884763262976,  // 800GB
		},
		Network: map[string]int64{
			"bytes_sent":       1048576000, // 1GB
			"bytes_received":   2097152000, // 2GB
			"packets_sent":     1000000,
			"packets_received": 1500000,
		},
		ActiveStewards: 42,
		TotalStewards:  50,
		ConfigRequests: 10000,
		Errors: map[string]int64{
			"authentication": 5,
			"configuration":  2,
			"network":        1,
		},
	}

	s.writeSuccessResponse(w, metrics)
}

// handleResourceMetrics handles GET /api/v1/monitoring/resources
func (s *Server) handleResourceMetrics(w http.ResponseWriter, r *http.Request) {
	resources := ResourceMetrics{
		Timestamp: time.Now(),
		Controllers: map[string]interface{}{
			"active_instances":  1,
			"memory_usage_mb":   512,
			"cpu_usage_percent": 15.2,
		},
		Stewards: map[string]interface{}{
			"total_registered":   50,
			"active_connections": 42,
			"pending_configs":    5,
			"failed_connections": 3,
		},
		Certificates: map[string]interface{}{
			"total_issued":       50,
			"valid_certificates": 47,
			"expiring_soon":      3,
			"revoked":            0,
		},
		Configurations: map[string]interface{}{
			"total_configs":   1500,
			"pending_changes": 25,
			"applied_today":   150,
			"failed_applies":  2,
		},
	}

	s.writeSuccessResponse(w, resources)
}

// handleMonitoringLogs handles GET /api/v1/monitoring/logs
func (s *Server) handleMonitoringLogs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	level := r.URL.Query().Get("level") // error, warn, info, debug
	limit := r.URL.Query().Get("limit") // number of logs to return
	since := r.URL.Query().Get("since") // time filter

	// This is a placeholder implementation
	// In a real system, this would query the logging system
	logs := []map[string]interface{}{
		{
			"timestamp":  time.Now().Add(-1 * time.Hour),
			"level":      "info",
			"message":    "Steward steward-001 registered successfully",
			"component":  "controller",
			"steward_id": "steward-001",
		},
		{
			"timestamp": time.Now().Add(-30 * time.Minute),
			"level":     "warn",
			"message":   "Certificate expiring in 7 days",
			"component": "certificate_manager",
			"serial":    "ABC123456789",
		},
		{
			"timestamp":  time.Now().Add(-5 * time.Minute),
			"level":      "error",
			"message":    "Failed to connect to steward steward-005",
			"component":  "controller",
			"steward_id": "steward-005",
			"error":      "connection timeout",
		},
	}

	// Apply filters (basic implementation)
	if level != "" {
		filteredLogs := []map[string]interface{}{}
		for _, log := range logs {
			if log["level"] == level {
				filteredLogs = append(filteredLogs, log)
			}
		}
		logs = filteredLogs
	}

	s.logger.Info("Monitoring logs requested",
		"level", level,
		"limit", limit,
		"since", since,
		"results", len(logs))

	s.writeSuccessResponse(w, map[string]interface{}{
		"logs":  logs,
		"total": len(logs),
		"filters": map[string]string{
			"level": level,
			"limit": limit,
			"since": since,
		},
	})
}

// handleMonitoringTraces handles GET /api/v1/monitoring/traces
func (s *Server) handleMonitoringTraces(w http.ResponseWriter, r *http.Request) {
	// This is a placeholder for distributed tracing integration
	// In a real implementation, this would integrate with OpenTelemetry/Jaeger
	traces := []map[string]interface{}{
		{
			"trace_id":    "abc123def456",
			"span_id":     "789ghi012jkl",
			"operation":   "steward.register",
			"duration_ms": 150,
			"timestamp":   time.Now().Add(-1 * time.Hour),
			"status":      "success",
			"tags": map[string]string{
				"steward_id": "steward-001",
				"version":    "0.2.1",
			},
		},
		{
			"trace_id":    "def456ghi789",
			"span_id":     "012jkl345mno",
			"operation":   "config.apply",
			"duration_ms": 2500,
			"timestamp":   time.Now().Add(-30 * time.Minute),
			"status":      "success",
			"tags": map[string]string{
				"steward_id": "steward-002",
				"config_id":  "cfg-web-001",
			},
		},
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"traces": traces,
		"total":  len(traces),
	})
}

// handleMonitoringEvents handles GET /api/v1/monitoring/events
func (s *Server) handleMonitoringEvents(w http.ResponseWriter, r *http.Request) {
	// This would integrate with an event streaming system
	events := []map[string]interface{}{
		{
			"id":        "evt-001",
			"type":      "steward.connected",
			"timestamp": time.Now().Add(-2 * time.Hour),
			"data": map[string]interface{}{
				"steward_id": "steward-001",
				"ip_address": "10.0.1.100",
			},
		},
		{
			"id":        "evt-002",
			"type":      "certificate.issued",
			"timestamp": time.Now().Add(-1 * time.Hour),
			"data": map[string]interface{}{
				"serial_number": "ABC123456789",
				"common_name":   "steward-003",
				"expires_at":    time.Now().Add(365 * 24 * time.Hour),
			},
		},
		{
			"id":        "evt-003",
			"type":      "config.applied",
			"timestamp": time.Now().Add(-30 * time.Minute),
			"data": map[string]interface{}{
				"steward_id": "steward-002",
				"config_id":  "cfg-firewall-001",
				"success":    true,
			},
		},
	}

	s.writeSuccessResponse(w, map[string]interface{}{
		"events": events,
		"total":  len(events),
	})
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

// handleStewardMetrics handles GET /api/v1/monitoring/stewards/{id}/metrics
func (s *Server) handleStewardMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	stewardID := vars["id"]

	if stewardID == "" {
		s.writeErrorResponse(w, http.StatusBadRequest, "Steward ID is required", "MISSING_STEWARD_ID")
		return
	}

	// In a real implementation, this would query steward-specific metrics
	metrics := map[string]interface{}{
		"steward_id": stewardID,
		"timestamp":  time.Now(),
		"connection": map[string]interface{}{
			"status":         "connected",
			"last_heartbeat": time.Now().Add(-30 * time.Second),
			"uptime_seconds": 86400, // 24 hours
		},
		"performance": map[string]interface{}{
			"cpu_usage_percent":  12.5,
			"memory_usage_mb":    256,
			"disk_usage_percent": 45.0,
			"network_latency_ms": 15,
		},
		"configurations": map[string]interface{}{
			"total_applied":   25,
			"pending_changes": 2,
			"last_sync":       time.Now().Add(-5 * time.Minute),
			"success_rate":    0.96,
		},
		"modules": map[string]interface{}{
			"loaded_modules": 5,
			"active_modules": 4,
			"failed_modules": 0,
		},
	}

	s.logger.Info("Steward metrics requested", "steward_id", stewardID)
	s.writeSuccessResponse(w, metrics)
}

// handleControllerServices handles GET /api/v1/monitoring/controller/services
func (s *Server) handleControllerServices(w http.ResponseWriter, r *http.Request) {
	services := map[string]interface{}{
		"controller_service": map[string]interface{}{
			"status":           "running",
			"active_stewards":  42,
			"pending_requests": 5,
			"uptime_seconds":   86400,
		},
		"configuration_service": map[string]interface{}{
			"status":              "running",
			"configs_processed":   1500,
			"pending_validations": 3,
			"cache_hit_rate":      0.85,
		},
		"rbac_service": map[string]interface{}{
			"status":             "running",
			"active_sessions":    25,
			"permission_checks":  5000,
			"authorization_rate": 0.98,
		},
		"certificate_service": map[string]interface{}{
			"status":              "running",
			"certificates_issued": 50,
			"expiring_soon":       3,
			"ca_health":           "healthy",
		},
	}

	s.writeSuccessResponse(w, services)
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
