// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package health

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// Handler provides HTTP handlers for health monitoring endpoints
type Handler struct {
	collector    MetricsCollector
	alertManager AlertManager
	traceManager TraceManager
	startTime    time.Time
}

// NewHandler creates a new health monitoring handler
func NewHandler(collector MetricsCollector, alertManager AlertManager, traceManager TraceManager) *Handler {
	return &Handler{
		collector:    collector,
		alertManager: alertManager,
		traceManager: traceManager,
		startTime:    time.Now(),
	}
}

// HandleSimpleHealth handles GET /api/v1/health
// Returns basic health status for load balancers and simple monitoring
func (h *Handler) HandleSimpleHealth(w http.ResponseWriter, r *http.Request) {
	// Simple health check - verify collector is available
	_, err := h.collector.GetCurrentMetrics()
	if err != nil {
		h.writeErrorResponse(w, http.StatusServiceUnavailable, "Health check failed", err.Error())
		return
	}

	// Determine overall health status
	status := "healthy"
	activeAlerts := h.alertManager.GetActiveAlerts()
	if len(activeAlerts) > 0 {
		status = "degraded"
	}

	response := map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().Format(time.RFC3339),
		"uptime":    time.Since(h.startTime).String(),
	}

	h.writeSuccessResponse(w, response)
}

// HandleDetailedHealth handles GET /api/v1/health/detailed
// Returns comprehensive health metrics and component status
func (h *Handler) HandleDetailedHealth(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.collector.GetCurrentMetrics()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get metrics", err.Error())
		return
	}

	// Get active alerts
	activeAlerts := h.alertManager.GetActiveAlerts()

	// Build component health status
	components := make(map[string]ComponentHealth)

	// MQTT component
	mqttStatus := "healthy"
	mqttMessage := "MQTT broker operating normally"
	if metrics.MQTT != nil {
		if metrics.MQTT.MessageQueueDepth > 1000 {
			mqttStatus = "degraded"
			mqttMessage = fmt.Sprintf("High message queue depth: %d", metrics.MQTT.MessageQueueDepth)
		}
		if metrics.MQTT.ConnectionErrors > 100 {
			mqttStatus = "unhealthy"
			mqttMessage = fmt.Sprintf("High connection errors: %d", metrics.MQTT.ConnectionErrors)
		}
		components["mqtt"] = ComponentHealth{
			Name:      "MQTT Broker",
			Status:    mqttStatus,
			Message:   mqttMessage,
			LastCheck: metrics.MQTT.CollectedAt,
			Details: map[string]interface{}{
				"active_connections": metrics.MQTT.ActiveConnections,
				"queue_depth":        metrics.MQTT.MessageQueueDepth,
				"throughput":         metrics.MQTT.MessageThroughput,
			},
		}
	}

	// Storage component
	storageStatus := "healthy"
	storageMessage := "Storage provider operating normally"
	if metrics.Storage != nil {
		if metrics.Storage.P95QueryLatencyMs > 1000 {
			storageStatus = "degraded"
			storageMessage = fmt.Sprintf("High query latency: %.2fms", metrics.Storage.P95QueryLatencyMs)
		}
		if metrics.Storage.QueryErrors > 50 {
			storageStatus = "unhealthy"
			storageMessage = fmt.Sprintf("High query errors: %d", metrics.Storage.QueryErrors)
		}
		components["storage"] = ComponentHealth{
			Name:      "Storage Provider",
			Status:    storageStatus,
			Message:   storageMessage,
			LastCheck: metrics.Storage.CollectedAt,
			Details: map[string]interface{}{
				"provider":         metrics.Storage.Provider,
				"pool_utilization": metrics.Storage.PoolUtilization,
				"avg_latency_ms":   metrics.Storage.AvgQueryLatencyMs,
				"p95_latency_ms":   metrics.Storage.P95QueryLatencyMs,
			},
		}
	}

	// Application component
	appStatus := "healthy"
	appMessage := "Application queues operating normally"
	if metrics.Application != nil {
		if metrics.Application.WorkflowQueueDepth > 500 || metrics.Application.ScriptQueueDepth > 500 {
			appStatus = "degraded"
			appMessage = fmt.Sprintf("High queue depth - workflows: %d, scripts: %d",
				metrics.Application.WorkflowQueueDepth, metrics.Application.ScriptQueueDepth)
		}
		components["application"] = ComponentHealth{
			Name:      "Application Services",
			Status:    appStatus,
			Message:   appMessage,
			LastCheck: metrics.Application.CollectedAt,
			Details: map[string]interface{}{
				"workflow_queue_depth": metrics.Application.WorkflowQueueDepth,
				"script_queue_depth":   metrics.Application.ScriptQueueDepth,
				"active_workflows":     metrics.Application.ActiveWorkflows,
				"active_scripts":       metrics.Application.ActiveScripts,
			},
		}
	}

	// System component
	systemStatus := "healthy"
	systemMessage := "System resources healthy"
	if metrics.System != nil {
		if metrics.System.CPUPercent > 80 || metrics.System.MemoryPercent > 80 {
			systemStatus = "degraded"
			systemMessage = fmt.Sprintf("High resource utilization - CPU: %.1f%%, Memory: %.1f%%",
				metrics.System.CPUPercent, metrics.System.MemoryPercent)
		}
		if metrics.System.CPUPercent > 90 || metrics.System.MemoryPercent > 90 {
			systemStatus = "unhealthy"
			systemMessage = fmt.Sprintf("Critical resource utilization - CPU: %.1f%%, Memory: %.1f%%",
				metrics.System.CPUPercent, metrics.System.MemoryPercent)
		}
		components["system"] = ComponentHealth{
			Name:      "System Resources",
			Status:    systemStatus,
			Message:   systemMessage,
			LastCheck: metrics.System.CollectedAt,
			Details: map[string]interface{}{
				"cpu_percent":    metrics.System.CPUPercent,
				"memory_percent": metrics.System.MemoryPercent,
				"goroutines":     metrics.System.GoroutineCount,
				"heap_bytes":     metrics.System.HeapBytes,
			},
		}
	}

	// Determine overall status
	overallStatus := "healthy"
	for _, component := range components {
		if component.Status == "unhealthy" {
			overallStatus = "unhealthy"
			break
		} else if component.Status == "degraded" && overallStatus != "unhealthy" {
			overallStatus = "degraded"
		}
	}

	healthStatus := HealthStatus{
		Status:        overallStatus,
		Timestamp:     time.Now(),
		Components:    components,
		Alerts:        activeAlerts,
		UptimeSeconds: int64(time.Since(h.startTime).Seconds()),
	}

	h.writeSuccessResponse(w, healthStatus)
}

// HandleMetrics handles GET /api/v1/health/metrics
// Returns current controller metrics
func (h *Handler) HandleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.collector.GetCurrentMetrics()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get metrics", err.Error())
		return
	}

	h.writeSuccessResponse(w, metrics)
}

// HandleMetricsHistory handles GET /api/v1/health/metrics/history
// Returns historical metrics within a time range
func (h *Handler) HandleMetricsHistory(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid start time", err.Error())
			return
		}
	} else {
		// Default to last hour
		start = time.Now().Add(-1 * time.Hour)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid end time", err.Error())
			return
		}
	} else {
		end = time.Now()
	}

	history, err := h.collector.GetMetricsHistory(start, end)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get metrics history", err.Error())
		return
	}

	response := map[string]interface{}{
		"start":   start.Format(time.RFC3339),
		"end":     end.Format(time.RFC3339),
		"count":   len(history),
		"metrics": history,
	}

	h.writeSuccessResponse(w, response)
}

// HandleAlerts handles GET /api/v1/health/alerts
// Returns active alerts
func (h *Handler) HandleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := h.alertManager.GetActiveAlerts()

	response := map[string]interface{}{
		"timestamp":    time.Now().Format(time.RFC3339),
		"active_count": len(alerts),
		"alerts":       alerts,
	}

	h.writeSuccessResponse(w, response)
}

// HandleAlertHistory handles GET /api/v1/health/alerts/history
// Returns alert history within a time range
func (h *Handler) HandleAlertHistory(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid start time", err.Error())
			return
		}
	} else {
		// Default to last 24 hours
		start = time.Now().Add(-24 * time.Hour)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid end time", err.Error())
			return
		}
	} else {
		end = time.Now()
	}

	history := h.alertManager.GetAlertHistory(start, end)

	response := map[string]interface{}{
		"start":  start.Format(time.RFC3339),
		"end":    end.Format(time.RFC3339),
		"count":  len(history),
		"alerts": history,
	}

	h.writeSuccessResponse(w, response)
}

// HandleTrace handles GET /api/v1/health/trace/{request_id}
// Returns a specific request trace
func (h *Handler) HandleTrace(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	requestID := vars["request_id"]

	if requestID == "" {
		h.writeErrorResponse(w, http.StatusBadRequest, "Request ID is required", "MISSING_REQUEST_ID")
		return
	}

	trace, err := h.traceManager.GetTrace(requestID)
	if err != nil {
		h.writeErrorResponse(w, http.StatusNotFound, "Trace not found", err.Error())
		return
	}

	h.writeSuccessResponse(w, trace)
}

// HandleTraces handles GET /api/v1/health/traces
// Returns traces within a time range
func (h *Handler) HandleTraces(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")

	var start, end time.Time
	var err error

	if startStr != "" {
		start, err = time.Parse(time.RFC3339, startStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid start time", err.Error())
			return
		}
	} else {
		// Default to last hour
		start = time.Now().Add(-1 * time.Hour)
	}

	if endStr != "" {
		end, err = time.Parse(time.RFC3339, endStr)
		if err != nil {
			h.writeErrorResponse(w, http.StatusBadRequest, "Invalid end time", err.Error())
			return
		}
	} else {
		end = time.Now()
	}

	traces, err := h.traceManager.GetTraces(start, end)
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get traces", err.Error())
		return
	}

	response := map[string]interface{}{
		"start":  start.Format(time.RFC3339),
		"end":    end.Format(time.RFC3339),
		"count":  len(traces),
		"traces": traces,
	}

	h.writeSuccessResponse(w, response)
}

// HandlePrometheusMetrics handles GET /metrics
// Returns metrics in Prometheus format
func (h *Handler) HandlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := h.collector.GetCurrentMetrics()
	if err != nil {
		h.writeErrorResponse(w, http.StatusInternalServerError, "Failed to get metrics", err.Error())
		return
	}

	// Build Prometheus format output
	var output string

	// MQTT metrics
	if metrics.MQTT != nil {
		output += "# HELP cfgms_mqtt_active_connections Number of active MQTT connections\n"
		output += "# TYPE cfgms_mqtt_active_connections gauge\n"
		output += fmt.Sprintf("cfgms_mqtt_active_connections %d\n", metrics.MQTT.ActiveConnections)

		output += "# HELP cfgms_mqtt_queue_depth MQTT message queue depth\n"
		output += "# TYPE cfgms_mqtt_queue_depth gauge\n"
		output += fmt.Sprintf("cfgms_mqtt_queue_depth %d\n", metrics.MQTT.MessageQueueDepth)

		output += "# HELP cfgms_mqtt_throughput MQTT message throughput (messages per second)\n"
		output += "# TYPE cfgms_mqtt_throughput gauge\n"
		output += fmt.Sprintf("cfgms_mqtt_throughput %.2f\n", metrics.MQTT.MessageThroughput)

		output += "# HELP cfgms_mqtt_connection_errors Total MQTT connection errors\n"
		output += "# TYPE cfgms_mqtt_connection_errors counter\n"
		output += fmt.Sprintf("cfgms_mqtt_connection_errors %d\n", metrics.MQTT.ConnectionErrors)
	}

	// Storage metrics
	if metrics.Storage != nil {
		output += "# HELP cfgms_storage_pool_utilization Storage connection pool utilization (0-1)\n"
		output += "# TYPE cfgms_storage_pool_utilization gauge\n"
		output += fmt.Sprintf("cfgms_storage_pool_utilization %.2f\n", metrics.Storage.PoolUtilization)

		output += "# HELP cfgms_storage_query_latency_avg_ms Average storage query latency in milliseconds\n"
		output += "# TYPE cfgms_storage_query_latency_avg_ms gauge\n"
		output += fmt.Sprintf("cfgms_storage_query_latency_avg_ms %.2f\n", metrics.Storage.AvgQueryLatencyMs)

		output += "# HELP cfgms_storage_query_latency_p95_ms P95 storage query latency in milliseconds\n"
		output += "# TYPE cfgms_storage_query_latency_p95_ms gauge\n"
		output += fmt.Sprintf("cfgms_storage_query_latency_p95_ms %.2f\n", metrics.Storage.P95QueryLatencyMs)

		output += "# HELP cfgms_storage_slow_queries Total slow queries (>1 second)\n"
		output += "# TYPE cfgms_storage_slow_queries counter\n"
		output += fmt.Sprintf("cfgms_storage_slow_queries %d\n", metrics.Storage.SlowQueryCount)
	}

	// Application metrics
	if metrics.Application != nil {
		output += "# HELP cfgms_workflow_queue_depth Workflow execution queue depth\n"
		output += "# TYPE cfgms_workflow_queue_depth gauge\n"
		output += fmt.Sprintf("cfgms_workflow_queue_depth %d\n", metrics.Application.WorkflowQueueDepth)

		output += "# HELP cfgms_script_queue_depth Script execution queue depth\n"
		output += "# TYPE cfgms_script_queue_depth gauge\n"
		output += fmt.Sprintf("cfgms_script_queue_depth %d\n", metrics.Application.ScriptQueueDepth)

		output += "# HELP cfgms_active_workflows Number of active workflow executions\n"
		output += "# TYPE cfgms_active_workflows gauge\n"
		output += fmt.Sprintf("cfgms_active_workflows %d\n", metrics.Application.ActiveWorkflows)

		output += "# HELP cfgms_active_scripts Number of active script executions\n"
		output += "# TYPE cfgms_active_scripts gauge\n"
		output += fmt.Sprintf("cfgms_active_scripts %d\n", metrics.Application.ActiveScripts)
	}

	// System metrics
	if metrics.System != nil {
		output += "# HELP cfgms_cpu_percent CPU utilization percentage\n"
		output += "# TYPE cfgms_cpu_percent gauge\n"
		output += fmt.Sprintf("cfgms_cpu_percent %.2f\n", metrics.System.CPUPercent)

		output += "# HELP cfgms_memory_percent Memory utilization percentage\n"
		output += "# TYPE cfgms_memory_percent gauge\n"
		output += fmt.Sprintf("cfgms_memory_percent %.2f\n", metrics.System.MemoryPercent)

		output += "# HELP cfgms_memory_bytes Memory usage in bytes\n"
		output += "# TYPE cfgms_memory_bytes gauge\n"
		output += fmt.Sprintf("cfgms_memory_bytes %d\n", metrics.System.MemoryUsedBytes)

		output += "# HELP cfgms_goroutines Number of goroutines\n"
		output += "# TYPE cfgms_goroutines gauge\n"
		output += fmt.Sprintf("cfgms_goroutines %d\n", metrics.System.GoroutineCount)

		output += "# HELP cfgms_heap_bytes Heap memory in bytes\n"
		output += "# TYPE cfgms_heap_bytes gauge\n"
		output += fmt.Sprintf("cfgms_heap_bytes %d\n", metrics.System.HeapBytes)
	}

	// Write Prometheus format response
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte(output)); err != nil {
		// Log error but can't return HTTP error after WriteHeader
		fmt.Printf("Failed to write Prometheus metrics: %v\n", err)
	}
}

// writeSuccessResponse writes a successful JSON response
func (h *Handler) writeSuccessResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		fmt.Printf("Failed to encode success response: %v\n", err)
	}
}

// writeErrorResponse writes an error JSON response
func (h *Handler) writeErrorResponse(w http.ResponseWriter, statusCode int, message, detail string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"error":     message,
		"detail":    detail,
		"status":    statusCode,
		"timestamp": time.Now().Format(time.RFC3339),
	}); err != nil {
		fmt.Printf("Failed to encode error response: %v\n", err)
	}
}
