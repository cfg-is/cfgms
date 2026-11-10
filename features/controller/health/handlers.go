// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package health

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/version"
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

	// Transport component
	transportStatus := "healthy"
	transportMessage := "Transport provider operating normally"
	if metrics.Transport != nil {
		if metrics.Transport.StreamErrors > 100 {
			transportStatus = "degraded"
			transportMessage = fmt.Sprintf("High stream error count: %d", metrics.Transport.StreamErrors)
		}
		if metrics.Transport.StreamErrors > 500 {
			transportStatus = "unhealthy"
			transportMessage = fmt.Sprintf("Critical stream error count: %d", metrics.Transport.StreamErrors)
		}
		components["transport"] = ComponentHealth{
			Name:      "Transport Provider",
			Status:    transportStatus,
			Message:   transportMessage,
			LastCheck: metrics.Transport.CollectedAt,
			Details: map[string]interface{}{
				"connected_stewards":    metrics.Transport.ConnectedStewards,
				"stream_errors":         metrics.Transport.StreamErrors,
				"messages_sent":         metrics.Transport.MessagesSent,
				"messages_received":     metrics.Transport.MessagesReceived,
				"reconnection_attempts": metrics.Transport.ReconnectionAttempts,
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
		Version:       version.ShortWithoutPrefix(),
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

// builtinFamily is one metric family rendered from a field of a ControllerMetrics
// section ("Transport", "Storage", ...). The section and field are looked up by
// name so the table below stays one short row per family.
type builtinFamily struct {
	name    string
	help    string
	kind    string
	section string
	field   string
}

// sample returns the formatted value and whether to render the family. A family
// is skipped when its section is nil (collector not configured) or, for storage,
// when the value is a negative "not instrumented" sentinel (as
// UnimplementedStorageStats in the controller server package reports), so a
// provider with no storage instrumentation exposes no storage series rather than
// a misleading -1.
func (f builtinFamily) sample(m *ControllerMetrics) (string, bool) {
	sec := reflect.ValueOf(m).Elem().FieldByName(f.section)
	if !sec.IsValid() || sec.Kind() != reflect.Pointer || sec.IsNil() {
		return "", false
	}
	return formatMetricValue(sec.Elem().FieldByName(f.field), f.section == "Storage")
}

// formatMetricValue formats an integer or float field; skipNegative drops
// negative values (the storage "not instrumented" sentinels).
func formatMetricValue(v reflect.Value, skipNegative bool) (string, bool) {
	switch {
	case !v.IsValid():
		return "", false
	case v.CanInt():
		return strconv.FormatInt(v.Int(), 10), !skipNegative || v.Int() >= 0
	case v.CanFloat():
		return strconv.FormatFloat(v.Float(), 'f', 2, 64), !skipNegative || v.Float() >= 0
	}
	return "", false
}

// builtinFamilies is the set of metric families the exposition renders from the
// collector snapshot, in output order. SignalRegistry refuses to register a
// name in this list, so a registered signal can never collide with it.
var builtinFamilies = slices.Concat(transportFamilies, storageFamilies, applicationFamilies, systemFamilies)

var transportFamilies = []builtinFamily{
	{"cfgms_transport_connected_stewards", "Number of connected stewards", "gauge", "Transport", "ConnectedStewards"},
	{"cfgms_transport_stream_errors", "Total transport stream errors", "counter", "Transport", "StreamErrors"},
	{"cfgms_transport_messages_sent", "Total messages sent", "counter", "Transport", "MessagesSent"},
	{"cfgms_transport_messages_received", "Total messages received", "counter", "Transport", "MessagesReceived"},
	{"cfgms_transport_reconnection_attempts", "Total reconnection attempts", "counter", "Transport", "ReconnectionAttempts"},
}

var storageFamilies = []builtinFamily{
	{"cfgms_storage_pool_utilization", "Storage connection pool utilization (0-1)", "gauge", "Storage", "PoolUtilization"},
	{"cfgms_storage_query_latency_avg_ms", "Average storage query latency in milliseconds", "gauge", "Storage", "AvgQueryLatencyMs"},
	{"cfgms_storage_query_latency_p95_ms", "P95 storage query latency in milliseconds", "gauge", "Storage", "P95QueryLatencyMs"},
	{"cfgms_storage_slow_queries", "Total slow queries (>1 second)", "counter", "Storage", "SlowQueryCount"},
}

var applicationFamilies = []builtinFamily{
	{"cfgms_workflow_queue_depth", "Workflow execution queue depth", "gauge", "Application", "WorkflowQueueDepth"},
	{"cfgms_script_queue_depth", "Script execution queue depth", "gauge", "Application", "ScriptQueueDepth"},
	{"cfgms_active_workflows", "Number of active workflow executions", "gauge", "Application", "ActiveWorkflows"},
	{"cfgms_active_scripts", "Number of active script executions", "gauge", "Application", "ActiveScripts"},
}

var systemFamilies = []builtinFamily{
	{"cfgms_cpu_percent", "CPU utilization percentage", "gauge", "System", "CPUPercent"},
	{"cfgms_memory_percent", "Memory utilization percentage", "gauge", "System", "MemoryPercent"},
	{"cfgms_memory_bytes", "Memory usage in bytes", "gauge", "System", "MemoryUsedBytes"},
	{"cfgms_goroutines", "Number of goroutines", "gauge", "System", "GoroutineCount"},
	{"cfgms_heap_bytes", "Heap memory in bytes", "gauge", "System", "HeapBytes"},
}

// isBuiltinSeriesName reports whether the exposition already emits name.
func isBuiltinSeriesName(name string) bool {
	for _, f := range builtinFamilies {
		if f.name == name {
			return true
		}
	}
	return false
}

// renderBuiltinFamilies writes the collector-snapshot metrics with HELP and TYPE lines.
func renderBuiltinFamilies(sb *strings.Builder, m *ControllerMetrics) {
	for _, f := range builtinFamilies {
		v, ok := f.sample(m)
		if !ok {
			continue
		}
		sb.WriteString("# HELP " + f.name + " " + escapeHelp(f.help) + "\n")
		sb.WriteString("# TYPE " + f.name + " " + f.kind + "\n")
		sb.WriteString(f.name + " " + v + "\n")
	}
}

// signalSource is implemented by collectors that carry a SignalRegistry.
type signalSource interface {
	Signals() *SignalRegistry
}

// HandlePrometheusMetrics handles GET /api/v1/health/metrics/prometheus.
// It renders the collector snapshot followed by the service-level signal
// registry in Prometheus text format. The output carries no tenant, steward or
// path data: built-in values are controller-wide and registry labels are drawn
// from closed, code-declared sets. Storage values the provider has not
// instrumented are omitted. Before the collector's first snapshot exists only
// the registry is rendered.
func (h *Handler) HandlePrometheusMetrics(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder

	// An error here only means no snapshot has been collected yet.
	if metrics, err := h.collector.GetCurrentMetrics(); err == nil && metrics != nil {
		renderBuiltinFamilies(&sb, metrics)
	}
	if src, ok := h.collector.(signalSource); ok {
		if reg := src.Signals(); reg != nil {
			reg.render(&sb)
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.WriteHeader(http.StatusOK)
	if _, err := io.WriteString(w, sb.String()); err != nil {
		// Can't return an HTTP error after WriteHeader.
		logging.ForModule("controller.health").Warn("Failed to write Prometheus metrics",
			"error", logging.SanitizeLogValue(err.Error()))
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
