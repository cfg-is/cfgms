// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package export

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// PrometheusExporter exports CFGMS metrics in Prometheus format.
// It provides a standard /metrics endpoint that can be scraped by Prometheus.
type PrometheusExporter struct {
	logger     logging.Logger
	httpServer *http.Server
	config     PrometheusConfig

	// Metrics storage for scraping
	mu          sync.RWMutex
	lastMetrics ExportData
	lastUpdate  time.Time
}

// PrometheusConfig contains configuration specific to Prometheus export.
type PrometheusConfig struct {
	ListenAddr      string `json:"listen_addr" yaml:"listen_addr"`
	MetricsPath     string `json:"metrics_path" yaml:"metrics_path"`
	EnableGoMetrics bool   `json:"enable_go_metrics" yaml:"enable_go_metrics"`
	MetricPrefix    string `json:"metric_prefix" yaml:"metric_prefix"`
}

// NewPrometheusExporter creates a new Prometheus metrics exporter.
func NewPrometheusExporter(logger logging.Logger) *PrometheusExporter {
	return &PrometheusExporter{
		logger: logger,
		config: PrometheusConfig{
			ListenAddr:      "0.0.0.0:2112",
			MetricsPath:     "/metrics",
			EnableGoMetrics: true,
			MetricPrefix:    "cfgms",
		},
	}
}

// Name returns the name of this exporter.
func (pe *PrometheusExporter) Name() string {
	return "prometheus"
}

// Configure initializes the Prometheus exporter with configuration.
func (pe *PrometheusExporter) Configure(config ExporterConfig) error {
	// Extract Prometheus-specific configuration
	if config.Config != nil {
		if listenAddr, ok := config.Config["listen_addr"].(string); ok {
			pe.config.ListenAddr = listenAddr
		}
		if metricsPath, ok := config.Config["metrics_path"].(string); ok {
			pe.config.MetricsPath = metricsPath
		}
		if enableGoMetrics, ok := config.Config["enable_go_metrics"].(bool); ok {
			pe.config.EnableGoMetrics = enableGoMetrics
		}
		if metricPrefix, ok := config.Config["metric_prefix"].(string); ok {
			pe.config.MetricPrefix = metricPrefix
		}
	}

	// Use endpoint from general config if available
	if config.Endpoint != "" {
		pe.config.ListenAddr = config.Endpoint
	}

	pe.logger.InfoCtx(context.Background(), "Configured Prometheus exporter",
		"listen_addr", pe.config.ListenAddr,
		"metrics_path", pe.config.MetricsPath,
		"metric_prefix", pe.config.MetricPrefix)

	return nil
}

// Start begins the Prometheus HTTP server for metrics scraping.
func (pe *PrometheusExporter) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(pe.config.MetricsPath, pe.handleMetrics)
	mux.HandleFunc("/health", pe.handleHealth)

	pe.httpServer = &http.Server{
		Addr:              pe.config.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second, // Prevent Slowloris attacks
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		pe.logger.InfoCtx(ctx, "Starting Prometheus metrics server",
			"addr", pe.config.ListenAddr,
			"path", pe.config.MetricsPath)

		if err := pe.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			pe.logger.ErrorCtx(ctx, "Prometheus metrics server failed",
				"error", err)
		}
	}()

	return nil
}

// Stop gracefully shuts down the Prometheus HTTP server.
func (pe *PrometheusExporter) Stop(ctx context.Context) error {
	if pe.httpServer == nil {
		return nil
	}

	pe.logger.InfoCtx(ctx, "Stopping Prometheus metrics server")

	shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return pe.httpServer.Shutdown(shutdownCtx)
}

// Export stores the metrics data for Prometheus scraping.
func (pe *PrometheusExporter) Export(ctx context.Context, data ExportData) error {
	// Store metrics for scraping (protected by mutex)
	pe.mu.Lock()
	pe.lastMetrics = data
	pe.lastUpdate = time.Now()
	pe.mu.Unlock()

	pe.logger.DebugCtx(ctx, "Updated Prometheus metrics",
		"metrics_count", len(pe.flattenMetrics(data)),
		"timestamp", data.Timestamp)

	return nil
}

// HealthCheck verifies the Prometheus exporter is operational.
func (pe *PrometheusExporter) HealthCheck(ctx context.Context) ExporterHealth {
	health := ExporterHealth{
		Name:            pe.Name(),
		LastHealthCheck: time.Now(),
	}

	if pe.httpServer == nil {
		health.Status = "unhealthy"
		health.Message = "HTTP server not started"
		return health
	}

	// Try to make a health check request to ourselves
	client := &http.Client{Timeout: 2 * time.Second}
	healthURL := fmt.Sprintf("http://%s/health", pe.config.ListenAddr)

	resp, err := client.Get(healthURL)
	if err != nil {
		health.Status = "unhealthy"
		health.Message = fmt.Sprintf("Health check failed: %v", err)
		return health
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but continue
			_ = err // Explicitly ignore error for cleanup operation
		}
	}()

	if resp.StatusCode == http.StatusOK {
		health.Status = "healthy"
		health.Message = "Prometheus metrics server operational"
		health.ResponseTime = time.Since(health.LastHealthCheck)
	} else {
		health.Status = "degraded"
		health.Message = fmt.Sprintf("Health check returned status %d", resp.StatusCode)
	}

	return health
}

// handleMetrics serves Prometheus metrics in the standard format.
func (pe *PrometheusExporter) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	// Get a consistent snapshot of metrics data (protected by mutex)
	pe.mu.RLock()
	lastMetrics := pe.lastMetrics
	lastUpdate := pe.lastUpdate
	pe.mu.RUnlock()

	// If no metrics data is available, return empty response
	if lastMetrics.Timestamp.IsZero() {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	metrics := pe.formatPrometheusMetrics(lastMetrics)

	// Write metrics
	for _, line := range metrics {
		if _, err := fmt.Fprintf(w, "%s\n", line); err != nil {
			// Log error but continue - can't return error from HTTP handler
			continue
		}
	}

	// Add timestamp of last update
	_, _ = fmt.Fprintf(w, "# Last updated: %s\n", lastUpdate.Format(time.RFC3339))
}

// handleHealth provides a simple health check endpoint.
func (pe *PrometheusExporter) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := fmt.Fprintf(w, `{"status":"healthy","service":"prometheus_exporter","timestamp":"%s"}`,
		time.Now().Format(time.RFC3339)); err != nil {
		// Can't return error to client at this point as headers are already sent
		if pe.logger != nil {
			pe.logger.Error("failed to write health response", "error", err)
		}
	}
}

// formatPrometheusMetrics converts CFGMS metrics to Prometheus format.
func (pe *PrometheusExporter) formatPrometheusMetrics(data ExportData) []string {
	var lines []string

	// Add help text and type information
	lines = append(lines, "# HELP cfgms_info Information about CFGMS system")
	lines = append(lines, "# TYPE cfgms_info gauge")
	lines = append(lines, fmt.Sprintf(`cfgms_info{source="%s",export_type="%s",correlation_id="%s"} 1`,
		data.Source, data.ExportType, data.CorrelationID))

	// Convert all metrics to flat key-value pairs
	allMetrics := pe.flattenMetrics(data)

	// Group metrics by type for better organization
	gaugeMetrics := make(map[string]float64)
	counterMetrics := make(map[string]float64)

	for key, value := range allMetrics {
		if floatVal, ok := pe.convertToFloat64(value); ok {
			metricName := pe.sanitizeMetricName(key)

			// Determine if it's a counter or gauge based on name patterns
			if pe.isCounterMetric(key) {
				counterMetrics[metricName] = floatVal
			} else {
				gaugeMetrics[metricName] = floatVal
			}
		}
	}

	// Add gauge metrics
	if len(gaugeMetrics) > 0 {
		lines = append(lines, "")
		for name, value := range gaugeMetrics {
			lines = append(lines, fmt.Sprintf("# TYPE %s gauge", name))
			lines = append(lines, fmt.Sprintf("%s %v", name, value))
		}
	}

	// Add counter metrics
	if len(counterMetrics) > 0 {
		lines = append(lines, "")
		for name, value := range counterMetrics {
			lines = append(lines, fmt.Sprintf("# TYPE %s counter", name))
			lines = append(lines, fmt.Sprintf("%s %v", name, value))
		}
	}

	// Add health status as labeled metrics
	if len(data.HealthStatus) > 0 {
		lines = append(lines, "")
		lines = append(lines, "# TYPE cfgms_component_health gauge")
		for component, health := range data.HealthStatus {
			healthValue := pe.healthStatusToFloat(health.Status)
			lines = append(lines, fmt.Sprintf(`cfgms_component_health{component="%s",status="%s"} %v`,
				component, health.Status, healthValue))
		}
	}

	return lines
}

// flattenMetrics converts nested metric structures to flat key-value pairs.
func (pe *PrometheusExporter) flattenMetrics(data ExportData) map[string]interface{} {
	flattened := make(map[string]interface{})

	// Flatten system metrics
	pe.flattenMap(flattened, "system", data.SystemMetrics)

	// Flatten resource metrics
	pe.flattenMap(flattened, "resource", data.ResourceMetrics)

	// Flatten component metrics
	pe.flattenMap(flattened, "steward", data.StewardMetrics)
	pe.flattenMap(flattened, "controller", data.ControllerMetrics)
	pe.flattenMap(flattened, "workflow", data.WorkflowMetrics)

	return flattened
}

// flattenMap recursively flattens a nested map with a given prefix.
func (pe *PrometheusExporter) flattenMap(result map[string]interface{}, prefix string, data map[string]interface{}) {
	for key, value := range data {
		fullKey := fmt.Sprintf("%s_%s", prefix, key)

		if nestedMap, ok := value.(map[string]interface{}); ok {
			pe.flattenMap(result, fullKey, nestedMap)
		} else {
			result[fullKey] = value
		}
	}
}

// convertToFloat64 attempts to convert various numeric types to float64.
func (pe *PrometheusExporter) convertToFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case uint:
		return float64(v), true
	case uint32:
		return float64(v), true
	case uint64:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// sanitizeMetricName converts metric names to Prometheus-compatible format.
func (pe *PrometheusExporter) sanitizeMetricName(name string) string {
	// Add prefix
	if pe.config.MetricPrefix != "" {
		name = pe.config.MetricPrefix + "_" + name
	}

	// Convert to lowercase and replace invalid characters
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "-", "_")
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, " ", "_")

	// Remove invalid characters (keep only alphanumeric and underscore)
	var result strings.Builder
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_' {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// isCounterMetric determines if a metric should be treated as a counter.
func (pe *PrometheusExporter) isCounterMetric(name string) bool {
	counterPatterns := []string{
		"count", "total", "requests", "errors", "failures",
		"successes", "sent", "received", "executed", "processed",
	}

	lowerName := strings.ToLower(name)
	for _, pattern := range counterPatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// healthStatusToFloat converts health status strings to numeric values.
func (pe *PrometheusExporter) healthStatusToFloat(status string) float64 {
	switch strings.ToLower(status) {
	case "healthy":
		return 1.0
	case "degraded":
		return 0.5
	case "unhealthy":
		return 0.0
	default:
		return -1.0 // Unknown status
	}
}
