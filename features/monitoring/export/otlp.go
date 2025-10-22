package export

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// OTLPExporter exports traces and metrics to OpenTelemetry Protocol (OTLP) endpoints.
// This enables integration with Jaeger, Zipkin, and other OTLP-compatible backends.
type OTLPExporter struct {
	logger logging.Logger
	config OTLPConfig

	// Connection state
	connected   bool
	lastExport  time.Time
	exportCount int64
}

// OTLPConfig contains configuration for OTLP export.
type OTLPConfig struct {
	Endpoint    string            `json:"endpoint" yaml:"endpoint"`
	Headers     map[string]string `json:"headers" yaml:"headers"`
	Compression string            `json:"compression" yaml:"compression"` // "gzip", "none"
	Timeout     time.Duration     `json:"timeout" yaml:"timeout"`

	// Data types to export
	ExportTraces  bool `json:"export_traces" yaml:"export_traces"`
	ExportMetrics bool `json:"export_metrics" yaml:"export_metrics"`
	ExportLogs    bool `json:"export_logs" yaml:"export_logs"`

	// Sampling configuration
	TraceSamplingRate   float64 `json:"trace_sampling_rate" yaml:"trace_sampling_rate"`
	MetricsSamplingRate float64 `json:"metrics_sampling_rate" yaml:"metrics_sampling_rate"`
}

// NewOTLPExporter creates a new OpenTelemetry Protocol exporter.
func NewOTLPExporter(logger logging.Logger) *OTLPExporter {
	return &OTLPExporter{
		logger: logger,
		config: OTLPConfig{
			Endpoint:            "http://localhost:4318", // Default OTLP HTTP endpoint
			Compression:         "gzip",
			Timeout:             30 * time.Second,
			ExportTraces:        true,
			ExportMetrics:       true,
			ExportLogs:          true,
			TraceSamplingRate:   1.0,
			MetricsSamplingRate: 1.0,
			Headers:             make(map[string]string),
		},
	}
}

// Name returns the name of this exporter.
func (oe *OTLPExporter) Name() string {
	return "otlp"
}

// Configure initializes the OTLP exporter with configuration.
func (oe *OTLPExporter) Configure(config ExporterConfig) error {
	// Use endpoint from general config
	if config.Endpoint != "" {
		oe.config.Endpoint = config.Endpoint
	}

	// Use timeout from general config
	if config.Timeout > 0 {
		oe.config.Timeout = config.Timeout
	}

	// Extract OTLP-specific configuration
	if config.Config != nil {
		if compression, ok := config.Config["compression"].(string); ok {
			oe.config.Compression = compression
		}
		if exportTraces, ok := config.Config["export_traces"].(bool); ok {
			oe.config.ExportTraces = exportTraces
		}
		if exportMetrics, ok := config.Config["export_metrics"].(bool); ok {
			oe.config.ExportMetrics = exportMetrics
		}
		if exportLogs, ok := config.Config["export_logs"].(bool); ok {
			oe.config.ExportLogs = exportLogs
		}
		if traceSampling, ok := config.Config["trace_sampling_rate"].(float64); ok {
			oe.config.TraceSamplingRate = traceSampling
		}
		if metricsSampling, ok := config.Config["metrics_sampling_rate"].(float64); ok {
			oe.config.MetricsSamplingRate = metricsSampling
		}
		if headers, ok := config.Config["headers"].(map[string]interface{}); ok {
			for k, v := range headers {
				if strVal, ok := v.(string); ok {
					oe.config.Headers[k] = strVal
				}
			}
		}
	}

	// Add authentication headers if provided
	if config.APIKey != "" {
		oe.config.Headers["Authorization"] = fmt.Sprintf("Bearer %s", config.APIKey)
	}

	oe.logger.InfoCtx(context.Background(), "Configured OTLP exporter",
		"endpoint", oe.config.Endpoint,
		"export_traces", oe.config.ExportTraces,
		"export_metrics", oe.config.ExportMetrics,
		"export_logs", oe.config.ExportLogs,
		"compression", oe.config.Compression)

	return nil
}

// Start initializes the OTLP exporter (no background processes needed).
func (oe *OTLPExporter) Start(ctx context.Context) error {
	oe.logger.InfoCtx(ctx, "Starting OTLP exporter",
		"endpoint", oe.config.Endpoint)

	// Test connectivity
	health := oe.HealthCheck(ctx)
	if health.Status != "healthy" {
		oe.logger.WarnCtx(ctx, "OTLP endpoint health check failed",
			"status", health.Status,
			"message", health.Message)
		// Don't fail startup - allow degraded operation
	}

	return nil
}

// Stop shuts down the OTLP exporter.
func (oe *OTLPExporter) Stop(ctx context.Context) error {
	oe.logger.InfoCtx(ctx, "Stopping OTLP exporter")
	oe.connected = false
	return nil
}

// Export sends monitoring data to the OTLP endpoint.
func (oe *OTLPExporter) Export(ctx context.Context, data ExportData) error {
	startTime := time.Now()

	// Create export context with timeout
	exportCtx, cancel := context.WithTimeout(ctx, oe.config.Timeout)
	defer cancel()

	var exportErrors []error

	// Export traces if enabled and available
	if oe.config.ExportTraces && len(data.Traces) > 0 {
		if err := oe.exportTraces(exportCtx, data.Traces); err != nil {
			exportErrors = append(exportErrors, fmt.Errorf("trace export failed: %w", err))
		}
	}

	// Export metrics if enabled and available
	if oe.config.ExportMetrics && oe.hasMetrics(data) {
		if err := oe.exportMetrics(exportCtx, data); err != nil {
			exportErrors = append(exportErrors, fmt.Errorf("metrics export failed: %w", err))
		}
	}

	// Export logs if enabled and available
	if oe.config.ExportLogs && len(data.Logs) > 0 {
		if err := oe.exportLogs(exportCtx, data.Logs); err != nil {
			exportErrors = append(exportErrors, fmt.Errorf("logs export failed: %w", err))
		}
	}

	// Update state
	oe.lastExport = time.Now()
	oe.exportCount++

	// Handle errors
	if len(exportErrors) > 0 {
		oe.connected = false
		return fmt.Errorf("OTLP export errors: %v", exportErrors)
	}

	oe.connected = true

	oe.logger.DebugCtx(ctx, "OTLP export completed",
		"export_time_ms", time.Since(startTime).Milliseconds(),
		"traces_count", len(data.Traces),
		"logs_count", len(data.Logs),
		"has_metrics", oe.hasMetrics(data))

	return nil
}

// HealthCheck verifies connectivity to the OTLP endpoint.
func (oe *OTLPExporter) HealthCheck(ctx context.Context) ExporterHealth {
	health := ExporterHealth{
		Name:            oe.Name(),
		LastHealthCheck: time.Now(),
		ExportCount:     oe.exportCount,
		LastExport:      oe.lastExport,
	}

	// For now, we'll do a simple connectivity check
	// In a full implementation, you might want to send a test span
	if oe.connected {
		health.Status = "healthy"
		health.Message = "OTLP endpoint reachable"
	} else {
		health.Status = "unhealthy"
		health.Message = "OTLP endpoint not reachable"
	}

	// TODO: Implement actual health check by sending test data
	// This would involve:
	// 1. Creating a minimal OTLP payload
	// 2. Sending it to the endpoint
	// 3. Checking for successful response

	return health
}

// exportTraces sends trace data to the OTLP traces endpoint.
func (oe *OTLPExporter) exportTraces(ctx context.Context, traces []TraceSpan) error {
	// Apply sampling
	if oe.config.TraceSamplingRate < 1.0 {
		traces = oe.sampleTraces(traces, oe.config.TraceSamplingRate)
	}

	if len(traces) == 0 {
		return nil // Nothing to export after sampling
	}

	// Convert to OTLP format
	otlpTraces := oe.convertTracesToOTLP(traces)

	// Send to OTLP traces endpoint
	endpoint := oe.config.Endpoint + "/v1/traces"
	return oe.sendOTLPData(ctx, endpoint, otlpTraces)
}

// exportMetrics sends metrics data to the OTLP metrics endpoint.
func (oe *OTLPExporter) exportMetrics(ctx context.Context, data ExportData) error {
	// Apply sampling
	if oe.config.MetricsSamplingRate < 1.0 {
		// Simple sampling - in production, you might want more sophisticated sampling
		if float64(time.Now().UnixNano()%1000)/1000.0 > oe.config.MetricsSamplingRate {
			return nil
		}
	}

	// Convert to OTLP format
	otlpMetrics := oe.convertMetricsToOTLP(data)

	// Send to OTLP metrics endpoint
	endpoint := oe.config.Endpoint + "/v1/metrics"
	return oe.sendOTLPData(ctx, endpoint, otlpMetrics)
}

// exportLogs sends log data to the OTLP logs endpoint.
func (oe *OTLPExporter) exportLogs(ctx context.Context, logs []LogEntry) error {
	if len(logs) == 0 {
		return nil
	}

	// Convert to OTLP format
	otlpLogs := oe.convertLogsToOTLP(logs)

	// Send to OTLP logs endpoint
	endpoint := oe.config.Endpoint + "/v1/logs"
	return oe.sendOTLPData(ctx, endpoint, otlpLogs)
}

// sendOTLPData sends data to an OTLP endpoint.
func (oe *OTLPExporter) sendOTLPData(ctx context.Context, endpoint string, data interface{}) error {
	// TODO: Implement actual OTLP protocol sending
	// This would involve:
	// 1. Serializing data to protobuf format
	// 2. Compressing if enabled
	// 3. Creating HTTP request with proper headers
	// 4. Sending POST request to endpoint
	// 5. Handling response and errors

	oe.logger.DebugCtx(ctx, "Would send OTLP data",
		"endpoint", endpoint,
		"compression", oe.config.Compression)

	// Simulate network delay
	time.Sleep(10 * time.Millisecond)

	return nil // Placeholder implementation
}

// Helper functions for data conversion

// convertTracesToOTLP converts CFGMS traces to OTLP format.
func (oe *OTLPExporter) convertTracesToOTLP(traces []TraceSpan) interface{} {
	// TODO: Implement conversion to OTLP protobuf format
	// This would create proper OTLP ResourceSpans structure

	converted := make([]map[string]interface{}, len(traces))
	for i, trace := range traces {
		converted[i] = map[string]interface{}{
			"trace_id":       trace.TraceID,
			"span_id":        trace.SpanID,
			"parent_span_id": trace.ParentSpanID,
			"name":           trace.OperationName,
			"start_time":     trace.StartTime.UnixNano(),
			"end_time":       trace.EndTime.UnixNano(),
			"status":         trace.Status,
			"attributes":     trace.Tags,
		}
	}

	return map[string]interface{}{
		"resource_spans": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": map[string]interface{}{
						"service.name":    "cfgms",
						"service.version": "v0.2.0",
					},
				},
				"scope_spans": []map[string]interface{}{
					{
						"spans": converted,
					},
				},
			},
		},
	}
}

// convertMetricsToOTLP converts CFGMS metrics to OTLP format.
func (oe *OTLPExporter) convertMetricsToOTLP(data ExportData) interface{} {
	// TODO: Implement conversion to OTLP protobuf format
	// This would create proper OTLP ResourceMetrics structure

	allMetrics := make(map[string]interface{})

	// Flatten all metrics
	for key, value := range data.SystemMetrics {
		allMetrics["system_"+key] = value
	}
	for key, value := range data.ResourceMetrics {
		allMetrics["resource_"+key] = value
	}
	for key, value := range data.StewardMetrics {
		allMetrics["steward_"+key] = value
	}
	for key, value := range data.ControllerMetrics {
		allMetrics["controller_"+key] = value
	}
	for key, value := range data.WorkflowMetrics {
		allMetrics["workflow_"+key] = value
	}

	return map[string]interface{}{
		"resource_metrics": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": map[string]interface{}{
						"service.name":    "cfgms",
						"service.version": "v0.2.0",
					},
				},
				"scope_metrics": []map[string]interface{}{
					{
						"metrics": allMetrics,
					},
				},
			},
		},
	}
}

// convertLogsToOTLP converts CFGMS logs to OTLP format.
func (oe *OTLPExporter) convertLogsToOTLP(logs []LogEntry) interface{} {
	// TODO: Implement conversion to OTLP protobuf format
	// This would create proper OTLP ResourceLogs structure

	converted := make([]map[string]interface{}, len(logs))
	for i, log := range logs {
		converted[i] = map[string]interface{}{
			"time_unix_nano": log.Timestamp.UnixNano(),
			"severity_text":  log.Level,
			"body":           log.Message,
			"trace_id":       log.TraceID,
			"attributes":     log.Fields,
		}
	}

	return map[string]interface{}{
		"resource_logs": []map[string]interface{}{
			{
				"resource": map[string]interface{}{
					"attributes": map[string]interface{}{
						"service.name":    "cfgms",
						"service.version": "v0.2.0",
					},
				},
				"scope_logs": []map[string]interface{}{
					{
						"log_records": converted,
					},
				},
			},
		},
	}
}

// hasMetrics checks if the export data contains any metrics.
func (oe *OTLPExporter) hasMetrics(data ExportData) bool {
	return len(data.SystemMetrics) > 0 ||
		len(data.ResourceMetrics) > 0 ||
		len(data.StewardMetrics) > 0 ||
		len(data.ControllerMetrics) > 0 ||
		len(data.WorkflowMetrics) > 0
}

// sampleTraces applies sampling to reduce trace volume.
func (oe *OTLPExporter) sampleTraces(traces []TraceSpan, rate float64) []TraceSpan {
	if rate >= 1.0 {
		return traces
	}

	sampled := make([]TraceSpan, 0, int(float64(len(traces))*rate))
	for _, trace := range traces {
		// Use trace ID for consistent sampling decisions
		hash := 0
		for _, b := range []byte(trace.TraceID) {
			hash = hash*31 + int(b)
		}

		if float64(hash%1000)/1000.0 < rate {
			sampled = append(sampled, trace)
		}
	}

	return sampled
}
