// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package export

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	logscollectorpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracecollectorpb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
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
		"endpoint", logging.SanitizeLogValue(oe.config.Endpoint),
		"export_traces", oe.config.ExportTraces,
		"export_metrics", oe.config.ExportMetrics,
		"export_logs", oe.config.ExportLogs,
		"compression", oe.config.Compression)

	return nil
}

// Start initializes the OTLP exporter (no background processes needed).
func (oe *OTLPExporter) Start(ctx context.Context) error {
	oe.logger.InfoCtx(ctx, "Starting OTLP exporter",
		"endpoint", logging.SanitizeLogValue(oe.config.Endpoint))

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

	if oe.connected {
		health.Status = "healthy"
		health.Message = "OTLP endpoint reachable"
	} else {
		health.Status = "unhealthy"
		health.Message = "OTLP endpoint not reachable"
	}

	return health
}

// exportTraces sends trace data to the OTLP traces endpoint.
func (oe *OTLPExporter) exportTraces(ctx context.Context, traces []TraceSpan) error {
	if oe.config.TraceSamplingRate < 1.0 {
		traces = oe.sampleTraces(traces, oe.config.TraceSamplingRate)
	}

	if len(traces) == 0 {
		return nil
	}

	return oe.sendTraces(ctx, oe.convertTracesToOTLP(traces))
}

// exportMetrics sends metrics data to the OTLP metrics endpoint.
func (oe *OTLPExporter) exportMetrics(ctx context.Context, data ExportData) error {
	if oe.config.MetricsSamplingRate < 1.0 {
		if float64(time.Now().UnixNano()%1000)/1000.0 > oe.config.MetricsSamplingRate {
			return nil
		}
	}

	return oe.sendMetrics(ctx, oe.convertMetricsToOTLP(data))
}

// exportLogs sends log data to the OTLP logs endpoint.
func (oe *OTLPExporter) exportLogs(ctx context.Context, logs []LogEntry) error {
	if len(logs) == 0 {
		return nil
	}

	return oe.sendLogs(ctx, oe.convertLogsToOTLP(logs))
}

// sendTraces marshals an ExportTraceServiceRequest and POSTs it to /v1/traces.
func (oe *OTLPExporter) sendTraces(ctx context.Context, req *tracecollectorpb.ExportTraceServiceRequest) error {
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal traces: %w", err)
	}
	return oe.postOTLP(ctx, oe.config.Endpoint+"/v1/traces", data)
}

// sendMetrics marshals an ExportMetricsServiceRequest and POSTs it to /v1/metrics.
func (oe *OTLPExporter) sendMetrics(ctx context.Context, req *metricscollectorpb.ExportMetricsServiceRequest) error {
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal metrics: %w", err)
	}
	return oe.postOTLP(ctx, oe.config.Endpoint+"/v1/metrics", data)
}

// sendLogs marshals an ExportLogsServiceRequest and POSTs it to /v1/logs.
func (oe *OTLPExporter) sendLogs(ctx context.Context, req *logscollectorpb.ExportLogsServiceRequest) error {
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal logs: %w", err)
	}
	return oe.postOTLP(ctx, oe.config.Endpoint+"/v1/logs", data)
}

// postOTLP optionally gzip-compresses data and POSTs it to the given OTLP URL
// with Content-Type: application/x-protobuf and all configured headers.
func (oe *OTLPExporter) postOTLP(ctx context.Context, url string, data []byte) error {
	var body io.Reader = bytes.NewReader(data)
	contentEncoding := ""

	if oe.config.Compression == "gzip" {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(data); err != nil {
			return fmt.Errorf("gzip compress: %w", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("gzip close: %w", err)
		}
		body = &buf
		contentEncoding = "gzip"
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	if contentEncoding != "" {
		httpReq.Header.Set("Content-Encoding", contentEncoding)
	}
	for k, v := range oe.config.Headers {
		httpReq.Header.Set(k, v)
	}

	client := &http.Client{Timeout: oe.config.Timeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("POST %s: %w", logging.SanitizeLogValue(url), err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 400 {
		return fmt.Errorf("OTLP server returned %d for %s", resp.StatusCode, logging.SanitizeLogValue(url))
	}

	return nil
}

// convertTracesToOTLP converts CFGMS TraceSpan slices to an ExportTraceServiceRequest.
func (oe *OTLPExporter) convertTracesToOTLP(traces []TraceSpan) *tracecollectorpb.ExportTraceServiceRequest {
	spans := make([]*tracepb.Span, 0, len(traces))
	for _, t := range traces {
		span := &tracepb.Span{
			TraceId:           decodeHexID(t.TraceID, 16),
			SpanId:            decodeHexID(t.SpanID, 8),
			ParentSpanId:      decodeHexID(t.ParentSpanID, 8),
			Name:              t.OperationName,
			StartTimeUnixNano: uint64(t.StartTime.UnixNano()),
			EndTimeUnixNano:   uint64(t.EndTime.UnixNano()),
			Status:            &tracepb.Status{Code: traceStatusCode(t.Status)},
			Attributes:        attrsFromMap(t.Tags),
		}
		spans = append(spans, span)
	}

	return &tracecollectorpb.ExportTraceServiceRequest{
		ResourceSpans: []*tracepb.ResourceSpans{
			{
				Resource: cfgmsResource(),
				ScopeSpans: []*tracepb.ScopeSpans{
					{Spans: spans},
				},
			},
		},
	}
}

// convertMetricsToOTLP converts all CFGMS metric maps to an ExportMetricsServiceRequest.
// Each key-value pair becomes a Gauge metric with a single timestamped data point.
func (oe *OTLPExporter) convertMetricsToOTLP(data ExportData) *metricscollectorpb.ExportMetricsServiceRequest {
	now := uint64(time.Now().UnixNano())
	metrics := make([]*metricspb.Metric, 0)

	addMetrics := func(prefix string, m map[string]interface{}) {
		for k, v := range m {
			f, ok := toFloat64(v)
			if !ok {
				continue
			}
			metrics = append(metrics, &metricspb.Metric{
				Name: prefix + k,
				Data: &metricspb.Metric_Gauge{
					Gauge: &metricspb.Gauge{
						DataPoints: []*metricspb.NumberDataPoint{
							{
								TimeUnixNano: now,
								Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: f},
							},
						},
					},
				},
			})
		}
	}

	addMetrics("system_", data.SystemMetrics)
	addMetrics("resource_", data.ResourceMetrics)
	addMetrics("steward_", data.StewardMetrics)
	addMetrics("controller_", data.ControllerMetrics)
	addMetrics("workflow_", data.WorkflowMetrics)

	return &metricscollectorpb.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{
			{
				Resource: cfgmsResource(),
				ScopeMetrics: []*metricspb.ScopeMetrics{
					{Metrics: metrics},
				},
			},
		},
	}
}

// convertLogsToOTLP converts CFGMS LogEntry slices to an ExportLogsServiceRequest.
func (oe *OTLPExporter) convertLogsToOTLP(logs []LogEntry) *logscollectorpb.ExportLogsServiceRequest {
	records := make([]*logspb.LogRecord, 0, len(logs))
	for _, log := range logs {
		records = append(records, &logspb.LogRecord{
			TimeUnixNano:   uint64(log.Timestamp.UnixNano()),
			SeverityNumber: logSeverityNumber(log.Level),
			SeverityText:   log.Level,
			Body:           &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: log.Message}},
			TraceId:        decodeHexID(log.TraceID, 16),
			Attributes:     attrsFromMap(log.Fields),
		})
	}

	return &logscollectorpb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{
			{
				Resource: cfgmsResource(),
				ScopeLogs: []*logspb.ScopeLogs{
					{LogRecords: records},
				},
			},
		},
	}
}

// cfgmsResource returns the standard CFGMS resource descriptor for OTLP payloads.
func cfgmsResource() *resourcepb.Resource {
	return &resourcepb.Resource{
		Attributes: []*commonpb.KeyValue{
			{Key: "service.name", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "cfgms"}}},
			{Key: "service.version", Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "v0.2.0"}}},
		},
	}
}

// attrsFromMap converts a map[string]interface{} to a slice of OTLP KeyValue attributes.
func attrsFromMap(m map[string]interface{}) []*commonpb.KeyValue {
	if len(m) == 0 {
		return nil
	}
	attrs := make([]*commonpb.KeyValue, 0, len(m))
	for k, v := range m {
		var av *commonpb.AnyValue
		switch tv := v.(type) {
		case string:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: tv}}
		case float64:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: tv}}
		case float32:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: float64(tv)}}
		case int:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(tv)}}
		case int64:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: tv}}
		case bool:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: tv}}
		default:
			av = &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: fmt.Sprintf("%v", v)}}
		}
		attrs = append(attrs, &commonpb.KeyValue{Key: k, Value: av})
	}
	return attrs
}

// traceStatusCode maps a CFGMS status string to an OTLP Status_StatusCode.
func traceStatusCode(status string) tracepb.Status_StatusCode {
	switch strings.ToLower(status) {
	case "ok":
		return tracepb.Status_STATUS_CODE_OK
	case "error":
		return tracepb.Status_STATUS_CODE_ERROR
	default:
		return tracepb.Status_STATUS_CODE_UNSET
	}
}

// logSeverityNumber maps a log level string to an OTLP SeverityNumber.
// Mapping: debug→5, info→9, warn/warning→13, error→17, default→0 (unspecified).
func logSeverityNumber(level string) logspb.SeverityNumber {
	switch strings.ToLower(level) {
	case "debug":
		return logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG
	case "info":
		return logspb.SeverityNumber_SEVERITY_NUMBER_INFO
	case "warn", "warning":
		return logspb.SeverityNumber_SEVERITY_NUMBER_WARN
	case "error":
		return logspb.SeverityNumber_SEVERITY_NUMBER_ERROR
	default:
		return logspb.SeverityNumber_SEVERITY_NUMBER_UNSPECIFIED
	}
}

// decodeHexID decodes a hex string into a fixed-length byte slice.
// Returns nil for invalid or empty input. Pads with leading zeros if shorter than length.
func decodeHexID(id string, length int) []byte {
	if id == "" {
		return nil
	}
	b, err := hex.DecodeString(id)
	if err != nil || len(b) == 0 {
		return nil
	}
	if len(b) == length {
		return b
	}
	result := make([]byte, length)
	if len(b) > length {
		copy(result, b[len(b)-length:])
	} else {
		copy(result[length-len(b):], b)
	}
	return result
}

// toFloat64 converts common numeric types to float64 for OTLP gauge data points.
func toFloat64(v interface{}) (float64, bool) {
	switch tv := v.(type) {
	case float64:
		return tv, true
	case float32:
		return float64(tv), true
	case int:
		return float64(tv), true
	case int32:
		return float64(tv), true
	case int64:
		return float64(tv), true
	case uint:
		return float64(tv), true
	case uint32:
		return float64(tv), true
	case uint64:
		return float64(tv), true
	default:
		return 0, false
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
