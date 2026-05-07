// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package export

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logscollectorpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracecollectorpb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

func newTestOTLPExporter(endpoint string) *OTLPExporter {
	oe := NewOTLPExporter(logging.NewNoopLogger())
	oe.config.Endpoint = endpoint
	oe.config.Compression = "none"
	oe.config.Timeout = 5 * time.Second
	return oe
}

// TestOTLPExporter_ExportTraces verifies that trace data is sent as valid
// protobuf-encoded ExportTraceServiceRequest with correct span fields.
func TestOTLPExporter_ExportTraces(t *testing.T) {
	var gotBody []byte
	var gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)

	traces := []TraceSpan{
		{
			TraceID:       "0102030405060708090a0b0c0d0e0f10",
			SpanID:        "0102030405060708",
			ParentSpanID:  "",
			OperationName: "test.operation",
			StartTime:     time.Unix(1000, 0),
			EndTime:       time.Unix(1001, 0),
			Status:        "ok",
			Tags:          map[string]interface{}{"env": "test"},
		},
	}

	req := oe.convertTracesToOTLP(traces)
	err := oe.sendTraces(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "application/x-protobuf", gotContentType)
	require.NotEmpty(t, gotBody)

	var decoded tracecollectorpb.ExportTraceServiceRequest
	require.NoError(t, proto.Unmarshal(gotBody, &decoded))

	require.Len(t, decoded.ResourceSpans, 1)
	rs := decoded.ResourceSpans[0]
	require.NotNil(t, rs.Resource)

	// Verify resource has service.name attribute
	var serviceName string
	for _, attr := range rs.Resource.Attributes {
		if attr.Key == "service.name" {
			serviceName = attr.Value.GetStringValue()
		}
	}
	assert.Equal(t, "cfgms", serviceName)

	require.Len(t, rs.ScopeSpans, 1)
	require.Len(t, rs.ScopeSpans[0].Spans, 1)

	span := rs.ScopeSpans[0].Spans[0]
	assert.Equal(t, "test.operation", span.Name)
	assert.Equal(t, uint64(time.Unix(1000, 0).UnixNano()), span.StartTimeUnixNano)
	assert.Equal(t, uint64(time.Unix(1001, 0).UnixNano()), span.EndTimeUnixNano)
	assert.Equal(t, tracepb.Status_STATUS_CODE_OK, span.Status.Code)
	assert.Len(t, span.TraceId, 16)
	assert.Len(t, span.SpanId, 8)

	// Verify attribute propagated
	var envVal string
	for _, attr := range span.Attributes {
		if attr.Key == "env" {
			envVal = attr.Value.GetStringValue()
		}
	}
	assert.Equal(t, "test", envVal)
}

// TestOTLPExporter_ExportTraces_StatusMapping verifies that trace status strings
// are mapped to correct OTLP status codes.
func TestOTLPExporter_ExportTraces_StatusMapping(t *testing.T) {
	tests := []struct {
		status   string
		expected tracepb.Status_StatusCode
	}{
		{"ok", tracepb.Status_STATUS_CODE_OK},
		{"OK", tracepb.Status_STATUS_CODE_OK},
		{"error", tracepb.Status_STATUS_CODE_ERROR},
		{"ERROR", tracepb.Status_STATUS_CODE_ERROR},
		{"unknown", tracepb.Status_STATUS_CODE_UNSET},
		{"", tracepb.Status_STATUS_CODE_UNSET},
	}

	for _, tc := range tests {
		t.Run(tc.status, func(t *testing.T) {
			code := traceStatusCode(tc.status)
			assert.Equal(t, tc.expected, code)
		})
	}
}

// TestOTLPExporter_ExportMetrics verifies that metrics data is sent as valid
// protobuf-encoded ExportMetricsServiceRequest with gauge data points.
func TestOTLPExporter_ExportMetrics(t *testing.T) {
	var gotBody []byte
	var gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)

	data := ExportData{
		SystemMetrics: map[string]interface{}{
			"cpu_usage": float64(45.5),
			"mem_used":  float64(1024),
		},
		StewardMetrics: map[string]interface{}{
			"active_sessions": float64(3),
		},
	}

	req := oe.convertMetricsToOTLP(data)
	err := oe.sendMetrics(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "application/x-protobuf", gotContentType)
	require.NotEmpty(t, gotBody)

	var decoded metricscollectorpb.ExportMetricsServiceRequest
	require.NoError(t, proto.Unmarshal(gotBody, &decoded))

	require.Len(t, decoded.ResourceMetrics, 1)
	rm := decoded.ResourceMetrics[0]
	require.NotNil(t, rm.Resource)

	require.Len(t, rm.ScopeMetrics, 1)
	metrics := rm.ScopeMetrics[0].Metrics
	require.NotEmpty(t, metrics)

	// Collect metric names and verify gauge data points
	metricNames := make(map[string]float64)
	for _, m := range metrics {
		gauge := m.GetGauge()
		require.NotNil(t, gauge, "metric %s must be a Gauge", m.Name)
		require.Len(t, gauge.DataPoints, 1)
		dp := gauge.DataPoints[0]
		metricNames[m.Name] = dp.GetAsDouble()
		assert.NotZero(t, dp.TimeUnixNano)
	}

	assert.Equal(t, float64(45.5), metricNames["system_cpu_usage"])
	assert.Equal(t, float64(1024), metricNames["system_mem_used"])
	assert.Equal(t, float64(3), metricNames["steward_active_sessions"])
}

// TestOTLPExporter_ExportLogs verifies that log data is sent as valid
// protobuf-encoded ExportLogsServiceRequest with correct severity number mapping.
func TestOTLPExporter_ExportLogs(t *testing.T) {
	var gotBody []byte
	var gotContentType string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentType = r.Header.Get("Content-Type")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		gotBody = body
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)

	logs := []LogEntry{
		{
			Timestamp: time.Unix(2000, 0),
			Level:     "info",
			Message:   "test message",
			TraceID:   "aabbccddeeff00112233445566778899",
			Fields:    map[string]interface{}{"component": "test"},
		},
		{
			Timestamp: time.Unix(2001, 0),
			Level:     "error",
			Message:   "error occurred",
		},
		{
			Timestamp: time.Unix(2002, 0),
			Level:     "debug",
			Message:   "debug info",
		},
		{
			Timestamp: time.Unix(2003, 0),
			Level:     "warn",
			Message:   "warning",
		},
	}

	req := oe.convertLogsToOTLP(logs)
	err := oe.sendLogs(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "application/x-protobuf", gotContentType)
	require.NotEmpty(t, gotBody)

	var decoded logscollectorpb.ExportLogsServiceRequest
	require.NoError(t, proto.Unmarshal(gotBody, &decoded))

	require.Len(t, decoded.ResourceLogs, 1)
	rl := decoded.ResourceLogs[0]
	require.NotNil(t, rl.Resource)

	require.Len(t, rl.ScopeLogs, 1)
	records := rl.ScopeLogs[0].LogRecords
	require.Len(t, records, 4)

	// Verify severity mapping: info→9, error→17, debug→5, warn→13
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_INFO, records[0].SeverityNumber)
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_ERROR, records[1].SeverityNumber)
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG, records[2].SeverityNumber)
	assert.Equal(t, logspb.SeverityNumber_SEVERITY_NUMBER_WARN, records[3].SeverityNumber)

	// Verify first record details
	assert.Equal(t, uint64(time.Unix(2000, 0).UnixNano()), records[0].TimeUnixNano)
	assert.Equal(t, "test message", records[0].Body.GetStringValue())
	assert.Equal(t, "info", records[0].SeverityText)
	assert.Len(t, records[0].TraceId, 16)

	// Verify attribute
	var componentVal string
	for _, attr := range records[0].Attributes {
		if attr.Key == "component" {
			componentVal = attr.Value.GetStringValue()
		}
	}
	assert.Equal(t, "test", componentVal)
}

// TestOTLPExporter_LogSeverityMapping verifies all level→SeverityNumber mappings.
func TestOTLPExporter_LogSeverityMapping(t *testing.T) {
	tests := []struct {
		level    string
		expected logspb.SeverityNumber
	}{
		{"debug", logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG}, // 5
		{"DEBUG", logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG},
		{"info", logspb.SeverityNumber_SEVERITY_NUMBER_INFO}, // 9
		{"INFO", logspb.SeverityNumber_SEVERITY_NUMBER_INFO},
		{"warn", logspb.SeverityNumber_SEVERITY_NUMBER_WARN}, // 13
		{"warning", logspb.SeverityNumber_SEVERITY_NUMBER_WARN},
		{"WARN", logspb.SeverityNumber_SEVERITY_NUMBER_WARN},
		{"error", logspb.SeverityNumber_SEVERITY_NUMBER_ERROR}, // 17
		{"ERROR", logspb.SeverityNumber_SEVERITY_NUMBER_ERROR},
		{"unknown", logspb.SeverityNumber_SEVERITY_NUMBER_UNSPECIFIED}, // 0
		{"", logspb.SeverityNumber_SEVERITY_NUMBER_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.level, func(t *testing.T) {
			sev := logSeverityNumber(tc.level)
			assert.Equal(t, tc.expected, sev)
		})
	}
}

// TestOTLPExporter_GzipCompression verifies that gzip-compressed payloads are
// sent with Content-Encoding: gzip and can be decoded by the receiver.
func TestOTLPExporter_GzipCompression(t *testing.T) {
	var decodedBody []byte
	var gotContentEncoding string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotContentEncoding = r.Header.Get("Content-Encoding")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		gr, err := gzip.NewReader(strings.NewReader(string(body)))
		require.NoError(t, err)
		defer func() { _ = gr.Close() }()

		decodedBody, err = io.ReadAll(gr)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)
	oe.config.Compression = "gzip"

	traces := []TraceSpan{
		{
			TraceID:       "aabbccddeeff00112233445566778899",
			SpanID:        "aabbccddeeff0011",
			OperationName: "gzip.test",
			StartTime:     time.Unix(3000, 0),
			EndTime:       time.Unix(3001, 0),
			Status:        "ok",
		},
	}

	req := oe.convertTracesToOTLP(traces)
	err := oe.sendTraces(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "gzip", gotContentEncoding)
	require.NotEmpty(t, decodedBody)

	var decoded tracecollectorpb.ExportTraceServiceRequest
	require.NoError(t, proto.Unmarshal(decodedBody, &decoded))
	require.Len(t, decoded.ResourceSpans, 1)
	require.Len(t, decoded.ResourceSpans[0].ScopeSpans[0].Spans, 1)
	assert.Equal(t, "gzip.test", decoded.ResourceSpans[0].ScopeSpans[0].Spans[0].Name)
}

// TestOTLPExporter_CustomHeaders verifies that custom headers from config are
// set on outgoing requests.
func TestOTLPExporter_CustomHeaders(t *testing.T) {
	var gotAuthHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)
	oe.config.Headers = map[string]string{
		"Authorization": "Bearer test-token",
	}

	req := oe.convertLogsToOTLP([]LogEntry{
		{Timestamp: time.Now(), Level: "info", Message: "test"},
	})
	err := oe.sendLogs(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "Bearer test-token", gotAuthHeader)
}

// TestOTLPExporter_ServerError verifies that HTTP 5xx responses result in errors.
func TestOTLPExporter_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)

	req := oe.convertTracesToOTLP([]TraceSpan{
		{TraceID: "01", SpanID: "02", OperationName: "fail", StartTime: time.Now(), EndTime: time.Now(), Status: "ok"},
	})
	err := oe.sendTraces(context.Background(), req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

// TestOTLPExporter_Export_Integration tests the full Export routing for all three
// signal types, verifying each is sent to the correct /v1/{signal} endpoint.
func TestOTLPExporter_Export_Integration(t *testing.T) {
	tracesReceived := 0
	metricsReceived := 0
	logsReceived := 0

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		switch r.URL.Path {
		case "/v1/traces":
			tracesReceived++
		case "/v1/metrics":
			metricsReceived++
		case "/v1/logs":
			logsReceived++
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)

	data := ExportData{
		Traces: []TraceSpan{
			{TraceID: "0102030405060708090a0b0c0d0e0f10", SpanID: "0102030405060708",
				OperationName: "op", StartTime: time.Now(), EndTime: time.Now(), Status: "ok"},
		},
		SystemMetrics: map[string]interface{}{"cpu": float64(10)},
		Logs: []LogEntry{
			{Timestamp: time.Now(), Level: "info", Message: "msg"},
		},
	}

	err := oe.Export(context.Background(), data)
	require.NoError(t, err)

	assert.Equal(t, 1, tracesReceived)
	assert.Equal(t, 1, metricsReceived)
	assert.Equal(t, 1, logsReceived)
}
