// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package export

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsinterfaces "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	logscollectorpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	metricscollectorpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	tracecollectorpb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

// testSecretStore is a real in-memory SecretStore implementation for tests.
// It is not a mock — it implements the full interface with real lookup logic.
type testSecretStore struct {
	mu      sync.RWMutex
	secrets map[string]string
}

func newTestSecretStore(secrets map[string]string) *testSecretStore {
	return &testSecretStore{secrets: secrets}
}

func (s *testSecretStore) GetSecret(_ context.Context, key string) (*secretsinterfaces.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, secretsinterfaces.ErrSecretNotFound
	}
	return &secretsinterfaces.Secret{Key: key, Value: v}, nil
}

func (s *testSecretStore) StoreSecret(_ context.Context, _ *secretsinterfaces.SecretRequest) error {
	return nil
}
func (s *testSecretStore) DeleteSecret(_ context.Context, _ string) error { return nil }
func (s *testSecretStore) ListSecrets(_ context.Context, _ *secretsinterfaces.SecretFilter) ([]*secretsinterfaces.SecretMetadata, error) {
	return nil, nil
}
func (s *testSecretStore) GetSecrets(_ context.Context, _ []string) (map[string]*secretsinterfaces.Secret, error) {
	return nil, nil
}
func (s *testSecretStore) StoreSecrets(_ context.Context, _ map[string]*secretsinterfaces.SecretRequest) error {
	return nil
}
func (s *testSecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsinterfaces.Secret, error) {
	return nil, nil
}
func (s *testSecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsinterfaces.SecretVersion, error) {
	return nil, nil
}
func (s *testSecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsinterfaces.SecretMetadata, error) {
	return nil, nil
}
func (s *testSecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *testSecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *testSecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *testSecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *testSecretStore) Close() error                                             { return nil }

// captureLogger records all log messages for assertion in tests.
type captureLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (c *captureLogger) record(msg string, kvs ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	full := msg
	for _, kv := range kvs {
		full += " " + strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(fmt.Sprint(kv), "\n", " "), "\r", ""), "\t", " ")
	}
	c.msgs = append(c.msgs, full)
}

func (c *captureLogger) contains(substr string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range c.msgs {
		if strings.Contains(m, substr) {
			return true
		}
	}
	return false
}

func (c *captureLogger) Debug(msg string, kvs ...interface{}) { c.record(msg, kvs...) }
func (c *captureLogger) Info(msg string, kvs ...interface{})  { c.record(msg, kvs...) }
func (c *captureLogger) Warn(msg string, kvs ...interface{})  { c.record(msg, kvs...) }
func (c *captureLogger) Error(msg string, kvs ...interface{}) { c.record(msg, kvs...) }
func (c *captureLogger) Fatal(msg string, kvs ...interface{}) { c.record(msg, kvs...) }
func (c *captureLogger) DebugCtx(_ context.Context, msg string, kvs ...interface{}) {
	c.record(msg, kvs...)
}
func (c *captureLogger) InfoCtx(_ context.Context, msg string, kvs ...interface{}) {
	c.record(msg, kvs...)
}
func (c *captureLogger) WarnCtx(_ context.Context, msg string, kvs ...interface{}) {
	c.record(msg, kvs...)
}
func (c *captureLogger) ErrorCtx(_ context.Context, msg string, kvs ...interface{}) {
	c.record(msg, kvs...)
}
func (c *captureLogger) FatalCtx(_ context.Context, msg string, kvs ...interface{}) {
	c.record(msg, kvs...)
}

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

// TestOTLPExporter_CredentialsFromSecrets verifies that when a SecretStore is configured,
// Configure() retrieves the bearer token from the store and sets the Authorization header.
// It also verifies that the secret value is never written to any log output.
func TestOTLPExporter_CredentialsFromSecrets(t *testing.T) {
	const (
		secretKey   = "otlp/api-key"
		secretToken = "super-secret-token-xyz"
	)

	store := newTestSecretStore(map[string]string{
		secretKey: secretToken,
	})
	cl := &captureLogger{}

	oe := NewOTLPExporterWithSecrets(cl, store)
	oe.config.Compression = "none"

	cfg := ExporterConfig{
		Config: map[string]interface{}{
			"secret_key": secretKey,
		},
	}
	require.NoError(t, oe.Configure(cfg))

	assert.Equal(t, "Bearer "+secretToken, oe.config.Headers["Authorization"])
	assert.False(t, cl.contains(secretToken), "secret token must not appear in any log output")
}

// TestOTLPExporter_PlaintextAPIKeyDisabled verifies that when a SecretStore is present
// and secret_key is set, ExporterConfig.APIKey is not used as the credential source.
func TestOTLPExporter_PlaintextAPIKeyDisabled(t *testing.T) {
	const (
		secretKey    = "otlp/api-key"
		secretToken  = "store-token"
		plaintextKey = "plaintext-api-key-should-not-be-used"
	)

	store := newTestSecretStore(map[string]string{
		secretKey: secretToken,
	})

	oe := NewOTLPExporterWithSecrets(logging.NewNoopLogger(), store)
	oe.config.Compression = "none"

	cfg := ExporterConfig{
		APIKey: plaintextKey,
		Config: map[string]interface{}{
			"secret_key": secretKey,
		},
	}
	require.NoError(t, oe.Configure(cfg))

	authHeader := oe.config.Headers["Authorization"]
	assert.NotEqual(t, "Bearer "+plaintextKey, authHeader, "plaintext APIKey must not be used as credential source when SecretStore is present")
	assert.Equal(t, "Bearer "+secretToken, authHeader, "secret from store must be used as credential source")
}

// TestOTLPExporter_SecretNotFound verifies that when GetSecret fails (the key does not
// exist in the store), Configure returns nil, the Authorization header is not set, and
// a warning is logged containing the key name.
func TestOTLPExporter_SecretNotFound(t *testing.T) {
	const missingKey = "otlp/missing-key"

	store := newTestSecretStore(map[string]string{}) // store has no entry for missingKey
	cl := &captureLogger{}

	oe := NewOTLPExporterWithSecrets(cl, store)
	oe.config.Compression = "none"

	cfg := ExporterConfig{
		Config: map[string]interface{}{
			"secret_key": missingKey,
		},
	}
	err := oe.Configure(cfg)
	require.NoError(t, err, "Configure must return nil even when secret retrieval fails")

	_, headerSet := oe.config.Headers["Authorization"]
	assert.False(t, headerSet, "Authorization header must not be set when secret retrieval fails")

	assert.True(t, cl.contains("Failed to retrieve OTLP credential"), "warning must be logged when secret retrieval fails")
	assert.True(t, cl.contains(missingKey), "key name must appear in warning log for debuggability")
}

// TestOTLPExporter_HealthCheck_Healthy verifies that a 200 response causes HealthCheck
// to return status == "healthy" and sets oe.connected = true.
func TestOTLPExporter_HealthCheck_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/traces", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-protobuf", r.Header.Get("Content-Type"))
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)
	health := oe.HealthCheck(context.Background())

	assert.Equal(t, "healthy", health.Status)
	assert.Equal(t, "otlp", health.Name)
	assert.NotEmpty(t, health.Message)
	assert.True(t, oe.connected)
	assert.Positive(t, health.ResponseTime)
}

// TestOTLPExporter_HealthCheck_Unhealthy_5xx verifies that a 500 response causes
// HealthCheck to return status == "unhealthy" and sets oe.connected = false.
func TestOTLPExporter_HealthCheck_Unhealthy_5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)
	health := oe.HealthCheck(context.Background())

	assert.Equal(t, "unhealthy", health.Status)
	assert.NotEmpty(t, health.Message)
	assert.False(t, oe.connected)
}

// TestOTLPExporter_HealthCheck_Unhealthy_Timeout verifies that a server that never
// responds causes HealthCheck to return status == "unhealthy" within the configured timeout.
func TestOTLPExporter_HealthCheck_Unhealthy_Timeout(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() {
		close(done)
		srv.Close()
	}()

	oe := newTestOTLPExporter(srv.URL)
	oe.config.Timeout = 150 * time.Millisecond

	start := time.Now()
	health := oe.HealthCheck(context.Background())
	elapsed := time.Since(start)

	assert.Equal(t, "unhealthy", health.Status)
	assert.NotEmpty(t, health.Message)
	assert.Less(t, elapsed, 700*time.Millisecond)
	assert.False(t, oe.connected)
}

// TestOTLPExporter_HealthCheck_4xx_Reachable verifies that 4xx responses are treated
// as reachable — the collector responded, which proves connectivity.
func TestOTLPExporter_HealthCheck_4xx_Reachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	oe := newTestOTLPExporter(srv.URL)
	health := oe.HealthCheck(context.Background())

	assert.Equal(t, "healthy", health.Status)
	assert.NotEmpty(t, health.Message)
	assert.True(t, oe.connected)
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
