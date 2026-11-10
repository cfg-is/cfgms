// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

const prometheusPath = "/api/v1/health/metrics/prometheus"

// TestPrometheusRouteOnlyOnPrivateRouter starts a real server with its real TLS
// listeners and checks that the Prometheus exposition is served on the private
// metrics listener only, behind authentication and the monitoring/read-metrics
// permission.
func TestPrometheusRouteOnlyOnPrivateRouter(t *testing.T) {
	t.Setenv("CFGMS_HTTP_LISTEN_ADDR", "127.0.0.1:0")

	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)
	collector := health.NewCollector(
		health.NewDefaultTransportCollector(&health.MockTransportProviderStats{}),
		health.NewDefaultStorageCollector(&health.MockStorageProviderStats{ProviderName: "flatfile", PoolUtilization: -1, AvgLatencyMs: -1, P95LatencyMs: -1, SlowQueries: -1}),
		health.NewDefaultApplicationCollector(&health.MockApplicationQueueStats{}),
		systemCollector,
	)
	gauge, err := collector.Signals().RegisterGauge("cfgms_route_test_depth", "Route test depth.", map[string][]string{"queue": {"primary"}})
	require.NoError(t, err)
	require.NoError(t, gauge.Set(7, map[string]string{"queue": "primary"}))
	require.NoError(t, collector.Start(context.Background(), time.Hour))
	t.Cleanup(func() { _ = collector.Stop() })
	require.Eventually(t, func() bool {
		_, metricsErr := collector.GetCurrentMetrics()
		return metricsErr == nil
	}, 5*time.Second, 10*time.Millisecond)

	certMgr := newTLSTestCertManager(t)
	server := setupTestServer(t)
	server.healthCollector = collector
	server.healthDetailHandler = health.NewHandler(collector,
		health.NewAlertManager(health.DefaultThresholds(), health.SMTPConfig{}), health.NewTraceManager(time.Hour))
	server.SetMetricsListener(bindLoopbackListener(t))
	server.cfg.Certificate.EnableCertManagement = true
	server.certManager = certMgr

	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Stop() })

	caPEM, err := certMgr.GetCACertificate()
	require.NoError(t, err)
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(caPEM))
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13,
		}},
	}
	t.Cleanup(client.CloseIdleConnections)

	get := func(addr, apiKey string) (int, string) {
		req, reqErr := http.NewRequest(http.MethodGet, "https://"+addr+prometheusPath, nil)
		require.NoError(t, reqErr)
		if apiKey != "" {
			req.Header.Set("X-API-Key", apiKey)
		}
		resp, doErr := client.Do(req)
		require.NoError(t, doErr)
		defer func() { _ = resp.Body.Close() }()
		body, readErr := io.ReadAll(resp.Body)
		require.NoError(t, readErr)
		return resp.StatusCode, string(body)
	}

	metricsAddr := server.metricsHTTPServer.Addr
	publicAddr := server.httpServer.Addr
	key := NewEphemeralTestKey(t, server, []string{"monitoring:read-metrics"}, "test-tenant", 5*time.Minute)

	status, body := get(metricsAddr, key)
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, "# TYPE cfgms_route_test_depth gauge\ncfgms_route_test_depth{queue=\"primary\"} 7\n")
	assert.Contains(t, body, "# TYPE cfgms_goroutines gauge\n")
	assert.NotContains(t, body, "cfgms_storage_", "unimplemented storage sentinels must not be exposed")
	assert.NotContains(t, body, "test-tenant")

	status, _ = get(metricsAddr, "")
	assert.Equal(t, http.StatusUnauthorized, status, "no credential")

	// A valid credential without monitoring:read-metrics is refused.
	otherKey := NewEphemeralTestKey(t, server, []string{"monitoring:read-alerts"}, "test-tenant", 5*time.Minute)
	status, _ = get(metricsAddr, otherKey)
	assert.Equal(t, http.StatusForbidden, status, "credential lacking read-metrics")

	// The public listener never serves it, even for an authorised credential.
	status, body = get(publicAddr, key)
	assert.Equal(t, http.StatusNotFound, status, body)

	// Same on the in-process public router.
	req := httptest.NewRequest(http.MethodGet, prometheusPath, nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	server.router.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// TestPrometheusRouteUnavailableWithoutHealthHandler covers a server built
// without a collector: the route is registered and authorised, and answers 503.
func TestPrometheusRouteUnavailableWithoutHealthHandler(t *testing.T) {
	s := setupTestServer(t)
	key := NewEphemeralTestKey(t, s, []string{"monitoring:read-metrics"}, "test-tenant", 5*time.Minute)

	req := httptest.NewRequest(http.MethodGet, prometheusPath, nil)
	req.Header.Set("X-API-Key", key)
	rec := httptest.NewRecorder()
	s.metricsRouter.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}
