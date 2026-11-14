// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

// newSignalsTestCollector builds a real health collector. It is never started:
// the API signals only need its signal registry.
func newSignalsTestCollector(t *testing.T) *health.Collector {
	t.Helper()
	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)
	return health.NewCollector(
		health.NewDefaultTransportCollector(&health.MockTransportProviderStats{}),
		health.NewDefaultStorageCollector(&health.MockStorageProviderStats{ProviderName: "flatfile", PoolUtilization: -1, AvgLatencyMs: -1, P95LatencyMs: -1, SlowQueries: -1}),
		health.NewDefaultApplicationCollector(&health.MockApplicationQueueStats{}),
		systemCollector,
	)
}

// scrapeSignals renders the collector's signal registry as a Prometheus scrape.
func scrapeSignals(t *testing.T, collector *health.Collector) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, collector.Signals().WriteText(&sb))
	return sb.String()
}

// requestsSample is the scrape line of the request counter for one series.
func requestsSample(routeClass, statusClass string, value string) string {
	return `cfgms_api_requests_total{route_class="` + routeClass + `",status_class="` + statusClass + `"} ` + value + "\n"
}

// durationCountSample is the scrape line of the duration histogram's observation
// count for one series.
func durationCountSample(routeClass, statusClass string, value string) string {
	return `cfgms_api_request_duration_seconds_count{route_class="` + routeClass + `",status_class="` + statusClass + `"} ` + value + "\n"
}

func TestRouteClassFromTemplate(t *testing.T) {
	tests := []struct {
		name     string
		template string
		want     string
	}{
		{"allowlisted collection", "/api/v1/stewards", "stewards"},
		{"allowlisted with path parameter", "/api/v1/stewards/{id}", "stewards"},
		{"allowlisted nested", "/api/v1/tenants/{tenant_id}/stewards/{id}/dna", "tenants"},
		{"hyphenated segment", "/api/v1/api-keys/{id}", "api-keys"},
		{"health", "/api/v1/health/metrics/prometheus", "health"},
		{"subrouter prefix is its first segment", "/api/v1/workflows", "workflows"},
		{"segment outside the allowlist", "/api/v1/not-an-api-area/{id}", routeClassOther},
		{"path parameter as first segment", "/api/v1/{anything}", routeClassOther},
		{"bare api prefix", "/api/v1", routeClassOther},
		{"api prefix with slash", "/api/v1/", routeClassOther},
		{"other version", "/api/v2/stewards", routeClassOther},
		{"similar prefix", "/api/v10/stewards", routeClassOther},
		{"spa fallback", "/", routeClassStatic},
		{"non-api route", "/assets/{file}", routeClassOther},
		{"empty template", "", routeClassOther},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, routeClassFromTemplate(tt.template))
		})
	}

	// Every class the function can return is declared as a label value, so a
	// recorded request is never rejected by the registry.
	for _, seg := range apiRouteClassAllowlist {
		assert.Equal(t, seg, routeClassFromTemplate("/api/v1/"+seg+"/{id}"), seg)
	}
}

// TestRouteClassCoversRegisteredRoutes guards the allowlist against drift: every
// first segment the real routers register under /api/v1 must be allowlisted.
func TestRouteClassCoversRegisteredRoutes(t *testing.T) {
	s := setupTestServer(t)
	for _, router := range []*mux.Router{s.router, s.metricsRouter} {
		err := router.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
			template, tplErr := route.GetPathTemplate()
			if tplErr != nil || template == "/api/v1" || template == "/api/v1/" || !strings.HasPrefix(template, "/api/v1/") {
				return nil
			}
			assert.NotEqual(t, routeClassOther, routeClassFromTemplate(template),
				"route %q has a first segment missing from apiRouteClassAllowlist", template)
			return nil
		})
		require.NoError(t, err)
	}
}

func TestStatusClassOf(t *testing.T) {
	for status, want := range map[int]string{200: "2xx", 204: "2xx", 302: "3xx", 404: "4xx", 429: "4xx", 500: "5xx", 599: "5xx"} {
		got, ok := statusClassOf(status)
		assert.True(t, ok, status)
		assert.Equal(t, want, got, status)
	}
	for _, status := range []int{0, 100, 199, 600, -1} {
		_, ok := statusClassOf(status)
		assert.False(t, ok, status)
	}
}

func getStatus(t *testing.T, client *http.Client, url string, header map[string]string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	require.NoError(t, err)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestAPISignalsRecordedByRouteClass drives a real server's public and private
// routers over real HTTP and checks the scrape.
func TestAPISignalsRecordedByRouteClass(t *testing.T) {
	collector := newSignalsTestCollector(t)
	s := setupTestServer(t)
	s.healthCollector = collector
	s.healthDetailHandler = health.NewHandler(collector,
		health.NewAlertManager(health.DefaultThresholds(), health.SMTPConfig{}), health.NewTraceManager(time.Hour))

	public := httptest.NewServer(s.router)
	t.Cleanup(public.Close)
	private := httptest.NewServer(s.metricsRouter)
	t.Cleanup(private.Close)
	client := public.Client()

	key := NewEphemeralTestKey(t, s, []string{"monitoring:read-metrics"}, "tenant-acme-corp", 5*time.Minute)

	// Public router: two matched 200s, two refused requests carrying a
	// tenant-looking and a steward-looking path segment, and a 403 for a
	// credential lacking the permission.
	assert.Equal(t, http.StatusOK, getStatus(t, client, public.URL+"/api/v1/health", nil))
	assert.Equal(t, http.StatusOK, getStatus(t, client, public.URL+"/api/v1/health", nil))
	assert.Equal(t, http.StatusUnauthorized, getStatus(t, client, public.URL+"/api/v1/tenants/tenant-acme-corp", nil))
	assert.Equal(t, http.StatusUnauthorized, getStatus(t, client, public.URL+"/api/v1/stewards/steward-0123456789", nil))
	assert.Equal(t, http.StatusForbidden, getStatus(t, client, public.URL+"/api/v1/stewards", map[string]string{"X-API-Key": key}))

	// Private router: the Prometheus route itself, authorised.
	assert.Equal(t, http.StatusOK, getStatus(t, client, private.URL+"/api/v1/health/metrics/prometheus", map[string]string{"X-API-Key": key}))

	out := scrapeSignals(t, collector)
	assert.Contains(t, out, "# TYPE cfgms_api_requests_total counter\n")
	assert.Contains(t, out, "# TYPE cfgms_api_request_duration_seconds histogram\n")

	// /api/v1/health twice on the public router and the Prometheus route once on
	// the private router share a route class and status class.
	assert.Contains(t, out, requestsSample("health", "2xx", "3"))
	assert.Contains(t, out, durationCountSample("health", "2xx", "3"))
	assert.Contains(t, out, requestsSample("tenants", "4xx", "1"))
	assert.Contains(t, out, durationCountSample("tenants", "4xx", "1"))
	assert.Contains(t, out, requestsSample("stewards", "4xx", "2"))
	assert.Contains(t, out, `cfgms_api_request_duration_seconds_bucket{route_class="health",status_class="2xx",le="+Inf"} 3`)

	// No label value, and no other part of the scrape, carries a request path
	// segment.
	for _, leaked := range []string{"tenant-acme-corp", "steward-0123456789", "0123456789", "/api/v1/tenants", "X-API-Key", key} {
		assert.NotContains(t, out, leaked)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "cfgms_api_") && strings.Contains(line, "{") {
			assert.NotContains(t, line, "/", "a route class label never holds a path: %s", line)
		}
	}
}

// TestAPISignalsCountUnauthorizedAndNotFound checks the requests that bypass or
// short-circuit the middleware chain: refusals by authenticationMiddleware, which
// the middleware sits outside of, and router-level 404 and 405, which skip Use()
// middleware and are recorded by their handlers.
func TestAPISignalsCountUnauthorizedAndNotFound(t *testing.T) {
	collector := newSignalsTestCollector(t)
	s := setupTestServer(t)
	s.healthCollector = collector

	public := httptest.NewServer(s.router)
	t.Cleanup(public.Close)
	client := public.Client()

	assert.Equal(t, http.StatusUnauthorized, getStatus(t, client, public.URL+"/api/v1/stewards", nil))
	assert.Equal(t, http.StatusUnauthorized, getStatus(t, client, public.URL+"/api/v1/stewards", map[string]string{"X-API-Key": "cfgms_invalid"}))
	// An unknown API path never reaches a route.
	assert.Equal(t, http.StatusNotFound, getStatus(t, client, public.URL+"/api/v1/nonexistent/tenant-acme-corp/area", nil))
	assert.Equal(t, http.StatusNotFound, getStatus(t, client, public.URL+"/api/v2/stewards", nil))
	// A method with no route on an existing path is a router-level 405.
	req, err := http.NewRequest(http.MethodDelete, public.URL+"/api/v1/health", nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)

	out := scrapeSignals(t, collector)
	assert.Contains(t, out, requestsSample("stewards", "4xx", "2"), "401 counts under its route class")
	assert.Contains(t, out, durationCountSample("stewards", "4xx", "2"))
	assert.Contains(t, out, requestsSample(routeClassOther, "4xx", "3"), "two 404s and one 405 count under other")
	assert.Contains(t, out, durationCountSample(routeClassOther, "4xx", "3"))
	assert.NotContains(t, out, "nonexistent")
	assert.NotContains(t, out, "tenant-acme-corp")
}

// TestAPISignalsSPAFallbackIsStatic checks that a request served by the SPA
// catch-all is counted under "static", never under its path.
func TestAPISignalsSPAFallbackIsStatic(t *testing.T) {
	collector := newSignalsTestCollector(t)
	s := setupTestServer(t)
	s.healthCollector = collector

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tenants/tenant-acme-corp/dashboard", nil)
	s.router.ServeHTTP(rec, req)

	out := scrapeSignals(t, collector)
	if !strings.Contains(out, requestsSample(routeClassStatic, "2xx", "1")) {
		// A binary built without a frontend embeds a placeholder, and the SPA route
		// is then deliberately not registered (Issue #3043): the request is a 404
		// recorded under "other".
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.Contains(t, out, requestsSample(routeClassOther, "4xx", "1"))
	}
	assert.NotContains(t, out, "tenant-acme-corp")
	assert.NotContains(t, out, "dashboard")
}

// TestSignalsMiddlewarePreservesHijackAndSkipsLatency checks over a real
// connection that the wrapped writer still hijacks, that the hijacked request is
// counted but kept out of the latency histogram, and that an ordinary request on
// the same route is observed.
func TestSignalsMiddlewarePreservesHijackAndSkipsLatency(t *testing.T) {
	collector := newSignalsTestCollector(t)
	s := setupTestServer(t)
	s.healthCollector = collector

	router := mux.NewRouter()
	router.Use(s.signalsMiddleware)
	router.HandleFunc("/api/v1/terminal/{id}", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("upgrade") != "1" {
			w.WriteHeader(http.StatusOK)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "writer cannot hijack", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n")
		_ = buf.Flush()
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	// The hijacked request: the client must see the 101 the handler wrote on the
	// raw connection, which it can only do if Hijack worked through the wrapper.
	req, err := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/terminal/session-1?upgrade=1", nil)
	require.NoError(t, err)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "test")
	resp, err := srv.Client().Transport.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusSwitchingProtocols, resp.StatusCode)

	// The counter is updated after the handler returns; wait for it.
	require.Eventually(t, func() bool {
		return strings.Contains(scrapeSignals(t, collector), requestsSample("terminal", "2xx", "1"))
	}, 5*time.Second, 5*time.Millisecond)
	out := scrapeSignals(t, collector)
	assert.NotContains(t, out, "cfgms_api_request_duration_seconds_count{", "a hijacked connection is not a latency observation")

	// An ordinary request on the same route class is observed.
	assert.Equal(t, http.StatusOK, getStatus(t, srv.Client(), srv.URL+"/api/v1/terminal/session-1", nil))
	out = scrapeSignals(t, collector)
	assert.Contains(t, out, requestsSample("terminal", "2xx", "2"))
	assert.Contains(t, out, durationCountSample("terminal", "2xx", "1"))
}

// TestResponseWriterHijackErrorIsNotRecorded covers a writer that cannot hijack:
// the error is returned and the writer is not marked hijacked.
func TestResponseWriterHijackErrorIsNotRecorded(t *testing.T) {
	rec := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: struct{ http.ResponseWriter }{rec}, statusCode: http.StatusOK}
	_, _, err := rw.Hijack()
	require.Error(t, err)
	assert.False(t, rw.hijacked)
}

// TestSignalsMiddlewareNilCollector checks that a server without a health
// collector serves requests unchanged, with the writer unwrapped.
func TestSignalsMiddlewareNilCollector(t *testing.T) {
	s := setupTestServer(t)
	require.Nil(t, s.healthCollector)

	var sawWriter http.ResponseWriter
	handler := s.signalsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sawWriter = w
		w.WriteHeader(http.StatusTeapot)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	assert.Equal(t, http.StatusTeapot, rec.Code)
	assert.Same(t, rec, sawWriter, "the middleware is a pass-through without a collector")

	// The real routers, including their 404 handler, also serve normally.
	for _, tc := range []struct {
		path string
		want int
	}{{"/api/v1/health", http.StatusOK}, {"/api/v1/nonexistent", http.StatusNotFound}} {
		rec = httptest.NewRecorder()
		s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
		assert.Equal(t, tc.want, rec.Code, tc.path)
	}
	assert.Nil(t, s.apiSignals.instruments)
}

// TestAPISignalsRegistrationFailureDisablesRecording checks that a collector that
// already owns the metric names does not break request serving: recording is
// disabled for that collector and requests still succeed.
func TestAPISignalsRegistrationFailureDisablesRecording(t *testing.T) {
	collector := newSignalsTestCollector(t)
	_, err := collector.Signals().RegisterCounter(apiRequestsTotalMetric, "Taken.", nil)
	require.NoError(t, err)

	s := setupTestServer(t)
	s.healthCollector = collector

	rec := httptest.NewRecorder()
	s.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Nil(t, s.apiSignals.instruments)
	assert.NotContains(t, scrapeSignals(t, collector), "route_class")
}

// signalDocPath is the canonical service-level signal document, relative to this
// package.
const signalDocPath = "../../../docs/operations/service-level-signals.md"

// TestSignalDocListsEveryRouteClass fails when a route class a controller can
// export is missing from the signal document: every apiRouteClassAllowlist
// member, plus "static" and "other". An API area added to the allowlist without a
// matching document change fails here, before any request reaches the registry.
func TestSignalDocListsEveryRouteClass(t *testing.T) {
	b, err := os.ReadFile(filepath.FromSlash(signalDocPath))
	require.NoError(t, err, "the signal document must exist")

	// Read the label rows, not the whole page: "other" and "health" are also
	// words and values elsewhere in the document.
	var routeRow, statusRow string
	for _, line := range strings.Split(string(b), "\n") {
		switch {
		case strings.HasPrefix(line, "| `route_class` |"):
			routeRow = line
		case strings.HasPrefix(line, "| `status_class` |"):
			statusRow = line
		}
	}
	require.NotEmpty(t, routeRow, "the Label values table must have a route_class row")
	require.NotEmpty(t, statusRow, "the Label values table must have a status_class row")

	classes := make([]string, 0, len(apiRouteClassAllowlist)+2)
	classes = append(classes, apiRouteClassAllowlist...)
	classes = append(classes, routeClassStatic, routeClassOther)
	for _, class := range classes {
		assert.Contains(t, routeRow, "`"+class+"`", "route_class %q is not documented in %s", class, signalDocPath)
	}
	for _, class := range apiStatusClasses {
		assert.Contains(t, statusRow, "`"+class+"`", "status_class %q is not documented in %s", class, signalDocPath)
	}
}
