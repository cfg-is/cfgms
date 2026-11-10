// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package health_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
)

// newSignalTestCollector builds a Collector with the real default collectors.
// Storage stats are supplied by the caller so tests can choose real values or
// the -1 "not instrumented" sentinels.
func newSignalTestCollector(t *testing.T, storage *health.MockStorageProviderStats) *health.Collector {
	t.Helper()
	systemCollector, err := health.NewDefaultSystemCollector()
	require.NoError(t, err)
	return health.NewCollector(
		health.NewDefaultTransportCollector(&health.MockTransportProviderStats{}),
		health.NewDefaultStorageCollector(storage),
		health.NewDefaultApplicationCollector(&health.MockApplicationQueueStats{}),
		systemCollector,
	)
}

// scrape starts the collector (so the built-in sections have a snapshot), then
// serves HandlePrometheusMetrics and returns the response.
func scrape(t *testing.T, c *health.Collector) *httptest.ResponseRecorder {
	t.Helper()
	require.NoError(t, c.Start(context.Background(), time.Hour))
	t.Cleanup(func() { _ = c.Stop() })
	require.Eventually(t, func() bool {
		_, err := c.GetCurrentMetrics()
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	h := health.NewHandler(c, health.NewAlertManager(health.DefaultThresholds(), health.SMTPConfig{}), health.NewTraceManager(time.Hour))
	rec := httptest.NewRecorder()
	h.HandlePrometheusMetrics(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health/metrics/prometheus", nil))
	return rec
}

func TestSignalRegistryRejectsUndeclaredLabel(t *testing.T) {
	reg := newSignalTestCollector(t, &health.MockStorageProviderStats{}).Signals()

	counter, err := reg.RegisterCounter("cfgms_test_events_total", "Test events.", map[string][]string{
		"result": {"ok", "error"},
	})
	require.NoError(t, err)
	gauge, err := reg.RegisterGauge("cfgms_test_depth", "Test depth.", map[string][]string{"queue": {"a"}})
	require.NoError(t, err)
	hist, err := reg.RegisterHistogram("cfgms_test_seconds", "Test latency.", []float64{1, 5}, map[string][]string{"op": {"read"}})
	require.NoError(t, err)

	// Undeclared label name, undeclared value, missing label: all errors.
	require.Error(t, counter.Inc(map[string]string{"tenant": "acme-corp"}))
	require.Error(t, counter.Inc(map[string]string{"result": "timeout"}))
	require.Error(t, counter.Inc(nil))
	require.Error(t, counter.Inc(map[string]string{"result": "ok", "extra": "x"}))
	require.Error(t, gauge.Set(1, map[string]string{"queue": "b"}))
	require.Error(t, hist.Observe(1, map[string]string{"op": "write"}))
	// Invalid sample values record nothing either.
	require.Error(t, counter.Add(-1, map[string]string{"result": "ok"}))

	var sb strings.Builder
	require.NoError(t, reg.WriteText(&sb))
	out := sb.String()
	assert.NotContains(t, out, "acme-corp")
	for _, line := range strings.Split(out, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		t.Fatalf("rejected records left a sample behind: %q", line)
	}

	// A declared label set still records.
	require.NoError(t, counter.Inc(map[string]string{"result": "ok"}))
	sb.Reset()
	require.NoError(t, reg.WriteText(&sb))
	assert.Contains(t, sb.String(), `cfgms_test_events_total{result="ok"} 1`)
}

func TestSignalRegistryRegistrationValidation(t *testing.T) {
	reg := newSignalTestCollector(t, &health.MockStorageProviderStats{}).Signals()

	_, err := reg.RegisterGauge("bad name", "x", nil)
	require.Error(t, err)
	_, err = reg.RegisterGauge("cfgms_ok", "x", map[string][]string{"le": {"1"}})
	require.Error(t, err, "le is reserved")
	_, err = reg.RegisterGauge("cfgms_ok", "x", map[string][]string{"__reserved": {"1"}})
	require.Error(t, err)
	_, err = reg.RegisterGauge("cfgms_ok", "x", map[string][]string{"bad-label": {"1"}})
	require.Error(t, err)
	_, err = reg.RegisterGauge("cfgms_ok", "x", map[string][]string{"empty": {}})
	require.Error(t, err, "a label must declare at least one allowed value")
	_, err = reg.RegisterHistogram("cfgms_h", "x", nil, nil)
	require.Error(t, err)
	_, err = reg.RegisterHistogram("cfgms_h", "x", []float64{5, 1}, nil)
	require.Error(t, err, "buckets must be increasing")
	_, err = reg.RegisterHistogram("cfgms_h", "x", []float64{1, 1}, nil)
	require.Error(t, err)

	// None of the failed registrations consumed the name.
	_, err = reg.RegisterGauge("cfgms_ok", "x", nil)
	require.NoError(t, err)
	_, err = reg.RegisterHistogram("cfgms_h", "x", []float64{1, 2}, nil)
	require.NoError(t, err)
}

func TestSignalRegistryNameCollision(t *testing.T) {
	reg := newSignalTestCollector(t, &health.MockStorageProviderStats{}).Signals()

	// Names the renderer already emits.
	for _, name := range []string{
		"cfgms_cpu_percent", "cfgms_goroutines", "cfgms_transport_connected_stewards", "cfgms_storage_pool_utilization",
		"cfgms_workflow_queue_depth",
	} {
		_, err := reg.RegisterGauge(name, "x", nil)
		require.Error(t, err, name)
		_, err = reg.RegisterCounter(name, "x", nil)
		require.Error(t, err, name)
	}

	// Duplicate registration, across metric kinds.
	_, err := reg.RegisterCounter("cfgms_dup_total", "x", nil)
	require.NoError(t, err)
	_, err = reg.RegisterCounter("cfgms_dup_total", "x", nil)
	require.Error(t, err)
	_, err = reg.RegisterGauge("cfgms_dup_total", "x", nil)
	require.Error(t, err)

	// A histogram also owns its _bucket, _sum and _count series names.
	_, err = reg.RegisterHistogram("cfgms_lat", "x", []float64{1}, nil)
	require.NoError(t, err)
	for _, name := range []string{"cfgms_lat_bucket", "cfgms_lat_sum", "cfgms_lat_count"} {
		_, err = reg.RegisterGauge(name, "x", nil)
		require.Error(t, err, name)
	}
	// ...and cannot shadow an existing metric's name.
	_, err = reg.RegisterHistogram("cfgms_dup_total_bucket", "x", []float64{1}, nil)
	require.NoError(t, err)
	_, err = reg.RegisterHistogram("cfgms_dup_total", "x", []float64{1}, nil)
	require.Error(t, err)
}

func TestSignalRegistryConcurrentRecord(t *testing.T) {
	c := newSignalTestCollector(t, &health.MockStorageProviderStats{})
	reg := c.Signals()
	counter, err := reg.RegisterCounter("cfgms_race_total", "Race.", map[string][]string{"result": {"ok", "error"}})
	require.NoError(t, err)
	gauge, err := reg.RegisterGauge("cfgms_race_gauge", "Race.", nil)
	require.NoError(t, err)
	hist, err := reg.RegisterHistogram("cfgms_race_seconds", "Race.", []float64{0.1, 1}, nil)
	require.NoError(t, err)

	const writers, perWriter = 8, 500
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var scrapes sync.WaitGroup
	scrapes.Add(1)
	go func() {
		defer scrapes.Done()
		for {
			select {
			case <-stop:
				return
			default:
				var sb strings.Builder
				_ = reg.WriteText(&sb)
			}
		}
	}()
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < perWriter; j++ {
				assert.NoError(t, counter.Inc(map[string]string{"result": "ok"}))
				assert.NoError(t, gauge.Set(float64(j), nil))
				assert.NoError(t, hist.Observe(0.5, nil))
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	scrapes.Wait()

	var sb strings.Builder
	require.NoError(t, reg.WriteText(&sb))
	assert.Contains(t, sb.String(), `cfgms_race_total{result="ok"} 4000`)
	assert.Contains(t, sb.String(), `cfgms_race_seconds_count 4000`)
}

func TestSignalRegistryHistogramBuckets(t *testing.T) {
	reg := newSignalTestCollector(t, &health.MockStorageProviderStats{}).Signals()
	hist, err := reg.RegisterHistogram("cfgms_op_seconds", "Op latency.", []float64{0.125, 1, 10}, map[string][]string{"op": {"read"}})
	require.NoError(t, err)

	labels := map[string]string{"op": "read"}
	for _, v := range []float64{0.0625, 0.125, 0.5, 1, 7, 100} {
		require.NoError(t, hist.Observe(v, labels))
	}
	require.Error(t, hist.Observe(nanValue(), labels))

	var sb strings.Builder
	require.NoError(t, reg.WriteText(&sb))
	out := sb.String()
	// Upper bounds are inclusive and counts cumulative.
	assert.Contains(t, out, `cfgms_op_seconds_bucket{op="read",le="0.125"} 2`)
	assert.Contains(t, out, `cfgms_op_seconds_bucket{op="read",le="1"} 4`)
	assert.Contains(t, out, `cfgms_op_seconds_bucket{op="read",le="10"} 5`)
	assert.Contains(t, out, `cfgms_op_seconds_bucket{op="read",le="+Inf"} 6`)
	assert.Contains(t, out, `cfgms_op_seconds_count{op="read"} 6`)
	assert.Contains(t, out, `cfgms_op_seconds_sum{op="read"} 108.6875`)
}

func nanValue() float64 {
	zero := 0.0
	return zero / zero
}

func TestPrometheusExpositionFormat(t *testing.T) {
	c := newSignalTestCollector(t, &health.MockStorageProviderStats{
		ProviderName: "flatfile", PoolUtilization: 0.25, AvgLatencyMs: 3, P95LatencyMs: 9, TotalQueries: 10, SlowQueries: 2,
	})
	reg := c.Signals()
	gauge, err := reg.RegisterGauge("cfgms_test_depth", "Depth of a test queue.", map[string][]string{"queue": {"a", "b"}})
	require.NoError(t, err)
	counter, err := reg.RegisterCounter("cfgms_test_events_total", "Events seen.", nil)
	require.NoError(t, err)
	require.NoError(t, gauge.Set(3, map[string]string{"queue": "a"}))
	require.NoError(t, counter.Add(2, nil))

	rec := scrape(t, c)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "text/plain; version=0.0.4", rec.Header().Get("Content-Type"))
	body := rec.Body.String()

	// Registry metrics, with HELP and TYPE ahead of their samples.
	assert.Contains(t, body, "# HELP cfgms_test_depth Depth of a test queue.\n# TYPE cfgms_test_depth gauge\ncfgms_test_depth{queue=\"a\"} 3\n")
	assert.Contains(t, body, "# HELP cfgms_test_events_total Events seen.\n# TYPE cfgms_test_events_total counter\ncfgms_test_events_total 2\n")
	// Existing collector values keep their names and types.
	assert.Contains(t, body, "# TYPE cfgms_transport_connected_stewards gauge\ncfgms_transport_connected_stewards 0\n")
	assert.Contains(t, body, "# TYPE cfgms_transport_stream_errors counter\n")
	assert.Contains(t, body, "# TYPE cfgms_storage_pool_utilization gauge\ncfgms_storage_pool_utilization 0.25\n")
	assert.Contains(t, body, "# TYPE cfgms_storage_slow_queries counter\ncfgms_storage_slow_queries 2\n")
	assert.Contains(t, body, "# TYPE cfgms_workflow_queue_depth gauge\n")
	assert.Contains(t, body, "# TYPE cfgms_cpu_percent gauge\n")
	assert.Contains(t, body, "# TYPE cfgms_goroutines gauge\n")

	// Every built-in family renders when its section is populated.
	for _, name := range []string{
		"cfgms_transport_connected_stewards", "cfgms_transport_stream_errors", "cfgms_transport_messages_sent",
		"cfgms_transport_messages_received", "cfgms_transport_reconnection_attempts",
		"cfgms_storage_pool_utilization", "cfgms_storage_query_latency_avg_ms", "cfgms_storage_query_latency_p95_ms",
		"cfgms_storage_slow_queries",
		"cfgms_workflow_queue_depth", "cfgms_script_queue_depth", "cfgms_active_workflows", "cfgms_active_scripts",
		"cfgms_cpu_percent", "cfgms_memory_percent", "cfgms_memory_bytes", "cfgms_goroutines", "cfgms_heap_bytes",
	} {
		assert.Contains(t, body, "# TYPE "+name+" ", name)
	}
	assert.Contains(t, body, "cfgms_storage_query_latency_avg_ms 3.00\n")

	// Every sample is preceded by a HELP and a TYPE for its family, and each
	// family is declared once.
	helped, typed := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		fields := strings.Fields(line)
		switch {
		case strings.HasPrefix(line, "# HELP "):
			require.False(t, helped[fields[2]], "duplicate HELP for %s", fields[2])
			helped[fields[2]] = true
		case strings.HasPrefix(line, "# TYPE "):
			require.False(t, typed[fields[2]], "duplicate TYPE for %s", fields[2])
			typed[fields[2]] = true
		default:
			name := fields[0]
			if i := strings.IndexByte(name, '{'); i >= 0 {
				name = name[:i]
			}
			require.True(t, helped[name] && typed[name], "sample %q has no preceding HELP/TYPE", line)
		}
	}
}

func TestPrometheusLabelEscaping(t *testing.T) {
	c := newSignalTestCollector(t, &health.MockStorageProviderStats{})
	reg := c.Signals()
	awkward := "a\\b\"c\nd"
	gauge, err := reg.RegisterGauge("cfgms_test_escape", "Help with \\ and\nnewline.", map[string][]string{"kind": {awkward}})
	require.NoError(t, err)
	require.NoError(t, gauge.Set(1, map[string]string{"kind": awkward}))

	body := scrape(t, c).Body.String()
	assert.Contains(t, body, `cfgms_test_escape{kind="a\\b\"c\nd"} 1`+"\n")
	assert.Contains(t, body, `# HELP cfgms_test_escape Help with \\ and\nnewline.`+"\n")
	assert.NotContains(t, body, "a\\b\"c\nd", "raw label value must not reach the output")
}

func TestPrometheusSkipsUnimplementedStorage(t *testing.T) {
	// The sentinel values server.UnimplementedStorageStats reports.
	c := newSignalTestCollector(t, &health.MockStorageProviderStats{
		ProviderName: "flatfile", PoolUtilization: -1, AvgLatencyMs: -1, P95LatencyMs: -1,
		TotalQueries: -1, SlowQueries: -1, QueryErrors: -1,
	})
	body := scrape(t, c).Body.String()

	assert.NotContains(t, body, "cfgms_storage_")
	assert.NotContains(t, body, "-1\n")
	// The other sections are unaffected.
	assert.Contains(t, body, "cfgms_cpu_percent")
	assert.Contains(t, body, "cfgms_transport_connected_stewards")
}

func TestSamplerRunsOnCollectorTick(t *testing.T) {
	c := newSignalTestCollector(t, &health.MockStorageProviderStats{})
	var runs atomic.Int64
	var sawCtx atomic.Bool
	c.RegisterSampler(func(ctx context.Context) {
		if ctx != nil && ctx.Err() == nil {
			sawCtx.Store(true)
		}
		runs.Add(1)
	})
	c.RegisterSampler(nil) // ignored

	require.NoError(t, c.Start(context.Background(), 20*time.Millisecond))
	require.Eventually(t, func() bool { return runs.Load() >= 3 }, 5*time.Second, 5*time.Millisecond,
		"sampler must run on the initial collection and on every tick")
	assert.True(t, sawCtx.Load())

	require.NoError(t, c.Stop())
	after := runs.Load()
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, after, runs.Load(), "sampler must not run after Stop")
}

func TestSamplerPanicDoesNotStopCollection(t *testing.T) {
	c := newSignalTestCollector(t, &health.MockStorageProviderStats{})
	var healthy atomic.Int64
	c.RegisterSampler(func(context.Context) { panic("sampler failure") })
	c.RegisterSampler(func(context.Context) { healthy.Add(1) })

	require.NoError(t, c.Start(context.Background(), 20*time.Millisecond))
	t.Cleanup(func() { _ = c.Stop() })
	require.Eventually(t, func() bool { return healthy.Load() >= 2 }, 5*time.Second, 5*time.Millisecond)
	_, err := c.GetCurrentMetrics()
	require.NoError(t, err)
}
