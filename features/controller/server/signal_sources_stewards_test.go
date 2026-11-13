// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/controller/heartbeat"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// statsControlPlane is the heartbeat-driving test control plane with settable
// stats. It is a functional test implementation, not a mock: GetStats returns
// whatever counters the test has set, as a provider would after traffic.
type statsControlPlane struct {
	hbTestControlPlane
	mu    sync.Mutex
	stats controlplaneTypes.ControlPlaneStats
	err   error
}

func (p *statsControlPlane) setStats(st controlplaneTypes.ControlPlaneStats) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats = st
}

func (p *statsControlPlane) setErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *statsControlPlane) GetStats(context.Context) (*controlplaneTypes.ControlPlaneStats, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	st := p.stats
	return &st, nil
}

func newStewardSignalsTestServer(t *testing.T, offlineTimeout time.Duration) (*Server, *statsControlPlane) {
	t.Helper()
	srv := newSignalSourceTestServer(t)
	cp := &statsControlPlane{}
	svc, err := heartbeat.New(&heartbeat.Config{
		ControlPlane:          cp,
		StewardOfflineTimeout: offlineTimeout,
		Logger:                logging.NewNoopLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })
	srv.heartbeatService = svc
	srv.controlPlane = cp
	return srv, cp
}

func scrapeStewardSignals(t *testing.T, srv *Server) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	return sb.String()
}

func beat(t *testing.T, cp *statsControlPlane, id string) {
	t.Helper()
	require.NoError(t, cp.sendHeartbeat(context.Background(), &controlplaneTypes.Heartbeat{
		StewardID: id,
		Status:    controlplaneTypes.StatusHealthy,
		Timestamp: time.Now(),
	}))
}

// TestStewardSignalsScrape drives a real collector and heartbeat service and
// checks the scraped series: the fresh-heartbeat gauge follows receipt time,
// the transport counters follow the provider's cumulative stats, and the
// connected-stewards series is left to the built-in renderer.
func TestStewardSignalsScrape(t *testing.T) {
	srv, cp := newStewardSignalsTestServer(t, 400*time.Millisecond)
	withSignalSources(t, registerStewardSignals)

	beat(t, cp, "steward-1")
	beat(t, cp, "steward-2")
	cp.setStats(controlplaneTypes.ControlPlaneStats{
		DeliveryFailures: 3, HeartbeatsDropped: 5, EventsDropped: 7, ResponsesDropped: 11,
		ConnectedStewards: 2,
	})

	srv.startHealthServices()
	t.Cleanup(srv.stopHealthServices)

	// The gauge sampler and the transport-counter sampler are separate
	// samplers that finish in no defined order within one collection pass, so
	// wait for every sample line asserted below, not just the gauge.
	wantSamples := []string{
		"cfgms_stewards_heartbeat_fresh 2\n",
		"cfgms_transport_delivery_failures_total 3\n",
		"cfgms_transport_heartbeats_dropped_total 5\n",
		"cfgms_transport_events_dropped_total 7\n",
		"cfgms_transport_responses_dropped_total 11\n",
	}
	require.Eventually(t, func() bool {
		body := scrapeStewardSignals(t, srv)
		for _, want := range wantSamples {
			if !strings.Contains(body, want) {
				return false
			}
		}
		return true
	}, 5*time.Second, 10*time.Millisecond, "the initial collection must sample the fresh count and all four transport counters")

	body := scrapeStewardSignals(t, srv)
	assert.Contains(t, body, "# TYPE cfgms_stewards_heartbeat_fresh gauge\n")
	assert.Contains(t, body, "# TYPE cfgms_transport_delivery_failures_total counter\ncfgms_transport_delivery_failures_total 3\n")
	for _, want := range wantSamples {
		assert.Contains(t, body, want)
	}
	assert.NotContains(t, body, "cfgms_transport_connected_stewards",
		"the signal registry must not emit the series the built-in renderer owns")
	assert.NotContains(t, body, "steward-1", "no steward identity may appear in a signal")
	assert.NotContains(t, body, "{", "steward signals carry no labels")

	// The built-in renderer still emits the connected-stewards series, so the
	// full exposition has it exactly once alongside the new signals.
	h := health.NewHandler(srv.healthCollector, health.NewAlertManager(health.DefaultThresholds(), health.SMTPConfig{}), health.NewTraceManager(time.Hour))
	// The collector runs its samplers before it stores the snapshot the
	// built-in renderer reads, so the signal can be visible a moment before
	// the snapshot is: wait for the snapshot rather than assume it.
	var rec *httptest.ResponseRecorder
	require.Eventually(t, func() bool {
		rec = httptest.NewRecorder()
		h.HandlePrometheusMetrics(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health/metrics/prometheus", nil))
		return strings.Contains(rec.Body.String(), "# TYPE cfgms_transport_connected_stewards ")
	}, 5*time.Second, 10*time.Millisecond, "the collector must publish its first snapshot")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, 1, strings.Count(rec.Body.String(), "# TYPE cfgms_transport_connected_stewards "))
	assert.Contains(t, rec.Body.String(), "cfgms_stewards_heartbeat_fresh 2\n")
}

// TestStewardSignalsTrackReceiptTime proves the gauge ages stewards out by
// controller receipt time without waiting for the heartbeat monitor tick.
func TestStewardSignalsTrackReceiptTime(t *testing.T) {
	srv, cp := newStewardSignalsTestServer(t, 200*time.Millisecond)
	require.NoError(t, registerStewardSignals(srv))
	beat(t, cp, "steward-1")
	startFastCollector(t, srv)

	eventuallyScrapes(t, srv, "cfgms_stewards_heartbeat_fresh 1\n")
	// The heartbeat monitor ticks every 5s by default, so this drop to zero can
	// only come from the receipt-time computation.
	eventuallyScrapes(t, srv, "cfgms_stewards_heartbeat_fresh 0\n")
}

// TestStewardTransportCountersAreCumulative proves each sample adds only what
// the provider counted since the previous one, tolerates an unchanged value,
// and treats a lower value as a provider restart rather than a decrease.
func TestStewardTransportCountersAreCumulative(t *testing.T) {
	srv, cp := newStewardSignalsTestServer(t, time.Minute)
	require.NoError(t, registerStewardSignals(srv))
	cp.setStats(controlplaneTypes.ControlPlaneStats{HeartbeatsDropped: 4})
	startFastCollector(t, srv)
	eventuallyScrapes(t, srv, "cfgms_transport_heartbeats_dropped_total 4\n")
	// Many further ticks with an unchanged value must not double count.
	time.Sleep(200 * time.Millisecond)
	assert.Contains(t, scrapeStewardSignals(t, srv), "cfgms_transport_heartbeats_dropped_total 4\n")

	cp.setStats(controlplaneTypes.ControlPlaneStats{HeartbeatsDropped: 9, EventsDropped: 1})
	eventuallyScrapes(t, srv, "cfgms_transport_heartbeats_dropped_total 9\n")
	assert.Contains(t, scrapeStewardSignals(t, srv), "cfgms_transport_events_dropped_total 1\n")

	// Provider restarted its counts: 2 new drops since the restart.
	cp.setStats(controlplaneTypes.ControlPlaneStats{HeartbeatsDropped: 2})
	eventuallyScrapes(t, srv, "cfgms_transport_heartbeats_dropped_total 11\n")

	// A stats error leaves the counters where they were.
	cp.setErr(errors.New("stats unavailable"))
	time.Sleep(200 * time.Millisecond)
	assert.Contains(t, scrapeStewardSignals(t, srv), "cfgms_transport_heartbeats_dropped_total 11\n")
}

// TestStewardSignalsAbsentComponents proves a missing component registers
// nothing for it instead of exporting a zero that looks like health.
func TestStewardSignalsAbsentComponents(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	require.NoError(t, registerStewardSignals(srv))
	assert.Empty(t, scrapeStewardSignals(t, srv))

	srv, _ = newStewardSignalsTestServer(t, time.Minute)
	srv.controlPlane = nil
	require.NoError(t, registerStewardSignals(srv))
	body := scrapeStewardSignals(t, srv)
	assert.Contains(t, body, "# TYPE cfgms_stewards_heartbeat_fresh gauge")
	assert.NotContains(t, body, "cfgms_transport_")
}

// TestStewardSignalsRegisterTwiceFails proves a name clash surfaces as an error
// from the source, which runSignalSources logs and skips.
func TestStewardSignalsRegisterTwiceFails(t *testing.T) {
	srv, _ := newStewardSignalsTestServer(t, time.Minute)
	require.NoError(t, registerStewardSignals(srv))
	assert.Error(t, registerStewardSignals(srv))
}

// startFastCollector starts the server's collector on a short interval so the
// registered samplers run repeatedly, and stops it with the test.
func startFastCollector(t *testing.T, srv *Server) {
	t.Helper()
	require.NoError(t, srv.healthCollector.Start(context.Background(), 20*time.Millisecond))
	t.Cleanup(func() { _ = srv.healthCollector.Stop() })
}

// eventuallyScrapes waits until the signal text contains want.
func eventuallyScrapes(t *testing.T, srv *Server, want string) {
	t.Helper()
	require.Eventually(t, func() bool {
		return strings.Contains(scrapeStewardSignals(t, srv), want)
	}, 5*time.Second, 10*time.Millisecond, "expected scrape to contain %q, got:\n%s", want, scrapeStewardSignals(t, srv))
}
