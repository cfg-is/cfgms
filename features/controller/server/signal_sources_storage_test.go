// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/fleet/storage"
	"github.com/cfgis/cfgms/features/controller/service"
	"github.com/cfgis/cfgms/pkg/logging"
)

// newStorageProbeTestServer builds a Server whose controller service sits on a
// real SQLite fleet store, and returns the store so a test can close it.
func newStorageProbeTestServer(t *testing.T) (*Server, *storage.Manager) {
	t.Helper()
	cfg := storage.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.EnableDeduplication = false
	mgr, err := storage.NewManager(cfg, logging.NewNoopLogger())
	require.NoError(t, err)
	t.Cleanup(func() { _ = mgr.Close() })

	srv := newSignalSourceTestServer(t)
	srv.controllerService = service.NewControllerServiceWithStorage(logging.NewNoopLogger(), mgr)
	return srv, mgr
}

// renderSignals returns the text exposition of srv's signal registry.
func renderSignals(t *testing.T, srv *Server) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, srv.healthCollector.Signals().WriteText(&sb))
	return sb.String()
}

func newTestProbe(t *testing.T, srv *Server, check func(context.Context) error, timeout time.Duration) *storageProbe {
	t.Helper()
	probe, err := newStorageProbe(srv.healthCollector.Signals(), check, timeout, srv.logger)
	require.NoError(t, err)
	return probe
}

// TestStorageProbeRecordsLatency: a probe of a live store sets the gauge to 1,
// observes one latency sample and records no failure. The probe is wired the
// way production wires it: through the registered source and the collector's
// own sampler tick.
func TestStorageProbeRecordsLatency(t *testing.T) {
	srv, _ := newStorageProbeTestServer(t)
	withSignalSources(t, registerStorageProbe)

	srv.startHealthServices()
	t.Cleanup(srv.stopHealthServices)

	require.Eventually(t, func() bool {
		return strings.Contains(renderSignals(t, srv), "cfgms_storage_probe_duration_seconds_count 1")
	}, 5*time.Second, 10*time.Millisecond, "the collector's initial tick must run the storage probe")

	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 1")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 0")
	assert.Contains(t, out, "cfgms_storage_probe_duration_seconds_bucket{le=\"+Inf\"} 1")
}

// TestStorageProbeSkippedWithoutControllerService: no controller service means
// no series at all, never a gauge stuck at 0.
func TestStorageProbeSkippedWithoutControllerService(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	require.NoError(t, registerStorageProbe(srv))
	assert.NotContains(t, renderSignals(t, srv), "cfgms_storage_")
}

// TestStorageProbeFailureThenRecovery: an unreachable store (closed mid-flight,
// as in TestStorageReady_ErrorWhenStoreUnreachable) drops the gauge to 0 and
// counts a failure; once a reachable store answers the gauge returns to 1.
func TestStorageProbeFailureThenRecovery(t *testing.T) {
	srv, mgr := newStorageProbeTestServer(t)
	healthy := srv.controllerService
	require.NoError(t, healthy.StorageReady(context.Background()))

	// An independent controller service over a second real store stands in for
	// the recovered backend.
	recoveredSrv, _ := newStorageProbeTestServer(t)
	var useRecovered atomic.Bool
	probe := newTestProbe(t, srv, func(ctx context.Context) error {
		if useRecovered.Load() {
			return recoveredSrv.controllerService.StorageReady(ctx)
		}
		return healthy.StorageReady(ctx)
	}, storageProbeTimeout)

	probe.sample(context.Background())
	assert.Contains(t, renderSignals(t, srv), "cfgms_storage_connected 1")

	require.NoError(t, mgr.Close())
	probe.sample(context.Background())
	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 0")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 1")
	assert.Contains(t, out, "cfgms_storage_probe_duration_seconds_count 2", "failed probes are timed too")

	useRecovered.Store(true)
	probe.sample(context.Background())
	out = renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 1")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 1")
}

// TestStorageProbeBackToBackSamplesNeverCountInFlight: a sample that returns
// must already have released the in-flight guard, so an instantly-succeeding
// check sampled back to back is never reported as a still-running probe. With
// the guard released after the result was published, the next sample could
// win the race against the previous goroutine's release and count a failure.
func TestStorageProbeBackToBackSamplesNeverCountInFlight(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	probe := newTestProbe(t, srv, func(context.Context) error { return nil }, storageProbeTimeout)

	const samples = 20000
	for i := 0; i < samples; i++ {
		probe.sample(context.Background())
		if !probe.inFlight.CompareAndSwap(false, false) {
			t.Fatalf("sample %d returned while its probe still held the in-flight guard", i)
		}
	}

	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 1")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 0")
}

// TestStorageProbePanicReleasesInFlight: a panicking check releases the guard
// before its failure is reported, so the next sample runs a fresh probe.
func TestStorageProbePanicReleasesInFlight(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	var calls atomic.Int32
	probe := newTestProbe(t, srv, func(context.Context) error {
		if calls.Add(1) == 1 {
			panic("driver bug")
		}
		return nil
	}, storageProbeTimeout)

	probe.sample(context.Background())
	probe.sample(context.Background())

	assert.Equal(t, int32(2), calls.Load(), "the sample after a panic must run a fresh probe")
	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 1")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 1")
}

// TestStorageProbeErrorTextIsNeverExported: the failure reason carries paths and
// driver text; none of it may reach the exposition.
func TestStorageProbeErrorTextIsNeverExported(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	probe := newTestProbe(t, srv, func(context.Context) error {
		return errors.New("dial tcp 10.9.8.7:5432: secret-reason-text")
	}, storageProbeTimeout)

	probe.sample(context.Background())

	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 0")
	assert.NotContains(t, out, "secret-reason-text")
	assert.NotContains(t, out, "10.9.8.7")
	assert.NotContains(t, out, "{error")
}

// TestStorageProbeDeadline: a database that never answers, and ignores its
// context, must not hold the sampler past the probe deadline. The next tick,
// while the hung probe is still running, records a failure without starting a
// second probe.
func TestStorageProbeDeadline(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	release := make(chan struct{})
	var started atomic.Int32
	t.Cleanup(func() { close(release) })
	probe := newTestProbe(t, srv, func(context.Context) error {
		started.Add(1)
		<-release
		return nil
	}, 50*time.Millisecond)

	begin := time.Now()
	probe.sample(context.Background())
	assert.Less(t, time.Since(begin), 2*time.Second, "sampler must return at the probe deadline")

	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 0")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 1")

	probe.sample(context.Background())
	assert.Equal(t, int32(1), started.Load(), "a hung probe must not be stacked with another")
	assert.Contains(t, renderSignals(t, srv), "cfgms_storage_probe_failures_total 2")
}

// TestStorageProbeDeadlineAppliedToStore: the real readiness check receives the
// probe deadline, so a store that honours its context stops at it.
func TestStorageProbeDeadlineAppliedToStore(t *testing.T) {
	srv, _ := newStorageProbeTestServer(t)
	var deadlineSet atomic.Bool
	probe := newTestProbe(t, srv, func(ctx context.Context) error {
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= storageProbeTimeout {
			deadlineSet.Store(true)
		}
		return srv.controllerService.StorageReady(ctx)
	}, storageProbeTimeout)

	probe.sample(context.Background())

	assert.True(t, deadlineSet.Load())
	assert.Equal(t, 5*time.Second, storageProbeTimeout)
	assert.Contains(t, renderSignals(t, srv), "cfgms_storage_connected 1")
}

// TestStorageProbePanicIsAFailure: a panicking check is a failed probe, not a
// crashed sampler goroutine.
func TestStorageProbePanicIsAFailure(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	probe := newTestProbe(t, srv, func(context.Context) error { panic("driver bug") }, storageProbeTimeout)

	probe.sample(context.Background())

	out := renderSignals(t, srv)
	assert.Contains(t, out, "cfgms_storage_connected 0")
	assert.Contains(t, out, "cfgms_storage_probe_failures_total 1")
}
