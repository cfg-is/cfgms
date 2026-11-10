// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/pkg/logging"
)

// storageProbeTimeout is the default deadline for one storage probe. A hung
// database must cost the sampler at most this long.
const storageProbeTimeout = 5 * time.Second

var errStorageProbeInFlight = errors.New("previous storage probe still running")

// storageProbeBuckets spans a healthy sub-millisecond round trip up to the
// default probe deadline.
var storageProbeBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}

func init() { registerSignalSource(registerStorageProbe) }

// storageProbe samples database connectivity by running the controller's
// real-state readiness check on every collector tick. The exported series carry
// no labels: the probe's error text is never exported, so no label can take a
// value from the database or its driver.
type storageProbe struct {
	check     func(ctx context.Context) error
	timeout   time.Duration
	connected *health.Gauge
	latency   *health.Histogram
	failures  *health.Counter
	inFlight  atomic.Bool
	logger    logging.Logger
}

// registerStorageProbe registers the storage signals and a sampler that probes
// the database through ControllerService.StorageReady. A server without a
// controller service exports nothing rather than a misleading 0.
func registerStorageProbe(s *Server) error {
	if s.controllerService == nil {
		return nil
	}
	probe, err := newStorageProbe(s.healthCollector.Signals(), s.controllerService.StorageReady, storageProbeTimeout, s.logger)
	if err != nil {
		return err
	}
	s.healthCollector.RegisterSampler(probe.sample)
	return nil
}

func newStorageProbe(sig *health.SignalRegistry, check func(context.Context) error, timeout time.Duration, logger logging.Logger) (*storageProbe, error) {
	connected, err := sig.RegisterGauge("cfgms_storage_connected",
		"Whether the last storage probe reached the database (1) or not (0).", nil)
	if err != nil {
		return nil, err
	}
	latency, err := sig.RegisterHistogram("cfgms_storage_probe_duration_seconds",
		"Duration of storage probes in seconds, including failed and timed-out probes.", storageProbeBuckets, nil)
	if err != nil {
		return nil, err
	}
	failures, err := sig.RegisterCounter("cfgms_storage_probe_failures_total",
		"Total storage probes that failed or exceeded their deadline.", nil)
	if err != nil {
		return nil, err
	}
	// Export the failure series at 0 from the start so rate() sees the first failure.
	if err := failures.Add(0, nil); err != nil {
		return nil, err
	}
	return &storageProbe{check: check, timeout: timeout, connected: connected, latency: latency, failures: failures, logger: logger}, nil
}

// sample runs one probe under the probe deadline and records the outcome. The
// check runs in its own goroutine so a driver that ignores its context cannot
// hold the sampler past the deadline; while such a probe is still running the
// next tick is recorded as a failure instead of piling up another goroutine.
func (p *storageProbe) sample(ctx context.Context) {
	start := time.Now()
	err := p.run(ctx)
	_ = p.latency.Observe(time.Since(start).Seconds(), nil)
	if err != nil {
		_ = p.connected.Set(0, nil)
		_ = p.failures.Inc(nil)
		p.logger.Warn("Storage probe failed", "error", logging.SanitizeLogValue(err.Error()))
		return
	}
	_ = p.connected.Set(1, nil)
}

func (p *storageProbe) run(ctx context.Context) error {
	if !p.inFlight.CompareAndSwap(false, true) {
		return errStorageProbeInFlight
	}
	probeCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		defer p.inFlight.Store(false)
		defer func() {
			if r := recover(); r != nil {
				done <- errors.New("storage probe panicked")
			}
		}()
		done <- p.check(probeCtx)
	}()

	select {
	case err := <-done:
		return err
	case <-probeCtx.Done():
		return probeCtx.Err()
	}
}
