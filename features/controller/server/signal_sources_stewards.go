// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"sync"

	"github.com/cfgis/cfgms/features/controller/health"
	controlplaneTypes "github.com/cfgis/cfgms/pkg/controlplane/types"
	"github.com/cfgis/cfgms/pkg/logging"
)

// Steward and transport signals. Every value describes this controller node
// only (its heartbeat service and control plane provider), never a cluster
// total, and carries no steward or tenant label.
//
// cfgms_transport_connected_stewards is deliberately not registered here: the
// health exposition already renders it from the collector snapshot, and the
// signal registry refuses a name the built-in renderer emits.

func init() { registerSignalSource(registerStewardSignals) }

// transportCounterFeed mirrors one cumulative ControlPlaneStats field into a
// signal counter. The counter can only be advanced by a delta, so the feed
// remembers the last value it saw.
type transportCounterFeed struct {
	name    string
	help    string
	read    func(*controlplaneTypes.ControlPlaneStats) int64
	counter *health.Counter
	last    int64
}

// registerStewardSignals registers the heartbeat-fresh gauge and the transport
// drop and failure counters, and the samplers that refresh them each collection
// tick. A signal whose backing component is absent (no heartbeat service, no
// control plane) is not registered rather than reported as a misleading zero.
func registerStewardSignals(s *Server) error {
	if s.heartbeatService != nil {
		if err := registerFreshHeartbeatSignal(s); err != nil {
			return err
		}
	}
	if s.controlPlane != nil {
		return registerTransportCounterSignals(s)
	}
	return nil
}

func registerFreshHeartbeatSignal(s *Server) error {
	fresh, err := s.healthCollector.Signals().RegisterGauge("cfgms_stewards_heartbeat_fresh",
		"Stewards whose latest heartbeat was received on this controller node within the steward offline timeout.", nil)
	if err != nil {
		return err
	}
	hb := s.heartbeatService
	s.healthCollector.RegisterSampler(func(context.Context) {
		if err := fresh.Set(float64(hb.FreshHeartbeatCount()), nil); err != nil {
			s.logger.Warn("Failed to record fresh heartbeat count", "error", logging.SanitizeLogValue(err.Error()))
		}
	})
	return nil
}

func registerTransportCounterSignals(s *Server) error {
	feeds := []*transportCounterFeed{
		{name: "cfgms_transport_delivery_failures_total", help: "Total message delivery failures on this controller node's control plane transport.",
			read: func(st *controlplaneTypes.ControlPlaneStats) int64 { return st.DeliveryFailures }},
		{name: "cfgms_transport_heartbeats_dropped_total", help: "Total steward heartbeats shed on this controller node's control plane transport.",
			read: func(st *controlplaneTypes.ControlPlaneStats) int64 { return st.HeartbeatsDropped }},
		{name: "cfgms_transport_events_dropped_total", help: "Total steward events shed on this controller node's control plane transport.",
			read: func(st *controlplaneTypes.ControlPlaneStats) int64 { return st.EventsDropped }},
		{name: "cfgms_transport_responses_dropped_total", help: "Total steward responses shed on this controller node's control plane transport.",
			read: func(st *controlplaneTypes.ControlPlaneStats) int64 { return st.ResponsesDropped }},
	}
	for _, f := range feeds {
		counter, err := s.healthCollector.Signals().RegisterCounter(f.name, f.help, nil)
		if err != nil {
			return err
		}
		f.counter = counter
	}

	cp := s.controlPlane
	var mu sync.Mutex // a slow tick's sampler may overlap the next one
	s.healthCollector.RegisterSampler(func(ctx context.Context) {
		stats, err := cp.GetStats(ctx)
		if err != nil {
			s.logger.Warn("Failed to read control plane stats for transport signals",
				"error", logging.SanitizeLogValue(err.Error()))
			return
		}
		if stats == nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, f := range feeds {
			if err := f.advance(f.read(stats)); err != nil {
				s.logger.Warn("Failed to record transport counter",
					"signal", f.name, "error", logging.SanitizeLogValue(err.Error()))
			}
		}
	})
	return nil
}

// advance moves the counter to the provider's current cumulative value. A value
// below the last one means the provider restarted its count, so the new value is
// all activity since that restart.
func (f *transportCounterFeed) advance(current int64) error {
	delta := current - f.last
	if current < f.last {
		delta = current
	}
	f.last = current
	if delta <= 0 {
		return nil
	}
	return f.counter.Add(float64(delta), nil)
}
