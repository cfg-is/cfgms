// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"fmt"
	"sync"

	"github.com/cfgis/cfgms/features/controller/health"
)

func init() { registerSignalSource(registerLeadershipSignals) }

// leadershipSampler turns a leadership predicate into two signals:
// cfgms_has_leadership (current value) and cfgms_leadership_changes_total (one
// increment per observed flip). It only sees the predicate at sampler ticks, so
// resolution is the collector interval; a flip that reverts inside one interval
// is not observed.
type leadershipSampler struct {
	has     func() bool
	gauge   *health.Gauge
	changes *health.Counter

	mu   sync.Mutex
	last bool
}

// newLeadershipSampler records the predicate's current value as the baseline,
// so the first sample after start is not counted as a change.
func newLeadershipSampler(has func() bool, gauge *health.Gauge, changes *health.Counter) (*leadershipSampler, error) {
	l := &leadershipSampler{has: has, gauge: gauge, changes: changes, last: has()}
	if err := gauge.Set(boolGauge(l.last), nil); err != nil {
		return nil, fmt.Errorf("set cfgms_has_leadership: %w", err)
	}
	// Add(0) materialises the series so the counter scrapes as 0 before the
	// first change instead of being absent.
	if err := changes.Add(0, nil); err != nil {
		return nil, fmt.Errorf("init cfgms_leadership_changes_total: %w", err)
	}
	return l, nil
}

func boolGauge(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// sample is the collector sampler hook.
func (l *leadershipSampler) sample(context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.has()
	if now != l.last {
		_ = l.changes.Inc(nil)
		l.last = now
	}
	_ = l.gauge.Set(boolGauge(now), nil)
}

// registerLeadershipSignals exports cfgms_has_leadership and
// cfgms_leadership_changes_total. The predicate is haManager.HasLeadership, the
// lease-backed authority primitive; the raw Raft flags are never read. With no
// HA manager the node is the only controller and always authoritative: the gauge
// is 1 and the counter stays 0.
func registerLeadershipSignals(s *Server) error {
	signals := s.healthCollector.Signals()

	gauge, err := signals.RegisterGauge("cfgms_has_leadership",
		"1 when this controller holds cluster leadership (lease-backed), 0 otherwise.", nil)
	if err != nil {
		return fmt.Errorf("register cfgms_has_leadership: %w", err)
	}
	changes, err := signals.RegisterCounter("cfgms_leadership_changes_total",
		"Leadership changes observed on this controller at the sampler interval; a change that reverts within one interval is not counted.", nil)
	if err != nil {
		return fmt.Errorf("register cfgms_leadership_changes_total: %w", err)
	}

	has := func() bool { return true }
	if s.haManager != nil {
		has = s.haManager.HasLeadership
	}
	sampler, err := newLeadershipSampler(has, gauge, changes)
	if err != nil {
		return err
	}
	s.healthCollector.RegisterSampler(sampler.sample)
	return nil
}
