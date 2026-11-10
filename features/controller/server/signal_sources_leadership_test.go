// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/pkg/ha"
	"github.com/cfgis/cfgms/pkg/logging"
	teststorage "github.com/cfgis/cfgms/pkg/testing/storage"
)

func newLeadershipTestSignals(t *testing.T) (*health.SignalRegistry, *health.Gauge, *health.Counter) {
	t.Helper()
	reg := health.NewSignalRegistry()
	gauge, err := reg.RegisterGauge("cfgms_has_leadership", "test", nil)
	require.NoError(t, err)
	counter, err := reg.RegisterCounter("cfgms_leadership_changes_total", "test", nil)
	require.NoError(t, err)
	return reg, gauge, counter
}

func scrapeRegistry(t *testing.T, reg *health.SignalRegistry) string {
	t.Helper()
	var sb strings.Builder
	require.NoError(t, reg.WriteText(&sb))
	return sb.String()
}

// TestLeadershipFlipLogic drives the sampler with an injected predicate.
func TestLeadershipFlipLogic(t *testing.T) {
	reg, gauge, counter := newLeadershipTestSignals(t)
	leader := false
	sampler, err := newLeadershipSampler(func() bool { return leader }, gauge, counter)
	require.NoError(t, err)
	ctx := context.Background()

	// No flip: baseline is not counted, repeated samples do not count.
	sampler.sample(ctx)
	sampler.sample(ctx)
	out := scrapeRegistry(t, reg)
	assert.Contains(t, out, "cfgms_has_leadership 0")
	assert.Contains(t, out, "cfgms_leadership_changes_total 0")

	// Gain.
	leader = true
	sampler.sample(ctx)
	sampler.sample(ctx)
	out = scrapeRegistry(t, reg)
	assert.Contains(t, out, "cfgms_has_leadership 1")
	assert.Contains(t, out, "cfgms_leadership_changes_total 1")

	// Loss.
	leader = false
	sampler.sample(ctx)
	out = scrapeRegistry(t, reg)
	assert.Contains(t, out, "cfgms_has_leadership 0")
	assert.Contains(t, out, "cfgms_leadership_changes_total 2")

	// A flip that reverts between two samples is not seen.
	leader = true
	leader = false
	sampler.sample(ctx)
	assert.Contains(t, scrapeRegistry(t, reg), "cfgms_leadership_changes_total 2")
}

// TestLeadershipFlipLogicInitialLeader proves a node that starts as leader
// reports 1 without counting the start as a change.
func TestLeadershipFlipLogicInitialLeader(t *testing.T) {
	reg, gauge, counter := newLeadershipTestSignals(t)
	sampler, err := newLeadershipSampler(func() bool { return true }, gauge, counter)
	require.NoError(t, err)

	out := scrapeRegistry(t, reg)
	assert.Contains(t, out, "cfgms_has_leadership 1")
	sampler.sample(context.Background())
	out = scrapeRegistry(t, reg)
	assert.Contains(t, out, "cfgms_has_leadership 1")
	assert.Contains(t, out, "cfgms_leadership_changes_total 0")
}

// TestSingleServerLeadershipGauge: with no HA manager the gauge is 1 and the
// counter stays 0 across sampler ticks.
func TestSingleServerLeadershipGauge(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	require.Nil(t, srv.haManager)
	require.NoError(t, registerLeadershipSignals(srv))

	out := scrapeSignals(t, srv)
	assert.Contains(t, out, "# TYPE cfgms_has_leadership gauge")
	assert.Contains(t, out, "# TYPE cfgms_leadership_changes_total counter")
	assert.Contains(t, out, "cfgms_has_leadership 1")
	assert.Contains(t, out, "cfgms_leadership_changes_total 0")

	require.NoError(t, srv.healthCollector.Start(context.Background(), 10*time.Millisecond))
	t.Cleanup(srv.stopHealthServices)
	time.Sleep(100 * time.Millisecond)
	out = scrapeSignals(t, srv)
	assert.Contains(t, out, "cfgms_has_leadership 1")
	assert.Contains(t, out, "cfgms_leadership_changes_total 0")
}

// TestLeadershipSourceIsRegistered proves the init()-time registration puts the
// source on the list startHealthServices runs.
func TestLeadershipSourceIsRegistered(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	assert.Equal(t, 0, srv.runSignalSources())
	assert.Contains(t, scrapeSignals(t, srv), "cfgms_has_leadership 1")
}

// TestLeadershipRegistrationFailure: a name clash is reported, not swallowed.
func TestLeadershipRegistrationFailure(t *testing.T) {
	srv := newSignalSourceTestServer(t)
	require.NoError(t, registerLeadershipSignals(srv))
	assert.Error(t, registerLeadershipSignals(srv))
}

// TestLeadershipWithRealHAManager binds the source to a real ha.Manager.
func TestLeadershipWithRealHAManager(t *testing.T) {
	storageManager, err := teststorage.CreateTestStorageManager()
	require.NoError(t, err)
	cfg := ha.DefaultConfig()
	cfg.Mode = ha.SingleServerMode
	cfg.Node.ID = "leadership-node-0001"
	manager, err := ha.NewManager(cfg, logging.NewNoopLogger(), storageManager)
	require.NoError(t, err)

	srv := newSignalSourceTestServer(t)
	srv.haManager = manager
	require.NoError(t, registerLeadershipSignals(srv))

	out := scrapeSignals(t, srv)
	assert.Equal(t, manager.HasLeadership(), strings.Contains(out, "cfgms_has_leadership 1"))
	assert.Contains(t, out, "cfgms_has_leadership 1")
	assert.Contains(t, out, "cfgms_leadership_changes_total 0")

	require.NoError(t, srv.healthCollector.Start(context.Background(), 10*time.Millisecond))
	t.Cleanup(srv.stopHealthServices)
	time.Sleep(100 * time.Millisecond)
	out = scrapeSignals(t, srv)
	assert.Contains(t, out, "cfgms_has_leadership 1")
	assert.Contains(t, out, "cfgms_leadership_changes_total 0")
}
