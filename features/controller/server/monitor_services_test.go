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
	"go.uber.org/goleak"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/pkg/logging"
)

var monitorComponentNames = []string{
	componentGRPCServer, componentStorage, componentCertificateCA, componentRBACService, componentTransport,
}

func controllerCollectorOf(t *testing.T, srv *Server) *monitoring.ControllerCollector {
	t.Helper()
	require.NotNil(t, srv.systemMonitor, "server must construct a system monitor")
	c, ok := srv.systemMonitor.GetCollector("controller")
	require.True(t, ok, "monitor must register the controller collector")
	cc, ok := c.(*monitoring.ControllerCollector)
	require.True(t, ok)
	return cc
}

// TestMonitor_RealProbesForAllFiveComponents starts a real controller and checks
// each UI component name resolves to a real, populated health result.
func TestMonitor_RealProbesForAllFiveComponents(t *testing.T) {
	srv := newStartableWiredEntityGraphTestServer(t, logging.NewNoopLogger())
	require.NoError(t, srv.Start())
	cc := controllerCollectorOf(t, srv)

	// transport/storage read the health collector's snapshot, populated by its
	// first collection after Start.
	require.Eventually(t, func() bool {
		_, err := srv.healthCollector.GetCurrentMetrics()
		return err == nil
	}, 10*time.Second, 50*time.Millisecond)

	ctx := context.Background()
	for _, name := range monitorComponentNames {
		t.Run(name, func(t *testing.T) {
			h, err := cc.GetServiceHealth(ctx, name)
			require.NoError(t, err)
			assert.Contains(t, []string{"healthy", "degraded", "unhealthy"}, h.Status)
			assert.NotEmpty(t, h.Message)
			assert.WithinDuration(t, time.Now(), h.LastChecked, time.Minute)
			assert.NotEqual(t, monitoring.GenericProbeFailureMessage, h.Message, "probe must succeed against a healthy controller")

			m, err := cc.GetServiceMetrics(ctx, name)
			require.NoError(t, err)
			assert.NotEmpty(t, m)
		})
	}

	for _, name := range []string{componentCertificateCA, componentRBACService} {
		h, err := cc.GetServiceHealth(ctx, name)
		require.NoError(t, err)
		assert.Equal(t, "healthy", h.Status, name)
	}

	_, err := cc.GetServiceHealth(ctx, "not_a_component")
	assert.ErrorIs(t, err, monitoring.ErrServiceNotFound)
}

// TestMonitor_MissingDependenciesReportNotConfigured proves a controller built
// without a component reports it unhealthy with fixed text rather than failing.
func TestMonitor_MissingDependenciesReportNotConfigured(t *testing.T) {
	mon, err := newControllerMonitor(logging.NewNoopLogger(), monitorDeps{})
	require.NoError(t, err)
	c, ok := mon.GetCollector("controller")
	require.True(t, ok)
	cc := c.(*monitoring.ControllerCollector)

	for _, name := range monitorComponentNames {
		h, err := cc.GetServiceHealth(context.Background(), name)
		require.NoError(t, err)
		assert.Equal(t, "unhealthy", h.Status, name)
		assert.NotEmpty(t, h.Message, name)
		assert.NotEqual(t, monitoring.GenericProbeFailureMessage, h.Message, name)
	}
}

// TestMonitor_StartsAndStopsWithoutLeaks covers the monitor lifecycle on its own:
// every goroutine Start launches is gone after Stop.
func TestMonitor_StartsAndStopsWithoutLeaks(t *testing.T) {
	existing := goleak.IgnoreCurrent()
	t.Cleanup(func() { goleak.VerifyNone(t, existing) })

	mon, err := newControllerMonitor(logging.NewNoopLogger(), monitorDeps{})
	require.NoError(t, err)
	require.NoError(t, mon.Start(context.Background()))
	require.NoError(t, mon.Stop(context.Background()))
}

// TestMonitor_StartsAndStopsWithServer covers the wiring: Server.Start launches
// the monitor and Server.Stop ends every goroutine it owns.
func TestMonitor_StartsAndStopsWithServer(t *testing.T) {
	existing := goleak.IgnoreCurrent()

	srv := newStartableWiredEntityGraphTestServer(t, logging.NewNoopLogger())
	require.NoError(t, srv.Start())

	// Start populates the monitor's resource snapshot synchronously, so a
	// non-zero timestamp proves the monitor was started by Server.Start.
	assert.False(t, srv.systemMonitor.GetResourceMetrics().CollectedAt.IsZero())

	require.NoError(t, srv.Stop())

	// The rest of the server has its own teardown coverage; scope this assertion
	// to the monitor's goroutines.
	require.Eventually(t, func() bool {
		err := goleak.Find(existing)
		return err == nil || !strings.Contains(err.Error(), "monitoring.(*SystemMonitor)")
	}, 5*time.Second, 50*time.Millisecond, "monitor goroutines must exit after Server.Stop")
}
