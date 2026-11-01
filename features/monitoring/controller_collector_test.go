// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package monitoring_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// stubControllerService is a concrete ControllerService used to drive the
// collector accessors with deterministic probe results.
type stubControllerService struct {
	name       string
	health     monitoring.ServiceHealth
	healthErr  error
	metrics    map[string]interface{}
	metricsErr error
}

func (s *stubControllerService) GetServiceName() string { return s.name }
func (s *stubControllerService) GetServiceHealth(context.Context) (monitoring.ServiceHealth, error) {
	return s.health, s.healthErr
}
func (s *stubControllerService) GetServiceMetrics(context.Context) (map[string]interface{}, error) {
	return s.metrics, s.metricsErr
}

func TestControllerCollector_GetServiceHealth(t *testing.T) {
	ctx := context.Background()
	cc := monitoring.NewControllerCollector(logging.NewNoopLogger())

	checked := time.Now().Add(-time.Minute)
	cc.RegisterService(&stubControllerService{
		name: "storage",
		health: monitoring.ServiceHealth{
			Status: "degraded", Message: "slow queries", LastChecked: checked,
			Details: map[string]interface{}{"path": "/var/lib/cfgms/secret"},
		},
	})

	h, err := cc.GetServiceHealth(ctx, "storage")
	require.NoError(t, err)
	assert.Equal(t, "degraded", h.Status)
	assert.Equal(t, "slow queries", h.Message)
	assert.True(t, h.LastChecked.Equal(checked))
	assert.Nil(t, h.Details, "details must never leave the accessor")
}

func TestControllerCollector_GetServiceHealth_ProbeErrorIsScrubbed(t *testing.T) {
	ctx := context.Background()
	cc := monitoring.NewControllerCollector(logging.NewNoopLogger())
	cc.RegisterService(&stubControllerService{
		name:      "certificate_ca",
		healthErr: errors.New("open /etc/cfgms/ca/ca.key: permission denied (token=s3cr3t-value)"),
	})

	before := time.Now()
	h, err := cc.GetServiceHealth(ctx, "certificate_ca")
	require.NoError(t, err)
	assert.Equal(t, "unhealthy", h.Status)
	assert.Equal(t, monitoring.GenericProbeFailureMessage, h.Message)
	assert.False(t, h.LastChecked.Before(before))
	assert.NotContains(t, h.Message, "/etc/cfgms")
	assert.NotContains(t, h.Message, "s3cr3t")
	assert.Nil(t, h.Details)
}

func TestControllerCollector_GetServiceHealth_Unknown(t *testing.T) {
	cc := monitoring.NewControllerCollector(logging.NewNoopLogger())
	_, err := cc.GetServiceHealth(context.Background(), "nope")
	assert.ErrorIs(t, err, monitoring.ErrServiceNotFound)
}

func TestControllerCollector_GetServiceMetrics(t *testing.T) {
	ctx := context.Background()
	cc := monitoring.NewControllerCollector(logging.NewNoopLogger())
	cc.RegisterService(&stubControllerService{name: "transport", metrics: map[string]interface{}{"connected_stewards": 3}})
	cc.RegisterService(&stubControllerService{name: "storage", metricsErr: errors.New("dial tcp 10.0.0.5:5432: password=hunter2")})

	m, err := cc.GetServiceMetrics(ctx, "transport")
	require.NoError(t, err)
	assert.Equal(t, 3, m["connected_stewards"])

	_, err = cc.GetServiceMetrics(ctx, "missing")
	assert.ErrorIs(t, err, monitoring.ErrServiceNotFound)

	_, err = cc.GetServiceMetrics(ctx, "storage")
	require.ErrorIs(t, err, monitoring.ErrServiceMetricsUnavailable)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.NotContains(t, err.Error(), "10.0.0.5")
}

// TestSystemMonitor_RestartAfterStop proves Stop/Start/Stop does not close the
// shutdown channel twice (the controller server is restarted in-process).
func TestSystemMonitor_RestartAfterStop(t *testing.T) {
	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{ServiceName: "restart-test", Enabled: false})
	require.NoError(t, err)
	t.Cleanup(cleanup)

	mon := monitoring.NewSystemMonitor(logging.NewNoopLogger(), tracer, nil)
	for i := 0; i < 3; i++ {
		require.NoError(t, mon.Start(context.Background()), "start #%d", i)
		require.NoError(t, mon.Stop(context.Background()), "stop #%d", i)
	}
	assert.NoError(t, mon.Stop(context.Background()), "extra Stop is a no-op")
}
