// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// probeService is a ControllerService with a fixed probe outcome.
type probeService struct {
	name       string
	health     monitoring.ServiceHealth
	healthErr  error
	metrics    map[string]interface{}
	metricsErr error
}

func (p *probeService) GetServiceName() string { return p.name }
func (p *probeService) GetServiceHealth(context.Context) (monitoring.ServiceHealth, error) {
	return p.health, p.healthErr
}
func (p *probeService) GetServiceMetrics(context.Context) (map[string]interface{}, error) {
	return p.metrics, p.metricsErr
}

// serverWithMonitor returns a Server whose systemMonitor is a real SystemMonitor
// with a real ControllerCollector holding the given services.
func serverWithMonitor(t *testing.T, services ...monitoring.ControllerService) *Server {
	t.Helper()
	srv := setupTestServer(t)

	tracer, cleanup, err := telemetry.Initialize(context.Background(), &telemetry.Config{ServiceName: "monitoring-handler-test", Enabled: false})
	require.NoError(t, err)
	t.Cleanup(cleanup)

	cc := monitoring.NewControllerCollector(logging.NewNoopLogger())
	for _, svc := range services {
		cc.RegisterService(svc)
	}
	mon := monitoring.NewSystemMonitor(logging.NewNoopLogger(), tracer, nil)
	mon.RegisterCollector(cc.GetComponentName(), cc)
	srv.systemMonitor = mon
	return srv
}

func callComponent(t *testing.T, h http.HandlerFunc, component string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/monitoring/components/x", nil)
	req = mux.SetURLVars(req, map[string]string{"component": component})
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestMonitoringComponentHealth_KnownComponents(t *testing.T) {
	names := []string{"grpc_server", "storage", "certificate_ca", "rbac_service", "transport"}
	var svcs []monitoring.ControllerService
	checked := time.Now().Add(-30 * time.Second).UTC().Truncate(time.Second)
	for _, n := range names {
		svcs = append(svcs, &probeService{name: n, health: monitoring.ServiceHealth{
			Status: "degraded", Message: n + " message", LastChecked: checked,
			Details: map[string]interface{}{"internal": "/var/lib/cfgms/x"},
		}})
	}
	srv := serverWithMonitor(t, svcs...)

	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			rec := callComponent(t, srv.handleMonitoringComponentHealth, n)
			require.Equal(t, http.StatusOK, rec.Code)

			var body struct {
				Data map[string]interface{} `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, "degraded", body.Data["status"])
			assert.Equal(t, n+" message", body.Data["message"])
			assert.Equal(t, checked.Format(time.RFC3339), body.Data["last_checked"])
			assert.Len(t, body.Data, 3, "response must carry only status, message, last_checked")
			assert.NotContains(t, rec.Body.String(), "/var/lib/cfgms")
		})
	}
}

func TestMonitoringComponentHealth_ProbeErrorNeverLeaks(t *testing.T) {
	srv := serverWithMonitor(t, &probeService{
		name:      "storage",
		healthErr: errors.New("open /var/lib/cfgms/secrets/db.key: permission denied; password=hunter2"),
	})

	rec := callComponent(t, srv.handleMonitoringComponentHealth, "storage")
	require.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.NotContains(t, body, "/var/lib/cfgms")
	assert.NotContains(t, body, "hunter2")
	assert.NotContains(t, body, "permission denied")
	assert.Contains(t, body, monitoring.GenericProbeFailureMessage)
	assert.Contains(t, body, `"unhealthy"`)
}

func TestMonitoringComponentHealth_UnknownIs404(t *testing.T) {
	srv := serverWithMonitor(t, &probeService{name: "storage", health: monitoring.ServiceHealth{Status: "healthy"}})

	rec := callComponent(t, srv.handleMonitoringComponentHealth, "no_such_component")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.NotContains(t, rec.Body.String(), "no_such_component")

	rec = callComponent(t, srv.handleMonitoringComponentMetrics, "no_such_component")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMonitoringComponentMetrics(t *testing.T) {
	srv := serverWithMonitor(t,
		&probeService{name: "transport", metrics: map[string]interface{}{"connected_stewards": 4}},
		&probeService{name: "storage", metricsErr: errors.New("dial tcp 10.1.2.3:5432: password=hunter2")},
	)

	rec := callComponent(t, srv.handleMonitoringComponentMetrics, "transport")
	require.Equal(t, http.StatusOK, rec.Code)
	var body struct {
		Data map[string]interface{} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.EqualValues(t, 4, body.Data["connected_stewards"])

	rec = callComponent(t, srv.handleMonitoringComponentMetrics, "storage")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotContains(t, rec.Body.String(), "hunter2")
	assert.NotContains(t, rec.Body.String(), "10.1.2.3")
}

func TestMonitoringComponent_NoMonitorIs503WithoutStubMessage(t *testing.T) {
	srv := setupTestServer(t)
	srv.systemMonitor = nil

	for _, h := range []http.HandlerFunc{srv.handleMonitoringComponentHealth, srv.handleMonitoringComponentMetrics} {
		rec := callComponent(t, h, "storage")
		assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.NotContains(t, rec.Body.String(), "Platform monitor not initialized")
	}
}

func TestMonitoringComponent_MissingNameIs400(t *testing.T) {
	srv := serverWithMonitor(t)
	assert.Equal(t, http.StatusBadRequest, callComponent(t, srv.handleMonitoringComponentHealth, "").Code)
	assert.Equal(t, http.StatusBadRequest, callComponent(t, srv.handleMonitoringComponentMetrics, "").Code)
}
