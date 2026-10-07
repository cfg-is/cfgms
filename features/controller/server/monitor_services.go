// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package server

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/features/controller/health"
	"github.com/cfgis/cfgms/features/monitoring"
	"github.com/cfgis/cfgms/features/rbac"
	"github.com/cfgis/cfgms/pkg/cert"
	controlplaneInterfaces "github.com/cfgis/cfgms/pkg/controlplane/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// Component names served by the monitoring component endpoints. They match the
// names handleBasicSystemHealth renders.
const (
	componentGRPCServer    = "grpc_server"
	componentStorage       = "storage"
	componentCertificateCA = "certificate_ca"
	componentRBACService   = "rbac_service"
	componentTransport     = "transport"
)

const (
	// errorRateDegradedThreshold is the error fraction above which transport and
	// storage report "degraded".
	errorRateDegradedThreshold = 0.05
	// slowQueryLatencyMs is the average query latency above which storage reports "degraded".
	slowQueryLatencyMs = 1000.0
	// caExpiryWarning is the remaining CA lifetime below which the CA reports "degraded".
	caExpiryWarning = 30 * 24 * time.Hour
	// rbacProbeTimeout bounds the RBAC no-op check.
	rbacProbeTimeout = 5 * time.Second
	// rbacProbeTenant is a tenant ID that owns no roles; listing its roles is a
	// read-only check that the RBAC manager and its store are answering.
	rbacProbeTenant = "__monitor_probe__"
)

// probeResult is what a service probe reports on success.
type probeResult struct {
	status  string
	message string
	metrics map[string]interface{}
}

// monitorService adapts a probe function to monitoring.ControllerService.
type monitorService struct {
	name  string
	probe func(ctx context.Context) (probeResult, error)
}

var _ monitoring.ControllerService = (*monitorService)(nil)

func (m *monitorService) GetServiceName() string { return m.name }

func (m *monitorService) GetServiceHealth(ctx context.Context) (monitoring.ServiceHealth, error) {
	start := time.Now()
	res, err := m.probe(ctx)
	if err != nil {
		return monitoring.ServiceHealth{}, err
	}
	return monitoring.ServiceHealth{
		ServiceName:  m.name,
		Status:       res.status,
		Message:      res.message,
		LastChecked:  time.Now(),
		ResponseTime: time.Since(start),
	}, nil
}

func (m *monitorService) GetServiceMetrics(ctx context.Context) (map[string]interface{}, error) {
	res, err := m.probe(ctx)
	if err != nil {
		return nil, err
	}
	return res.metrics, nil
}

// monitorDeps are the live controller components the service probes read.
// Any may be nil; a nil dependency reports its component unhealthy (not configured).
type monitorDeps struct {
	healthCollector *health.Collector
	controlPlane    controlplaneInterfaces.ControlPlaneProvider
	certManager     *cert.Manager
	rbacManager     *rbac.Manager
}

// newControllerMonitor builds a SystemMonitor whose controller collector holds
// one real-probe service per component name. The caller starts and stops it.
func newControllerMonitor(logger logging.Logger, deps monitorDeps) (*monitoring.SystemMonitor, error) {
	tracer, _, err := telemetry.Initialize(context.Background(), &telemetry.Config{
		ServiceName: "cfgms-controller-monitor",
		Enabled:     false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize monitor tracer: %w", err)
	}

	collector := monitoring.NewControllerCollector(logger)
	for _, svc := range newMonitorServices(deps) {
		collector.RegisterService(svc)
	}

	monitor := monitoring.NewSystemMonitor(logger, tracer, nil)
	monitor.RegisterCollector(collector.GetComponentName(), collector)
	return monitor, nil
}

func newMonitorServices(d monitorDeps) []monitoring.ControllerService {
	return []monitoring.ControllerService{
		&monitorService{name: componentGRPCServer, probe: d.probeGRPCServer},
		&monitorService{name: componentStorage, probe: d.probeStorage},
		&monitorService{name: componentCertificateCA, probe: d.probeCertificateCA},
		&monitorService{name: componentRBACService, probe: d.probeRBAC},
		&monitorService{name: componentTransport, probe: d.probeTransport},
	}
}

// notConfigured reports a component that is absent from this controller. The
// message is fixed text, so it is safe to serve; only real probe failures go
// through the error path (and are scrubbed by the collector).
func notConfigured(message string) probeResult {
	return probeResult{
		status:  "unhealthy",
		message: message,
		metrics: map[string]interface{}{"configured": false},
	}
}

// currentHealthMetrics returns the health collector's latest snapshot, or a
// ready-made result when there is none to read yet.
func (d monitorDeps) currentHealthMetrics() (*health.ControllerMetrics, *probeResult) {
	if d.healthCollector == nil {
		r := notConfigured("Health collector not configured")
		return nil, &r
	}
	m, err := d.healthCollector.GetCurrentMetrics()
	if err != nil {
		return nil, &probeResult{
			status:  "degraded",
			message: "Health metrics not collected yet",
			metrics: map[string]interface{}{"collected": false},
		}
	}
	return m, nil
}

func (d monitorDeps) probeGRPCServer(ctx context.Context) (probeResult, error) {
	if d.controlPlane == nil {
		return notConfigured("gRPC server not configured"), nil
	}
	listening := d.controlPlane.IsConnected()
	res := probeResult{metrics: map[string]interface{}{"listening": listening}}
	if stats, err := d.controlPlane.GetStats(ctx); err == nil && stats != nil {
		res.metrics["connected_stewards"] = stats.ConnectedStewards
		res.metrics["uptime_seconds"] = stats.Uptime.Seconds()
	}
	if listening {
		res.status, res.message = "healthy", "gRPC server is listening"
	} else {
		res.status, res.message = "unhealthy", "gRPC server is not listening"
	}
	return res, nil
}

func (d monitorDeps) probeTransport(context.Context) (probeResult, error) {
	m, early := d.currentHealthMetrics()
	if early != nil {
		return *early, nil
	}
	if m.Transport == nil {
		return notConfigured("Transport not configured"), nil
	}
	t := m.Transport
	res := probeResult{metrics: map[string]interface{}{
		"connected_stewards":    t.ConnectedStewards,
		"stream_errors":         t.StreamErrors,
		"messages_sent":         t.MessagesSent,
		"messages_received":     t.MessagesReceived,
		"reconnection_attempts": t.ReconnectionAttempts,
		"avg_latency_ms":        t.AvgLatency.Milliseconds(),
	}}
	total := t.MessagesSent + t.MessagesReceived
	switch {
	case total > 0 && float64(t.StreamErrors)/float64(total) > errorRateDegradedThreshold:
		res.status, res.message = "degraded", "Elevated transport stream error rate"
	case t.ConnectedStewards == 0:
		res.status, res.message = "healthy", "Transport running, no stewards connected"
	default:
		res.status, res.message = "healthy", fmt.Sprintf("%d steward(s) connected", t.ConnectedStewards)
	}
	return res, nil
}

func (d monitorDeps) probeStorage(context.Context) (probeResult, error) {
	m, early := d.currentHealthMetrics()
	if early != nil {
		return *early, nil
	}
	if m.Storage == nil || m.Storage.Provider == "" {
		return notConfigured("Storage provider not reporting"), nil
	}
	s := m.Storage
	res := probeResult{metrics: map[string]interface{}{
		"provider":             s.Provider,
		"total_queries":        s.TotalQueries,
		"query_errors":         s.QueryErrors,
		"avg_query_latency_ms": s.AvgQueryLatencyMs,
		"p95_query_latency_ms": s.P95QueryLatencyMs,
		"slow_query_count":     s.SlowQueryCount,
	}}
	switch {
	case s.TotalQueries < 0 || s.QueryErrors < 0:
		// -1 sentinel: the provider does not instrument query metrics.
		res.status, res.message = "healthy", "Storage provider active, query metrics not instrumented"
	case s.TotalQueries > 0 && float64(s.QueryErrors)/float64(s.TotalQueries) > errorRateDegradedThreshold:
		res.status, res.message = "degraded", "Elevated storage query error rate"
	case s.AvgQueryLatencyMs > slowQueryLatencyMs:
		res.status, res.message = "degraded", "High storage query latency"
	default:
		res.status, res.message = "healthy", "Storage queries succeeding"
	}
	return res, nil
}

func (d monitorDeps) probeCertificateCA(context.Context) (probeResult, error) {
	if d.certManager == nil {
		return notConfigured("Certificate manager not configured"), nil
	}
	caPEM, err := d.certManager.GetCACertificate()
	if err != nil {
		return probeResult{}, fmt.Errorf("load CA: %w", err)
	}
	ca, err := cert.ParseCertificateFromPEM(caPEM)
	if err != nil {
		return probeResult{}, fmt.Errorf("parse CA: %w", err)
	}

	remaining := time.Until(ca.NotAfter)
	res := probeResult{metrics: map[string]interface{}{
		"expires_in_days": int64(remaining.Hours() / 24),
		"not_after":       ca.NotAfter.UTC(),
	}}
	switch {
	case remaining <= 0:
		res.status, res.message = "unhealthy", "Certificate authority has expired"
	case remaining < caExpiryWarning:
		res.status, res.message = "degraded", "Certificate authority expires soon"
	default:
		res.status, res.message = "healthy", "Certificate authority loaded"
	}
	return res, nil
}

func (d monitorDeps) probeRBAC(ctx context.Context) (probeResult, error) {
	if d.rbacManager == nil {
		return notConfigured("RBAC manager not configured"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, rbacProbeTimeout)
	defer cancel()

	start := time.Now()
	if _, err := d.rbacManager.ListRoles(ctx, rbacProbeTenant); err != nil {
		return probeResult{}, fmt.Errorf("rbac check: %w", err)
	}
	elapsed := time.Since(start)
	return probeResult{
		status:  "healthy",
		message: "RBAC manager responding",
		metrics: map[string]interface{}{"check_latency_ms": elapsed.Milliseconds()},
	}, nil
}
