// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// ControllerCollector collects metrics from controller services.
// This collector gathers metrics from various controller components including
// configuration services, RBAC systems, and certificate management.
type ControllerCollector struct {
	logger     logging.Logger
	services   map[string]ControllerService
	startTime  time.Time
	lastUpdate time.Time
}

// ControllerService defines the interface for controller service monitoring.
type ControllerService interface {
	// GetServiceMetrics returns current metrics for the service
	GetServiceMetrics(ctx context.Context) (map[string]interface{}, error)

	// GetServiceHealth returns the health status of the service
	GetServiceHealth(ctx context.Context) (ServiceHealth, error)

	// GetServiceName returns the name of the service
	GetServiceName() string
}

// ServiceHealth contains health information for a controller service.
type ServiceHealth struct {
	ServiceName  string                 `json:"service_name"`
	Status       string                 `json:"status"` // "healthy", "degraded", "unhealthy"
	Message      string                 `json:"message"`
	LastChecked  time.Time              `json:"last_checked"`
	ResponseTime time.Duration          `json:"response_time"`
	ErrorRate    float64                `json:"error_rate"`
	Details      map[string]interface{} `json:"details,omitempty"`
}

// ControllerMetrics contains aggregated metrics for the controller.
type ControllerMetrics struct {
	// Service metrics
	ServicesCount     int `json:"services_count"`
	HealthyServices   int `json:"healthy_services"`
	DegradedServices  int `json:"degraded_services"`
	UnhealthyServices int `json:"unhealthy_services"`

	// Request metrics
	TotalRequests       int64         `json:"total_requests"`
	SuccessfulRequests  int64         `json:"successful_requests"`
	FailedRequests      int64         `json:"failed_requests"`
	AverageResponseTime time.Duration `json:"average_response_time"`

	// Configuration metrics
	ConfigurationsManaged int64 `json:"configurations_managed"`
	ConfigurationsSent    int64 `json:"configurations_sent"`
	ConfigurationErrors   int64 `json:"configuration_errors"`

	// RBAC metrics
	ActiveSessions         int64 `json:"active_sessions"`
	AuthenticationRequests int64 `json:"authentication_requests"`
	AuthorizationFailures  int64 `json:"authorization_failures"`

	// Certificate metrics
	CertificatesIssued   int64 `json:"certificates_issued"`
	CertificatesRevoked  int64 `json:"certificates_revoked"`
	CertificatesExpiring int64 `json:"certificates_expiring"`

	// Workflow metrics
	WorkflowsExecuted   int64 `json:"workflows_executed"`
	WorkflowsSuccessful int64 `json:"workflows_successful"`
	WorkflowsFailed     int64 `json:"workflows_failed"`

	// System metrics
	Uptime         time.Duration          `json:"uptime"`
	LastUpdated    time.Time              `json:"last_updated"`
	ServiceMetrics map[string]interface{} `json:"service_metrics"`
}

// NewControllerCollector creates a new controller metrics collector.
func NewControllerCollector(logger logging.Logger) *ControllerCollector {
	return &ControllerCollector{
		logger:     logger,
		services:   make(map[string]ControllerService),
		startTime:  time.Now(),
		lastUpdate: time.Now(),
	}
}

// RegisterService registers a controller service for monitoring.
func (cc *ControllerCollector) RegisterService(service ControllerService) {
	serviceName := service.GetServiceName()
	cc.services[serviceName] = service

	cc.logger.Info("Registered controller service for monitoring",
		"service_name", serviceName)
}

// CollectMetrics implements the MetricsCollector interface.
func (cc *ControllerCollector) CollectMetrics(ctx context.Context) (map[string]interface{}, error) {
	startTime := time.Now()

	metrics := &ControllerMetrics{
		ServicesCount:  len(cc.services),
		Uptime:         time.Since(cc.startTime),
		LastUpdated:    time.Now(),
		ServiceMetrics: make(map[string]interface{}),
	}

	// Collect metrics from each registered service
	for serviceName, service := range cc.services {
		serviceMetrics, err := service.GetServiceMetrics(ctx)
		if err != nil {
			cc.logger.WarnCtx(ctx, "Failed to collect service metrics",
				"service_name", serviceName,
				"error", err)
			continue
		}

		metrics.ServiceMetrics[serviceName] = serviceMetrics

		// Aggregate specific metrics if available
		cc.aggregateServiceMetrics(metrics, serviceName, serviceMetrics)
	}

	// Calculate service health distribution
	cc.calculateServiceHealth(ctx, metrics)

	// Convert to map for interface compliance
	result := map[string]interface{}{
		"services_count":           metrics.ServicesCount,
		"healthy_services":         metrics.HealthyServices,
		"degraded_services":        metrics.DegradedServices,
		"unhealthy_services":       metrics.UnhealthyServices,
		"total_requests":           metrics.TotalRequests,
		"successful_requests":      metrics.SuccessfulRequests,
		"failed_requests":          metrics.FailedRequests,
		"average_response_time_ms": metrics.AverageResponseTime.Milliseconds(),
		"configurations_managed":   metrics.ConfigurationsManaged,
		"configurations_sent":      metrics.ConfigurationsSent,
		"configuration_errors":     metrics.ConfigurationErrors,
		"active_sessions":          metrics.ActiveSessions,
		"authentication_requests":  metrics.AuthenticationRequests,
		"authorization_failures":   metrics.AuthorizationFailures,
		"certificates_issued":      metrics.CertificatesIssued,
		"certificates_revoked":     metrics.CertificatesRevoked,
		"certificates_expiring":    metrics.CertificatesExpiring,
		"workflows_executed":       metrics.WorkflowsExecuted,
		"workflows_successful":     metrics.WorkflowsSuccessful,
		"workflows_failed":         metrics.WorkflowsFailed,
		"uptime_seconds":           metrics.Uptime.Seconds(),
		"last_updated":             metrics.LastUpdated,
		"service_metrics":          metrics.ServiceMetrics,
		"collection_time_ms":       time.Since(startTime).Milliseconds(),
	}

	cc.lastUpdate = time.Now()

	cc.logger.DebugCtx(ctx, "Controller metrics collected",
		"services_count", metrics.ServicesCount,
		"healthy_services", metrics.HealthyServices,
		"collection_time_ms", time.Since(startTime).Milliseconds())

	return result, nil
}

// GetComponentName implements the MetricsCollector interface.
func (cc *ControllerCollector) GetComponentName() string {
	return "controller"
}

// GetHealthStatus implements the MetricsCollector interface.
func (cc *ControllerCollector) GetHealthStatus(ctx context.Context) (HealthStatus, error) {
	healthyCount := 0
	degradedCount := 0
	unhealthyCount := 0
	totalServices := len(cc.services)

	healthDetails := make(map[string]interface{})

	// Check health of each service
	for serviceName, service := range cc.services {
		health, err := service.GetServiceHealth(ctx)
		if err != nil {
			unhealthyCount++
			healthDetails[serviceName] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
			continue
		}

		healthDetails[serviceName] = map[string]interface{}{
			"status":        health.Status,
			"message":       health.Message,
			"response_time": health.ResponseTime.Milliseconds(),
			"error_rate":    health.ErrorRate,
		}

		switch health.Status {
		case "healthy":
			healthyCount++
		case "degraded":
			degradedCount++
		default:
			unhealthyCount++
		}
	}

	// Determine overall controller health
	var status string
	var message string

	if totalServices == 0 {
		status = "healthy"
		message = "No services registered"
	} else {
		healthyPercent := float64(healthyCount) / float64(totalServices) * 100

		switch {
		case healthyPercent >= 100:
			status = "healthy"
			message = "All services healthy"
		case healthyPercent >= 80:
			status = "degraded"
			message = fmt.Sprintf("%.1f%% services healthy", healthyPercent)
		default:
			status = "unhealthy"
			message = fmt.Sprintf("%.1f%% services healthy", healthyPercent)
		}
	}

	return HealthStatus{
		Status:      status,
		Message:     message,
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"total_services":     totalServices,
			"healthy_services":   healthyCount,
			"degraded_services":  degradedCount,
			"unhealthy_services": unhealthyCount,
			"uptime_seconds":     time.Since(cc.startTime).Seconds(),
			"service_health":     healthDetails,
		},
	}, nil
}

// aggregateServiceMetrics aggregates metrics from individual services.
func (cc *ControllerCollector) aggregateServiceMetrics(metrics *ControllerMetrics, serviceName string, serviceMetrics map[string]interface{}) {
	// Helper function to safely extract int64 values
	getInt64 := func(key string) int64 {
		if val, ok := serviceMetrics[key]; ok {
			switch v := val.(type) {
			case int64:
				return v
			case int:
				return int64(v)
			case float64:
				return int64(v)
			}
		}
		return 0
	}

	// Helper function to safely extract duration values
	getDuration := func(key string) time.Duration {
		if val, ok := serviceMetrics[key]; ok {
			switch v := val.(type) {
			case time.Duration:
				return v
			case int64:
				return time.Duration(v) * time.Millisecond
			case float64:
				return time.Duration(v) * time.Millisecond
			}
		}
		return 0
	}

	// Aggregate based on service type
	switch serviceName {
	case "configuration_service":
		metrics.ConfigurationsManaged += getInt64("configurations_managed")
		metrics.ConfigurationsSent += getInt64("configurations_sent")
		metrics.ConfigurationErrors += getInt64("configuration_errors")

	case "rbac_service":
		metrics.ActiveSessions += getInt64("active_sessions")
		metrics.AuthenticationRequests += getInt64("authentication_requests")
		metrics.AuthorizationFailures += getInt64("authorization_failures")

	case "certificate_service":
		metrics.CertificatesIssued += getInt64("certificates_issued")
		metrics.CertificatesRevoked += getInt64("certificates_revoked")
		metrics.CertificatesExpiring += getInt64("certificates_expiring")

	case "workflow_service":
		metrics.WorkflowsExecuted += getInt64("workflows_executed")
		metrics.WorkflowsSuccessful += getInt64("workflows_successful")
		metrics.WorkflowsFailed += getInt64("workflows_failed")
	}

	// Aggregate common request metrics
	metrics.TotalRequests += getInt64("total_requests")
	metrics.SuccessfulRequests += getInt64("successful_requests")
	metrics.FailedRequests += getInt64("failed_requests")

	// Calculate average response time (weighted by request count)
	responseTime := getDuration("average_response_time")
	requestCount := getInt64("total_requests")
	if requestCount > 0 && responseTime > 0 {
		totalTime := metrics.AverageResponseTime * time.Duration(metrics.TotalRequests-requestCount)
		totalTime += responseTime * time.Duration(requestCount)
		metrics.AverageResponseTime = totalTime / time.Duration(metrics.TotalRequests)
	}
}

// calculateServiceHealth calculates the health distribution of services.
func (cc *ControllerCollector) calculateServiceHealth(ctx context.Context, metrics *ControllerMetrics) {
	for _, service := range cc.services {
		health, err := service.GetServiceHealth(ctx)
		if err != nil {
			metrics.UnhealthyServices++
			continue
		}

		switch health.Status {
		case "healthy":
			metrics.HealthyServices++
		case "degraded":
			metrics.DegradedServices++
		default:
			metrics.UnhealthyServices++
		}
	}
}
