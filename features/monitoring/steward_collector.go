// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 CFGMS Contributors
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// StewardCollector collects metrics from steward management systems.
// This collector interfaces with the controller's steward registry to provide
// system-wide steward health and status information.
type StewardCollector struct {
	logger     logging.Logger
	registry   StewardRegistry
	lastUpdate time.Time
}

// StewardRegistry defines the interface for accessing steward information.
// This interface allows the collector to work with different steward management systems.
type StewardRegistry interface {
	// GetAllStewards returns information about all registered stewards
	GetAllStewards(ctx context.Context) ([]StewardInfo, error)

	// GetStewardHealth returns health information for a specific steward
	GetStewardHealth(ctx context.Context, stewardID string) (*StewardHealth, error)

	// GetRegistryStats returns overall registry statistics
	GetRegistryStats(ctx context.Context) (*RegistryStats, error)
}

// StewardInfo contains information about a registered steward.
type StewardInfo struct {
	ID             string                 `json:"id"`
	Status         string                 `json:"status"` // "connected", "disconnected", "unknown"
	Health         string                 `json:"health"` // "healthy", "degraded", "unhealthy"
	LastSeen       time.Time              `json:"last_seen"`
	Version        string                 `json:"version"`
	TenantID       string                 `json:"tenant_id"`
	ConnectionTime time.Time              `json:"connection_time"`
	Metrics        map[string]interface{} `json:"metrics,omitempty"`
	DNAInfo        map[string]interface{} `json:"dna_info,omitempty"`
}

// StewardHealth contains detailed health information for a steward.
type StewardHealth struct {
	StewardID       string                  `json:"steward_id"`
	OverallHealth   string                  `json:"overall_health"`
	LastHealthCheck time.Time               `json:"last_health_check"`
	HealthDetails   map[string]interface{}  `json:"health_details"`
	ConfigStatus    *ConfigurationStatus    `json:"config_status,omitempty"`
	ResourceMetrics *StewardResourceMetrics `json:"resource_metrics,omitempty"`
}

// ConfigurationStatus contains configuration-related status for a steward.
type ConfigurationStatus struct {
	LastConfigurationApplied time.Time `json:"last_configuration_applied"`
	ConfigurationVersion     string    `json:"configuration_version"`
	ConfigurationErrors      int       `json:"configuration_errors"`
	ConfigurationSuccesses   int       `json:"configuration_successes"`
}

// StewardResourceMetrics contains resource usage metrics from a steward.
type StewardResourceMetrics struct {
	CPUUsage    float64 `json:"cpu_usage"`
	MemoryUsage uint64  `json:"memory_usage"`
	DiskUsage   uint64  `json:"disk_usage"`
	NetworkIO   uint64  `json:"network_io"`
}

// RegistryStats contains overall statistics about the steward registry.
type RegistryStats struct {
	TotalStewards     int            `json:"total_stewards"`
	ConnectedStewards int            `json:"connected_stewards"`
	HealthyStewards   int            `json:"healthy_stewards"`
	DegradedStewards  int            `json:"degraded_stewards"`
	UnhealthyStewards int            `json:"unhealthy_stewards"`
	TenantBreakdown   map[string]int `json:"tenant_breakdown"`
	VersionBreakdown  map[string]int `json:"version_breakdown"`
	Uptime            time.Duration  `json:"uptime"`
	LastUpdated       time.Time      `json:"last_updated"`
}

// NewStewardCollector creates a new steward metrics collector.
func NewStewardCollector(logger logging.Logger, registry StewardRegistry) *StewardCollector {
	return &StewardCollector{
		logger:     logger,
		registry:   registry,
		lastUpdate: time.Now(),
	}
}

// CollectMetrics implements the MetricsCollector interface.
func (sc *StewardCollector) CollectMetrics(ctx context.Context) (map[string]interface{}, error) {
	startTime := time.Now()

	// Get registry statistics
	stats, err := sc.registry.GetRegistryStats(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry stats: %w", err)
	}

	// Get all stewards for detailed metrics
	stewards, err := sc.registry.GetAllStewards(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get stewards: %w", err)
	}

	// Calculate additional metrics
	metrics := map[string]interface{}{
		// Registry statistics
		"total_stewards":     stats.TotalStewards,
		"connected_stewards": stats.ConnectedStewards,
		"healthy_stewards":   stats.HealthyStewards,
		"degraded_stewards":  stats.DegradedStewards,
		"unhealthy_stewards": stats.UnhealthyStewards,
		"tenant_breakdown":   stats.TenantBreakdown,
		"version_breakdown":  stats.VersionBreakdown,
		"registry_uptime":    stats.Uptime.Seconds(),

		// Collection metadata
		"collection_time_ms": time.Since(startTime).Milliseconds(),
		"last_updated":       time.Now(),
		"stewards_count":     len(stewards),
	}

	// Add connection quality metrics
	connectionMetrics := sc.calculateConnectionMetrics(stewards)
	for key, value := range connectionMetrics {
		metrics[key] = value
	}

	// Add health trend metrics
	healthMetrics := sc.calculateHealthMetrics(stewards)
	for key, value := range healthMetrics {
		metrics[key] = value
	}

	sc.lastUpdate = time.Now()

	sc.logger.DebugCtx(ctx, "Steward metrics collected",
		"total_stewards", stats.TotalStewards,
		"connected_stewards", stats.ConnectedStewards,
		"collection_time_ms", time.Since(startTime).Milliseconds())

	return metrics, nil
}

// GetComponentName implements the MetricsCollector interface.
func (sc *StewardCollector) GetComponentName() string {
	return "steward_registry"
}

// GetHealthStatus implements the MetricsCollector interface.
func (sc *StewardCollector) GetHealthStatus(ctx context.Context) (HealthStatus, error) {
	stats, err := sc.registry.GetRegistryStats(ctx)
	if err != nil {
		return HealthStatus{
			Status:      "unhealthy",
			Message:     fmt.Sprintf("Failed to get registry stats: %v", err),
			LastChecked: time.Now(),
		}, nil
	}

	// Determine overall health based on connected stewards
	var status string
	var message string

	if stats.TotalStewards == 0 {
		status = "healthy"
		message = "No stewards registered"
	} else {
		connectedPercent := float64(stats.ConnectedStewards) / float64(stats.TotalStewards) * 100
		healthyPercent := float64(stats.HealthyStewards) / float64(stats.TotalStewards) * 100

		switch {
		case connectedPercent >= 95 && healthyPercent >= 90:
			status = "healthy"
			message = fmt.Sprintf("%.1f%% connected, %.1f%% healthy", connectedPercent, healthyPercent)
		case connectedPercent >= 80 && healthyPercent >= 70:
			status = "degraded"
			message = fmt.Sprintf("%.1f%% connected, %.1f%% healthy", connectedPercent, healthyPercent)
		default:
			status = "unhealthy"
			message = fmt.Sprintf("%.1f%% connected, %.1f%% healthy", connectedPercent, healthyPercent)
		}
	}

	return HealthStatus{
		Status:      status,
		Message:     message,
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"total_stewards":     stats.TotalStewards,
			"connected_stewards": stats.ConnectedStewards,
			"healthy_stewards":   stats.HealthyStewards,
			"degraded_stewards":  stats.DegradedStewards,
			"unhealthy_stewards": stats.UnhealthyStewards,
			"tenant_count":       len(stats.TenantBreakdown),
			"version_count":      len(stats.VersionBreakdown),
		},
	}, nil
}

// calculateConnectionMetrics calculates connection-related metrics.
func (sc *StewardCollector) calculateConnectionMetrics(stewards []StewardInfo) map[string]interface{} {
	if len(stewards) == 0 {
		return map[string]interface{}{
			"avg_connection_duration": 0,
			"connection_stability":    0,
		}
	}

	now := time.Now()
	totalConnectionDuration := time.Duration(0)
	stableConnections := 0

	for _, steward := range stewards {
		if steward.Status == "connected" {
			connectionDuration := now.Sub(steward.ConnectionTime)
			totalConnectionDuration += connectionDuration

			// Consider connections stable if they've been up for more than 5 minutes
			if connectionDuration > 5*time.Minute {
				stableConnections++
			}
		}
	}

	avgDuration := time.Duration(0)
	if len(stewards) > 0 {
		avgDuration = totalConnectionDuration / time.Duration(len(stewards))
	}

	stabilityPercent := float64(0)
	if len(stewards) > 0 {
		stabilityPercent = float64(stableConnections) / float64(len(stewards)) * 100
	}

	return map[string]interface{}{
		"avg_connection_duration_seconds": avgDuration.Seconds(),
		"connection_stability_percent":    stabilityPercent,
		"stable_connections":              stableConnections,
	}
}

// calculateHealthMetrics calculates health-related metrics.
func (sc *StewardCollector) calculateHealthMetrics(stewards []StewardInfo) map[string]interface{} {
	if len(stewards) == 0 {
		return map[string]interface{}{
			"health_score":          100,
			"recent_health_changes": 0,
		}
	}

	healthyCount := 0
	recentChanges := 0
	now := time.Now()

	for _, steward := range stewards {
		if steward.Health == "healthy" {
			healthyCount++
		}

		// Count health changes in the last hour (based on last seen time as proxy)
		if now.Sub(steward.LastSeen) < time.Hour {
			recentChanges++
		}
	}

	healthScore := float64(healthyCount) / float64(len(stewards)) * 100

	return map[string]interface{}{
		"health_score_percent":  healthScore,
		"recent_health_changes": recentChanges,
		"healthy_count":         healthyCount,
	}
}
