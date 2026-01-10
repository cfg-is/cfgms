// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
// Package monitoring provides internal platform monitoring interfaces and types.
//
// This package defines the core interfaces for comprehensive platform monitoring
// including health checks, performance telemetry, and anomaly detection across
// Controller, Steward, and Outpost components.
package monitoring

import (
	"context"
	"time"
)

// PlatformMonitor provides comprehensive internal monitoring for CFGMS components.
type PlatformMonitor interface {
	// Component health monitoring
	RegisterHealthChecker(component string, checker HealthChecker) error
	GetComponentHealth(ctx context.Context, component string) (*ComponentHealth, error)
	GetSystemHealth(ctx context.Context) (*SystemHealth, error)

	// Performance telemetry
	RegisterMetricsCollector(component string, collector MetricsCollector) error
	GetComponentMetrics(ctx context.Context, component string) (*ComponentMetrics, error)
	GetSystemMetrics(ctx context.Context) (*SystemMetrics, error)

	// Anomaly detection
	RegisterAnomalyDetector(component string, detector AnomalyDetector) error
	GetAnomalies(ctx context.Context) ([]*Anomaly, error)

	// Lifecycle management
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool
}

// HealthChecker performs health checks on system components.
type HealthChecker interface {
	CheckHealth(ctx context.Context) (*ComponentHealth, error)
	GetHealthEndpoints(ctx context.Context) ([]HealthEndpoint, error)
}

// MetricsCollector collects performance and operational metrics.
type MetricsCollector interface {
	CollectMetrics(ctx context.Context) (*ComponentMetrics, error)
	GetMetricsSchema() MetricsSchema
}

// AnomalyDetector detects unusual patterns in component behavior.
type AnomalyDetector interface {
	DetectAnomalies(ctx context.Context, metrics *ComponentMetrics) ([]*Anomaly, error)
	GetDetectionRules() []DetectionRule
	UpdateDetectionRules(rules []DetectionRule) error
}

// SystemHealth represents the overall system health status.
type SystemHealth struct {
	Status     HealthStatus                `json:"status"`
	Timestamp  time.Time                   `json:"timestamp"`
	Components map[string]*ComponentHealth `json:"components"`
	Summary    HealthSummary               `json:"summary"`
	Uptime     time.Duration               `json:"uptime"`
	Version    string                      `json:"version"`
}

// ComponentHealth represents the health status of a specific component.
type ComponentHealth struct {
	ComponentName string                 `json:"component_name"`
	Status        HealthStatus           `json:"status"`
	Timestamp     time.Time              `json:"timestamp"`
	Message       string                 `json:"message,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Dependencies  []DependencyHealth     `json:"dependencies,omitempty"`
	Metrics       *ComponentMetrics      `json:"metrics,omitempty"`
	LastCheck     time.Time              `json:"last_check"`
}

// HealthStatus represents the health state of a component.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusUnknown   HealthStatus = "unknown"
)

// HealthSummary provides aggregated health information.
type HealthSummary struct {
	TotalComponents   int                  `json:"total_components"`
	HealthyComponents int                  `json:"healthy_components"`
	StatusCounts      map[HealthStatus]int `json:"status_counts"`
	CriticalIssues    []string             `json:"critical_issues,omitempty"`
}

// DependencyHealth represents the health of a component dependency.
type DependencyHealth struct {
	Name      string       `json:"name"`
	Status    HealthStatus `json:"status"`
	Message   string       `json:"message,omitempty"`
	Timestamp time.Time    `json:"timestamp"`
}

// HealthEndpoint represents a health check endpoint.
type HealthEndpoint struct {
	Name           string            `json:"name"`
	URL            string            `json:"url"`
	Method         string            `json:"method"`
	Headers        map[string]string `json:"headers,omitempty"`
	Timeout        time.Duration     `json:"timeout"`
	ExpectedStatus int               `json:"expected_status"`
}

// SystemMetrics represents aggregated metrics across all components.
type SystemMetrics struct {
	Timestamp   time.Time                    `json:"timestamp"`
	Components  map[string]*ComponentMetrics `json:"components"`
	Aggregated  *AggregatedMetrics           `json:"aggregated"`
	Performance *PerformanceMetrics          `json:"performance"`
}

// ComponentMetrics represents metrics for a specific component.
type ComponentMetrics struct {
	ComponentName string                 `json:"component_name"`
	Timestamp     time.Time              `json:"timestamp"`
	Performance   *PerformanceMetrics    `json:"performance"`
	Resource      *ResourceMetrics       `json:"resource"`
	Business      map[string]interface{} `json:"business,omitempty"`
	Custom        map[string]interface{} `json:"custom,omitempty"`
}

// PerformanceMetrics represents performance-related metrics.
type PerformanceMetrics struct {
	ResponseTime      time.Duration `json:"response_time"`
	Throughput        float64       `json:"throughput"`
	ErrorRate         float64       `json:"error_rate"`
	SuccessRate       float64       `json:"success_rate"`
	RequestCount      int64         `json:"request_count"`
	ActiveConnections int64         `json:"active_connections"`
}

// ResourceMetrics represents system resource utilization metrics.
type ResourceMetrics struct {
	CPUPercent      float64 `json:"cpu_percent"`
	MemoryBytes     int64   `json:"memory_bytes"`
	MemoryPercent   float64 `json:"memory_percent"`
	DiskBytes       int64   `json:"disk_bytes"`
	DiskPercent     float64 `json:"disk_percent"`
	NetworkBytesIn  int64   `json:"network_bytes_in"`
	NetworkBytesOut int64   `json:"network_bytes_out"`
	Goroutines      int     `json:"goroutines"`
	FileDescriptors int     `json:"file_descriptors"`
}

// AggregatedMetrics represents system-wide aggregated metrics.
type AggregatedMetrics struct {
	TotalRequests       int64            `json:"total_requests"`
	AverageResponseTime time.Duration    `json:"average_response_time"`
	SystemErrorRate     float64          `json:"system_error_rate"`
	TotalThroughput     float64          `json:"total_throughput"`
	ResourceUtilization *ResourceMetrics `json:"resource_utilization"`
}

// MetricsSchema defines the structure and metadata for component metrics.
type MetricsSchema struct {
	ComponentName string                      `json:"component_name"`
	Fields        map[string]MetricsFieldSpec `json:"fields"`
	Version       string                      `json:"version"`
}

// MetricsFieldSpec defines specification for a metrics field.
type MetricsFieldSpec struct {
	Type        string      `json:"type"`
	Description string      `json:"description"`
	Unit        string      `json:"unit,omitempty"`
	Min         interface{} `json:"min,omitempty"`
	Max         interface{} `json:"max,omitempty"`
}

// Anomaly represents a detected anomaly in system behavior.
type Anomaly struct {
	ID            string                 `json:"id"`
	ComponentName string                 `json:"component_name"`
	Type          AnomalyType            `json:"type"`
	Severity      AnomalySeverity        `json:"severity"`
	Title         string                 `json:"title"`
	Description   string                 `json:"description"`
	DetectedAt    time.Time              `json:"detected_at"`
	ResolvedAt    *time.Time             `json:"resolved_at,omitempty"`
	Status        AnomalyStatus          `json:"status"`
	Metrics       *ComponentMetrics      `json:"metrics,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
	Actions       []string               `json:"actions,omitempty"`
}

// AnomalyType represents different types of anomalies.
type AnomalyType string

const (
	AnomalyTypePerformance AnomalyType = "performance"
	AnomalyTypeResource    AnomalyType = "resource"
	AnomalyTypeError       AnomalyType = "error"
	AnomalyTypeBehavioral  AnomalyType = "behavioral"
)

// AnomalySeverity represents the severity level of an anomaly.
type AnomalySeverity string

const (
	AnomalySeverityLow      AnomalySeverity = "low"
	AnomalySeverityMedium   AnomalySeverity = "medium"
	AnomalySeverityHigh     AnomalySeverity = "high"
	AnomalySeverityCritical AnomalySeverity = "critical"
)

// AnomalyStatus represents the current status of an anomaly.
type AnomalyStatus string

const (
	AnomalyStatusActive   AnomalyStatus = "active"
	AnomalyStatusResolved AnomalyStatus = "resolved"
	AnomalyStatusIgnored  AnomalyStatus = "ignored"
)

// DetectionRule defines rules for anomaly detection.
type DetectionRule struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      AnomalyType            `json:"type"`
	Metric    string                 `json:"metric"`
	Condition string                 `json:"condition"`
	Threshold float64                `json:"threshold"`
	Duration  time.Duration          `json:"duration"`
	Severity  AnomalySeverity        `json:"severity"`
	Enabled   bool                   `json:"enabled"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// MonitoringConfig represents configuration for the monitoring system.
type MonitoringConfig struct {
	// Health check intervals
	HealthCheckInterval       time.Duration `json:"health_check_interval" yaml:"health_check_interval"`
	MetricsCollectionInterval time.Duration `json:"metrics_collection_interval" yaml:"metrics_collection_interval"`
	AnomalyDetectionInterval  time.Duration `json:"anomaly_detection_interval" yaml:"anomaly_detection_interval"`

	// Retention policies
	MetricsRetentionPeriod time.Duration `json:"metrics_retention_period" yaml:"metrics_retention_period"`
	AnomalyRetentionPeriod time.Duration `json:"anomaly_retention_period" yaml:"anomaly_retention_period"`

	// Performance settings
	MaxConcurrentChecks int           `json:"max_concurrent_checks" yaml:"max_concurrent_checks"`
	HealthCheckTimeout  time.Duration `json:"health_check_timeout" yaml:"health_check_timeout"`
	MetricsTimeout      time.Duration `json:"metrics_timeout" yaml:"metrics_timeout"`

	// Integration settings
	EnableAuditLogging     bool `json:"enable_audit_logging" yaml:"enable_audit_logging"`
	EnableRESTEndpoints    bool `json:"enable_rest_endpoints" yaml:"enable_rest_endpoints"`
	EnableAnomalyDetection bool `json:"enable_anomaly_detection" yaml:"enable_anomaly_detection"`
}

// DefaultMonitoringConfig returns the default monitoring configuration.
func DefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		HealthCheckInterval:       30 * time.Second,
		MetricsCollectionInterval: 60 * time.Second,
		AnomalyDetectionInterval:  5 * time.Minute,
		MetricsRetentionPeriod:    24 * time.Hour,
		AnomalyRetentionPeriod:    7 * 24 * time.Hour,
		MaxConcurrentChecks:       10,
		HealthCheckTimeout:        5 * time.Second,
		MetricsTimeout:            10 * time.Second,
		EnableAuditLogging:        true,
		EnableRESTEndpoints:       true,
		EnableAnomalyDetection:    true,
	}
}
