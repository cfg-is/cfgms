// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package performance

import (
	"context"
	"time"
)

// Collector is the main performance metrics collector interface
type Collector interface {
	// Start begins metric collection with the configured interval
	Start(ctx context.Context) error

	// Stop halts metric collection
	Stop() error

	// GetCurrentMetrics returns the most recent metrics snapshot
	GetCurrentMetrics() (*PerformanceMetrics, error)

	// GetMetricsHistory returns metrics within the specified time range
	GetMetricsHistory(start, end time.Time) ([]*PerformanceMetrics, error)

	// GetConfig returns the current collector configuration
	GetConfig() *CollectorConfig

	// UpdateConfig updates the collector configuration
	UpdateConfig(config *CollectorConfig) error
}

// SystemCollector collects system-wide performance metrics
// This interface has platform-specific implementations for Windows, Linux, and macOS
type SystemCollector interface {
	// CollectMetrics gathers system metrics
	CollectMetrics(ctx context.Context) (*SystemMetrics, error)

	// GetPlatform returns the platform name (windows, linux, darwin)
	GetPlatform() string
}

// ProcessCollector collects process-specific metrics
type ProcessCollector interface {
	// GetTopProcesses returns the top N processes by CPU/memory usage
	GetTopProcesses(ctx context.Context, count int) ([]ProcessMetrics, error)

	// GetWatchlistProcesses returns metrics for processes in the watchlist
	GetWatchlistProcesses(ctx context.Context, watchlist []string) ([]ProcessMetrics, error)

	// GetServiceStatus returns status for services in the watchlist
	GetServiceStatus(ctx context.Context, services []string) ([]ProcessMetrics, error)

	// GetProcessByPID returns metrics for a specific process
	GetProcessByPID(ctx context.Context, pid int32) (*ProcessMetrics, error)
}

// StorageBackend defines the interface for time-series storage
type StorageBackend interface {
	// Connect establishes connection to the storage backend
	Connect(ctx context.Context) error

	// Close closes the connection to the storage backend
	Close() error

	// WriteMetrics writes performance metrics to storage
	WriteMetrics(ctx context.Context, metrics *PerformanceMetrics) error

	// QueryMetrics retrieves metrics within a time range
	QueryMetrics(ctx context.Context, stewardID string, start, end time.Time) ([]*PerformanceMetrics, error)

	// DeleteOldMetrics removes metrics older than the retention period
	DeleteOldMetrics(ctx context.Context, retentionPeriod time.Duration) error

	// GetStorageType returns the storage type (influxdb, timescaledb)
	GetStorageType() string
}

// AlertManager manages threshold-based alerting
type AlertManager interface {
	// Start begins alert monitoring
	Start(ctx context.Context) error

	// Stop halts alert monitoring
	Stop() error

	// EvaluateMetrics checks metrics against thresholds and generates alerts
	EvaluateMetrics(metrics *PerformanceMetrics) ([]Alert, error)

	// GetActiveAlerts returns all active alerts
	GetActiveAlerts() []Alert

	// GetAlertHistory returns alerts within the specified time range
	GetAlertHistory(start, end time.Time) []Alert

	// AddThreshold adds a new threshold configuration
	AddThreshold(threshold Threshold) error

	// RemoveThreshold removes a threshold configuration
	RemoveThreshold(metricName string) error

	// ResolveAlert marks an alert as resolved
	ResolveAlert(alertID string) error
}

// RemediationEngine manages workflow-triggered remediation actions
type RemediationEngine interface {
	// Start begins remediation monitoring
	Start(ctx context.Context) error

	// Stop halts remediation monitoring
	Stop() error

	// TriggerRemediation triggers a workflow for an alert
	TriggerRemediation(ctx context.Context, alert Alert, workflowID string) (*RemediationAction, error)

	// GetRemediationStatus returns the status of a remediation action
	GetRemediationStatus(actionID string) (*RemediationAction, error)

	// GetRemediationHistory returns remediation actions within a time range
	GetRemediationHistory(start, end time.Time) []RemediationAction
}
