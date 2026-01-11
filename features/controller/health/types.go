// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package health

import (
	"time"
)

// MetricType represents the type of metric being collected
type MetricType string

const (
	MetricTypeMQTT        MetricType = "mqtt"
	MetricTypeStorage     MetricType = "storage"
	MetricTypeApplication MetricType = "application"
	MetricTypeSystem      MetricType = "system"
)

// MetricSeverity represents the severity level of a metric threshold breach
type MetricSeverity string

const (
	SeverityInfo     MetricSeverity = "info"
	SeverityWarning  MetricSeverity = "warning"
	SeverityCritical MetricSeverity = "critical"
)

// ControllerMetrics represents comprehensive controller health metrics
type ControllerMetrics struct {
	Timestamp time.Time `json:"timestamp"`

	// MQTT Broker Metrics
	MQTT *MQTTMetrics `json:"mqtt"`

	// Storage Provider Metrics
	Storage *StorageMetrics `json:"storage"`

	// Application Metrics
	Application *ApplicationMetrics `json:"application"`

	// System Metrics
	System *SystemMetrics `json:"system"`
}

// MQTTMetrics represents MQTT broker metrics
type MQTTMetrics struct {
	// Active steward connections
	ActiveConnections int64 `json:"active_connections"`

	// Message queue depth
	MessageQueueDepth int64 `json:"message_queue_depth"`

	// Message throughput (messages per second)
	MessageThroughput float64 `json:"message_throughput"`

	// Total messages sent
	TotalMessagesSent int64 `json:"total_messages_sent"`

	// Total messages received
	TotalMessagesReceived int64 `json:"total_messages_received"`

	// Connection errors
	ConnectionErrors int64 `json:"connection_errors"`

	// Last collection time
	CollectedAt time.Time `json:"collected_at"`
}

// StorageMetrics represents storage provider metrics
type StorageMetrics struct {
	// Provider type (git, database, etc.)
	Provider string `json:"provider"`

	// Connection pool utilization (0.0 - 1.0)
	PoolUtilization float64 `json:"pool_utilization"`

	// Average query latency in milliseconds
	AvgQueryLatencyMs float64 `json:"avg_query_latency_ms"`

	// P95 query latency in milliseconds
	P95QueryLatencyMs float64 `json:"p95_query_latency_ms"`

	// Slow query count (>1 second)
	SlowQueryCount int64 `json:"slow_query_count"`

	// Total queries executed
	TotalQueries int64 `json:"total_queries"`

	// Query errors
	QueryErrors int64 `json:"query_errors"`

	// Last collection time
	CollectedAt time.Time `json:"collected_at"`
}

// ApplicationMetrics represents application-level metrics
type ApplicationMetrics struct {
	// Workflow queue depth
	WorkflowQueueDepth int64 `json:"workflow_queue_depth"`

	// Maximum wait time in workflow queue (seconds)
	WorkflowMaxWaitTime float64 `json:"workflow_max_wait_time"`

	// Active workflow executions
	ActiveWorkflows int64 `json:"active_workflows"`

	// Script execution queue depth
	ScriptQueueDepth int64 `json:"script_queue_depth"`

	// Maximum wait time in script queue (seconds)
	ScriptMaxWaitTime float64 `json:"script_max_wait_time"`

	// Active script executions
	ActiveScripts int64 `json:"active_scripts"`

	// Configuration push queue depth
	ConfigQueueDepth int64 `json:"config_queue_depth"`

	// Last collection time
	CollectedAt time.Time `json:"collected_at"`
}

// SystemMetrics represents system-level resource metrics
type SystemMetrics struct {
	// CPU utilization percentage (0-100)
	CPUPercent float64 `json:"cpu_percent"`

	// Memory usage in bytes
	MemoryUsedBytes int64 `json:"memory_used_bytes"`

	// Memory usage percentage (0-100)
	MemoryPercent float64 `json:"memory_percent"`

	// Heap memory in bytes
	HeapBytes int64 `json:"heap_bytes"`

	// RSS memory in bytes
	RSSBytes int64 `json:"rss_bytes"`

	// Number of goroutines
	GoroutineCount int64 `json:"goroutine_count"`

	// Number of open file descriptors
	OpenFileDescriptors int64 `json:"open_file_descriptors"`

	// Last collection time
	CollectedAt time.Time `json:"collected_at"`
}

// Threshold represents a metric threshold configuration
type Threshold struct {
	// Metric name (e.g., "workflow_queue_depth")
	MetricName string `json:"metric_name"`

	// Threshold value
	Value float64 `json:"value"`

	// Comparison operator (>, <, >=, <=, ==)
	Operator string `json:"operator"`

	// Severity level when threshold is breached
	Severity MetricSeverity `json:"severity"`

	// Duration the threshold must be breached before alerting
	Duration time.Duration `json:"duration"`
}

// Alert represents a metric threshold breach alert
type Alert struct {
	// Unique alert ID
	ID string `json:"id"`

	// Alert timestamp
	Timestamp time.Time `json:"timestamp"`

	// Severity level
	Severity MetricSeverity `json:"severity"`

	// Alert title
	Title string `json:"title"`

	// Alert description
	Description string `json:"description"`

	// Metric type
	MetricType MetricType `json:"metric_type"`

	// Metric name
	MetricName string `json:"metric_name"`

	// Current metric value
	CurrentValue float64 `json:"current_value"`

	// Threshold value
	ThresholdValue float64 `json:"threshold_value"`

	// Alert status (active, resolved, suppressed)
	Status string `json:"status"`

	// First breach time
	FirstBreachTime time.Time `json:"first_breach_time"`

	// Last breach time
	LastBreachTime time.Time `json:"last_breach_time"`

	// Resolution time (if resolved)
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// HealthStatus represents the overall health status of the controller
type HealthStatus struct {
	// Overall status (healthy, degraded, unhealthy)
	Status string `json:"status"`

	// Timestamp
	Timestamp time.Time `json:"timestamp"`

	// Component health statuses
	Components map[string]ComponentHealth `json:"components"`

	// Active alerts
	Alerts []Alert `json:"alerts"`

	// Uptime in seconds
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// ComponentHealth represents the health status of a single component
type ComponentHealth struct {
	// Component name
	Name string `json:"name"`

	// Status (healthy, degraded, unhealthy)
	Status string `json:"status"`

	// Message
	Message string `json:"message"`

	// Last check time
	LastCheck time.Time `json:"last_check"`

	// Details
	Details map[string]interface{} `json:"details,omitempty"`
}

// RequestTrace represents tracing information for a request
type RequestTrace struct {
	// Unique request ID
	RequestID string `json:"request_id"`

	// Trace ID for distributed tracing
	TraceID string `json:"trace_id,omitempty"`

	// Parent request ID (for nested requests)
	ParentRequestID string `json:"parent_request_id,omitempty"`

	// Request start time
	StartTime time.Time `json:"start_time"`

	// Request end time
	EndTime *time.Time `json:"end_time,omitempty"`

	// Duration in milliseconds
	DurationMs float64 `json:"duration_ms,omitempty"`

	// Operation name
	Operation string `json:"operation"`

	// Component name
	Component string `json:"component"`

	// Status (success, error, timeout)
	Status string `json:"status"`

	// Error message (if any)
	Error string `json:"error,omitempty"`

	// Metadata
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	// Spans (sub-operations)
	Spans []RequestSpan `json:"spans,omitempty"`
}

// RequestSpan represents a sub-operation within a request
type RequestSpan struct {
	// Span ID
	SpanID string `json:"span_id"`

	// Parent span ID
	ParentSpanID string `json:"parent_span_id,omitempty"`

	// Operation name
	Operation string `json:"operation"`

	// Start time
	StartTime time.Time `json:"start_time"`

	// End time
	EndTime *time.Time `json:"end_time,omitempty"`

	// Duration in milliseconds
	DurationMs float64 `json:"duration_ms,omitempty"`

	// Status
	Status string `json:"status"`

	// Tags
	Tags map[string]string `json:"tags,omitempty"`
}
