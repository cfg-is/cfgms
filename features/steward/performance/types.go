package performance

import "time"

// PerformanceMetrics represents a complete snapshot of endpoint performance metrics
type PerformanceMetrics struct {
	// Core identification
	StewardID   string    `json:"steward_id"`
	Hostname    string    `json:"hostname"`
	Timestamp   time.Time `json:"timestamp"`
	CollectedAt time.Time `json:"collected_at"`

	// System metrics
	System *SystemMetrics `json:"system,omitempty"`

	// Process metrics
	TopProcesses  []ProcessMetrics `json:"top_processes,omitempty"`
	WatchlistData []ProcessMetrics `json:"watchlist_processes,omitempty"`

	// Online status
	Online bool `json:"online"`
}

// SystemMetrics represents system-wide performance metrics
type SystemMetrics struct {
	// CPU metrics
	CPUPercent       float64   `json:"cpu_percent"`        // Overall CPU usage percentage (0-100)
	CPUPercentPerCore []float64 `json:"cpu_percent_per_core,omitempty"` // Per-core CPU usage

	// Memory metrics
	MemoryUsedBytes  int64   `json:"memory_used_bytes"`  // Used memory in bytes
	MemoryTotalBytes int64   `json:"memory_total_bytes"` // Total memory in bytes
	MemoryPercent    float64 `json:"memory_percent"`     // Memory usage percentage (0-100)
	SwapUsedBytes    int64   `json:"swap_used_bytes"`    // Swap used in bytes
	SwapTotalBytes   int64   `json:"swap_total_bytes"`   // Swap total in bytes

	// Disk I/O metrics
	DiskReadBytesPerSec  int64 `json:"disk_read_bytes_per_sec"`  // Disk read throughput
	DiskWriteBytesPerSec int64 `json:"disk_write_bytes_per_sec"` // Disk write throughput
	DiskReadOpsPerSec    int64 `json:"disk_read_ops_per_sec"`    // Disk read operations
	DiskWriteOpsPerSec   int64 `json:"disk_write_ops_per_sec"`   // Disk write operations

	// Network I/O metrics
	NetRecvBytesPerSec int64 `json:"net_recv_bytes_per_sec"` // Network receive throughput
	NetSentBytesPerSec int64 `json:"net_sent_bytes_per_sec"` // Network send throughput
	NetRecvPktsPerSec  int64 `json:"net_recv_pkts_per_sec"`  // Network receive packet rate
	NetSentPktsPerSec  int64 `json:"net_sent_pkts_per_sec"`  // Network send packet rate

	// Collection metadata
	CollectedAt time.Time `json:"collected_at"`
}

// ProcessMetrics represents metrics for a single process
type ProcessMetrics struct {
	// Process identification
	PID      int32  `json:"pid"`
	Name     string `json:"name"`
	Cmdline  string `json:"cmdline,omitempty"`
	Username string `json:"username,omitempty"`

	// Resource usage
	CPUPercent    float64 `json:"cpu_percent"`     // CPU usage percentage
	MemoryBytes   int64   `json:"memory_bytes"`    // Memory usage in bytes
	MemoryPercent float64 `json:"memory_percent"`  // Memory usage percentage

	// Additional metrics
	ThreadCount   int32     `json:"thread_count,omitempty"`
	CreateTime    time.Time `json:"create_time,omitempty"`
	Status        string    `json:"status,omitempty"` // running, sleeping, stopped, zombie, etc.

	// Watchlist specific
	IsWatchlisted bool `json:"is_watchlisted,omitempty"`
	ServiceName   string `json:"service_name,omitempty"` // For service watchlist entries
}

// CollectorConfig defines configuration for the performance collector
type CollectorConfig struct {
	// Collection interval
	Interval time.Duration `json:"interval"` // Default: 60 seconds

	// Top process tracking
	TopProcessCount int `json:"top_process_count"` // Default: 10

	// Watchlist configuration
	ProcessWatchlist []string `json:"process_watchlist,omitempty"` // Process names to watch
	ServiceWatchlist []string `json:"service_watchlist,omitempty"` // Service names to watch

	// Retention configuration
	RetentionPeriod time.Duration `json:"retention_period"` // Default: 30 days

	// Performance tuning
	MaxCPUPercent float64 `json:"max_cpu_percent"` // Maximum CPU usage for collector (default: 1.0%)

	// Storage backend
	StorageEnabled bool   `json:"storage_enabled"` // Enable time-series storage
	StorageType    string `json:"storage_type"`    // "influxdb" or "timescaledb"

	// Alerting configuration
	AlertingEnabled bool        `json:"alerting_enabled"`
	Thresholds      []Threshold `json:"thresholds,omitempty"`
}

// Threshold defines a metric threshold for alerting
type Threshold struct {
	MetricName string        `json:"metric_name"` // e.g., "cpu_percent", "memory_percent"
	Value      float64       `json:"value"`       // Threshold value
	Operator   string        `json:"operator"`    // ">", ">=", "<", "<=", "=="
	Severity   string        `json:"severity"`    // "warning" or "critical"
	Duration   time.Duration `json:"duration"`    // How long breach must persist
}

// Alert represents a triggered threshold alert
type Alert struct {
	ID              string    `json:"id"`
	StewardID       string    `json:"steward_id"`
	Timestamp       time.Time `json:"timestamp"`
	Severity        string    `json:"severity"` // "warning" or "critical"
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	MetricName      string    `json:"metric_name"`
	CurrentValue    float64   `json:"current_value"`
	ThresholdValue  float64   `json:"threshold_value"`
	Status          string    `json:"status"` // "active" or "resolved"
	FirstBreachTime time.Time `json:"first_breach_time"`
	LastBreachTime  time.Time `json:"last_breach_time"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`

	// Process-specific alerts
	ProcessName string `json:"process_name,omitempty"`
	ProcessPID  int32  `json:"process_pid,omitempty"`
}

// RemediationAction represents a workflow-triggered remediation action
type RemediationAction struct {
	ID          string                 `json:"id"`
	AlertID     string                 `json:"alert_id"`
	WorkflowID  string                 `json:"workflow_id"`
	Status      string                 `json:"status"` // "pending", "triggered", "completed", "failed"
	TriggeredAt time.Time              `json:"triggered_at"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

// DefaultConfig returns the default collector configuration
func DefaultConfig() *CollectorConfig {
	return &CollectorConfig{
		Interval:        60 * time.Second,
		TopProcessCount: 10,
		RetentionPeriod: 30 * 24 * time.Hour, // 30 days
		MaxCPUPercent:   1.0,
		StorageEnabled:  false, // Disabled by default
		StorageType:     "influxdb",
		AlertingEnabled: false, // Disabled by default
		Thresholds:      []Threshold{},
	}
}
