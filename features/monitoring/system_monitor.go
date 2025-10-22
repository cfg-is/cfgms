// Package monitoring provides system-wide monitoring capabilities for CFGMS.
//
// This package builds upon the existing workflow monitoring framework to provide
// comprehensive monitoring across stewards, controllers, and system resources.
// It integrates with the telemetry package for correlation and distributed tracing.
//
// Key Features:
//   - System-wide health and metrics aggregation
//   - Real-time event streaming for monitoring systems
//   - Integration with existing workflow monitoring
//   - Cross-endpoint correlation using telemetry data
//   - Resource monitoring (CPU, memory, disk usage)
//   - Configuration execution tracking
//
// Example Usage:
//
//	monitor := monitoring.NewSystemMonitor(logger, telemetryTracer)
//	monitor.RegisterCollector("stewards", stewardCollector)
//	monitor.Start(ctx)
//
//	// Get system health
//	health := monitor.GetSystemHealth()
//
//	// Get aggregated metrics
//	metrics := monitor.GetMetrics()
package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/monitoring/export"
	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// SystemMonitor provides comprehensive monitoring for the entire CFGMS system.
// It aggregates metrics from stewards, controllers, and workflows.
type SystemMonitor struct {
	logger logging.Logger
	tracer *telemetry.Tracer

	// Core monitoring components
	workflowMonitor *workflow.Monitor
	collectors      map[string]MetricsCollector
	watchers        map[string][]SystemEventWatcher

	// Export management
	exportManager  *export.ExportManager
	exportRegistry *export.ExporterRegistry

	// Metrics storage
	systemMetrics   *SystemMetrics
	resourceMetrics *ResourceMetrics

	// State management
	mu         sync.RWMutex
	running    bool
	shutdownCh chan struct{}

	// Configuration
	config *MonitorConfig
}

// SystemMetrics contains aggregated metrics for the entire system.
type SystemMetrics struct {
	// System-wide counters
	TotalStewards     int64 `json:"total_stewards"`
	ConnectedStewards int64 `json:"connected_stewards"`
	HealthyStewards   int64 `json:"healthy_stewards"`

	// Configuration metrics
	ConfigurationsApplied int64 `json:"configurations_applied"`
	ConfigurationErrors   int64 `json:"configuration_errors"`

	// Workflow metrics (aggregated from workflow monitor)
	WorkflowExecutions int64 `json:"workflow_executions"`
	WorkflowSuccesses  int64 `json:"workflow_successes"`
	WorkflowFailures   int64 `json:"workflow_failures"`

	// Performance metrics
	AverageResponseTime time.Duration `json:"average_response_time"`
	AverageConfigTime   time.Duration `json:"average_config_time"`

	// Timestamps
	LastUpdated time.Time `json:"last_updated"`
	StartTime   time.Time `json:"start_time"`

	// Component-specific metrics
	ComponentMetrics map[string]interface{} `json:"component_metrics,omitempty"`
}

// ResourceMetrics contains system resource usage information.
type ResourceMetrics struct {
	// CPU metrics
	CPUUsagePercent float64 `json:"cpu_usage_percent"`
	CPUCores        int     `json:"cpu_cores"`

	// Memory metrics
	MemoryUsedBytes    uint64  `json:"memory_used_bytes"`
	MemoryTotalBytes   uint64  `json:"memory_total_bytes"`
	MemoryUsagePercent float64 `json:"memory_usage_percent"`

	// Garbage collection metrics
	GCPauses []time.Duration `json:"gc_pauses"`
	GCCycles uint32          `json:"gc_cycles"`

	// Goroutines
	Goroutines int `json:"goroutines"`

	// Timestamp
	CollectedAt time.Time `json:"collected_at"`
}

// SystemEvent represents a system-wide event for monitoring.
type SystemEvent struct {
	ID            string                 `json:"id"`
	Type          SystemEventType        `json:"type"`
	Source        string                 `json:"source"`    // "controller", "steward-id", "workflow-engine"
	Component     string                 `json:"component"` // "health", "config", "workflow", etc.
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	SpanID        string                 `json:"span_id,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	Severity      EventSeverity          `json:"severity"`
}

// SystemEventType defines the type of system event.
type SystemEventType string

const (
	// Steward events
	EventStewardConnected    SystemEventType = "steward_connected"
	EventStewardDisconnected SystemEventType = "steward_disconnected"
	EventStewardHealthChange SystemEventType = "steward_health_change"

	// Configuration events
	EventConfigurationApplied SystemEventType = "configuration_applied"
	EventConfigurationFailed  SystemEventType = "configuration_failed"
	EventConfigurationDrift   SystemEventType = "configuration_drift"

	// System events
	EventSystemStartup  SystemEventType = "system_startup"
	EventSystemShutdown SystemEventType = "system_shutdown"
	EventResourceAlert  SystemEventType = "resource_alert"

	// Workflow events (from workflow monitor)
	EventWorkflowStarted   SystemEventType = "workflow_started"
	EventWorkflowCompleted SystemEventType = "workflow_completed"
	EventWorkflowFailed    SystemEventType = "workflow_failed"
)

// EventSeverity defines the severity level of events.
type EventSeverity string

const (
	SeverityInfo     EventSeverity = "info"
	SeverityWarning  EventSeverity = "warning"
	SeverityError    EventSeverity = "error"
	SeverityCritical EventSeverity = "critical"
)

// MetricsCollector defines the interface for collecting metrics from different components.
type MetricsCollector interface {
	// CollectMetrics returns the current metrics for the component
	CollectMetrics(ctx context.Context) (map[string]interface{}, error)

	// GetComponentName returns the name of the component
	GetComponentName() string

	// GetHealthStatus returns the health status of the component
	GetHealthStatus(ctx context.Context) (HealthStatus, error)
}

// SystemEventWatcher defines the interface for watching system events.
type SystemEventWatcher interface {
	// OnSystemEvent is called when a system event occurs
	OnSystemEvent(event SystemEvent)

	// GetWatcherName returns the name of the watcher
	GetWatcherName() string
}

// HealthStatus represents the health status of a component.
type HealthStatus struct {
	Status      string                 `json:"status"` // "healthy", "degraded", "unhealthy"
	Message     string                 `json:"message"`
	LastChecked time.Time              `json:"last_checked"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// MonitorConfig contains configuration for the system monitor.
type MonitorConfig struct {
	// Collection intervals
	MetricsInterval     time.Duration `json:"metrics_interval"`
	ResourceInterval    time.Duration `json:"resource_interval"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`

	// Resource monitoring settings
	EnableResourceMonitoring bool `json:"enable_resource_monitoring"`
	EnableDetailedGCMetrics  bool `json:"enable_detailed_gc_metrics"`

	// Alert thresholds
	CPUAlertThreshold       float64 `json:"cpu_alert_threshold"`
	MemoryAlertThreshold    float64 `json:"memory_alert_threshold"`
	GoroutineAlertThreshold int     `json:"goroutine_alert_threshold"`

	// Event settings
	MaxEventHistory        int  `json:"max_event_history"`
	EnableEventCorrelation bool `json:"enable_event_correlation"`

	// Export configuration
	ExportConfig *export.ExportConfig `json:"export_config,omitempty"`
}

// DefaultMonitorConfig returns a configuration with sensible defaults.
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		MetricsInterval:          30 * time.Second,
		ResourceInterval:         10 * time.Second,
		HealthCheckInterval:      60 * time.Second,
		EnableResourceMonitoring: true,
		EnableDetailedGCMetrics:  true,
		CPUAlertThreshold:        80.0,
		MemoryAlertThreshold:     85.0,
		GoroutineAlertThreshold:  1000,
		MaxEventHistory:          1000,
		EnableEventCorrelation:   true,
	}
}

// NewSystemMonitor creates a new system monitor with the given configuration.
func NewSystemMonitor(logger logging.Logger, tracer *telemetry.Tracer, config *MonitorConfig) *SystemMonitor {
	if config == nil {
		config = DefaultMonitorConfig()
	} else {
		// Ensure required fields have defaults if not set
		if config.MetricsInterval <= 0 {
			config.MetricsInterval = 30 * time.Second
		}
		if config.ResourceInterval <= 0 {
			config.ResourceInterval = 60 * time.Second
		}
		if config.HealthCheckInterval <= 0 {
			config.HealthCheckInterval = 30 * time.Second
		}
	}

	// Create exporter registry
	exportRegistry := export.NewExporterRegistry(logger, tracer)

	// Create export manager if export is configured
	var exportManager *export.ExportManager
	if config.ExportConfig != nil {
		var err error
		exportManager, err = exportRegistry.CreateExportManagerFromConfig(config.ExportConfig)
		if err != nil {
			logger.WarnCtx(context.Background(), "Failed to create export manager from config",
				"error", err)
			// Continue without export functionality
		}
	}

	monitor := &SystemMonitor{
		logger:          logger,
		tracer:          tracer,
		workflowMonitor: workflow.NewMonitor(logger),
		collectors:      make(map[string]MetricsCollector),
		watchers:        make(map[string][]SystemEventWatcher),
		exportRegistry:  exportRegistry,
		exportManager:   exportManager,
		config:          config,
		shutdownCh:      make(chan struct{}),
		systemMetrics: &SystemMetrics{
			StartTime:        time.Now(),
			LastUpdated:      time.Now(),
			ComponentMetrics: make(map[string]interface{}),
		},
		resourceMetrics: &ResourceMetrics{
			CollectedAt: time.Now(),
		},
	}

	return monitor
}

// RegisterCollector registers a metrics collector for a specific component.
func (sm *SystemMonitor) RegisterCollector(name string, collector MetricsCollector) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.collectors[name] = collector
	sm.logger.InfoCtx(context.Background(), "Registered metrics collector",
		"collector_name", name,
		"component_name", collector.GetComponentName())
}

// RegisterWatcher registers an event watcher for system events.
func (sm *SystemMonitor) RegisterWatcher(eventType string, watcher SystemEventWatcher) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.watchers[eventType] == nil {
		sm.watchers[eventType] = make([]SystemEventWatcher, 0)
	}

	sm.watchers[eventType] = append(sm.watchers[eventType], watcher)
	sm.logger.InfoCtx(context.Background(), "Registered system event watcher",
		"event_type", eventType,
		"watcher_name", watcher.GetWatcherName())
}

// Start begins the system monitoring processes.
func (sm *SystemMonitor) Start(ctx context.Context) error {
	sm.mu.Lock()
	if sm.running {
		sm.mu.Unlock()
		return fmt.Errorf("system monitor is already running")
	}
	sm.running = true
	sm.mu.Unlock()

	ctx, span := sm.tracer.Start(ctx, "system_monitor.start")
	defer span.End()

	sm.logger.InfoCtx(ctx, "Starting system monitor",
		"metrics_interval", sm.config.MetricsInterval,
		"resource_monitoring", sm.config.EnableResourceMonitoring)

	// Emit startup event
	sm.emitEvent(SystemEvent{
		ID:        telemetry.GenerateCorrelationID(),
		Type:      EventSystemStartup,
		Source:    "system_monitor",
		Component: "monitor",
		Timestamp: time.Now(),
		Severity:  SeverityInfo,
		Data: map[string]interface{}{
			"config": sm.config,
		},
	})

	// Start export manager if configured
	if sm.exportManager != nil {
		if err := sm.exportManager.Start(ctx); err != nil {
			sm.logger.WarnCtx(ctx, "Failed to start export manager", "error", err)
			// Continue without export functionality
		} else {
			sm.logger.InfoCtx(ctx, "Export manager started successfully")
		}
	}

	// Start background monitoring goroutines
	go sm.metricsCollectionLoop(ctx)

	if sm.config.EnableResourceMonitoring {
		go sm.resourceMonitoringLoop(ctx)
	}

	go sm.healthCheckLoop(ctx)

	return nil
}

// Stop gracefully shuts down the system monitor.
func (sm *SystemMonitor) Stop(ctx context.Context) error {
	sm.mu.Lock()
	if !sm.running {
		sm.mu.Unlock()
		return nil
	}
	sm.running = false
	sm.mu.Unlock()

	ctx, span := sm.tracer.Start(ctx, "system_monitor.stop")
	defer span.End()

	sm.logger.InfoCtx(ctx, "Stopping system monitor")

	// Emit shutdown event
	sm.emitEvent(SystemEvent{
		ID:        telemetry.GenerateCorrelationID(),
		Type:      EventSystemShutdown,
		Source:    "system_monitor",
		Component: "monitor",
		Timestamp: time.Now(),
		Severity:  SeverityInfo,
	})

	// Stop export manager if running
	if sm.exportManager != nil {
		if err := sm.exportManager.Stop(ctx); err != nil {
			sm.logger.WarnCtx(ctx, "Failed to stop export manager", "error", err)
		} else {
			sm.logger.InfoCtx(ctx, "Export manager stopped successfully")
		}
	}

	// Signal shutdown and wait for goroutines
	close(sm.shutdownCh)

	// Wait for graceful shutdown, respecting context timeout
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(100 * time.Millisecond):
		// Give a brief moment for cleanup, then return success
		return nil
	}
}

// GetSystemHealth returns the current system health status.
func (sm *SystemMonitor) GetSystemHealth() map[string]HealthStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	health := make(map[string]HealthStatus)

	// Get health from all registered collectors
	for name, collector := range sm.collectors {
		status, err := collector.GetHealthStatus(context.Background())
		if err != nil {
			health[name] = HealthStatus{
				Status:      "unhealthy",
				Message:     fmt.Sprintf("Health check failed: %v", err),
				LastChecked: time.Now(),
			}
		} else {
			health[name] = status
		}
	}

	// Add system monitor health
	health["system_monitor"] = HealthStatus{
		Status:      "healthy",
		Message:     "System monitor operational",
		LastChecked: time.Now(),
		Details: map[string]interface{}{
			"running":          sm.running,
			"collectors_count": len(sm.collectors),
			"watchers_count":   len(sm.watchers),
			"uptime_seconds":   time.Since(sm.systemMetrics.StartTime).Seconds(),
		},
	}

	return health
}

// GetMetrics returns the current system metrics.
func (sm *SystemMonitor) GetMetrics() *SystemMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Return a copy to prevent external modification
	metrics := *sm.systemMetrics
	return &metrics
}

// GetResourceMetrics returns the current resource metrics.
func (sm *SystemMonitor) GetResourceMetrics() *ResourceMetrics {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// Return a copy to prevent external modification
	metrics := *sm.resourceMetrics
	return &metrics
}
