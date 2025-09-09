// Package export provides third-party integration capabilities for CFGMS monitoring.
//
// This package implements a pluggable architecture for exporting monitoring data
// to external systems like Prometheus, Grafana, ELK stack, and OpenTelemetry backends.
//
// Key Features:
//   - Pluggable exporter architecture with standardized interfaces
//   - Built-in support for popular monitoring tools (Prometheus, Jaeger, Elasticsearch)
//   - Configurable export intervals, filtering, and sampling
//   - Health monitoring for export integrations themselves
//   - Graceful degradation when external services are unavailable
//
// Example Usage:
//
//	config := &ExportConfig{
//		Exporters: map[string]ExporterConfig{
//			"prometheus": {
//				Enabled:  true,
//				Endpoint: "0.0.0.0:2112",
//				Config:   map[string]interface{}{"path": "/metrics"},
//			},
//		},
//	}
//	
//	manager := NewExportManager(logger, config)
//	manager.RegisterExporter("prometheus", NewPrometheusExporter())
//	manager.Start(ctx)
package export

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// ExportManager orchestrates all monitoring data exporters.
// It manages the lifecycle of exporters and coordinates data export operations.
type ExportManager struct {
	logger    logging.Logger
	tracer    *telemetry.Tracer
	config    *ExportConfig
	
	// Exporter management
	exporters map[string]MonitoringExporter
	mu        sync.RWMutex
	
	// State management
	running    bool
	shutdownCh chan struct{}
	
	// Export coordination
	dataChannel chan ExportData
	errorCh     chan ExportError
	
	// Health tracking
	exporterHealth map[string]ExporterHealth
	healthMu       sync.RWMutex
}

// MonitoringExporter defines the interface for third-party monitoring integrations.
// Each exporter handles converting and sending CFGMS monitoring data to external systems.
type MonitoringExporter interface {
	// Name returns the unique name of this exporter
	Name() string
	
	// Export sends monitoring data to the external system
	Export(ctx context.Context, data ExportData) error
	
	// Configure initializes the exporter with configuration parameters
	Configure(config ExporterConfig) error
	
	// HealthCheck verifies the exporter can connect to its external system
	HealthCheck(ctx context.Context) ExporterHealth
	
	// Start begins any background operations (optional)
	Start(ctx context.Context) error
	
	// Stop gracefully shuts down the exporter
	Stop(ctx context.Context) error
}

// ExportData contains all monitoring data available for export.
// Exporters can select which data types they need.
type ExportData struct {
	// System metrics
	SystemMetrics   map[string]interface{} `json:"system_metrics"`
	ResourceMetrics map[string]interface{} `json:"resource_metrics"`
	
	// Component-specific metrics
	StewardMetrics    map[string]interface{} `json:"steward_metrics,omitempty"`
	ControllerMetrics map[string]interface{} `json:"controller_metrics,omitempty"`
	WorkflowMetrics   map[string]interface{} `json:"workflow_metrics,omitempty"`
	
	// Events and logs
	Events []SystemEvent `json:"events,omitempty"`
	Logs   []LogEntry    `json:"logs,omitempty"`
	
	// Distributed tracing
	Traces []TraceSpan `json:"traces,omitempty"`
	
	// Health information
	HealthStatus map[string]HealthStatus `json:"health_status"`
	
	// Metadata
	Timestamp     time.Time              `json:"timestamp"`
	CorrelationID string                 `json:"correlation_id"`
	Source        string                 `json:"source"` // "controller", "steward-id"
	ExportType    ExportType             `json:"export_type"`
}

// SystemEvent represents a system event for export.
type SystemEvent struct {
	ID            string                 `json:"id"`
	Type          string                 `json:"type"`
	Source        string                 `json:"source"`
	Component     string                 `json:"component"`
	Timestamp     time.Time              `json:"timestamp"`
	Severity      string                 `json:"severity"`
	Message       string                 `json:"message"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
}

// LogEntry represents a log entry for export.
type LogEntry struct {
	Timestamp     time.Time              `json:"timestamp"`
	Level         string                 `json:"level"`
	Message       string                 `json:"message"`
	Component     string                 `json:"component"`
	Source        string                 `json:"source"`
	CorrelationID string                 `json:"correlation_id,omitempty"`
	TraceID       string                 `json:"trace_id,omitempty"`
	Fields        map[string]interface{} `json:"fields,omitempty"`
}

// TraceSpan represents a distributed trace span for export.
type TraceSpan struct {
	TraceID       string                 `json:"trace_id"`
	SpanID        string                 `json:"span_id"`
	ParentSpanID  string                 `json:"parent_span_id,omitempty"`
	OperationName string                 `json:"operation_name"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	Status        string                 `json:"status"`
	Tags          map[string]interface{} `json:"tags,omitempty"`
	Logs          []TraceLog             `json:"logs,omitempty"`
}

// TraceLog represents a log within a trace span.
type TraceLog struct {
	Timestamp time.Time              `json:"timestamp"`
	Fields    map[string]interface{} `json:"fields"`
}

// HealthStatus represents component health for export.
type HealthStatus struct {
	Status      string                 `json:"status"`
	Message     string                 `json:"message"`
	LastChecked time.Time              `json:"last_checked"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// ExportType defines the type of export operation.
type ExportType string

const (
	ExportTypeScheduled ExportType = "scheduled" // Regular scheduled export
	ExportTypeTriggered ExportType = "triggered" // Event-triggered export
	ExportTypeManual    ExportType = "manual"    // Manually requested export
)

// ExporterHealth contains health information about an exporter.
type ExporterHealth struct {
	Name           string        `json:"name"`
	Status         string        `json:"status"` // "healthy", "degraded", "unhealthy"
	Message        string        `json:"message"`
	LastExport     time.Time     `json:"last_export"`
	LastError      error         `json:"last_error,omitempty"`
	ResponseTime   time.Duration `json:"response_time"`
	ExportCount    int64         `json:"export_count"`
	ErrorCount     int64         `json:"error_count"`
	LastHealthCheck time.Time    `json:"last_health_check"`
}

// ExportError represents an error during export operations.
type ExportError struct {
	ExporterName string    `json:"exporter_name"`
	Error        error     `json:"error"`
	Data         ExportData `json:"data"`
	Timestamp    time.Time `json:"timestamp"`
	Attempt      int       `json:"attempt"`
}

// ExportConfig contains configuration for the export manager and exporters.
type ExportConfig struct {
	// Global settings
	Enabled         bool          `json:"enabled" yaml:"enabled"`
	ExportInterval  time.Duration `json:"export_interval" yaml:"export_interval"`
	BufferSize      int           `json:"buffer_size" yaml:"buffer_size"`
	MaxRetries      int           `json:"max_retries" yaml:"max_retries"`
	RetryBackoff    time.Duration `json:"retry_backoff" yaml:"retry_backoff"`
	HealthCheckInterval time.Duration `json:"health_check_interval" yaml:"health_check_interval"`
	
	// Exporter configurations
	Exporters map[string]ExporterConfig `json:"exporters" yaml:"exporters"`
	
	// Filtering and sampling
	MetricsFilter   []string `json:"metrics_filter" yaml:"metrics_filter"`
	EventsFilter    []string `json:"events_filter" yaml:"events_filter"`
	LogsFilter      []string `json:"logs_filter" yaml:"logs_filter"`
	SamplingRate    float64  `json:"sampling_rate" yaml:"sampling_rate"`
}

// ExporterConfig contains configuration for a specific exporter.
type ExporterConfig struct {
	Enabled   bool                   `json:"enabled" yaml:"enabled"`
	Endpoint  string                 `json:"endpoint" yaml:"endpoint"`
	Timeout   time.Duration          `json:"timeout" yaml:"timeout"`
	Config    map[string]interface{} `json:"config" yaml:"config"`
	
	// Authentication
	APIKey    string `json:"api_key" yaml:"api_key"`
	Username  string `json:"username" yaml:"username"`
	Password  string `json:"password" yaml:"password"`
	TLSConfig *TLSConfig `json:"tls_config" yaml:"tls_config"`
	
	// Export settings
	ExportTypes []ExportType `json:"export_types" yaml:"export_types"`
	DataTypes   []string     `json:"data_types" yaml:"data_types"` // "metrics", "logs", "traces", "events"
}

// TLSConfig contains TLS configuration for exporters.
type TLSConfig struct {
	Enabled            bool   `json:"enabled" yaml:"enabled"`
	CertFile           string `json:"cert_file" yaml:"cert_file"`
	KeyFile            string `json:"key_file" yaml:"key_file"`
	CAFile             string `json:"ca_file" yaml:"ca_file"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify" yaml:"insecure_skip_verify"`
}

// DefaultExportConfig returns a configuration with sensible defaults.
func DefaultExportConfig() *ExportConfig {
	return &ExportConfig{
		Enabled:             false, // Disabled by default
		ExportInterval:      30 * time.Second,
		BufferSize:          1000,
		MaxRetries:          3,
		RetryBackoff:        5 * time.Second,
		HealthCheckInterval: 60 * time.Second,
		SamplingRate:        1.0, // Export everything by default
		Exporters:           make(map[string]ExporterConfig),
	}
}

// NewExportManager creates a new export manager with the given configuration.
func NewExportManager(logger logging.Logger, tracer *telemetry.Tracer, config *ExportConfig) *ExportManager {
	if config == nil {
		config = DefaultExportConfig()
	}
	
	return &ExportManager{
		logger:         logger,
		tracer:         tracer,
		config:         config,
		exporters:      make(map[string]MonitoringExporter),
		exporterHealth: make(map[string]ExporterHealth),
		shutdownCh:     make(chan struct{}),
		dataChannel:    make(chan ExportData, config.BufferSize),
		errorCh:        make(chan ExportError, 100),
	}
}

// RegisterExporter registers a monitoring exporter with the manager.
func (em *ExportManager) RegisterExporter(name string, exporter MonitoringExporter) error {
	em.mu.Lock()
	defer em.mu.Unlock()
	
	if _, exists := em.exporters[name]; exists {
		return fmt.Errorf("exporter %s is already registered", name)
	}
	
	// Configure the exporter if configuration exists
	if exporterConfig, exists := em.config.Exporters[name]; exists && exporterConfig.Enabled {
		if err := exporter.Configure(exporterConfig); err != nil {
			return fmt.Errorf("failed to configure exporter %s: %w", name, err)
		}
	}
	
	em.exporters[name] = exporter
	em.exporterHealth[name] = ExporterHealth{
		Name:   name,
		Status: "registered",
		Message: "Exporter registered successfully",
	}
	
	em.logger.InfoCtx(context.Background(), "Registered monitoring exporter",
		"exporter_name", name,
		"exporter_type", exporter.Name())
	
	return nil
}

// Start begins the export manager operations.
func (em *ExportManager) Start(ctx context.Context) error {
	em.mu.Lock()
	if em.running {
		em.mu.Unlock()
		return fmt.Errorf("export manager is already running")
	}
	em.running = true
	em.mu.Unlock()
	
	if !em.config.Enabled {
		em.logger.InfoCtx(ctx, "Export manager disabled by configuration")
		return nil
	}
	
	ctx, span := em.tracer.Start(ctx, "export_manager.start")
	defer span.End()
	
	em.logger.InfoCtx(ctx, "Starting export manager",
		"exporters_count", len(em.exporters),
		"export_interval", em.config.ExportInterval)
	
	// Start all enabled exporters
	for name, exporter := range em.exporters {
		if exporterConfig, exists := em.config.Exporters[name]; exists && exporterConfig.Enabled {
			if err := exporter.Start(ctx); err != nil {
				em.logger.WarnCtx(ctx, "Failed to start exporter",
					"exporter_name", name,
					"error", err)
				em.updateExporterHealth(name, "unhealthy", fmt.Sprintf("Start failed: %v", err), err)
			} else {
				em.updateExporterHealth(name, "healthy", "Started successfully", nil)
			}
		}
	}
	
	// Start background goroutines
	go em.exportLoop(ctx)
	go em.healthCheckLoop(ctx)
	go em.errorHandlingLoop(ctx)
	
	return nil
}

// Stop gracefully shuts down the export manager.
func (em *ExportManager) Stop(ctx context.Context) error {
	em.mu.Lock()
	if !em.running {
		em.mu.Unlock()
		return nil
	}
	em.running = false
	em.mu.Unlock()
	
	ctx, span := em.tracer.Start(ctx, "export_manager.stop")
	defer span.End()
	
	em.logger.InfoCtx(ctx, "Stopping export manager")
	
	// Signal shutdown
	close(em.shutdownCh)
	
	// Stop all exporters
	for name, exporter := range em.exporters {
		if err := exporter.Stop(ctx); err != nil {
			em.logger.WarnCtx(ctx, "Error stopping exporter",
				"exporter_name", name,
				"error", err)
		}
	}
	
	// Close channels
	close(em.dataChannel)
	close(em.errorCh)
	
	return nil
}

// Export queues monitoring data for export to all enabled exporters.
func (em *ExportManager) Export(data ExportData) error {
	if !em.config.Enabled || !em.running {
		return nil // Silently ignore if disabled
	}
	
	// Apply sampling
	samplingRate := em.config.SamplingRate
	if samplingRate == 0.0 {
		// If SamplingRate is explicitly 0.0, never export
		// If it's unset (also 0.0), we should export everything
		// We can't distinguish between these cases, so assume 0.0 means never export
		return nil
	}
	
	if samplingRate < 1.0 {
		// Simple random sampling - in production, you might want more sophisticated sampling
		if float64(time.Now().UnixNano()%1000)/1000.0 > samplingRate {
			return nil
		}
	}
	
	// Set correlation ID if not present
	if data.CorrelationID == "" {
		data.CorrelationID = telemetry.GenerateCorrelationID()
	}
	
	// Set timestamp if not present
	if data.Timestamp.IsZero() {
		data.Timestamp = time.Now()
	}
	
	// For test environments, check if we should process synchronously
	if data.ExportType == ExportTypeManual {
		// Process synchronously for manual/test exports
		em.processExportData(context.Background(), data)
		return nil
	}
	
	select {
	case em.dataChannel <- data:
		return nil
	default:
		return fmt.Errorf("export buffer is full, dropping data")
	}
}

// GetExporterHealth returns the health status of all exporters.
func (em *ExportManager) GetExporterHealth() map[string]ExporterHealth {
	em.healthMu.RLock()
	defer em.healthMu.RUnlock()
	
	health := make(map[string]ExporterHealth)
	for name, status := range em.exporterHealth {
		health[name] = status
	}
	
	return health
}

// updateExporterHealth updates the health status of an exporter.
func (em *ExportManager) updateExporterHealth(name, status, message string, err error) {
	em.healthMu.Lock()
	defer em.healthMu.Unlock()
	
	health := em.exporterHealth[name]
	health.Status = status
	health.Message = message
	health.LastError = err
	health.LastHealthCheck = time.Now()
	
	if err != nil {
		health.ErrorCount++
	}
	
	em.exporterHealth[name] = health
}