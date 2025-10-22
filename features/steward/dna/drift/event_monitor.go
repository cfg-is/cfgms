// Package drift provides event-driven drift monitoring service.

package drift

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/features/steward/dna/events"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// eventMonitor implements event-driven drift monitoring with real-time detection.
type eventMonitor struct {
	logger   logging.Logger
	config   *EventMonitorConfig
	detector Detector
	storage  *storage.Manager

	// Event system
	eventPublisher  events.EventPublisher
	driftSubscriber events.EventSubscriber

	// Fallback timer-based monitoring
	timerMonitoring  bool
	monitoredDevices map[string]*DeviceMonitorInfo
	scanInterval     time.Duration

	// Control channels
	stopChan   chan struct{}
	deviceChan chan DeviceOperation

	// Synchronization
	mu sync.RWMutex

	// Event handling
	eventHandlers []EventHandler

	// Statistics
	stats   *EventMonitorStats
	running bool
}

// EventMonitorConfig defines configuration for event-driven drift monitoring.
type EventMonitorConfig struct {
	// Event-based monitoring
	EnableEventMonitoring bool `json:"enable_event_monitoring"`
	EventWorkerCount      int  `json:"event_worker_count"`
	EventQueueSize        int  `json:"event_queue_size"`

	// Drift detection settings
	ComparisonWindow      time.Duration `json:"comparison_window"`
	MaxDetectionTime      time.Duration `json:"max_detection_time"`
	EnableAsyncProcessing bool          `json:"enable_async_processing"`

	// Fallback timer-based monitoring
	EnableFallbackTimer   bool          `json:"enable_fallback_timer"`
	FallbackInterval      time.Duration `json:"fallback_interval"`
	FallbackDeviceTimeout time.Duration `json:"fallback_device_timeout"`

	// Device management
	MaxMonitoredDevices int           `json:"max_monitored_devices"`
	HealthCheckInterval time.Duration `json:"health_check_interval"`

	// Performance settings
	MaxConcurrentScans     int  `json:"max_concurrent_scans"`
	EnableParallelScanning bool `json:"enable_parallel_scanning"`

	// Event handling
	MaxEventBuffer       int           `json:"max_event_buffer"`
	EventProcessingDelay time.Duration `json:"event_processing_delay"`

	// Error handling
	MaxRetries     int           `json:"max_retries"`
	RetryBackoff   time.Duration `json:"retry_backoff"`
	ErrorThreshold int           `json:"error_threshold"`
}

// EventMonitorStats provides statistics for event-driven drift monitoring.
type EventMonitorStats struct {
	// Event-based monitoring stats
	EventsProcessed     int64         `json:"events_processed"`
	EventDriftDetected  int64         `json:"event_drift_detected"`
	EventProcessingTime time.Duration `json:"event_processing_time"`

	// Fallback timer stats
	TimerScansPerformed int64         `json:"timer_scans_performed"`
	TimerDriftDetected  int64         `json:"timer_drift_detected"`
	TimerScanTime       time.Duration `json:"timer_scan_time"`

	// Overall stats
	TotalDriftEvents int64 `json:"total_drift_events"`
	MonitoredDevices int   `json:"monitored_devices"`
	DevicesWithDrift int   `json:"devices_with_drift"`

	// Performance stats
	AverageDetectionTime time.Duration `json:"average_detection_time"`
	LastDetectionTime    time.Time     `json:"last_detection_time"`

	// System health
	MonitoringStatus MonitorStatus `json:"monitoring_status"`
	LastScanTime     time.Time     `json:"last_scan_time"`
	ScanInterval     time.Duration `json:"scan_interval"`

	// Error tracking
	EventErrors int64 `json:"event_errors"`
	TimerErrors int64 `json:"timer_errors"`
}

// NewEventMonitor creates a new event-driven drift monitoring service.
func NewEventMonitor(config *EventMonitorConfig, detector Detector, storage *storage.Manager, logger logging.Logger) (Monitor, error) {
	if config == nil {
		config = DefaultEventMonitorConfig()
	}

	if err := validateEventMonitorConfig(config); err != nil {
		return nil, fmt.Errorf("invalid event monitor config: %w", err)
	}

	if detector == nil {
		return nil, fmt.Errorf("detector is required")
	}

	if storage == nil {
		return nil, fmt.Errorf("storage manager is required")
	}

	m := &eventMonitor{
		logger:           logger,
		config:           config,
		detector:         detector,
		storage:          storage,
		monitoredDevices: make(map[string]*DeviceMonitorInfo),
		scanInterval:     config.FallbackInterval,
		stopChan:         make(chan struct{}),
		deviceChan:       make(chan DeviceOperation, 100),
		eventHandlers:    make([]EventHandler, 0),
		stats: &EventMonitorStats{
			MonitoringStatus: MonitorStatusStopped,
			ScanInterval:     config.FallbackInterval,
		},
	}

	// Initialize event system if enabled
	if config.EnableEventMonitoring {
		if err := m.initializeEventSystem(); err != nil {
			return nil, fmt.Errorf("failed to initialize event system: %w", err)
		}
	}

	if logger != nil {
		logger.Info("Event drift monitor initialized",
			"event_monitoring", config.EnableEventMonitoring,
			"fallback_timer", config.EnableFallbackTimer,
			"comparison_window", config.ComparisonWindow)
	}

	return m, nil
}

// initializeEventSystem sets up the event-based monitoring system.
func (m *eventMonitor) initializeEventSystem() error {
	// Create event publisher
	publisherConfig := &events.PublisherConfig{
		WorkerCount:   m.config.EventWorkerCount,
		QueueSize:     m.config.EventQueueSize,
		WorkerTimeout: m.config.MaxDetectionTime,
	}

	m.eventPublisher = events.NewPublisher(m.logger, publisherConfig)

	// Create drift detection subscriber
	subscriberConfig := &events.DriftSubscriberConfig{
		EnableRealTimeDetection: true,
		ComparisonWindow:        m.config.ComparisonWindow,
		MaxDetectionTime:        m.config.MaxDetectionTime,
		EventProcessingTimeout:  m.config.MaxDetectionTime,
	}

	// For now, we'll use simplified interfaces to avoid import cycles
	// In a real implementation, this would use the actual detector and storage
	m.driftSubscriber = events.NewDriftSubscriber(
		nil, // detector - would need adapter
		nil, // storage - would need adapter
		subscriberConfig,
		m.logger,
	)

	// Subscribe to DNA change events
	if err := m.eventPublisher.Subscribe(events.EventTypeDNAWrite, m.driftSubscriber); err != nil {
		return fmt.Errorf("failed to subscribe to DNA write events: %w", err)
	}

	return nil
}

// Start begins event-driven drift monitoring.
func (m *eventMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		return fmt.Errorf("event monitor is already running")
	}

	m.running = true
	m.stats.MonitoringStatus = MonitorStatusRunning

	if m.logger != nil {
		m.logger.Info("Starting event-driven drift monitoring service",
			"event_monitoring", m.config.EnableEventMonitoring,
			"fallback_timer", m.config.EnableFallbackTimer,
			"monitored_devices", len(m.monitoredDevices))
	}

	// Start event system if enabled
	if m.config.EnableEventMonitoring && m.eventPublisher != nil {
		if err := m.eventPublisher.Start(ctx); err != nil {
			return fmt.Errorf("failed to start event publisher: %w", err)
		}
	}

	// Start background workers
	go m.deviceOperationWorker(ctx)
	go m.healthCheckWorker(ctx)

	// Start fallback timer-based monitoring if enabled
	if m.config.EnableFallbackTimer || m.timerMonitoring {
		go m.fallbackScanWorker(ctx)
	}

	return nil
}

// Stop halts event-driven drift monitoring.
func (m *eventMonitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.running {
		return fmt.Errorf("event monitor is not running")
	}

	if m.logger != nil {
		m.logger.Info("Stopping event-driven drift monitoring service")
	}

	// Stop event system
	if m.eventPublisher != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.eventPublisher.Stop(ctx); err != nil && m.logger != nil {
			m.logger.Warn("Error stopping event publisher", "error", err)
		}
	}

	// Signal stop
	close(m.stopChan)
	m.running = false
	m.stats.MonitoringStatus = MonitorStatusStopped

	return nil
}

// SetInterval updates the fallback monitoring scan interval.
func (m *eventMonitor) SetInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Apply bounds
	if interval < time.Minute {
		interval = time.Minute
	}
	if interval > time.Hour {
		interval = time.Hour
	}

	m.scanInterval = interval
	m.stats.ScanInterval = interval

	if m.logger != nil {
		m.logger.Info("Fallback scan interval updated", "new_interval", interval)
	}
}

// GetMonitoredDevices returns list of devices being monitored.
func (m *eventMonitor) GetMonitoredDevices() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	devices := make([]string, 0, len(m.monitoredDevices))
	for deviceID := range m.monitoredDevices {
		devices = append(devices, deviceID)
	}

	return devices
}

// AddDevice adds a device to event-driven drift monitoring.
func (m *eventMonitor) AddDevice(deviceID string) error {
	if deviceID == "" {
		return fmt.Errorf("device ID cannot be empty")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Check capacity
	if len(m.monitoredDevices) >= m.config.MaxMonitoredDevices {
		return fmt.Errorf("maximum monitored devices exceeded (%d)", m.config.MaxMonitoredDevices)
	}

	// Check if already monitored
	if _, exists := m.monitoredDevices[deviceID]; exists {
		return fmt.Errorf("device %s is already being monitored", deviceID)
	}

	// Add device
	info := &DeviceMonitorInfo{
		DeviceID:     deviceID,
		LastScanTime: time.Time{},
		NextScanTime: time.Now().Add(m.scanInterval),
		Status:       DeviceStatusActive,
		HealthStatus: "healthy",
	}

	m.monitoredDevices[deviceID] = info
	m.stats.MonitoredDevices = len(m.monitoredDevices)

	if m.logger != nil {
		m.logger.Info("Device added to event-driven monitoring", "device_id", deviceID)
	}

	return nil
}

// RemoveDevice removes a device from event-driven drift monitoring.
func (m *eventMonitor) RemoveDevice(deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.monitoredDevices[deviceID]; !exists {
		return fmt.Errorf("device %s is not being monitored", deviceID)
	}

	delete(m.monitoredDevices, deviceID)
	m.stats.MonitoredDevices = len(m.monitoredDevices)

	if m.logger != nil {
		m.logger.Info("Device removed from event-driven monitoring", "device_id", deviceID)
	}

	return nil
}

// GetMonitorStats returns event monitoring statistics.
func (m *eventMonitor) GetMonitorStats() *MonitorStats {
	m.mu.RLock()
	eventStats := *m.stats
	m.mu.RUnlock()

	// Convert event stats to legacy format
	legacyStats := &MonitorStats{
		MonitoredDevices:    eventStats.MonitoredDevices,
		DevicesWithDrift:    eventStats.DevicesWithDrift,
		MonitoringStatus:    eventStats.MonitoringStatus,
		LastScanTime:        eventStats.LastScanTime,
		ScanInterval:        eventStats.ScanInterval,
		ScansCompleted:      eventStats.TimerScansPerformed,
		AverageScanDuration: eventStats.TimerScanTime,
	}

	return legacyStats
}

// GetEventStats returns detailed event monitoring statistics.
func (m *eventMonitor) GetEventStats() *EventMonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := *m.stats

	// Add event publisher stats if available
	if m.eventPublisher != nil {
		publisherStats := m.eventPublisher.GetStats()
		stats.EventsProcessed = publisherStats.EventsProcessed
		stats.EventErrors = publisherStats.EventsFailed
		stats.EventProcessingTime = publisherStats.AverageProcessingTime
	}

	return &stats
}

// AddEventHandler adds an event handler for drift events.
func (m *eventMonitor) AddEventHandler(handler EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.eventHandlers = append(m.eventHandlers, handler)

	info := handler.GetHandlerInfo()
	if m.logger != nil {
		m.logger.Info("Event handler added to event monitor",
			"handler_name", info.Name,
			"priority", info.Priority,
			"async", info.Async)
	}
}

// PublishDNAChangeEvent publishes a DNA change event for real-time processing.
func (m *eventMonitor) PublishDNAChangeEvent(ctx context.Context, event *events.DNAChangeEvent) error {
	if m.eventPublisher == nil {
		return fmt.Errorf("event publisher not initialized")
	}

	return m.eventPublisher.Publish(ctx, events.EventTypeDNAWrite, event)
}

// Helper methods (stub implementations for now)
func (m *eventMonitor) deviceOperationWorker(ctx context.Context) {
	// Implementation would handle device operations
}

func (m *eventMonitor) healthCheckWorker(ctx context.Context) {
	// Implementation would perform health checks
}

func (m *eventMonitor) fallbackScanWorker(ctx context.Context) {
	// Implementation would perform fallback timer-based scanning
}

// DefaultEventMonitorConfig returns sensible defaults for event-driven drift monitoring.
func DefaultEventMonitorConfig() *EventMonitorConfig {
	return &EventMonitorConfig{
		EnableEventMonitoring:  true,
		EventWorkerCount:       3,
		EventQueueSize:         50,
		ComparisonWindow:       10 * time.Minute,
		MaxDetectionTime:       30 * time.Second,
		EnableAsyncProcessing:  true,
		EnableFallbackTimer:    true,
		FallbackInterval:       5 * time.Minute, // Fallback scanning every 5 minutes
		FallbackDeviceTimeout:  15 * time.Minute,
		MaxMonitoredDevices:    1000,
		HealthCheckInterval:    10 * time.Minute,
		MaxConcurrentScans:     10,
		EnableParallelScanning: true,
		MaxEventBuffer:         1000,
		EventProcessingDelay:   1 * time.Second,
		MaxRetries:             3,
		RetryBackoff:           30 * time.Second,
		ErrorThreshold:         5,
	}
}

func validateEventMonitorConfig(config *EventMonitorConfig) error {
	if !config.EnableEventMonitoring && !config.EnableFallbackTimer {
		return fmt.Errorf("at least one monitoring method must be enabled")
	}

	if config.ComparisonWindow < time.Minute {
		return fmt.Errorf("comparison window must be at least 1 minute")
	}

	if config.MaxMonitoredDevices <= 0 {
		return fmt.Errorf("max monitored devices must be positive")
	}

	return nil
}
