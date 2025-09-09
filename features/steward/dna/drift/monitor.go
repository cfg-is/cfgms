// Package drift provides continuous drift monitoring service with background scanning.

package drift

import (
	"context"
	"fmt"
	"sync"
	"time"

	commonpb "github.com/cfgis/cfgms/api/proto/common"
	"github.com/cfgis/cfgms/features/steward/dna/storage"
	"github.com/cfgis/cfgms/pkg/logging"
)

// monitor implements the Monitor interface for continuous drift monitoring.
type monitor struct {
	logger    logging.Logger
	config    *MonitorConfig
	detector  Detector
	storage   *storage.Manager
	
	// Monitoring state
	running         bool
	monitoredDevices map[string]*DeviceMonitorInfo
	scanInterval    time.Duration
	
	// Control channels
	stopChan        chan struct{}
	deviceChan      chan DeviceOperation
	
	// Synchronization
	mu              sync.RWMutex
	
	// Event handling
	eventHandlers   []EventHandler
	
	// Statistics
	stats           *MonitorStats
}

// MonitorConfig defines configuration for drift monitoring.
type MonitorConfig struct {
	// Scanning configuration
	DefaultScanInterval    time.Duration `json:"default_scan_interval" yaml:"default_scan_interval"`
	MinScanInterval       time.Duration `json:"min_scan_interval" yaml:"min_scan_interval"`
	MaxScanInterval       time.Duration `json:"max_scan_interval" yaml:"max_scan_interval"`
	
	// Device management
	MaxMonitoredDevices   int           `json:"max_monitored_devices" yaml:"max_monitored_devices"`
	DeviceTimeout         time.Duration `json:"device_timeout" yaml:"device_timeout"`
	HealthCheckInterval   time.Duration `json:"health_check_interval" yaml:"health_check_interval"`
	
	// Performance
	MaxConcurrentScans    int           `json:"max_concurrent_scans" yaml:"max_concurrent_scans"`
	ScanBatchSize        int           `json:"scan_batch_size" yaml:"scan_batch_size"`
	EnableParallelScanning bool         `json:"enable_parallel_scanning" yaml:"enable_parallel_scanning"`
	
	// Storage configuration
	HistoryLookbackPeriod time.Duration `json:"history_lookback_period" yaml:"history_lookback_period"`
	ComparisonWindow      time.Duration `json:"comparison_window" yaml:"comparison_window"`
	
	// Event handling
	MaxEventBuffer        int           `json:"max_event_buffer" yaml:"max_event_buffer"`
	EventProcessingDelay  time.Duration `json:"event_processing_delay" yaml:"event_processing_delay"`
	
	// Error handling
	MaxRetries           int           `json:"max_retries" yaml:"max_retries"`
	RetryBackoff         time.Duration `json:"retry_backoff" yaml:"retry_backoff"`
	ErrorThreshold       int           `json:"error_threshold" yaml:"error_threshold"`
}

// DeviceMonitorInfo tracks monitoring information for a device.
type DeviceMonitorInfo struct {
	DeviceID         string        `json:"device_id"`
	LastScanTime     time.Time     `json:"last_scan_time"`
	NextScanTime     time.Time     `json:"next_scan_time"`
	ScanCount        int64         `json:"scan_count"`
	LastDriftTime    *time.Time    `json:"last_drift_time,omitempty"`
	DriftEventCount  int64         `json:"drift_event_count"`
	ErrorCount       int64         `json:"error_count"`
	Status          DeviceStatus  `json:"status"`
	CustomInterval   *time.Duration `json:"custom_interval,omitempty"`
	LastDNAHash      string        `json:"last_dna_hash"`
	HealthStatus     string        `json:"health_status"`
}

// DeviceOperation represents an operation on a monitored device.
type DeviceOperation struct {
	Type     DeviceOpType `json:"type"`
	DeviceID string       `json:"device_id"`
	Data     interface{}  `json:"data,omitempty"`
}

// EventHandler defines the interface for handling drift events.
type EventHandler interface {
	HandleEvent(ctx context.Context, event *DriftEvent) error
	GetHandlerInfo() *HandlerInfo
}

// HandlerInfo provides information about an event handler.
type HandlerInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Priority    int    `json:"priority"`
	Async       bool   `json:"async"`
}

// Enum types

// DeviceStatus represents the monitoring status of a device.
type DeviceStatus string

const (
	DeviceStatusActive    DeviceStatus = "active"
	DeviceStatusInactive  DeviceStatus = "inactive"
	DeviceStatusError     DeviceStatus = "error"
	DeviceStatusSuspended DeviceStatus = "suspended"
)

// DeviceOpType represents types of device operations.
type DeviceOpType string

const (
	DeviceOpAdd    DeviceOpType = "add"
	DeviceOpRemove DeviceOpType = "remove"
	DeviceOpUpdate DeviceOpType = "update"
	DeviceOpScan   DeviceOpType = "scan"
)

// NewMonitor creates a new drift monitoring service.
func NewMonitor(config *MonitorConfig, detector Detector, storage *storage.Manager, logger logging.Logger) (Monitor, error) {
	if config == nil {
		config = DefaultMonitorConfig()
	}
	
	if err := validateMonitorConfig(config); err != nil {
		return nil, fmt.Errorf("invalid monitor config: %w", err)
	}
	
	if detector == nil {
		return nil, fmt.Errorf("detector is required")
	}
	
	if storage == nil {
		return nil, fmt.Errorf("storage manager is required")
	}
	
	m := &monitor{
		logger:           logger,
		config:           config,
		detector:         detector,
		storage:          storage,
		monitoredDevices: make(map[string]*DeviceMonitorInfo),
		scanInterval:     config.DefaultScanInterval,
		stopChan:         make(chan struct{}),
		deviceChan:       make(chan DeviceOperation, 100),
		eventHandlers:    make([]EventHandler, 0),
		stats: &MonitorStats{
			ScanInterval:        config.DefaultScanInterval,
			MonitoringStatus:    MonitorStatusStopped,
		},
	}
	
	logger.Info("Drift monitor initialized",
		"scan_interval", config.DefaultScanInterval,
		"max_devices", config.MaxMonitoredDevices,
		"parallel_scanning", config.EnableParallelScanning)
	
	return m, nil
}

// Start begins continuous drift monitoring.
func (m *monitor) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.running {
		return fmt.Errorf("monitor is already running")
	}
	
	m.running = true
	m.stats.MonitoringStatus = MonitorStatusRunning
	
	m.logger.Info("Starting drift monitoring service",
		"monitored_devices", len(m.monitoredDevices),
		"scan_interval", m.scanInterval)
	
	// Start background goroutines
	go m.scanWorker(ctx)
	go m.deviceOperationWorker(ctx)
	go m.healthCheckWorker(ctx)
	
	return nil
}

// Stop halts drift monitoring.
func (m *monitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.running {
		return fmt.Errorf("monitor is not running")
	}
	
	m.logger.Info("Stopping drift monitoring service")
	
	// Signal stop
	close(m.stopChan)
	m.running = false
	m.stats.MonitoringStatus = MonitorStatusStopped
	
	return nil
}

// SetInterval updates the monitoring scan interval.
func (m *monitor) SetInterval(interval time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if interval < m.config.MinScanInterval {
		interval = m.config.MinScanInterval
	}
	if interval > m.config.MaxScanInterval {
		interval = m.config.MaxScanInterval
	}
	
	m.scanInterval = interval
	m.stats.ScanInterval = interval
	
	if m.logger != nil {
		m.logger.Info("Scan interval updated", "new_interval", interval)
	}
}

// GetMonitoredDevices returns list of devices being monitored.
func (m *monitor) GetMonitoredDevices() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	devices := make([]string, 0, len(m.monitoredDevices))
	for deviceID := range m.monitoredDevices {
		devices = append(devices, deviceID)
	}
	
	return devices
}

// AddDevice adds a device to drift monitoring.
func (m *monitor) AddDevice(deviceID string) error {
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
		DeviceID:      deviceID,
		LastScanTime:  time.Time{},
		NextScanTime:  time.Now().Add(m.scanInterval),
		Status:        DeviceStatusActive,
		HealthStatus:  "healthy",
	}
	
	m.monitoredDevices[deviceID] = info
	m.stats.MonitoredDevices = len(m.monitoredDevices)
	
	// Send operation to worker
	if m.running {
		select {
		case m.deviceChan <- DeviceOperation{Type: DeviceOpAdd, DeviceID: deviceID}:
		default:
			m.logger.Warn("Device operation channel full, operation may be delayed")
		}
	}
	
	if m.logger != nil {
		m.logger.Info("Device added to monitoring", "device_id", deviceID)
	}
	
	return nil
}

// RemoveDevice removes a device from drift monitoring.
func (m *monitor) RemoveDevice(deviceID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if _, exists := m.monitoredDevices[deviceID]; !exists {
		return fmt.Errorf("device %s is not being monitored", deviceID)
	}
	
	delete(m.monitoredDevices, deviceID)
	m.stats.MonitoredDevices = len(m.monitoredDevices)
	
	// Send operation to worker
	if m.running {
		select {
		case m.deviceChan <- DeviceOperation{Type: DeviceOpRemove, DeviceID: deviceID}:
		default:
			m.logger.Warn("Device operation channel full, operation may be delayed")
		}
	}
	
	if m.logger != nil {
		m.logger.Info("Device removed from monitoring", "device_id", deviceID)
	}
	
	return nil
}

// GetMonitorStats returns monitoring statistics.
func (m *monitor) GetMonitorStats() *MonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	
	// Update current statistics
	stats := *m.stats
	stats.MonitoredDevices = len(m.monitoredDevices)
	stats.LastScanTime = time.Now() // This would be updated by scan worker
	
	// Count devices with drift
	devicesWithDrift := 0
	for _, info := range m.monitoredDevices {
		if info.DriftEventCount > 0 {
			devicesWithDrift++
		}
	}
	stats.DevicesWithDrift = devicesWithDrift
	
	return &stats
}

// AddEventHandler adds an event handler for drift events.
func (m *monitor) AddEventHandler(handler EventHandler) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	m.eventHandlers = append(m.eventHandlers, handler)
	
	info := handler.GetHandlerInfo()
	m.logger.Info("Event handler added",
		"handler_name", info.Name,
		"priority", info.Priority,
		"async", info.Async)
}

// Private methods

func (m *monitor) scanWorker(ctx context.Context) {
	ticker := time.NewTicker(m.scanInterval)
	defer ticker.Stop()
	
	m.logger.Info("Scan worker started")
	
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Scan worker stopped due to context cancellation")
			return
		case <-m.stopChan:
			m.logger.Info("Scan worker stopped")
			return
		case <-ticker.C:
			m.performScan(ctx)
		}
	}
}

func (m *monitor) deviceOperationWorker(ctx context.Context) {
	m.logger.Info("Device operation worker started")
	
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Device operation worker stopped due to context cancellation")
			return
		case <-m.stopChan:
			m.logger.Info("Device operation worker stopped")
			return
		case op := <-m.deviceChan:
			m.processDeviceOperation(ctx, op)
		}
	}
}

func (m *monitor) healthCheckWorker(ctx context.Context) {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()
	
	m.logger.Info("Health check worker started")
	
	for {
		select {
		case <-ctx.Done():
			m.logger.Info("Health check worker stopped due to context cancellation")
			return
		case <-m.stopChan:
			m.logger.Info("Health check worker stopped")
			return
		case <-ticker.C:
			m.performHealthCheck(ctx)
		}
	}
}

func (m *monitor) performScan(ctx context.Context) {
	startTime := time.Now()
	m.stats.LastScanTime = startTime
	
	m.mu.RLock()
	devicesToScan := m.getDevicesToScan()
	m.mu.RUnlock()
	
	if len(devicesToScan) == 0 {
		return
	}
	
	m.logger.Debug("Starting drift scan", "devices_to_scan", len(devicesToScan))
	
	scannedCount := 0
	if m.config.EnableParallelScanning {
		scannedCount = m.performParallelScan(ctx, devicesToScan)
	} else {
		scannedCount = m.performSequentialScan(ctx, devicesToScan)
	}
	
	// Update statistics
	m.stats.ScansCompleted++
	m.stats.AverageScanDuration = time.Since(startTime)
	
	m.logger.Debug("Drift scan completed",
		"devices_scanned", scannedCount,
		"scan_duration", time.Since(startTime))
}

func (m *monitor) getDevicesToScan() []string {
	var devices []string
	now := time.Now()
	
	for deviceID, info := range m.monitoredDevices {
		if info.Status == DeviceStatusActive && now.After(info.NextScanTime) {
			devices = append(devices, deviceID)
		}
	}
	
	return devices
}

func (m *monitor) performParallelScan(ctx context.Context, devices []string) int {
	concurrency := m.config.MaxConcurrentScans
	if concurrency <= 0 {
		concurrency = 5
	}
	
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	scannedCount := 0
	
	for _, deviceID := range devices {
		select {
		case <-ctx.Done():
			return scannedCount
		case semaphore <- struct{}{}:
			wg.Add(1)
			go func(devID string) {
				defer wg.Done()
				defer func() { <-semaphore }()
				
				if m.scanDevice(ctx, devID) {
					scannedCount++
				}
			}(deviceID)
		}
	}
	
	wg.Wait()
	return scannedCount
}

func (m *monitor) performSequentialScan(ctx context.Context, devices []string) int {
	scannedCount := 0
	
	for _, deviceID := range devices {
		select {
		case <-ctx.Done():
			return scannedCount
		default:
			if m.scanDevice(ctx, deviceID) {
				scannedCount++
			}
		}
	}
	
	return scannedCount
}

func (m *monitor) scanDevice(ctx context.Context, deviceID string) bool {
	m.logger.Debug("Scanning device for drift", "device_id", deviceID)
	
	// Get device info
	m.mu.RLock()
	_, exists := m.monitoredDevices[deviceID]
	m.mu.RUnlock()
	
	if !exists {
		if m.logger != nil {
			m.logger.Warn("Device not found in monitored devices", "device_id", deviceID)
		}
		return false
	}
	
	// Get current and previous DNA
	current, err := m.getCurrentDNA(ctx, deviceID)
	if err != nil {
		m.logger.Error("Failed to get current DNA", "error", err, "device_id", deviceID)
		m.updateDeviceError(deviceID, err)
		return false
	}
	
	previous, err := m.getPreviousDNA(ctx, deviceID)
	if err != nil {
		m.logger.Debug("Failed to get previous DNA (may be first scan)", "error", err, "device_id", deviceID)
		// First scan - store current DNA and return
		m.updateDeviceSuccess(deviceID, current)
		return true
	}
	
	// Detect drift
	events, err := m.detector.DetectDrift(ctx, previous, current)
	if err != nil {
		m.logger.Error("Failed to detect drift", "error", err, "device_id", deviceID)
		m.updateDeviceError(deviceID, err)
		return false
	}
	
	// Process events
	if len(events) > 0 {
		m.logger.Info("Drift detected", "device_id", deviceID, "event_count", len(events))
		m.processEvents(ctx, events)
		
		// Update device drift statistics
		m.mu.Lock()
		if deviceInfo, exists := m.monitoredDevices[deviceID]; exists {
			deviceInfo.DriftEventCount += int64(len(events))
			now := time.Now()
			deviceInfo.LastDriftTime = &now
		}
		m.mu.Unlock()
	}
	
	// Update device scan info
	m.updateDeviceSuccess(deviceID, current)
	
	return true
}

func (m *monitor) getCurrentDNA(ctx context.Context, deviceID string) (*commonpb.DNA, error) {
	// This would typically collect fresh DNA from the device
	// For now, get the most recent from storage
	record, err := m.storage.GetCurrent(ctx, deviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get current DNA: %w", err)
	}
	
	return record.DNA, nil
}

func (m *monitor) getPreviousDNA(ctx context.Context, deviceID string) (*commonpb.DNA, error) {
	// Get DNA from comparison window ago
	options := &storage.QueryOptions{
		TimeRange: &storage.TimeRange{
			Start: time.Now().Add(-m.config.ComparisonWindow),
			End:   time.Now().Add(-m.config.ComparisonWindow + time.Minute), // Small window
		},
		Limit:       1,
		IncludeData: true,
	}
	
	result, err := m.storage.GetHistory(ctx, deviceID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to get previous DNA: %w", err)
	}
	
	if len(result.Records) == 0 {
		return nil, fmt.Errorf("no previous DNA found for device %s", deviceID)
	}
	
	return result.Records[0].DNA, nil
}

func (m *monitor) processEvents(ctx context.Context, events []*DriftEvent) {
	for _, event := range events {
		// Handle with registered handlers
		for _, handler := range m.eventHandlers {
			handlerInfo := handler.GetHandlerInfo()
			
			if handlerInfo.Async {
				// Handle asynchronously
				go func(h EventHandler, e *DriftEvent) {
					if err := h.HandleEvent(ctx, e); err != nil {
						m.logger.Error("Async event handler failed",
							"error", err,
							"handler", handlerInfo.Name,
							"event_id", e.ID)
					}
				}(handler, event)
			} else {
				// Handle synchronously
				if err := handler.HandleEvent(ctx, event); err != nil {
					m.logger.Error("Event handler failed",
						"error", err,
						"handler", handlerInfo.Name,
						"event_id", event.ID)
				}
			}
		}
	}
}

func (m *monitor) updateDeviceSuccess(deviceID string, currentDNA *commonpb.DNA) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if info, exists := m.monitoredDevices[deviceID]; exists {
		info.LastScanTime = time.Now()
		info.NextScanTime = time.Now().Add(m.scanInterval)
		info.ScanCount++
		info.Status = DeviceStatusActive
		info.HealthStatus = "healthy"
		
		// Update DNA hash for comparison
		if currentDNA != nil {
			info.LastDNAHash = fmt.Sprintf("%x", currentDNA.Id)
		}
	}
}

func (m *monitor) updateDeviceError(deviceID string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if info, exists := m.monitoredDevices[deviceID]; exists {
		info.ErrorCount++
		info.LastScanTime = time.Now()
		info.NextScanTime = time.Now().Add(m.scanInterval * 2) // Back off on errors
		
		// Update status based on error count
		if info.ErrorCount >= int64(m.config.ErrorThreshold) {
			info.Status = DeviceStatusError
			info.HealthStatus = "unhealthy"
		} else {
			info.HealthStatus = "degraded"
		}
	}
}

func (m *monitor) processDeviceOperation(ctx context.Context, op DeviceOperation) {
	switch op.Type {
	case DeviceOpAdd:
		// Device already added in AddDevice method
		m.logger.Debug("Device add operation processed", "device_id", op.DeviceID)
	case DeviceOpRemove:
		// Device already removed in RemoveDevice method
		m.logger.Debug("Device remove operation processed", "device_id", op.DeviceID)
	case DeviceOpUpdate:
		// Handle device updates
		m.logger.Debug("Device update operation processed", "device_id", op.DeviceID)
	case DeviceOpScan:
		// Trigger immediate scan
		m.scanDevice(ctx, op.DeviceID)
	}
}

func (m *monitor) performHealthCheck(ctx context.Context) {
	m.logger.Debug("Performing health check on monitored devices")
	
	m.mu.RLock()
	devices := make([]*DeviceMonitorInfo, 0, len(m.monitoredDevices))
	for _, info := range m.monitoredDevices {
		devices = append(devices, info)
	}
	m.mu.RUnlock()
	
	for _, info := range devices {
		// Check if device hasn't been scanned recently
		if time.Since(info.LastScanTime) > m.config.DeviceTimeout {
			m.logger.Warn("Device scan timeout", 
				"device_id", info.DeviceID,
				"last_scan", info.LastScanTime)
			
			m.mu.Lock()
			if deviceInfo, exists := m.monitoredDevices[info.DeviceID]; exists {
				deviceInfo.Status = DeviceStatusInactive
				deviceInfo.HealthStatus = "degraded"
			}
			m.mu.Unlock()
		}
	}
}

// DefaultMonitorConfig returns a default configuration for drift monitoring.
func DefaultMonitorConfig() *MonitorConfig {
	return &MonitorConfig{
		DefaultScanInterval:    5 * time.Minute,  // Meet 5-minute requirement
		MinScanInterval:       1 * time.Minute,
		MaxScanInterval:       60 * time.Minute,
		MaxMonitoredDevices:   1000,
		DeviceTimeout:         15 * time.Minute,
		HealthCheckInterval:   10 * time.Minute,
		MaxConcurrentScans:    10,
		ScanBatchSize:        50,
		EnableParallelScanning: true,
		HistoryLookbackPeriod: 24 * time.Hour,
		ComparisonWindow:      10 * time.Minute,  // Compare with DNA from 10 minutes ago
		MaxEventBuffer:        1000,
		EventProcessingDelay:  1 * time.Second,
		MaxRetries:           3,
		RetryBackoff:         30 * time.Second,
		ErrorThreshold:       5,
	}
}

func validateMonitorConfig(config *MonitorConfig) error {
	if config.DefaultScanInterval < time.Minute {
		return fmt.Errorf("default scan interval must be at least 1 minute")
	}
	
	if config.MaxMonitoredDevices <= 0 {
		return fmt.Errorf("max monitored devices must be positive")
	}
	
	if config.MaxConcurrentScans <= 0 {
		config.MaxConcurrentScans = 5
	}
	
	if config.ScanBatchSize <= 0 {
		config.ScanBatchSize = 10
	}
	
	return nil
}