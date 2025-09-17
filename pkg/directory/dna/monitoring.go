// Package dna - Directory DNA Monitoring Integration
//
// This file integrates DirectoryDNA monitoring with CFGMS's existing monitoring
// and observability systems, providing metrics, health checks, and alerting
// capabilities for directory drift detection.

package dna

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

// DirectoryDNAMonitoringSystem integrates directory DNA collection and drift detection
// with CFGMS's monitoring infrastructure.
type DirectoryDNAMonitoringSystem struct {
	collector       DirectoryDNACollector
	driftDetector   DirectoryDriftDetector
	storage         DirectoryDNAStorage
	logger          *logging.ModuleLogger
	
	// Monitoring configuration
	config          *MonitoringConfig
	
	// State management
	mutex           sync.RWMutex
	isRunning       bool
	startTime       time.Time
	stopChan        chan struct{}
	doneChan        chan struct{}
	
	// Metrics and statistics
	metrics         *DirectoryMonitoringMetrics
	
	// Health monitoring
	healthChecker   *DirectoryHealthChecker
}

// MonitoringConfig defines configuration for directory DNA monitoring.
type MonitoringConfig struct {
	// Collection Settings
	CollectionInterval    time.Duration `json:"collection_interval"`     // How often to collect DNA
	DriftCheckInterval    time.Duration `json:"drift_check_interval"`    // How often to check for drift
	HealthCheckInterval   time.Duration `json:"health_check_interval"`   // How often to perform health checks
	
	// Monitoring Scope
	MonitoredObjectTypes  []interfaces.DirectoryObjectType `json:"monitored_object_types"`
	MonitoredProviders    []string      `json:"monitored_providers"`
	MonitoredTenants      []string      `json:"monitored_tenants,omitempty"`
	
	// Alert Configuration
	AlertOnDriftSeverity  DriftSeverity `json:"alert_on_drift_severity"`  // Minimum severity for alerts
	AlertOnHealthIssues   bool          `json:"alert_on_health_issues"`   // Alert on health issues
	
	// Performance Tuning
	MaxConcurrentCollections int       `json:"max_concurrent_collections"`
	MaxConcurrentDriftChecks int       `json:"max_concurrent_drift_checks"`
	CollectionTimeout        time.Duration `json:"collection_timeout"`
	
	// Retention
	MetricsRetention      time.Duration `json:"metrics_retention"`        // How long to keep metrics
	HealthDataRetention   time.Duration `json:"health_data_retention"`    // How long to keep health data
}

// DirectoryMonitoringMetrics provides comprehensive metrics for directory monitoring.
type DirectoryMonitoringMetrics struct {
	// Collection Metrics
	TotalCollections       int64         `json:"total_collections"`
	SuccessfulCollections  int64         `json:"successful_collections"`
	FailedCollections      int64         `json:"failed_collections"`
	AverageCollectionTime  time.Duration `json:"avg_collection_time"`
	LastCollectionTime     time.Time     `json:"last_collection_time"`
	
	// Drift Detection Metrics
	TotalDriftChecks       int64         `json:"total_drift_checks"`
	DriftsDetected         int64         `json:"drifts_detected"`
	CriticalDriftsDetected int64         `json:"critical_drifts_detected"`
	AverageDriftCheckTime  time.Duration `json:"avg_drift_check_time"`
	LastDriftCheckTime     time.Time     `json:"last_drift_check_time"`
	
	// Object Metrics
	ObjectsMonitored       map[interfaces.DirectoryObjectType]int64 `json:"objects_monitored"`
	ObjectsWithDrift       map[interfaces.DirectoryObjectType]int64 `json:"objects_with_drift"`
	
	// Provider Metrics
	ProviderMetrics        map[string]*ProviderMonitoringMetrics `json:"provider_metrics"`
	
	// Performance Metrics
	SystemCpuUsage         float64       `json:"system_cpu_usage"`
	SystemMemoryUsage      int64         `json:"system_memory_usage"`
	StorageUsage           int64         `json:"storage_usage"`
	
	// Health Metrics
	OverallHealth          string        `json:"overall_health"`
	ComponentHealth        map[string]string `json:"component_health"`
	HealthIssueCount       int64         `json:"health_issue_count"`
	LastHealthCheck        time.Time     `json:"last_health_check"`
	
	// Uptime
	MonitoringUptime       time.Duration `json:"monitoring_uptime"`
	LastRestart            time.Time     `json:"last_restart"`
}

// ProviderMonitoringMetrics provides metrics for a specific directory provider.
type ProviderMonitoringMetrics struct {
	ProviderName           string        `json:"provider_name"`
	ObjectsMonitored       int64         `json:"objects_monitored"`
	LastCollectionTime     time.Time     `json:"last_collection_time"`
	CollectionSuccessRate  float64       `json:"collection_success_rate"`
	AverageResponseTime    time.Duration `json:"avg_response_time"`
	ErrorCount             int64         `json:"error_count"`
	DriftsDetected         int64         `json:"drifts_detected"`
	HealthStatus           string        `json:"health_status"`
}

// DirectoryHealthChecker performs comprehensive health checks for directory monitoring.
type DirectoryHealthChecker struct {
	collector      DirectoryDNACollector
	driftDetector  DirectoryDriftDetector
	storage        DirectoryDNAStorage
	logger         logging.Logger
	
	// Health check configuration
	checkInterval  time.Duration
	timeout        time.Duration
	
	// Health state
	lastCheck      time.Time
	currentStatus  *DirectoryHealthStatus
}

// DirectoryHealthStatus represents the overall health of directory monitoring.
type DirectoryHealthStatus struct {
	OverallStatus          HealthStatus            `json:"overall_status"`
	LastCheck              time.Time               `json:"last_check"`
	ComponentStatuses      map[string]HealthStatus `json:"component_statuses"`
	Issues                 []HealthIssue           `json:"issues,omitempty"`
	Recommendations        []string                `json:"recommendations,omitempty"`
	
	// Component-specific health
	CollectorHealth        *ComponentHealth        `json:"collector_health"`
	DriftDetectorHealth    *ComponentHealth        `json:"drift_detector_health"`
	StorageHealth          *ComponentHealth        `json:"storage_health"`
	
	// System health
	ResourceUsage          *ResourceUsage          `json:"resource_usage"`
	PerformanceMetrics     *PerformanceMetrics     `json:"performance_metrics"`
}

// ComponentHealth represents the health of a specific component.
type ComponentHealth struct {
	Status                 HealthStatus            `json:"status"`
	LastCheck              time.Time               `json:"last_check"`
	Uptime                 time.Duration           `json:"uptime"`
	ErrorRate              float64                 `json:"error_rate"`
	ResponseTime           time.Duration           `json:"response_time"`
	ThroughputRate         float64                 `json:"throughput_rate"`
	Issues                 []string                `json:"issues,omitempty"`
}

// ResourceUsage represents system resource usage metrics.
type ResourceUsage struct {
	CpuUsagePercent        float64                 `json:"cpu_usage_percent"`
	MemoryUsageMB          int64                   `json:"memory_usage_mb"`
	DiskUsageMB            int64                   `json:"disk_usage_mb"`
	NetworkIOPS            float64                 `json:"network_iops"`
	DiskIOPS               float64                 `json:"disk_iops"`
}

// PerformanceMetrics represents performance metrics for directory monitoring.
type PerformanceMetrics struct {
	CollectionsPerSecond   float64                 `json:"collections_per_second"`
	DriftChecksPerSecond   float64                 `json:"drift_checks_per_second"`
	AverageLatency         time.Duration           `json:"average_latency"`
	P95Latency             time.Duration           `json:"p95_latency"`
	P99Latency             time.Duration           `json:"p99_latency"`
	ThroughputMBps         float64                 `json:"throughput_mbps"`
}

// HealthStatus represents health status levels.
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
	HealthStatusCritical  HealthStatus = "critical"
)

// HealthIssue represents a health issue with severity and details.
type HealthIssue struct {
	Severity               string                  `json:"severity"`
	Component              string                  `json:"component"`
	Issue                  string                  `json:"issue"`
	Impact                 string                  `json:"impact"`
	Recommendation         string                  `json:"recommendation"`
	FirstDetected          time.Time               `json:"first_detected"`
	LastDetected           time.Time               `json:"last_detected"`
}

// NewDirectoryDNAMonitoringSystem creates a new directory DNA monitoring system.
func NewDirectoryDNAMonitoringSystem(
	collector DirectoryDNACollector,
	driftDetector DirectoryDriftDetector,
	storage DirectoryDNAStorage,
	logger logging.Logger,
) *DirectoryDNAMonitoringSystem {
	// Create structured logger for directory DNA monitoring
	dnaLogger := logging.ForComponent("directory_dna").WithField("component", "monitoring")

	return &DirectoryDNAMonitoringSystem{
		collector:     collector,
		driftDetector: driftDetector,
		storage:       storage,
		logger:        dnaLogger,
		config:        getDefaultMonitoringConfig(),
		metrics:       &DirectoryMonitoringMetrics{
			ObjectsMonitored:  make(map[interfaces.DirectoryObjectType]int64),
			ObjectsWithDrift:  make(map[interfaces.DirectoryObjectType]int64),
			ProviderMetrics:   make(map[string]*ProviderMonitoringMetrics),
			ComponentHealth:   make(map[string]string),
		},
		healthChecker: &DirectoryHealthChecker{
			collector:     collector,
			driftDetector: driftDetector,
			storage:       storage,
			logger:        logger,
			checkInterval: 30 * time.Second,
			timeout:       10 * time.Second,
			currentStatus: &DirectoryHealthStatus{
				OverallStatus:     HealthStatusHealthy,
				LastCheck:         time.Now(),
				ComponentStatuses: make(map[string]HealthStatus),
			},
		},
	}
}

// getDefaultMonitoringConfig returns default monitoring configuration.
func getDefaultMonitoringConfig() *MonitoringConfig {
	return &MonitoringConfig{
		CollectionInterval:       15 * time.Minute,
		DriftCheckInterval:       5 * time.Minute,
		HealthCheckInterval:      30 * time.Second,
		MonitoredObjectTypes:     []interfaces.DirectoryObjectType{
			interfaces.DirectoryObjectTypeUser,
			interfaces.DirectoryObjectTypeGroup,
			interfaces.DirectoryObjectTypeOU,
		},
		AlertOnDriftSeverity:     DriftSeverityMedium,
		AlertOnHealthIssues:      true,
		MaxConcurrentCollections: 5,
		MaxConcurrentDriftChecks: 10,
		CollectionTimeout:        30 * time.Second,
		MetricsRetention:         7 * 24 * time.Hour,
		HealthDataRetention:      24 * time.Hour,
	}
}

// Monitoring Control Methods

// Start starts the directory DNA monitoring system.
func (m *DirectoryDNAMonitoringSystem) Start(ctx context.Context) error {
	m.mutex.Lock()
	if m.isRunning {
		m.mutex.Unlock()
		return fmt.Errorf("monitoring system is already running")
	}
	
	m.isRunning = true
	m.startTime = time.Now()
	m.stopChan = make(chan struct{})
	m.doneChan = make(chan struct{})
	m.mutex.Unlock()
	
	m.logger.InfoCtx(ctx, "Starting directory DNA monitoring system",
		"operation", "monitoring_start",
		"collection_interval", m.config.CollectionInterval,
		"drift_check_interval", m.config.DriftCheckInterval,
		"component", "directory_dna")
	
	// Start monitoring goroutines
	go m.monitoringLoop(ctx)
	go m.healthCheckLoop(ctx)
	
	// Initialize metrics
	m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
		metrics.LastRestart = time.Now()
		metrics.OverallHealth = "starting"
	})
	
	return nil
}

// Stop stops the directory DNA monitoring system.
func (m *DirectoryDNAMonitoringSystem) Stop() error {
	m.mutex.Lock()
	if !m.isRunning {
		m.mutex.Unlock()
		return fmt.Errorf("monitoring system is not running")
	}
	
	close(m.stopChan)
	m.mutex.Unlock()
	
	m.logger.Info("Stopping directory DNA monitoring system")
	
	// Wait for monitoring loops to complete
	select {
	case <-m.doneChan:
		m.logger.Info("Directory DNA monitoring system stopped successfully")
	case <-time.After(30 * time.Second):
		m.logger.Warn("Directory DNA monitoring system stop timeout")
	}
	
	m.mutex.Lock()
	m.isRunning = false
	m.mutex.Unlock()
	
	return nil
}

// IsRunning returns whether the monitoring system is currently running.
func (m *DirectoryDNAMonitoringSystem) IsRunning() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.isRunning
}

// Monitoring Loop Implementation

// monitoringLoop runs the main monitoring loop.
func (m *DirectoryDNAMonitoringSystem) monitoringLoop(ctx context.Context) {
	defer close(m.doneChan)
	
	collectionTicker := time.NewTicker(m.config.CollectionInterval)
	defer collectionTicker.Stop()
	
	driftCheckTicker := time.NewTicker(m.config.DriftCheckInterval)
	defer driftCheckTicker.Stop()
	
	for {
		select {
		case <-m.stopChan:
			m.logger.Info("Monitoring loop stopped")
			return
			
		case <-ctx.Done():
			m.logger.Info("Monitoring loop cancelled by context")
			return
			
		case <-collectionTicker.C:
			m.performDNACollection(ctx)
			
		case <-driftCheckTicker.C:
			m.performDriftCheck(ctx)
		}
	}
}

// healthCheckLoop runs the health checking loop.
func (m *DirectoryDNAMonitoringSystem) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(m.config.HealthCheckInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.stopChan:
			return
			
		case <-ctx.Done():
			return
			
		case <-ticker.C:
			m.performHealthCheck(ctx)
		}
	}
}

// performDNACollection performs periodic DNA collection.
func (m *DirectoryDNAMonitoringSystem) performDNACollection(ctx context.Context) {
	collectionStart := time.Now()
	m.logger.Debug("Starting DNA collection cycle")
	
	// Update metrics
	m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
		metrics.TotalCollections++
		metrics.LastCollectionTime = collectionStart
	})
	
	// Collect DNA for monitored object types
	var totalCollected int64
	var errors []error
	
	for _, objectType := range m.config.MonitoredObjectTypes {
		collected, err := m.collectDNAForObjectType(ctx, objectType)
		if err != nil {
			errors = append(errors, err)
			m.logger.Warn("DNA collection failed for object type",
				"object_type", objectType, "error", err)
		} else {
			totalCollected += collected
			
			// Update object-specific metrics
			m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
				metrics.ObjectsMonitored[objectType] += collected
			})
		}
	}
	
	// Update collection metrics
	duration := time.Since(collectionStart)
	if len(errors) == 0 {
		m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
			metrics.SuccessfulCollections++
			metrics.AverageCollectionTime = m.updateAverageTime(
				metrics.AverageCollectionTime, duration, metrics.TotalCollections)
		})
	} else {
		m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
			metrics.FailedCollections++
		})
	}
	
	m.logger.Debug("DNA collection cycle completed",
		"duration", duration,
		"objects_collected", totalCollected,
		"errors", len(errors))
}

// collectDNAForObjectType collects DNA for a specific object type.
func (m *DirectoryDNAMonitoringSystem) collectDNAForObjectType(ctx context.Context, objectType interfaces.DirectoryObjectType) (int64, error) {
	var collected int64
	
	switch objectType {
	case interfaces.DirectoryObjectTypeUser:
		userDNA, err := m.collector.CollectAllUsers(ctx, nil)
		if err != nil {
			return 0, fmt.Errorf("failed to collect user DNA: %w", err)
		}
		collected = int64(len(userDNA))
		
		// Store collected DNA
		for _, dna := range userDNA {
			if err := m.storage.StoreDirectoryDNA(ctx, dna); err != nil {
				m.logger.Warn("Failed to store user DNA", "user_id", dna.ObjectID, "error", err)
			}
		}
		
	case interfaces.DirectoryObjectTypeGroup:
		groupDNA, err := m.collector.CollectAllGroups(ctx, nil)
		if err != nil {
			return 0, fmt.Errorf("failed to collect group DNA: %w", err)
		}
		collected = int64(len(groupDNA))
		
		// Store collected DNA
		for _, dna := range groupDNA {
			if err := m.storage.StoreDirectoryDNA(ctx, dna); err != nil {
				m.logger.Warn("Failed to store group DNA", "group_id", dna.ObjectID, "error", err)
			}
		}
		
	case interfaces.DirectoryObjectTypeOU:
		ouDNA, err := m.collector.CollectAllOUs(ctx, nil)
		if err != nil {
			return 0, fmt.Errorf("failed to collect OU DNA: %w", err)
		}
		collected = int64(len(ouDNA))
		
		// Store collected DNA
		for _, dna := range ouDNA {
			if err := m.storage.StoreDirectoryDNA(ctx, dna); err != nil {
				m.logger.Warn("Failed to store OU DNA", "ou_id", dna.ObjectID, "error", err)
			}
		}
	}
	
	return collected, nil
}

// performDriftCheck performs periodic drift detection.
func (m *DirectoryDNAMonitoringSystem) performDriftCheck(ctx context.Context) {
	checkStart := time.Now()
	m.logger.Debug("Starting drift check cycle")
	
	// Update metrics
	m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
		metrics.TotalDriftChecks++
		metrics.LastDriftCheckTime = checkStart
	})
	
	// This would implement comprehensive drift checking logic
	// For now, just update metrics
	duration := time.Since(checkStart)
	m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
		metrics.AverageDriftCheckTime = m.updateAverageTime(
			metrics.AverageDriftCheckTime, duration, metrics.TotalDriftChecks)
	})
	
	m.logger.Debug("Drift check cycle completed", "duration", duration)
}

// performHealthCheck performs comprehensive health checks.
func (m *DirectoryDNAMonitoringSystem) performHealthCheck(ctx context.Context) {
	checkStart := time.Now()
	
	// Update health check time
	m.healthChecker.lastCheck = checkStart
	
	// Check each component
	status := &DirectoryHealthStatus{
		LastCheck:         checkStart,
		ComponentStatuses: make(map[string]HealthStatus),
	}
	
	// Check collector health
	collectorHealth := m.checkCollectorHealth(ctx)
	status.CollectorHealth = collectorHealth
	status.ComponentStatuses["collector"] = collectorHealth.Status
	
	// Check drift detector health
	detectorHealth := m.checkDriftDetectorHealth(ctx)
	status.DriftDetectorHealth = detectorHealth
	status.ComponentStatuses["drift_detector"] = detectorHealth.Status
	
	// Check storage health
	storageHealth := m.checkStorageHealth(ctx)
	status.StorageHealth = storageHealth
	status.ComponentStatuses["storage"] = storageHealth.Status
	
	// Determine overall status
	status.OverallStatus = m.calculateOverallHealth(status)
	
	// Update metrics
	m.updateMetrics(func(metrics *DirectoryMonitoringMetrics) {
		metrics.LastHealthCheck = checkStart
		metrics.OverallHealth = string(status.OverallStatus)
		for component, health := range status.ComponentStatuses {
			metrics.ComponentHealth[component] = string(health)
		}
	})
	
	// Update health checker status
	m.mutex.Lock()
	m.healthChecker.currentStatus = status
	m.mutex.Unlock()
	
	m.logger.Debug("Health check completed",
		"overall_status", status.OverallStatus,
		"duration", time.Since(checkStart))
}

// Component Health Checking Methods

// checkCollectorHealth checks the health of the DNA collector.
func (m *DirectoryDNAMonitoringSystem) checkCollectorHealth(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		LastCheck: time.Now(),
		Status:    HealthStatusHealthy,
		Uptime:    time.Since(m.startTime),
	}
	
	// Get collector stats if available
	if stats := m.collector.GetCollectionStats(); stats != nil {
		if stats.ErrorCount > 0 {
			errorRate := float64(stats.ErrorCount) / float64(stats.TotalCollections)
			health.ErrorRate = errorRate
			
			if errorRate > 0.1 { // More than 10% error rate
				health.Status = HealthStatusDegraded
				health.Issues = append(health.Issues, "High error rate in DNA collection")
			}
		}
		
		health.ResponseTime = stats.AverageCollectionTime
		if stats.TotalCollections > 0 {
			health.ThroughputRate = float64(stats.TotalCollections) / time.Since(m.startTime).Hours()
		}
	}
	
	return health
}

// checkDriftDetectorHealth checks the health of the drift detector.
func (m *DirectoryDNAMonitoringSystem) checkDriftDetectorHealth(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		LastCheck: time.Now(),
		Status:    HealthStatusHealthy,
		Uptime:    time.Since(m.startTime),
	}
	
	// Check if drift detector is monitoring
	if !m.driftDetector.IsMonitoring() {
		health.Status = HealthStatusDegraded
		health.Issues = append(health.Issues, "Drift detector not monitoring")
	}
	
	// Get drift detector stats if available
	if detectorStats := m.driftDetector.GetDriftDetectionStats(); detectorStats != nil {
		if detectorStats.HandlerErrors > 0 {
			errorRate := float64(detectorStats.HandlerErrors) / float64(detectorStats.HandlersTriggered)
			health.ErrorRate = errorRate
			
			if errorRate > 0.05 { // More than 5% error rate
				health.Status = HealthStatusDegraded
				health.Issues = append(health.Issues, "High error rate in drift handlers")
			}
		}
		
		health.ResponseTime = detectorStats.AverageComparisonTime
	}
	
	return health
}

// checkStorageHealth checks the health of the storage system.
func (m *DirectoryDNAMonitoringSystem) checkStorageHealth(ctx context.Context) *ComponentHealth {
	health := &ComponentHealth{
		LastCheck: time.Now(),
		Status:    HealthStatusHealthy,
		Uptime:    time.Since(m.startTime),
	}
	
	// Get storage stats if available
	if stats, err := m.storage.GetDirectoryStats(ctx); err == nil {
		if stats.CollectionHealth != "healthy" {
			health.Status = HealthStatusDegraded
			health.Issues = append(health.Issues, "Storage collection health degraded")
		}
		
		// Check storage usage
		if stats.TotalStorageUsed > 0 {
			// This would check against configured limits
			health.ThroughputRate = float64(stats.TotalObjects) / time.Since(m.startTime).Hours()
		}
	} else {
		health.Status = HealthStatusUnhealthy
		health.Issues = append(health.Issues, fmt.Sprintf("Cannot get storage stats: %v", err))
	}
	
	return health
}

// calculateOverallHealth determines overall system health from component health.
func (m *DirectoryDNAMonitoringSystem) calculateOverallHealth(status *DirectoryHealthStatus) HealthStatus {
	unhealthyCount := 0
	degradedCount := 0
	
	for _, componentHealth := range status.ComponentStatuses {
		switch componentHealth {
		case HealthStatusUnhealthy, HealthStatusCritical:
			unhealthyCount++
		case HealthStatusDegraded:
			degradedCount++
		}
	}
	
	// Determine overall health
	if unhealthyCount > 0 {
		return HealthStatusUnhealthy
	} else if degradedCount > 1 {
		return HealthStatusDegraded
	} else if degradedCount == 1 {
		return HealthStatusDegraded
	}
	
	return HealthStatusHealthy
}

// Utility Methods

// updateMetrics safely updates monitoring metrics.
func (m *DirectoryDNAMonitoringSystem) updateMetrics(updater func(*DirectoryMonitoringMetrics)) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	// Update uptime
	m.metrics.MonitoringUptime = time.Since(m.startTime)
	
	// Apply updates
	updater(m.metrics)
}

// updateAverageTime updates a running average time.
func (m *DirectoryDNAMonitoringSystem) updateAverageTime(currentAvg time.Duration, newTime time.Duration, count int64) time.Duration {
	if count <= 1 {
		return newTime
	}
	
	// Simple running average: (old_avg * (n-1) + new_value) / n
	totalNanoseconds := int64(currentAvg)*count + int64(newTime)
	return time.Duration(totalNanoseconds / (count + 1))
}

// Public API Methods

// GetMetrics returns current monitoring metrics.
func (m *DirectoryDNAMonitoringSystem) GetMetrics() *DirectoryMonitoringMetrics {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Return a copy to prevent race conditions
	metricsCopy := *m.metrics
	
	// Deep copy maps
	metricsCopy.ObjectsMonitored = make(map[interfaces.DirectoryObjectType]int64)
	for k, v := range m.metrics.ObjectsMonitored {
		metricsCopy.ObjectsMonitored[k] = v
	}
	
	metricsCopy.ObjectsWithDrift = make(map[interfaces.DirectoryObjectType]int64)
	for k, v := range m.metrics.ObjectsWithDrift {
		metricsCopy.ObjectsWithDrift[k] = v
	}
	
	metricsCopy.ComponentHealth = make(map[string]string)
	for k, v := range m.metrics.ComponentHealth {
		metricsCopy.ComponentHealth[k] = v
	}
	
	return &metricsCopy
}

// GetHealthStatus returns current health status.
func (m *DirectoryDNAMonitoringSystem) GetHealthStatus() *DirectoryHealthStatus {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	if m.healthChecker.currentStatus == nil {
		return &DirectoryHealthStatus{
			OverallStatus:     HealthStatusHealthy,
			LastCheck:         time.Now(),
			ComponentStatuses: make(map[string]HealthStatus),
		}
	}
	
	// Return a copy
	statusCopy := *m.healthChecker.currentStatus
	statusCopy.ComponentStatuses = make(map[string]HealthStatus)
	for k, v := range m.healthChecker.currentStatus.ComponentStatuses {
		statusCopy.ComponentStatuses[k] = v
	}
	
	return &statusCopy
}

// UpdateConfig updates the monitoring configuration.
func (m *DirectoryDNAMonitoringSystem) UpdateConfig(config *MonitoringConfig) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}
	
	// Validate configuration
	if config.CollectionInterval <= 0 {
		return fmt.Errorf("collection interval must be positive")
	}
	if config.DriftCheckInterval <= 0 {
		return fmt.Errorf("drift check interval must be positive")
	}
	if config.HealthCheckInterval <= 0 {
		return fmt.Errorf("health check interval must be positive")
	}
	
	m.config = config
	
	m.logger.Info("Monitoring configuration updated",
		"collection_interval", config.CollectionInterval,
		"drift_check_interval", config.DriftCheckInterval)
	
	return nil
}

// GetConfig returns the current monitoring configuration.
func (m *DirectoryDNAMonitoringSystem) GetConfig() *MonitoringConfig {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	
	// Return a copy
	configCopy := *m.config
	
	// Deep copy slices
	configCopy.MonitoredObjectTypes = make([]interfaces.DirectoryObjectType, len(m.config.MonitoredObjectTypes))
	copy(configCopy.MonitoredObjectTypes, m.config.MonitoredObjectTypes)
	
	configCopy.MonitoredProviders = make([]string, len(m.config.MonitoredProviders))
	copy(configCopy.MonitoredProviders, m.config.MonitoredProviders)
	
	configCopy.MonitoredTenants = make([]string, len(m.config.MonitoredTenants))
	copy(configCopy.MonitoredTenants, m.config.MonitoredTenants)
	
	return &configCopy
}