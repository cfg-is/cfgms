package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/telemetry"
)

// platformMonitor implements the PlatformMonitor interface.
type platformMonitor struct {
	mu sync.RWMutex

	// Core dependencies
	logger logging.Logger
	tracer *telemetry.Tracer
	config *MonitoringConfig

	// Component registries
	healthCheckers    map[string]HealthChecker
	metricsCollectors map[string]MetricsCollector
	anomalyDetectors  map[string]AnomalyDetector

	// Runtime state
	running   bool
	startTime time.Time
	ctx       context.Context
	cancel    context.CancelFunc

	// Background workers
	healthCheckTicker   *time.Ticker
	metricsTicket      *time.Ticker
	anomalyTicker      *time.Ticker

	// Data storage
	lastHealthResults map[string]*ComponentHealth
	lastMetrics      map[string]*ComponentMetrics
	activeAnomalies  []*Anomaly
}

// NewPlatformMonitor creates a new platform monitoring instance.
func NewPlatformMonitor(logger logging.Logger, tracer *telemetry.Tracer, config *MonitoringConfig) PlatformMonitor {
	if config == nil {
		config = DefaultMonitoringConfig()
	}

	return &platformMonitor{
		logger:            logger,
		tracer:            tracer,
		config:            config,
		healthCheckers:    make(map[string]HealthChecker),
		metricsCollectors: make(map[string]MetricsCollector),
		anomalyDetectors:  make(map[string]AnomalyDetector),
		lastHealthResults: make(map[string]*ComponentHealth),
		lastMetrics:      make(map[string]*ComponentMetrics),
		activeAnomalies:  make([]*Anomaly, 0),
	}
}

// RegisterHealthChecker registers a health checker for a component.
func (pm *platformMonitor) RegisterHealthChecker(component string, checker HealthChecker) error {
	if component == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if checker == nil {
		return fmt.Errorf("health checker cannot be nil")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.healthCheckers[component] = checker
	pm.logger.InfoCtx(context.Background(), "Registered health checker",
		"component", component)

	return nil
}

// RegisterMetricsCollector registers a metrics collector for a component.
func (pm *platformMonitor) RegisterMetricsCollector(component string, collector MetricsCollector) error {
	if component == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if collector == nil {
		return fmt.Errorf("metrics collector cannot be nil")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.metricsCollectors[component] = collector
	pm.logger.InfoCtx(context.Background(), "Registered metrics collector",
		"component", component)

	return nil
}

// RegisterAnomalyDetector registers an anomaly detector for a component.
func (pm *platformMonitor) RegisterAnomalyDetector(component string, detector AnomalyDetector) error {
	if component == "" {
		return fmt.Errorf("component name cannot be empty")
	}
	if detector == nil {
		return fmt.Errorf("anomaly detector cannot be nil")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.anomalyDetectors[component] = detector
	pm.logger.InfoCtx(context.Background(), "Registered anomaly detector",
		"component", component)

	return nil
}

// GetComponentHealth retrieves health status for a specific component.
func (pm *platformMonitor) GetComponentHealth(ctx context.Context, component string) (*ComponentHealth, error) {
	pm.mu.RLock()
	checker, exists := pm.healthCheckers[component]
	lastResult := pm.lastHealthResults[component]
	pm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no health checker registered for component: %s", component)
	}

	// Try to get fresh health status
	ctx, span := pm.tracer.Start(ctx, "platform_monitor.get_component_health")
	defer span.End()

	health, err := checker.CheckHealth(ctx)
	if err != nil {
		pm.logger.ErrorCtx(ctx, "Health check failed",
			"component", component, "error", err.Error())

		// Return last known result if available
		if lastResult != nil {
			lastResult.Status = HealthStatusUnknown
			lastResult.Message = fmt.Sprintf("Health check failed: %v", err)
			return lastResult, nil
		}

		return &ComponentHealth{
			ComponentName: component,
			Status:        HealthStatusUnknown,
			Timestamp:     time.Now(),
			Message:       fmt.Sprintf("Health check failed: %v", err),
			LastCheck:     time.Now(),
		}, err
	}

	// Update cache
	pm.mu.Lock()
	pm.lastHealthResults[component] = health
	pm.mu.Unlock()

	return health, nil
}

// GetSystemHealth retrieves overall system health status.
func (pm *platformMonitor) GetSystemHealth(ctx context.Context) (*SystemHealth, error) {
	ctx, span := pm.tracer.Start(ctx, "platform_monitor.get_system_health")
	defer span.End()

	pm.mu.RLock()
	components := make([]string, 0, len(pm.healthCheckers))
	for component := range pm.healthCheckers {
		components = append(components, component)
	}
	pm.mu.RUnlock()

	systemHealth := &SystemHealth{
		Timestamp:  time.Now(),
		Components: make(map[string]*ComponentHealth),
		Summary: HealthSummary{
			TotalComponents: len(components),
			StatusCounts:    make(map[HealthStatus]int),
		},
		Uptime:  time.Since(pm.startTime),
		Version: getVersion(),
	}

	// Collect health for all components
	healthyCounts := 0
	for _, component := range components {
		health, err := pm.GetComponentHealth(ctx, component)
		if err != nil {
			pm.logger.WarnCtx(ctx, "Failed to get component health",
				"component", component, "error", err.Error())
			continue
		}

		systemHealth.Components[component] = health
		systemHealth.Summary.StatusCounts[health.Status]++

		switch health.Status {
		case HealthStatusHealthy:
			healthyCounts++
		case HealthStatusUnhealthy:
			systemHealth.Summary.CriticalIssues = append(
				systemHealth.Summary.CriticalIssues,
				fmt.Sprintf("%s: %s", component, health.Message))
		}
	}

	systemHealth.Summary.HealthyComponents = healthyCounts

	// Determine overall system status
	if healthyCounts == len(components) {
		systemHealth.Status = HealthStatusHealthy
	} else if systemHealth.Summary.StatusCounts[HealthStatusUnhealthy] > 0 {
		systemHealth.Status = HealthStatusUnhealthy
	} else {
		systemHealth.Status = HealthStatusDegraded
	}

	return systemHealth, nil
}

// GetComponentMetrics retrieves metrics for a specific component.
func (pm *platformMonitor) GetComponentMetrics(ctx context.Context, component string) (*ComponentMetrics, error) {
	pm.mu.RLock()
	collector, exists := pm.metricsCollectors[component]
	pm.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("no metrics collector registered for component: %s", component)
	}

	ctx, span := pm.tracer.Start(ctx, "platform_monitor.get_component_metrics")
	defer span.End()

	metrics, err := collector.CollectMetrics(ctx)
	if err != nil {
		pm.logger.ErrorCtx(ctx, "Metrics collection failed",
			"component", component, "error", err.Error())
		return nil, err
	}

	// Update cache
	pm.mu.Lock()
	pm.lastMetrics[component] = metrics
	pm.mu.Unlock()

	return metrics, nil
}

// GetSystemMetrics retrieves aggregated system metrics.
func (pm *platformMonitor) GetSystemMetrics(ctx context.Context) (*SystemMetrics, error) {
	ctx, span := pm.tracer.Start(ctx, "platform_monitor.get_system_metrics")
	defer span.End()

	pm.mu.RLock()
	components := make([]string, 0, len(pm.metricsCollectors))
	for component := range pm.metricsCollectors {
		components = append(components, component)
	}
	pm.mu.RUnlock()

	systemMetrics := &SystemMetrics{
		Timestamp:  time.Now(),
		Components: make(map[string]*ComponentMetrics),
		Aggregated: &AggregatedMetrics{
			ResourceUtilization: &ResourceMetrics{},
		},
		Performance: &PerformanceMetrics{},
	}

	// Collect metrics from all components
	totalRequests := int64(0)
	totalResponseTime := time.Duration(0)
	totalThroughput := float64(0)
	totalErrors := float64(0)
	validComponents := 0

	for _, component := range components {
		metrics, err := pm.GetComponentMetrics(ctx, component)
		if err != nil {
			pm.logger.WarnCtx(ctx, "Failed to get component metrics",
				"component", component, "error", err.Error())
			continue
		}

		systemMetrics.Components[component] = metrics
		validComponents++

		// Aggregate metrics
		if metrics.Performance != nil {
			totalRequests += metrics.Performance.RequestCount
			totalResponseTime += metrics.Performance.ResponseTime
			totalThroughput += metrics.Performance.Throughput
			totalErrors += metrics.Performance.ErrorRate
		}

		// Aggregate resource metrics
		if metrics.Resource != nil {
			systemMetrics.Aggregated.ResourceUtilization.CPUPercent += metrics.Resource.CPUPercent
			systemMetrics.Aggregated.ResourceUtilization.MemoryBytes += metrics.Resource.MemoryBytes
			systemMetrics.Aggregated.ResourceUtilization.DiskBytes += metrics.Resource.DiskBytes
			systemMetrics.Aggregated.ResourceUtilization.NetworkBytesIn += metrics.Resource.NetworkBytesIn
			systemMetrics.Aggregated.ResourceUtilization.NetworkBytesOut += metrics.Resource.NetworkBytesOut
			systemMetrics.Aggregated.ResourceUtilization.Goroutines += metrics.Resource.Goroutines
			systemMetrics.Aggregated.ResourceUtilization.FileDescriptors += metrics.Resource.FileDescriptors
		}
	}

	// Calculate averages
	if validComponents > 0 {
		systemMetrics.Aggregated.TotalRequests = totalRequests
		systemMetrics.Aggregated.AverageResponseTime = totalResponseTime / time.Duration(validComponents)
		systemMetrics.Aggregated.TotalThroughput = totalThroughput
		systemMetrics.Aggregated.SystemErrorRate = totalErrors / float64(validComponents)

		// Average resource utilization
		systemMetrics.Aggregated.ResourceUtilization.CPUPercent /= float64(validComponents)
	}

	return systemMetrics, nil
}

// GetAnomalies retrieves current system anomalies.
func (pm *platformMonitor) GetAnomalies(ctx context.Context) ([]*Anomaly, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Return copy of active anomalies
	anomalies := make([]*Anomaly, len(pm.activeAnomalies))
	copy(anomalies, pm.activeAnomalies)

	return anomalies, nil
}

// Start begins the monitoring background processes.
func (pm *platformMonitor) Start(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.running {
		return fmt.Errorf("platform monitor is already running")
	}

	pm.ctx, pm.cancel = context.WithCancel(ctx)
	pm.startTime = time.Now()
	pm.running = true

	// Start background workers
	pm.healthCheckTicker = time.NewTicker(pm.config.HealthCheckInterval)
	pm.metricsTicket = time.NewTicker(pm.config.MetricsCollectionInterval)
	if pm.config.EnableAnomalyDetection {
		pm.anomalyTicker = time.NewTicker(pm.config.AnomalyDetectionInterval)
	}

	go pm.healthCheckWorker()
	go pm.metricsWorker()
	if pm.config.EnableAnomalyDetection {
		go pm.anomalyWorker()
	}

	pm.logger.InfoCtx(ctx, "Platform monitor started",
		"health_check_interval", pm.config.HealthCheckInterval,
		"metrics_interval", pm.config.MetricsCollectionInterval,
		"anomaly_detection_enabled", pm.config.EnableAnomalyDetection)

	return nil
}

// Stop stops the monitoring background processes.
func (pm *platformMonitor) Stop(ctx context.Context) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if !pm.running {
		return nil
	}

	pm.running = false
	pm.cancel()

	// Stop tickers
	if pm.healthCheckTicker != nil {
		pm.healthCheckTicker.Stop()
	}
	if pm.metricsTicket != nil {
		pm.metricsTicket.Stop()
	}
	if pm.anomalyTicker != nil {
		pm.anomalyTicker.Stop()
	}

	pm.logger.InfoCtx(ctx, "Platform monitor stopped")
	return nil
}

// IsRunning returns whether the monitor is currently running.
func (pm *platformMonitor) IsRunning() bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return pm.running
}

// Background worker functions

func (pm *platformMonitor) healthCheckWorker() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-pm.healthCheckTicker.C:
			pm.performHealthChecks()
		}
	}
}

func (pm *platformMonitor) metricsWorker() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-pm.metricsTicket.C:
			pm.collectMetrics()
		}
	}
}

func (pm *platformMonitor) anomalyWorker() {
	for {
		select {
		case <-pm.ctx.Done():
			return
		case <-pm.anomalyTicker.C:
			pm.detectAnomalies()
		}
	}
}

func (pm *platformMonitor) performHealthChecks() {
	ctx, span := pm.tracer.Start(pm.ctx, "platform_monitor.health_check_cycle")
	defer span.End()

	pm.mu.RLock()
	components := make([]string, 0, len(pm.healthCheckers))
	for component := range pm.healthCheckers {
		components = append(components, component)
	}
	pm.mu.RUnlock()

	for _, component := range components {
		_, err := pm.GetComponentHealth(ctx, component)
		if err != nil {
			pm.logger.WarnCtx(ctx, "Background health check failed",
				"component", component, "error", err.Error())
		}
	}
}

func (pm *platformMonitor) collectMetrics() {
	ctx, span := pm.tracer.Start(pm.ctx, "platform_monitor.metrics_collection_cycle")
	defer span.End()

	pm.mu.RLock()
	components := make([]string, 0, len(pm.metricsCollectors))
	for component := range pm.metricsCollectors {
		components = append(components, component)
	}
	pm.mu.RUnlock()

	for _, component := range components {
		_, err := pm.GetComponentMetrics(ctx, component)
		if err != nil {
			pm.logger.WarnCtx(ctx, "Background metrics collection failed",
				"component", component, "error", err.Error())
		}
	}
}

func (pm *platformMonitor) detectAnomalies() {
	ctx, span := pm.tracer.Start(pm.ctx, "platform_monitor.anomaly_detection_cycle")
	defer span.End()

	pm.mu.RLock()
	detectors := make(map[string]AnomalyDetector, len(pm.anomalyDetectors))
	for component, detector := range pm.anomalyDetectors {
		detectors[component] = detector
	}
	pm.mu.RUnlock()

	for component, detector := range detectors {
		// Get latest metrics for component
		pm.mu.RLock()
		metrics := pm.lastMetrics[component]
		pm.mu.RUnlock()

		if metrics == nil {
			continue
		}

		// Detect anomalies
		anomalies, err := detector.DetectAnomalies(ctx, metrics)
		if err != nil {
			pm.logger.WarnCtx(ctx, "Anomaly detection failed",
				"component", component, "error", err.Error())
			continue
		}

		// Update active anomalies
		if len(anomalies) > 0 {
			pm.mu.Lock()
			pm.activeAnomalies = append(pm.activeAnomalies, anomalies...)
			pm.mu.Unlock()

			for _, anomaly := range anomalies {
				pm.logger.WarnCtx(ctx, "Anomaly detected",
					"component", component,
					"type", anomaly.Type,
					"severity", anomaly.Severity,
					"description", anomaly.Description)
			}
		}
	}

	// Clean up resolved anomalies
	pm.cleanupResolvedAnomalies()
}

func (pm *platformMonitor) cleanupResolvedAnomalies() {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	cutoff := time.Now().Add(-pm.config.AnomalyRetentionPeriod)
	activeAnomalies := make([]*Anomaly, 0)

	for _, anomaly := range pm.activeAnomalies {
		if anomaly.Status == AnomalyStatusActive ||
		   (anomaly.ResolvedAt != nil && anomaly.ResolvedAt.After(cutoff)) {
			activeAnomalies = append(activeAnomalies, anomaly)
		}
	}

	pm.activeAnomalies = activeAnomalies
}

// getVersion returns the current system version
func getVersion() string {
	// TODO: Get actual version from build info
	return "0.5.0-beta"
}