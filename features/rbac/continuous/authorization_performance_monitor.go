package continuous

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AuthorizationPerformanceMonitor provides real-time performance monitoring
// for authorization operations with SLA tracking and alerting
type AuthorizationPerformanceMonitor struct {
	// Configuration
	config *PerformanceMonitorConfig

	// Metrics tracking
	metrics *LivePerformanceMetrics

	// SLA monitoring
	slaTracker *SLATracker

	// Control
	stopChannel chan struct{}
	running     bool
	mutex       sync.RWMutex
}

// PerformanceMonitorConfig contains performance monitoring configuration
type PerformanceMonitorConfig struct {
	// SLA thresholds
	MaxLatencyMs      int     `json:"max_latency_ms"`      // Target <10ms
	MinCacheHitRate   float64 `json:"min_cache_hit_rate"`  // Target >90%
	MaxMemoryUsageMB  float64 `json:"max_memory_usage_mb"` // Memory limit
	MaxGoroutineCount int     `json:"max_goroutine_count"` // Goroutine limit

	// Monitoring intervals
	MetricsInterval     time.Duration `json:"metrics_interval"`      // Metrics collection frequency
	SLACheckInterval    time.Duration `json:"sla_check_interval"`    // SLA validation frequency
	AlertCooldownPeriod time.Duration `json:"alert_cooldown_period"` // Alert throttling

	// Thresholds for alerting
	LatencyP95Threshold time.Duration `json:"latency_p95_threshold"`  // P95 latency alert threshold
	ThroughputMinRPS    float64       `json:"throughput_min_rps"`     // Minimum throughput
	ErrorRateMaxPercent float64       `json:"error_rate_max_percent"` // Maximum error rate

	// Monitoring features
	EnableRealTimeAlerts   bool `json:"enable_real_time_alerts"`  // Enable real-time alerting
	EnableTrendAnalysis    bool `json:"enable_trend_analysis"`    // Enable trend analysis
	EnableCapacityPlanning bool `json:"enable_capacity_planning"` // Enable capacity planning

	// Export settings
	MetricsExportEnabled  bool          `json:"metrics_export_enabled"`  // Enable metrics export
	MetricsExportInterval time.Duration `json:"metrics_export_interval"` // Export frequency
	MetricsExportFormat   string        `json:"metrics_export_format"`   // Export format (prometheus, json)
}

// LivePerformanceMetrics tracks real-time authorization performance metrics
type LivePerformanceMetrics struct {
	// Request metrics
	RequestsPerSecond  float64 `json:"requests_per_second"`
	TotalRequests      int64   `json:"total_requests"`
	SuccessfulRequests int64   `json:"successful_requests"`
	FailedRequests     int64   `json:"failed_requests"`

	// Latency metrics
	CurrentLatencyMs float64 `json:"current_latency_ms"`
	AverageLatencyMs float64 `json:"average_latency_ms"`
	P50LatencyMs     float64 `json:"p50_latency_ms"`
	P95LatencyMs     float64 `json:"p95_latency_ms"`
	P99LatencyMs     float64 `json:"p99_latency_ms"`
	MaxLatencyMs     float64 `json:"max_latency_ms"`

	// Cache metrics
	CacheHitRate   float64 `json:"cache_hit_rate"`
	CacheHits      int64   `json:"cache_hits"`
	CacheMisses    int64   `json:"cache_misses"`
	CacheSize      int     `json:"cache_size"`
	CacheEvictions int64   `json:"cache_evictions"`

	// Concurrency metrics
	ActiveSessions     int `json:"active_sessions"`
	ConcurrentRequests int `json:"concurrent_requests"`
	PeakConcurrency    int `json:"peak_concurrency"`

	// Resource metrics
	MemoryUsageMB   float64 `json:"memory_usage_mb"`
	GoroutineCount  int     `json:"goroutine_count"`
	CPUUsagePercent float64 `json:"cpu_usage_percent"`

	// Error metrics
	ErrorRate           float64 `json:"error_rate"`
	TimeoutCount        int64   `json:"timeout_count"`
	CircuitBreakerTrips int64   `json:"circuit_breaker_trips"`

	// Business metrics
	PermissionDenials int64 `json:"permission_denials"`
	PolicyViolations  int64 `json:"policy_violations"`
	SecurityAlerts    int64 `json:"security_alerts"`

	// Time tracking
	LastUpdated      time.Time     `json:"last_updated"`
	MonitoringUptime time.Duration `json:"monitoring_uptime"`

	// Trend data
	LatencyTrend    []float64 `json:"latency_trend"`
	ThroughputTrend []float64 `json:"throughput_trend"`
	ErrorRateTrend  []float64 `json:"error_rate_trend"`

	mutex sync.RWMutex
}

// SLATracker monitors and tracks SLA compliance
type SLATracker struct {
	// SLA definitions
	slaTargets map[string]SLATarget

	// SLA compliance tracking
	complianceHistory []SLAComplianceRecord
	currentCompliance map[string]float64

	// Alert management
	activeAlerts  map[string]*SLAAlert
	alertHistory  []SLAAlert
	lastAlertTime map[string]time.Time

	mutex sync.RWMutex
}

// SLATarget defines an SLA target metric
type SLATarget struct {
	Name             string        `json:"name"`
	Description      string        `json:"description"`
	MetricType       string        `json:"metric_type"` // latency, throughput, availability
	TargetValue      float64       `json:"target_value"`
	TargetOperator   string        `json:"target_operator"`  // <, >, <=, >=, ==
	MeasurementUnit  string        `json:"measurement_unit"` // ms, rps, percent
	CompliancePeriod time.Duration `json:"compliance_period"`
	Severity         AlertSeverity `json:"severity"`
}

// SLAComplianceRecord records SLA compliance over time
type SLAComplianceRecord struct {
	Timestamp       time.Time `json:"timestamp"`
	SLAName         string    `json:"sla_name"`
	ActualValue     float64   `json:"actual_value"`
	TargetValue     float64   `json:"target_value"`
	IsCompliant     bool      `json:"is_compliant"`
	ComplianceScore float64   `json:"compliance_score"`
}

// SLAAlert represents an SLA violation alert
type SLAAlert struct {
	ID           string        `json:"id"`
	SLAName      string        `json:"sla_name"`
	AlertType    AlertType     `json:"alert_type"`
	Severity     AlertSeverity `json:"severity"`
	Message      string        `json:"message"`
	ActualValue  float64       `json:"actual_value"`
	TargetValue  float64       `json:"target_value"`
	Timestamp    time.Time     `json:"timestamp"`
	Acknowledged bool          `json:"acknowledged"`
	ResolvedAt   time.Time     `json:"resolved_at,omitempty"`
	Duration     time.Duration `json:"duration"`
}

// AlertType defines the type of alert
type AlertType string

const (
	AlertTypeLatencyViolation      AlertType = "latency_violation"
	AlertTypeThroughputDegradation AlertType = "throughput_degradation"
	AlertTypeCachePerformance      AlertType = "cache_performance"
	AlertTypeMemoryUsage           AlertType = "memory_usage"
	AlertTypeErrorRate             AlertType = "error_rate"
	AlertTypeCapacityLimit         AlertType = "capacity_limit"
)

// AlertSeverity defines alert severity levels
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// NewAuthorizationPerformanceMonitor creates a new authorization performance monitor
func NewAuthorizationPerformanceMonitor(config *PerformanceMonitorConfig) *AuthorizationPerformanceMonitor {
	if config == nil {
		config = DefaultPerformanceMonitorConfig()
	}

	return &AuthorizationPerformanceMonitor{
		config: config,
		metrics: &LivePerformanceMetrics{
			LastUpdated:     time.Now(),
			LatencyTrend:    make([]float64, 0, 100),
			ThroughputTrend: make([]float64, 0, 100),
			ErrorRateTrend:  make([]float64, 0, 100),
		},
		slaTracker: &SLATracker{
			slaTargets:        createDefaultSLATargets(),
			complianceHistory: make([]SLAComplianceRecord, 0, 1000),
			currentCompliance: make(map[string]float64),
			activeAlerts:      make(map[string]*SLAAlert),
			alertHistory:      make([]SLAAlert, 0, 500),
			lastAlertTime:     make(map[string]time.Time),
		},
		stopChannel: make(chan struct{}),
	}
}

// Start begins performance monitoring
func (apm *AuthorizationPerformanceMonitor) Start(ctx context.Context) error {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	if apm.running {
		return fmt.Errorf("authorization performance monitor is already running")
	}

	// Start monitoring loops
	go apm.metricsCollectionLoop(ctx)
	go apm.slaMonitoringLoop(ctx)
	go apm.alertProcessingLoop(ctx)

	if apm.config.MetricsExportEnabled {
		go apm.metricsExportLoop(ctx)
	}

	apm.running = true
	return nil
}

// Stop gracefully stops performance monitoring
func (apm *AuthorizationPerformanceMonitor) Stop() error {
	apm.mutex.Lock()
	defer apm.mutex.Unlock()

	if !apm.running {
		return fmt.Errorf("authorization performance monitor is not running")
	}

	close(apm.stopChannel)
	apm.running = false
	return nil
}

// RecordAuthorizationMetric records a single authorization operation metric
func (apm *AuthorizationPerformanceMonitor) RecordAuthorizationMetric(metric *AuthorizationMetric) {
	apm.metrics.mutex.Lock()
	defer apm.metrics.mutex.Unlock()

	// Update request counters
	apm.metrics.TotalRequests++
	if metric.Success {
		apm.metrics.SuccessfulRequests++
	} else {
		apm.metrics.FailedRequests++
	}

	// Update latency metrics
	latencyMs := float64(metric.Latency.Milliseconds())
	apm.updateLatencyMetrics(latencyMs)

	// Update cache metrics
	if metric.CacheHit {
		apm.metrics.CacheHits++
	} else {
		apm.metrics.CacheMisses++
	}

	// Update error metrics
	if metric.Error != nil {
		apm.metrics.ErrorRate = float64(apm.metrics.FailedRequests) / float64(apm.metrics.TotalRequests)
	}

	// Update timestamp
	apm.metrics.LastUpdated = time.Now()
}

// GetCurrentMetrics returns current performance metrics
func (apm *AuthorizationPerformanceMonitor) GetCurrentMetrics() *LivePerformanceMetrics {
	apm.metrics.mutex.RLock()
	defer apm.metrics.mutex.RUnlock()

	// Return a copy to prevent data races - copy fields individually to avoid copying mutex
	metricsCopy := &LivePerformanceMetrics{
		RequestsPerSecond:   apm.metrics.RequestsPerSecond,
		TotalRequests:       apm.metrics.TotalRequests,
		SuccessfulRequests:  apm.metrics.SuccessfulRequests,
		FailedRequests:      apm.metrics.FailedRequests,
		CurrentLatencyMs:    apm.metrics.CurrentLatencyMs,
		AverageLatencyMs:    apm.metrics.AverageLatencyMs,
		P50LatencyMs:        apm.metrics.P50LatencyMs,
		P95LatencyMs:        apm.metrics.P95LatencyMs,
		P99LatencyMs:        apm.metrics.P99LatencyMs,
		MaxLatencyMs:        apm.metrics.MaxLatencyMs,
		CacheHitRate:        apm.metrics.CacheHitRate,
		CacheHits:           apm.metrics.CacheHits,
		CacheMisses:         apm.metrics.CacheMisses,
		CacheSize:           apm.metrics.CacheSize,
		CacheEvictions:      apm.metrics.CacheEvictions,
		ErrorRate:           apm.metrics.ErrorRate,
		MemoryUsageMB:       apm.metrics.MemoryUsageMB,
		GoroutineCount:      apm.metrics.GoroutineCount,
		CPUUsagePercent:     apm.metrics.CPUUsagePercent,
		ActiveSessions:      apm.metrics.ActiveSessions,
		ConcurrentRequests:  apm.metrics.ConcurrentRequests,
		PeakConcurrency:     apm.metrics.PeakConcurrency,
		TimeoutCount:        apm.metrics.TimeoutCount,
		CircuitBreakerTrips: apm.metrics.CircuitBreakerTrips,
		PermissionDenials:   apm.metrics.PermissionDenials,
		PolicyViolations:    apm.metrics.PolicyViolations,
		SecurityAlerts:      apm.metrics.SecurityAlerts,
		MonitoringUptime:    apm.metrics.MonitoringUptime,
		LastUpdated:         apm.metrics.LastUpdated,
	}
	return metricsCopy
}

// GetSLACompliance returns current SLA compliance status
func (apm *AuthorizationPerformanceMonitor) GetSLACompliance() map[string]float64 {
	apm.slaTracker.mutex.RLock()
	defer apm.slaTracker.mutex.RUnlock()

	compliance := make(map[string]float64)
	for name, score := range apm.slaTracker.currentCompliance {
		compliance[name] = score
	}
	return compliance
}

// GetActiveAlerts returns currently active SLA alerts
func (apm *AuthorizationPerformanceMonitor) GetActiveAlerts() []*SLAAlert {
	apm.slaTracker.mutex.RLock()
	defer apm.slaTracker.mutex.RUnlock()

	alerts := make([]*SLAAlert, 0, len(apm.slaTracker.activeAlerts))
	for _, alert := range apm.slaTracker.activeAlerts {
		alerts = append(alerts, alert)
	}
	return alerts
}

// Internal monitoring loops

func (apm *AuthorizationPerformanceMonitor) metricsCollectionLoop(ctx context.Context) {
	ticker := time.NewTicker(apm.config.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-apm.stopChannel:
			return
		case <-ticker.C:
			apm.collectSystemMetrics()
		}
	}
}

func (apm *AuthorizationPerformanceMonitor) slaMonitoringLoop(ctx context.Context) {
	ticker := time.NewTicker(apm.config.SLACheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-apm.stopChannel:
			return
		case <-ticker.C:
			apm.checkSLACompliance()
		}
	}
}

func (apm *AuthorizationPerformanceMonitor) alertProcessingLoop(ctx context.Context) {
	// Process and manage alerts
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-apm.stopChannel:
			return
		case <-ticker.C:
			apm.processAlerts()
		}
	}
}

func (apm *AuthorizationPerformanceMonitor) metricsExportLoop(ctx context.Context) {
	ticker := time.NewTicker(apm.config.MetricsExportInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-apm.stopChannel:
			return
		case <-ticker.C:
			apm.exportMetrics()
		}
	}
}

// Helper methods

func (apm *AuthorizationPerformanceMonitor) updateLatencyMetrics(latencyMs float64) {
	// Update current and average latency
	apm.metrics.CurrentLatencyMs = latencyMs

	// Update max latency
	if latencyMs > apm.metrics.MaxLatencyMs {
		apm.metrics.MaxLatencyMs = latencyMs
	}

	// Update average latency (exponential moving average)
	alpha := 0.1
	apm.metrics.AverageLatencyMs = (1-alpha)*apm.metrics.AverageLatencyMs + alpha*latencyMs

	// Add to trend data
	apm.metrics.LatencyTrend = append(apm.metrics.LatencyTrend, latencyMs)
	if len(apm.metrics.LatencyTrend) > 100 {
		apm.metrics.LatencyTrend = apm.metrics.LatencyTrend[1:]
	}

	// Update percentiles (simplified implementation)
	apm.updateLatencyPercentiles()
}

func (apm *AuthorizationPerformanceMonitor) updateLatencyPercentiles() {
	// Simplified percentile calculation using trend data
	if len(apm.metrics.LatencyTrend) == 0 {
		return
	}

	// For production, would use proper percentile calculation
	apm.metrics.P50LatencyMs = apm.calculatePercentile(apm.metrics.LatencyTrend, 0.50)
	apm.metrics.P95LatencyMs = apm.calculatePercentile(apm.metrics.LatencyTrend, 0.95)
	apm.metrics.P99LatencyMs = apm.calculatePercentile(apm.metrics.LatencyTrend, 0.99)
}

func (apm *AuthorizationPerformanceMonitor) calculatePercentile(data []float64, percentile float64) float64 {
	if len(data) == 0 {
		return 0
	}

	// Simplified percentile calculation
	index := int(float64(len(data)) * percentile)
	if index >= len(data) {
		index = len(data) - 1
	}

	return data[index]
}

func (apm *AuthorizationPerformanceMonitor) collectSystemMetrics() {
	// Collect system resource metrics
	// This would integrate with runtime metrics, process monitors, etc.
	apm.metrics.mutex.Lock()
	defer apm.metrics.mutex.Unlock()

	// Update monitoring uptime
	apm.metrics.MonitoringUptime = time.Since(apm.metrics.LastUpdated)
}

func (apm *AuthorizationPerformanceMonitor) checkSLACompliance() {
	apm.slaTracker.mutex.Lock()
	defer apm.slaTracker.mutex.Unlock()

	currentTime := time.Now()
	currentMetrics := apm.GetCurrentMetrics()

	for slaName, target := range apm.slaTracker.slaTargets {
		compliance := apm.evaluateSLATarget(target, currentMetrics)

		// Record compliance
		record := SLAComplianceRecord{
			Timestamp:       currentTime,
			SLAName:         slaName,
			ActualValue:     compliance.ActualValue,
			TargetValue:     target.TargetValue,
			IsCompliant:     compliance.IsCompliant,
			ComplianceScore: compliance.ComplianceScore,
		}

		apm.slaTracker.complianceHistory = append(apm.slaTracker.complianceHistory, record)
		apm.slaTracker.currentCompliance[slaName] = compliance.ComplianceScore

		// Generate alerts if SLA is violated
		if !compliance.IsCompliant && apm.config.EnableRealTimeAlerts {
			apm.generateSLAAlert(target, compliance)
		}
	}
}

func (apm *AuthorizationPerformanceMonitor) processAlerts() {
	// Process and manage active alerts
	// Clean up resolved alerts, apply cooldown periods, etc.
}

func (apm *AuthorizationPerformanceMonitor) exportMetrics() {
	// Export metrics in configured format
	// This would integrate with Prometheus, StatsD, etc.
}

// Supporting types and functions

// AuthorizationMetric represents a single authorization operation metric
type AuthorizationMetric struct {
	Timestamp    time.Time
	SessionID    string
	SubjectID    string
	PermissionID string
	ResourceID   string
	Success      bool
	Latency      time.Duration
	CacheHit     bool
	Error        error
	Context      map[string]string
}

type SLACompliance struct {
	ActualValue     float64
	IsCompliant     bool
	ComplianceScore float64
}

func (apm *AuthorizationPerformanceMonitor) evaluateSLATarget(target SLATarget, metrics *LivePerformanceMetrics) SLACompliance {
	var actualValue float64

	// Extract actual value based on metric type
	switch target.MetricType {
	case "latency":
		actualValue = metrics.AverageLatencyMs
	case "throughput":
		actualValue = metrics.RequestsPerSecond
	case "cache_hit_rate":
		actualValue = metrics.CacheHitRate * 100
	case "error_rate":
		actualValue = metrics.ErrorRate * 100
	default:
		actualValue = 0
	}

	// Evaluate compliance
	isCompliant := apm.evaluateTargetOperator(actualValue, target.TargetValue, target.TargetOperator)

	// Calculate compliance score (0-100)
	var complianceScore float64
	if isCompliant {
		complianceScore = 100.0
	} else {
		// Calculate partial compliance based on how far off we are
		deviation := abs(actualValue-target.TargetValue) / target.TargetValue
		complianceScore = max(0, 100.0*(1-deviation))
	}

	return SLACompliance{
		ActualValue:     actualValue,
		IsCompliant:     isCompliant,
		ComplianceScore: complianceScore,
	}
}

func (apm *AuthorizationPerformanceMonitor) evaluateTargetOperator(actual, target float64, operator string) bool {
	switch operator {
	case "<":
		return actual < target
	case "<=":
		return actual <= target
	case ">":
		return actual > target
	case ">=":
		return actual >= target
	case "==":
		return actual == target
	default:
		return false
	}
}

func (apm *AuthorizationPerformanceMonitor) generateSLAAlert(target SLATarget, compliance SLACompliance) {
	// Check cooldown period
	if lastAlert, exists := apm.slaTracker.lastAlertTime[target.Name]; exists {
		if time.Since(lastAlert) < apm.config.AlertCooldownPeriod {
			return // Still in cooldown
		}
	}

	alert := &SLAAlert{
		ID:          fmt.Sprintf("sla-%s-%d", target.Name, time.Now().UnixNano()),
		SLAName:     target.Name,
		AlertType:   AlertTypeLatencyViolation, // Would map based on target type
		Severity:    target.Severity,
		Message:     fmt.Sprintf("SLA violation: %s actual=%.2f, target=%.2f", target.Name, compliance.ActualValue, target.TargetValue),
		ActualValue: compliance.ActualValue,
		TargetValue: target.TargetValue,
		Timestamp:   time.Now(),
	}

	apm.slaTracker.activeAlerts[alert.ID] = alert
	apm.slaTracker.alertHistory = append(apm.slaTracker.alertHistory, *alert)
	apm.slaTracker.lastAlertTime[target.Name] = time.Now()
}

// Configuration defaults

// DefaultPerformanceMonitorConfig returns default performance monitor configuration
func DefaultPerformanceMonitorConfig() *PerformanceMonitorConfig {
	return &PerformanceMonitorConfig{
		MaxLatencyMs:           10,
		MinCacheHitRate:        0.90,
		MaxMemoryUsageMB:       512,
		MaxGoroutineCount:      1000,
		MetricsInterval:        5 * time.Second,
		SLACheckInterval:       30 * time.Second,
		AlertCooldownPeriod:    5 * time.Minute,
		LatencyP95Threshold:    15 * time.Millisecond,
		ThroughputMinRPS:       50,
		ErrorRateMaxPercent:    5.0,
		EnableRealTimeAlerts:   true,
		EnableTrendAnalysis:    true,
		EnableCapacityPlanning: true,
		MetricsExportEnabled:   true,
		MetricsExportInterval:  1 * time.Minute,
		MetricsExportFormat:    "prometheus",
	}
}

func createDefaultSLATargets() map[string]SLATarget {
	return map[string]SLATarget{
		"authorization_latency": {
			Name:             "authorization_latency",
			Description:      "Authorization requests must complete within 10ms",
			MetricType:       "latency",
			TargetValue:      10.0,
			TargetOperator:   "<",
			MeasurementUnit:  "ms",
			CompliancePeriod: 5 * time.Minute,
			Severity:         AlertSeverityError,
		},
		"cache_hit_rate": {
			Name:             "cache_hit_rate",
			Description:      "Permission cache hit rate must exceed 90%",
			MetricType:       "cache_hit_rate",
			TargetValue:      90.0,
			TargetOperator:   ">",
			MeasurementUnit:  "percent",
			CompliancePeriod: 5 * time.Minute,
			Severity:         AlertSeverityWarning,
		},
		"throughput": {
			Name:             "throughput",
			Description:      "System must maintain minimum 50 RPS throughput",
			MetricType:       "throughput",
			TargetValue:      50.0,
			TargetOperator:   ">",
			MeasurementUnit:  "rps",
			CompliancePeriod: 5 * time.Minute,
			Severity:         AlertSeverityError,
		},
		"error_rate": {
			Name:             "error_rate",
			Description:      "Error rate must remain below 5%",
			MetricType:       "error_rate",
			TargetValue:      5.0,
			TargetOperator:   "<",
			MeasurementUnit:  "percent",
			CompliancePeriod: 5 * time.Minute,
			Severity:         AlertSeverityCritical,
		},
	}
}

// Utility functions
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
