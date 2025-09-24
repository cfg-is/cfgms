package monitoring

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// BasicAnomalyDetector provides basic anomaly detection functionality.
type BasicAnomalyDetector struct {
	componentName string
	logger        logging.Logger
	rules         []DetectionRule
	history       []MetricsSnapshot
	maxHistory    int
}

// MetricsSnapshot represents a snapshot of metrics at a point in time.
type MetricsSnapshot struct {
	Timestamp time.Time
	Metrics   *ComponentMetrics
}

// NewBasicAnomalyDetector creates a new basic anomaly detector.
func NewBasicAnomalyDetector(componentName string, logger logging.Logger) *BasicAnomalyDetector {
	detector := &BasicAnomalyDetector{
		componentName: componentName,
		logger:        logger,
		rules:         make([]DetectionRule, 0),
		history:       make([]MetricsSnapshot, 0),
		maxHistory:    100, // Keep last 100 snapshots
	}

	// Add default detection rules
	detector.addDefaultRules()
	return detector
}

// addDefaultRules adds default anomaly detection rules.
func (bad *BasicAnomalyDetector) addDefaultRules() {
	// High error rate rule
	bad.rules = append(bad.rules, DetectionRule{
		ID:        "high_error_rate",
		Name:      "High Error Rate",
		Type:      AnomalyTypeError,
		Metric:    "error_rate",
		Condition: "greater_than",
		Threshold: 10.0, // 10% error rate
		Duration:  5 * time.Minute,
		Severity:  AnomalySeverityHigh,
		Enabled:   true,
	})

	// High response time rule
	bad.rules = append(bad.rules, DetectionRule{
		ID:        "high_response_time",
		Name:      "High Response Time",
		Type:      AnomalyTypePerformance,
		Metric:    "response_time",
		Condition: "greater_than",
		Threshold: 5000.0, // 5 seconds in milliseconds
		Duration:  3 * time.Minute,
		Severity:  AnomalySeverityMedium,
		Enabled:   true,
	})

	// High memory usage rule
	bad.rules = append(bad.rules, DetectionRule{
		ID:        "high_memory_usage",
		Name:      "High Memory Usage",
		Type:      AnomalyTypeResource,
		Metric:    "memory_percent",
		Condition: "greater_than",
		Threshold: 90.0, // 90% memory usage
		Duration:  2 * time.Minute,
		Severity:  AnomalySeverityHigh,
		Enabled:   true,
	})

	// Low throughput rule
	bad.rules = append(bad.rules, DetectionRule{
		ID:        "low_throughput",
		Name:      "Low Throughput",
		Type:      AnomalyTypePerformance,
		Metric:    "throughput",
		Condition: "less_than",
		Threshold: 1.0, // Less than 1 request per second
		Duration:  5 * time.Minute,
		Severity:  AnomalySeverityLow,
		Enabled:   true,
	})

	// High CPU usage rule
	bad.rules = append(bad.rules, DetectionRule{
		ID:        "high_cpu_usage",
		Name:      "High CPU Usage",
		Type:      AnomalyTypeResource,
		Metric:    "cpu_percent",
		Condition: "greater_than",
		Threshold: 80.0, // 80% CPU usage
		Duration:  3 * time.Minute,
		Severity:  AnomalySeverityMedium,
		Enabled:   true,
	})
}

// DetectAnomalies detects anomalies based on current metrics.
func (bad *BasicAnomalyDetector) DetectAnomalies(ctx context.Context, metrics *ComponentMetrics) ([]*Anomaly, error) {
	anomalies := make([]*Anomaly, 0)

	// Add current metrics to history
	bad.addToHistory(metrics)

	// Check each enabled rule
	for _, rule := range bad.rules {
		if !rule.Enabled {
			continue
		}

		anomaly := bad.checkRule(ctx, rule, metrics)
		if anomaly != nil {
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies, nil
}

// GetDetectionRules returns the current detection rules.
func (bad *BasicAnomalyDetector) GetDetectionRules() []DetectionRule {
	return bad.rules
}

// UpdateDetectionRules updates the detection rules.
func (bad *BasicAnomalyDetector) UpdateDetectionRules(rules []DetectionRule) error {
	bad.rules = rules
	bad.logger.InfoCtx(context.Background(), "Updated detection rules",
		"component", bad.componentName, "rule_count", len(rules))
	return nil
}

// addToHistory adds metrics to the history buffer.
func (bad *BasicAnomalyDetector) addToHistory(metrics *ComponentMetrics) {
	snapshot := MetricsSnapshot{
		Timestamp: metrics.Timestamp,
		Metrics:   metrics,
	}

	bad.history = append(bad.history, snapshot)

	// Keep only the last maxHistory entries
	if len(bad.history) > bad.maxHistory {
		bad.history = bad.history[1:]
	}
}

// checkRule checks a specific detection rule against current metrics.
func (bad *BasicAnomalyDetector) checkRule(ctx context.Context, rule DetectionRule, metrics *ComponentMetrics) *Anomaly {
	value := bad.extractMetricValue(metrics, rule.Metric)
	if value == nil {
		return nil
	}

	// Check if rule condition is met
	conditionMet := bad.evaluateCondition(rule.Condition, *value, rule.Threshold)
	if !conditionMet {
		return nil
	}

	// Check if condition has been met for the required duration
	if !bad.checkDuration(rule.Metric, rule.Condition, rule.Threshold, rule.Duration) {
		return nil
	}

	// Create anomaly
	anomaly := &Anomaly{
		ID:            fmt.Sprintf("%s_%s_%d", bad.componentName, rule.ID, time.Now().Unix()),
		ComponentName: bad.componentName,
		Type:          rule.Type,
		Severity:      rule.Severity,
		Title:         rule.Name,
		Description:   bad.generateDescription(rule, *value),
		DetectedAt:    time.Now(),
		Status:        AnomalyStatusActive,
		Metrics:       metrics,
		Context: map[string]interface{}{
			"rule_id":     rule.ID,
			"metric":      rule.Metric,
			"value":       *value,
			"threshold":   rule.Threshold,
			"condition":   rule.Condition,
			"duration":    rule.Duration.String(),
		},
		Actions: bad.generateActions(rule, *value),
	}

	return anomaly
}

// extractMetricValue extracts a specific metric value from ComponentMetrics.
func (bad *BasicAnomalyDetector) extractMetricValue(metrics *ComponentMetrics, metricName string) *float64 {
	switch metricName {
	case "error_rate":
		if metrics.Performance != nil {
			return &metrics.Performance.ErrorRate
		}
	case "response_time":
		if metrics.Performance != nil {
			value := float64(metrics.Performance.ResponseTime.Milliseconds())
			return &value
		}
	case "throughput":
		if metrics.Performance != nil {
			return &metrics.Performance.Throughput
		}
	case "cpu_percent":
		if metrics.Resource != nil {
			return &metrics.Resource.CPUPercent
		}
	case "memory_percent":
		if metrics.Resource != nil {
			return &metrics.Resource.MemoryPercent
		}
	case "memory_bytes":
		if metrics.Resource != nil {
			value := float64(metrics.Resource.MemoryBytes)
			return &value
		}
	case "goroutines":
		if metrics.Resource != nil {
			value := float64(metrics.Resource.Goroutines)
			return &value
		}
	default:
		// Check custom metrics
		if val, exists := metrics.Custom[metricName]; exists {
			if floatVal, ok := val.(float64); ok {
				return &floatVal
			}
			if intVal, ok := val.(int); ok {
				floatVal := float64(intVal)
				return &floatVal
			}
			if int64Val, ok := val.(int64); ok {
				floatVal := float64(int64Val)
				return &floatVal
			}
		}
		// Check business metrics
		if val, exists := metrics.Business[metricName]; exists {
			if floatVal, ok := val.(float64); ok {
				return &floatVal
			}
			if intVal, ok := val.(int); ok {
				floatVal := float64(intVal)
				return &floatVal
			}
			if int64Val, ok := val.(int64); ok {
				floatVal := float64(int64Val)
				return &floatVal
			}
		}
	}
	return nil
}

// evaluateCondition evaluates a condition against a value and threshold.
func (bad *BasicAnomalyDetector) evaluateCondition(condition string, value, threshold float64) bool {
	switch condition {
	case "greater_than":
		return value > threshold
	case "less_than":
		return value < threshold
	case "equals":
		return math.Abs(value-threshold) < 0.001 // Float comparison with tolerance
	case "greater_than_or_equal":
		return value >= threshold
	case "less_than_or_equal":
		return value <= threshold
	default:
		return false
	}
}

// checkDuration checks if a condition has been met for the required duration.
func (bad *BasicAnomalyDetector) checkDuration(metric, condition string, threshold float64, duration time.Duration) bool {
	cutoffTime := time.Now().Add(-duration)

	// Check history to see if condition has been consistently met
	consistentViolations := 0
	totalChecks := 0

	for _, snapshot := range bad.history {
		if snapshot.Timestamp.Before(cutoffTime) {
			continue
		}

		totalChecks++
		value := bad.extractMetricValue(snapshot.Metrics, metric)
		if value != nil && bad.evaluateCondition(condition, *value, threshold) {
			consistentViolations++
		}
	}

	// Require at least 80% of checks in the duration to violate the condition
	if totalChecks < 2 {
		return false // Not enough history
	}

	violationRate := float64(consistentViolations) / float64(totalChecks)
	return violationRate >= 0.8
}

// generateDescription generates a human-readable description for the anomaly.
func (bad *BasicAnomalyDetector) generateDescription(rule DetectionRule, value float64) string {
	switch rule.Condition {
	case "greater_than":
		return fmt.Sprintf("%s is %.2f, which is greater than the threshold of %.2f",
			rule.Metric, value, rule.Threshold)
	case "less_than":
		return fmt.Sprintf("%s is %.2f, which is less than the threshold of %.2f",
			rule.Metric, value, rule.Threshold)
	case "equals":
		return fmt.Sprintf("%s is %.2f, which equals the threshold of %.2f",
			rule.Metric, value, rule.Threshold)
	default:
		return fmt.Sprintf("%s is %.2f, condition: %s %.2f",
			rule.Metric, value, rule.Condition, rule.Threshold)
	}
}

// generateActions generates suggested actions for the anomaly.
func (bad *BasicAnomalyDetector) generateActions(rule DetectionRule, value float64) []string {
	actions := make([]string, 0)

	switch rule.Type {
	case AnomalyTypeError:
		actions = append(actions, "Check application logs for error details")
		actions = append(actions, "Review recent deployments or configuration changes")
		actions = append(actions, "Validate external service dependencies")
	case AnomalyTypePerformance:
		switch rule.Metric {
		case "response_time":
			actions = append(actions, "Check database connection pool status")
			actions = append(actions, "Review slow query logs")
			actions = append(actions, "Analyze network latency to dependencies")
		case "throughput":
			actions = append(actions, "Check for resource bottlenecks")
			actions = append(actions, "Review load balancer configuration")
			actions = append(actions, "Verify client connectivity")
		}
	case AnomalyTypeResource:
		switch rule.Metric {
		case "memory_percent", "memory_bytes":
			actions = append(actions, "Check for memory leaks")
			actions = append(actions, "Review garbage collection metrics")
			actions = append(actions, "Consider scaling up memory resources")
		case "cpu_percent":
			actions = append(actions, "Identify CPU-intensive processes")
			actions = append(actions, "Check for infinite loops or runaway processes")
			actions = append(actions, "Consider scaling up CPU resources")
		}
	case AnomalyTypeBehavioral:
		actions = append(actions, "Review recent system changes")
		actions = append(actions, "Check for unusual user activity patterns")
		actions = append(actions, "Validate security policies and access controls")
	}

	// Add severity-specific actions
	switch rule.Severity {
	case AnomalySeverityCritical:
		actions = append(actions, "IMMEDIATE ACTION REQUIRED - Consider emergency escalation")
	case AnomalySeverityHigh:
		actions = append(actions, "Prioritize investigation and resolution")
	}

	return actions
}

// StatisticalAnomalyDetector provides statistical anomaly detection using z-score.
type StatisticalAnomalyDetector struct {
	*BasicAnomalyDetector
	zScoreThreshold float64
}

// NewStatisticalAnomalyDetector creates a new statistical anomaly detector.
func NewStatisticalAnomalyDetector(componentName string, logger logging.Logger) *StatisticalAnomalyDetector {
	return &StatisticalAnomalyDetector{
		BasicAnomalyDetector: NewBasicAnomalyDetector(componentName, logger),
		zScoreThreshold:      2.0, // 2 standard deviations
	}
}

// DetectAnomalies detects anomalies using statistical analysis.
func (sad *StatisticalAnomalyDetector) DetectAnomalies(ctx context.Context, metrics *ComponentMetrics) ([]*Anomaly, error) {
	// First, run basic rule-based detection
	anomalies, err := sad.BasicAnomalyDetector.DetectAnomalies(ctx, metrics)
	if err != nil {
		return nil, err
	}

	// Add statistical anomaly detection
	statisticalAnomalies := sad.detectStatisticalAnomalies(ctx, metrics)
	anomalies = append(anomalies, statisticalAnomalies...)

	return anomalies, nil
}

// detectStatisticalAnomalies detects anomalies using z-score analysis.
func (sad *StatisticalAnomalyDetector) detectStatisticalAnomalies(ctx context.Context, metrics *ComponentMetrics) []*Anomaly {
	anomalies := make([]*Anomaly, 0)

	// Need at least 10 data points for statistical analysis
	if len(sad.history) < 10 {
		return anomalies
	}

	// Metrics to analyze statistically
	metricsToAnalyze := []string{"response_time", "throughput", "error_rate", "cpu_percent", "memory_percent"}

	for _, metricName := range metricsToAnalyze {
		anomaly := sad.analyzeMetricStatistically(ctx, metrics, metricName)
		if anomaly != nil {
			anomalies = append(anomalies, anomaly)
		}
	}

	return anomalies
}

// analyzeMetricStatistically analyzes a specific metric for statistical anomalies.
func (sad *StatisticalAnomalyDetector) analyzeMetricStatistically(ctx context.Context, metrics *ComponentMetrics, metricName string) *Anomaly {
	// Extract current value
	currentValue := sad.extractMetricValue(metrics, metricName)
	if currentValue == nil {
		return nil
	}

	// Calculate mean and standard deviation from history
	values := make([]float64, 0)
	for _, snapshot := range sad.history {
		if value := sad.extractMetricValue(snapshot.Metrics, metricName); value != nil {
			values = append(values, *value)
		}
	}

	if len(values) < 10 {
		return nil
	}

	mean := calculateMean(values)
	stdDev := calculateStandardDeviation(values, mean)

	// Calculate z-score
	zScore := (*currentValue - mean) / stdDev

	// Check if z-score exceeds threshold
	if math.Abs(zScore) > sad.zScoreThreshold {
		severity := AnomalySeverityLow
		if math.Abs(zScore) > 3.0 {
			severity = AnomalySeverityHigh
		} else if math.Abs(zScore) > 2.5 {
			severity = AnomalySeverityMedium
		}

		return &Anomaly{
			ID:            fmt.Sprintf("%s_statistical_%s_%d", sad.componentName, metricName, time.Now().Unix()),
			ComponentName: sad.componentName,
			Type:          AnomalyTypeBehavioral,
			Severity:      severity,
			Title:         fmt.Sprintf("Statistical Anomaly in %s", metricName),
			Description:   fmt.Sprintf("%s value of %.2f deviates significantly from normal (z-score: %.2f, mean: %.2f, stddev: %.2f)", metricName, *currentValue, zScore, mean, stdDev),
			DetectedAt:    time.Now(),
			Status:        AnomalyStatusActive,
			Metrics:       metrics,
			Context: map[string]interface{}{
				"metric":           metricName,
				"current_value":    *currentValue,
				"historical_mean":  mean,
				"standard_deviation": stdDev,
				"z_score":          zScore,
				"threshold":        sad.zScoreThreshold,
				"sample_size":      len(values),
			},
			Actions: []string{
				"Investigate recent changes that may have caused this deviation",
				"Compare with other components to identify system-wide patterns",
				"Review logs during the anomaly timeframe",
			},
		}
	}

	return nil
}

// Helper functions for statistical calculations

func calculateMean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, value := range values {
		sum += value
	}
	return sum / float64(len(values))
}

func calculateStandardDeviation(values []float64, mean float64) float64 {
	if len(values) < 2 {
		return 0
	}

	sumSquaredDiff := 0.0
	for _, value := range values {
		diff := value - mean
		sumSquaredDiff += diff * diff
	}

	variance := sumSquaredDiff / float64(len(values)-1)
	return math.Sqrt(variance)
}