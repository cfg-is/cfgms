// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package performance

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// DefaultAlertManager implements AlertManager
type DefaultAlertManager struct {
	stewardID string

	mu sync.RWMutex

	// Thresholds configuration
	thresholds map[string]Threshold // key: metric name

	// Alert state
	activeAlerts   map[string]*Alert    // key: alert ID
	alertHistory   []Alert              // all alerts (including resolved)
	breachTracking map[string]time.Time // key: metric name, value: first breach time

	// Rate limiting
	lastNotification map[string]time.Time // key: metric name, value: last notification time
	rateLimitPeriod  time.Duration        // minimum time between notifications for same issue

	// Control
	ctx        context.Context
	cancelFunc context.CancelFunc
	started    bool
}

// NewAlertManager creates a new alert manager
func NewAlertManager(stewardID string, thresholds []Threshold) AlertManager {
	thresholdMap := make(map[string]Threshold)
	for _, t := range thresholds {
		thresholdMap[t.MetricName] = t
	}

	return &DefaultAlertManager{
		stewardID:        stewardID,
		thresholds:       thresholdMap,
		activeAlerts:     make(map[string]*Alert),
		alertHistory:     make([]Alert, 0),
		breachTracking:   make(map[string]time.Time),
		lastNotification: make(map[string]time.Time),
		rateLimitPeriod:  15 * time.Minute, // 1 alert per 15 minutes per issue
	}
}

// Start begins alert monitoring
func (m *DefaultAlertManager) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.started {
		return fmt.Errorf("alert manager already started")
	}

	m.ctx, m.cancelFunc = context.WithCancel(ctx)
	m.started = true

	return nil
}

// Stop halts alert monitoring
func (m *DefaultAlertManager) Stop() error {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return fmt.Errorf("alert manager not started")
	}

	m.cancelFunc()
	m.started = false
	m.mu.Unlock()

	return nil
}

// EvaluateMetrics checks metrics against thresholds and generates alerts
func (m *DefaultAlertManager) EvaluateMetrics(metrics *PerformanceMetrics) ([]Alert, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	newAlerts := make([]Alert, 0)

	// Evaluate each threshold
	for metricName, threshold := range m.thresholds {
		// Extract metric value
		value, processName, processPID, err := m.extractMetricValue(metrics, metricName)
		if err != nil {
			continue // Skip if metric not found
		}

		// Check if threshold is breached
		breached := m.evaluateThreshold(value, threshold)

		if breached {
			// Track breach time
			breachKey := metricName
			if processName != "" {
				breachKey = fmt.Sprintf("%s:%s", metricName, processName)
			}

			if _, exists := m.breachTracking[breachKey]; !exists {
				m.breachTracking[breachKey] = now
			}

			firstBreachTime := m.breachTracking[breachKey]
			breachDuration := now.Sub(firstBreachTime)

			// Only alert if breach duration exceeds threshold duration
			if breachDuration >= threshold.Duration {
				// Check rate limiting for critical alerts
				if threshold.Severity == "critical" {
					if lastNotif, exists := m.lastNotification[breachKey]; exists {
						if now.Sub(lastNotif) < m.rateLimitPeriod {
							continue // Rate limited
						}
					}
				}

				// Create or update alert
				alert := m.createOrUpdateAlert(
					metricName,
					threshold,
					value,
					firstBreachTime,
					now,
					processName,
					processPID,
				)

				newAlerts = append(newAlerts, *alert)

				// Update last notification time
				m.lastNotification[breachKey] = now
			}
		} else {
			// Threshold not breached - resolve any active alerts
			breachKey := metricName
			if processName != "" {
				breachKey = fmt.Sprintf("%s:%s", metricName, processName)
			}

			m.resolveAlert(breachKey, now)
			delete(m.breachTracking, breachKey)
		}
	}

	return newAlerts, nil
}

// extractMetricValue extracts a specific metric value from PerformanceMetrics
func (m *DefaultAlertManager) extractMetricValue(metrics *PerformanceMetrics, metricName string) (float64, string, int32, error) {
	// System metrics
	if metrics.System != nil {
		switch metricName {
		case "cpu_percent":
			return metrics.System.CPUPercent, "", 0, nil
		case "memory_percent":
			return metrics.System.MemoryPercent, "", 0, nil
		case "disk_read_bytes_per_sec":
			return float64(metrics.System.DiskReadBytesPerSec), "", 0, nil
		case "disk_write_bytes_per_sec":
			return float64(metrics.System.DiskWriteBytesPerSec), "", 0, nil
		case "net_recv_bytes_per_sec":
			return float64(metrics.System.NetRecvBytesPerSec), "", 0, nil
		case "net_sent_bytes_per_sec":
			return float64(metrics.System.NetSentBytesPerSec), "", 0, nil
		}
	}

	// Process metrics - check top processes
	if metricName == "process_cpu_percent" || metricName == "process_memory_percent" {
		for _, proc := range metrics.TopProcesses {
			var value float64
			if metricName == "process_cpu_percent" {
				value = proc.CPUPercent
			} else {
				value = proc.MemoryPercent
			}

			// Return the highest value found
			threshold := m.thresholds[metricName]
			if m.evaluateThreshold(value, threshold) {
				return value, proc.Name, proc.PID, nil
			}
		}
	}

	return 0, "", 0, fmt.Errorf("metric not found: %s", metricName)
}

// evaluateThreshold checks if a value breaches the threshold
func (m *DefaultAlertManager) evaluateThreshold(value float64, threshold Threshold) bool {
	switch threshold.Operator {
	case ">":
		return value > threshold.Value
	case ">=":
		return value >= threshold.Value
	case "<":
		return value < threshold.Value
	case "<=":
		return value <= threshold.Value
	case "==":
		return value == threshold.Value
	default:
		return false
	}
}

// createOrUpdateAlert creates a new alert or updates an existing one
func (m *DefaultAlertManager) createOrUpdateAlert(
	metricName string,
	threshold Threshold,
	currentValue float64,
	firstBreachTime, lastBreachTime time.Time,
	processName string,
	processPID int32,
) *Alert {
	// Check if alert already exists
	var alert *Alert
	for _, a := range m.activeAlerts {
		if a.MetricName == metricName && a.ProcessName == processName && a.Status == "active" {
			alert = a
			break
		}
	}

	if alert == nil {
		// Create new alert
		title := fmt.Sprintf("%s threshold breached", metricName)
		description := fmt.Sprintf("%s is %s %.2f (threshold: %.2f)",
			metricName, threshold.Operator, currentValue, threshold.Value)

		if processName != "" {
			title = fmt.Sprintf("Process %s: %s threshold breached", processName, metricName)
			description = fmt.Sprintf("Process %s (PID %d): %s is %s %.2f (threshold: %.2f)",
				processName, processPID, metricName, threshold.Operator, currentValue, threshold.Value)
		}

		alert = &Alert{
			ID:              uuid.New().String(),
			StewardID:       m.stewardID,
			Timestamp:       firstBreachTime,
			Severity:        threshold.Severity,
			Title:           title,
			Description:     description,
			MetricName:      metricName,
			CurrentValue:    currentValue,
			ThresholdValue:  threshold.Value,
			Status:          "active",
			FirstBreachTime: firstBreachTime,
			LastBreachTime:  lastBreachTime,
			ProcessName:     processName,
			ProcessPID:      processPID,
		}
		m.activeAlerts[alert.ID] = alert
		m.alertHistory = append(m.alertHistory, *alert)
	} else {
		// Update existing alert
		alert.LastBreachTime = lastBreachTime
		alert.CurrentValue = currentValue

		description := fmt.Sprintf("%s is %s %.2f (threshold: %.2f)",
			metricName, threshold.Operator, currentValue, threshold.Value)
		if processName != "" {
			description = fmt.Sprintf("Process %s (PID %d): %s is %s %.2f (threshold: %.2f)",
				processName, processPID, metricName, threshold.Operator, currentValue, threshold.Value)
		}
		alert.Description = description
	}

	return alert
}

// resolveAlert resolves an active alert
func (m *DefaultAlertManager) resolveAlert(breachKey string, resolvedAt time.Time) {
	for _, alert := range m.activeAlerts {
		alertKey := alert.MetricName
		if alert.ProcessName != "" {
			alertKey = fmt.Sprintf("%s:%s", alert.MetricName, alert.ProcessName)
		}

		if alertKey == breachKey && alert.Status == "active" {
			alert.Status = "resolved"
			alert.ResolvedAt = &resolvedAt

			// Update in history
			for i := range m.alertHistory {
				if m.alertHistory[i].ID == alert.ID {
					m.alertHistory[i] = *alert
					break
				}
			}

			delete(m.activeAlerts, alert.ID)
		}
	}
}

// GetActiveAlerts returns all active alerts
func (m *DefaultAlertManager) GetActiveAlerts() []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alerts := make([]Alert, 0, len(m.activeAlerts))
	for _, alert := range m.activeAlerts {
		alerts = append(alerts, *alert)
	}

	return alerts
}

// GetAlertHistory returns alerts within the specified time range
func (m *DefaultAlertManager) GetAlertHistory(start, end time.Time) []Alert {
	m.mu.RLock()
	defer m.mu.RUnlock()

	alerts := make([]Alert, 0)
	for _, alert := range m.alertHistory {
		if (alert.Timestamp.After(start) || alert.Timestamp.Equal(start)) &&
			(alert.Timestamp.Before(end) || alert.Timestamp.Equal(end)) {
			alerts = append(alerts, alert)
		}
	}

	return alerts
}

// AddThreshold adds a new threshold configuration
func (m *DefaultAlertManager) AddThreshold(threshold Threshold) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.thresholds[threshold.MetricName] = threshold
	return nil
}

// RemoveThreshold removes a threshold configuration
func (m *DefaultAlertManager) RemoveThreshold(metricName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.thresholds, metricName)
	return nil
}

// ResolveAlert marks an alert as resolved
func (m *DefaultAlertManager) ResolveAlert(alertID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	alert, exists := m.activeAlerts[alertID]
	if !exists {
		return fmt.Errorf("alert not found: %s", alertID)
	}

	now := time.Now()
	alert.Status = "resolved"
	alert.ResolvedAt = &now

	// Update in history
	for i := range m.alertHistory {
		if m.alertHistory[i].ID == alertID {
			m.alertHistory[i] = *alert
			break
		}
	}

	delete(m.activeAlerts, alertID)
	return nil
}
