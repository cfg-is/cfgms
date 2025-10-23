// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package health

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/cert"
)

// AlertManager manages threshold-based alerting and notifications
type AlertManager interface {
	// Start begins alert monitoring
	Start(ctx context.Context) error

	// Stop halts alert monitoring
	Stop() error

	// EvaluateMetrics checks metrics against thresholds and generates alerts
	EvaluateMetrics(metrics *ControllerMetrics) error

	// GetActiveAlerts returns all active alerts
	GetActiveAlerts() []Alert

	// GetAlertHistory returns alerts within the specified time range
	GetAlertHistory(start, end time.Time) []Alert

	// AddThreshold adds a new threshold configuration
	AddThreshold(threshold Threshold) error

	// RemoveThreshold removes a threshold configuration
	RemoveThreshold(metricName string) error
}

// SMTPConfig defines SMTP server configuration for email alerts
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	UseTLS   bool
}

// DefaultAlertManager implements AlertManager
type DefaultAlertManager struct {
	mu sync.RWMutex

	// Thresholds configuration
	thresholds map[string]Threshold // key: metric name

	// Alert state
	activeAlerts   map[string]*Alert // key: alert ID
	alertHistory   []Alert
	breachTracking map[string]time.Time // key: metric name, value: first breach time

	// Rate limiting
	lastNotification map[string]time.Time // key: metric name, value: last notification time
	rateLimitPeriod  time.Duration        // minimum time between notifications for same issue

	// Email configuration
	smtpConfig SMTPConfig

	// Control
	ctx        context.Context
	cancelFunc context.CancelFunc
	wg         sync.WaitGroup
	started    bool
}

// NewAlertManager creates a new alert manager
func NewAlertManager(thresholds []Threshold, smtpConfig SMTPConfig) *DefaultAlertManager {
	thresholdMap := make(map[string]Threshold)
	for _, t := range thresholds {
		thresholdMap[t.MetricName] = t
	}

	return &DefaultAlertManager{
		thresholds:       thresholdMap,
		activeAlerts:     make(map[string]*Alert),
		alertHistory:     make([]Alert, 0),
		breachTracking:   make(map[string]time.Time),
		lastNotification: make(map[string]time.Time),
		rateLimitPeriod:  15 * time.Minute, // 1 alert per 15 minutes per issue
		smtpConfig:       smtpConfig,
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

	m.wg.Wait()
	return nil
}

// EvaluateMetrics checks metrics against thresholds and generates alerts
func (m *DefaultAlertManager) EvaluateMetrics(metrics *ControllerMetrics) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Evaluate each threshold
	for metricName, threshold := range m.thresholds {
		// Extract metric value
		value, metricType, err := m.extractMetricValue(metrics, metricName)
		if err != nil {
			continue // Skip if metric not found
		}

		// Check if threshold is breached
		breached := m.evaluateThreshold(value, threshold)

		if breached {
			// Track breach time
			if _, exists := m.breachTracking[metricName]; !exists {
				m.breachTracking[metricName] = now
			}

			firstBreachTime := m.breachTracking[metricName]
			breachDuration := now.Sub(firstBreachTime)

			// Only alert if breach duration exceeds threshold duration
			if breachDuration >= threshold.Duration {
				// Check if this is a CRITICAL severity threshold
				if threshold.Severity == SeverityCritical {
					// Check rate limiting
					if lastNotif, exists := m.lastNotification[metricName]; exists {
						if now.Sub(lastNotif) < m.rateLimitPeriod {
							continue // Rate limited
						}
					}

					// Create or update alert
					m.createOrUpdateAlert(metricName, metricType, threshold, value, firstBreachTime, now)

					// Send notification
					if err := m.sendEmailNotification(metricName, metricType, threshold, value); err != nil {
						// Log error but don't fail
						fmt.Printf("Failed to send email notification: %v\n", err)
					}

					// Update last notification time
					m.lastNotification[metricName] = now
				}
			}
		} else {
			// Threshold not breached - resolve any active alerts
			m.resolveAlert(metricName, now)
			delete(m.breachTracking, metricName)
		}
	}

	return nil
}

// extractMetricValue extracts a specific metric value from ControllerMetrics
func (m *DefaultAlertManager) extractMetricValue(metrics *ControllerMetrics, metricName string) (float64, MetricType, error) {
	// MQTT metrics
	if metrics.MQTT != nil {
		switch metricName {
		case "mqtt_active_connections":
			return float64(metrics.MQTT.ActiveConnections), MetricTypeMQTT, nil
		case "mqtt_queue_depth":
			return float64(metrics.MQTT.MessageQueueDepth), MetricTypeMQTT, nil
		case "mqtt_connection_errors":
			return float64(metrics.MQTT.ConnectionErrors), MetricTypeMQTT, nil
		}
	}

	// Storage metrics
	if metrics.Storage != nil {
		switch metricName {
		case "storage_pool_utilization":
			return metrics.Storage.PoolUtilization, MetricTypeStorage, nil
		case "storage_avg_latency_ms":
			return metrics.Storage.AvgQueryLatencyMs, MetricTypeStorage, nil
		case "storage_p95_latency_ms":
			return metrics.Storage.P95QueryLatencyMs, MetricTypeStorage, nil
		case "storage_slow_queries":
			return float64(metrics.Storage.SlowQueryCount), MetricTypeStorage, nil
		case "storage_query_errors":
			return float64(metrics.Storage.QueryErrors), MetricTypeStorage, nil
		}
	}

	// Application metrics
	if metrics.Application != nil {
		switch metricName {
		case "workflow_queue_depth":
			return float64(metrics.Application.WorkflowQueueDepth), MetricTypeApplication, nil
		case "workflow_max_wait_time":
			return metrics.Application.WorkflowMaxWaitTime, MetricTypeApplication, nil
		case "script_queue_depth":
			return float64(metrics.Application.ScriptQueueDepth), MetricTypeApplication, nil
		case "script_max_wait_time":
			return metrics.Application.ScriptMaxWaitTime, MetricTypeApplication, nil
		case "config_queue_depth":
			return float64(metrics.Application.ConfigQueueDepth), MetricTypeApplication, nil
		}
	}

	// System metrics
	if metrics.System != nil {
		switch metricName {
		case "cpu_percent":
			return metrics.System.CPUPercent, MetricTypeSystem, nil
		case "memory_percent":
			return metrics.System.MemoryPercent, MetricTypeSystem, nil
		case "goroutine_count":
			return float64(metrics.System.GoroutineCount), MetricTypeSystem, nil
		case "heap_bytes":
			return float64(metrics.System.HeapBytes), MetricTypeSystem, nil
		}
	}

	return 0, "", fmt.Errorf("metric not found: %s", metricName)
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
	metricType MetricType,
	threshold Threshold,
	currentValue float64,
	firstBreachTime, lastBreachTime time.Time,
) {
	// Check if alert already exists
	var alert *Alert
	for _, a := range m.activeAlerts {
		if a.MetricName == metricName && a.Status == "active" {
			alert = a
			break
		}
	}

	if alert == nil {
		// Create new alert
		alert = &Alert{
			ID:              uuid.New().String(),
			Timestamp:       firstBreachTime,
			Severity:        threshold.Severity,
			Title:           fmt.Sprintf("%s threshold breached", metricName),
			Description:     fmt.Sprintf("%s is %s %.2f (threshold: %.2f)", metricName, threshold.Operator, currentValue, threshold.Value),
			MetricType:      metricType,
			MetricName:      metricName,
			CurrentValue:    currentValue,
			ThresholdValue:  threshold.Value,
			Status:          "active",
			FirstBreachTime: firstBreachTime,
			LastBreachTime:  lastBreachTime,
		}
		m.activeAlerts[alert.ID] = alert
		m.alertHistory = append(m.alertHistory, *alert)
	} else {
		// Update existing alert
		alert.LastBreachTime = lastBreachTime
		alert.CurrentValue = currentValue
		alert.Description = fmt.Sprintf("%s is %s %.2f (threshold: %.2f)", metricName, threshold.Operator, currentValue, threshold.Value)
	}
}

// resolveAlert resolves an active alert
func (m *DefaultAlertManager) resolveAlert(metricName string, resolvedAt time.Time) {
	for _, alert := range m.activeAlerts {
		if alert.MetricName == metricName && alert.Status == "active" {
			alert.Status = "resolved"
			alert.ResolvedAt = &resolvedAt
			delete(m.activeAlerts, alert.ID)
		}
	}
}

// sendEmailNotification sends an email alert notification
func (m *DefaultAlertManager) sendEmailNotification(
	metricName string,
	metricType MetricType,
	threshold Threshold,
	currentValue float64,
) error {
	if m.smtpConfig.Host == "" {
		return nil // Email not configured
	}

	// Build email message
	subject := fmt.Sprintf("[CRITICAL] CFGMS Controller Alert: %s", metricName)
	body := fmt.Sprintf(`CFGMS Controller Health Alert

Severity: CRITICAL
Metric Type: %s
Metric Name: %s
Current Value: %.2f
Threshold: %s %.2f
Time: %s

This alert indicates that the controller metric has exceeded its configured threshold.
Please investigate the controller health and take appropriate action.

---
This is an automated alert from CFGMS Controller Health Monitoring.
`, metricType, metricName, currentValue, threshold.Operator, threshold.Value, time.Now().Format(time.RFC3339))

	// Build email message with headers
	message := fmt.Sprintf("From: %s\r\n", m.smtpConfig.From)
	message += fmt.Sprintf("To: %s\r\n", m.smtpConfig.To[0])
	message += fmt.Sprintf("Subject: %s\r\n", subject)
	message += "Content-Type: text/plain; charset=UTF-8\r\n"
	message += "\r\n"
	message += body

	// Send email
	auth := smtp.PlainAuth("", m.smtpConfig.Username, m.smtpConfig.Password, m.smtpConfig.Host)
	addr := fmt.Sprintf("%s:%d", m.smtpConfig.Host, m.smtpConfig.Port)

	if m.smtpConfig.UseTLS {
		// Use TLS connection with basic TLS config from pkg/cert
		tlsConfig, err := cert.CreateBasicTLSConfig(nil, nil, tls.VersionTLS12)
		if err != nil {
			return fmt.Errorf("failed to create TLS config: %w", err)
		}
		tlsConfig.ServerName = m.smtpConfig.Host

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
		defer func() {
			if err := conn.Close(); err != nil {
				fmt.Printf("Failed to close SMTP connection: %v\n", err)
			}
		}()

		client, err := smtp.NewClient(conn, m.smtpConfig.Host)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer func() {
			if err := client.Close(); err != nil {
				fmt.Printf("Failed to close SMTP client: %v\n", err)
			}
		}()

		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}

		if err := client.Mail(m.smtpConfig.From); err != nil {
			return fmt.Errorf("failed to set sender: %w", err)
		}

		for _, to := range m.smtpConfig.To {
			if err := client.Rcpt(to); err != nil {
				return fmt.Errorf("failed to set recipient: %w", err)
			}
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("failed to get data writer: %w", err)
		}

		_, err = w.Write([]byte(message))
		if err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}

		err = w.Close()
		if err != nil {
			return fmt.Errorf("failed to close writer: %w", err)
		}

		return client.Quit()
	}

	// Use plain SMTP
	return smtp.SendMail(addr, auth, m.smtpConfig.From, m.smtpConfig.To, []byte(message))
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
		if alert.Timestamp.After(start) && alert.Timestamp.Before(end) {
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

// DefaultThresholds returns the default threshold configurations
func DefaultThresholds() []Threshold {
	return []Threshold{
		{
			MetricName: "mqtt_queue_depth",
			Value:      1000,
			Operator:   ">",
			Severity:   SeverityCritical,
			Duration:   5 * time.Minute,
		},
		{
			MetricName: "workflow_queue_depth",
			Value:      500,
			Operator:   ">",
			Severity:   SeverityCritical,
			Duration:   5 * time.Minute,
		},
		{
			MetricName: "script_queue_depth",
			Value:      500,
			Operator:   ">",
			Severity:   SeverityCritical,
			Duration:   5 * time.Minute,
		},
		{
			MetricName: "storage_p95_latency_ms",
			Value:      1000,
			Operator:   ">",
			Severity:   SeverityCritical,
			Duration:   5 * time.Minute,
		},
		{
			MetricName: "cpu_percent",
			Value:      90,
			Operator:   ">",
			Severity:   SeverityCritical,
			Duration:   10 * time.Minute,
		},
		{
			MetricName: "memory_percent",
			Value:      90,
			Operator:   ">",
			Severity:   SeverityCritical,
			Duration:   10 * time.Minute,
		},
	}
}
