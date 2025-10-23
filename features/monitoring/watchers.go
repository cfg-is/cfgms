// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package monitoring

import (
	"context"
	"fmt"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// Context key types to avoid collisions
type contextKey string

const (
	watcherNameKey   contextKey = "watcher_name"
	correlationIDKey contextKey = "correlation_id"
)

// LoggingWatcher logs all system events to the configured logger.
// This provides a simple way to ensure all system events are captured in logs.
type LoggingWatcher struct {
	logger logging.Logger
	name   string
}

// NewLoggingWatcher creates a new logging event watcher.
func NewLoggingWatcher(logger logging.Logger, name string) *LoggingWatcher {
	return &LoggingWatcher{
		logger: logger,
		name:   name,
	}
}

// OnSystemEvent implements the SystemEventWatcher interface.
func (lw *LoggingWatcher) OnSystemEvent(event SystemEvent) {
	ctx := context.Background()

	// Add correlation context if available
	if event.CorrelationID != "" {
		ctx = context.WithValue(ctx, correlationIDKey, event.CorrelationID)
	}

	switch event.Severity {
	case SeverityInfo:
		lw.logger.InfoCtx(ctx, "System event",
			"event_id", event.ID,
			"event_type", event.Type,
			"source", event.Source,
			"component", event.Component,
			"correlation_id", event.CorrelationID,
			"trace_id", event.TraceID,
			"data", event.Data)

	case SeverityWarning:
		lw.logger.WarnCtx(ctx, "System event (warning)",
			"event_id", event.ID,
			"event_type", event.Type,
			"source", event.Source,
			"component", event.Component,
			"correlation_id", event.CorrelationID,
			"trace_id", event.TraceID,
			"data", event.Data)

	case SeverityError, SeverityCritical:
		lw.logger.ErrorCtx(ctx, "System event (error)",
			"event_id", event.ID,
			"event_type", event.Type,
			"source", event.Source,
			"component", event.Component,
			"correlation_id", event.CorrelationID,
			"trace_id", event.TraceID,
			"data", event.Data,
			"severity", event.Severity)

	default:
		lw.logger.DebugCtx(ctx, "System event",
			"event_id", event.ID,
			"event_type", event.Type,
			"source", event.Source,
			"component", event.Component,
			"correlation_id", event.CorrelationID,
			"trace_id", event.TraceID,
			"data", event.Data)
	}
}

// GetWatcherName implements the SystemEventWatcher interface.
func (lw *LoggingWatcher) GetWatcherName() string {
	return lw.name
}

// MetricsWatcher tracks system events for metrics calculation.
// This watcher maintains counters and statistics about system events.
type MetricsWatcher struct {
	logger      logging.Logger
	name        string
	eventCounts map[SystemEventType]int64
	eventTimes  map[SystemEventType]time.Time
}

// NewMetricsWatcher creates a new metrics event watcher.
func NewMetricsWatcher(logger logging.Logger, name string) *MetricsWatcher {
	return &MetricsWatcher{
		logger:      logger,
		name:        name,
		eventCounts: make(map[SystemEventType]int64),
		eventTimes:  make(map[SystemEventType]time.Time),
	}
}

// OnSystemEvent implements the SystemEventWatcher interface.
func (mw *MetricsWatcher) OnSystemEvent(event SystemEvent) {
	// Update event counters
	mw.eventCounts[event.Type]++
	mw.eventTimes[event.Type] = event.Timestamp

	// Log metrics updates for high-severity events
	if event.Severity == SeverityError || event.Severity == SeverityCritical {
		mw.logger.InfoCtx(context.Background(), "Event metrics updated",
			"event_type", event.Type,
			"event_count", mw.eventCounts[event.Type],
			"source", event.Source,
			"severity", event.Severity)
	}
}

// GetWatcherName implements the SystemEventWatcher interface.
func (mw *MetricsWatcher) GetWatcherName() string {
	return mw.name
}

// GetEventCounts returns the current event counts.
func (mw *MetricsWatcher) GetEventCounts() map[SystemEventType]int64 {
	// Return a copy to prevent external modification
	counts := make(map[SystemEventType]int64)
	for eventType, count := range mw.eventCounts {
		counts[eventType] = count
	}
	return counts
}

// GetLastEventTimes returns the timestamps of the last occurrence of each event type.
func (mw *MetricsWatcher) GetLastEventTimes() map[SystemEventType]time.Time {
	// Return a copy to prevent external modification
	times := make(map[SystemEventType]time.Time)
	for eventType, timestamp := range mw.eventTimes {
		times[eventType] = timestamp
	}
	return times
}

// AlertingWatcher sends alerts for critical system events.
// This watcher can be extended to integrate with external alerting systems.
type AlertingWatcher struct {
	logger    logging.Logger
	name      string
	alerter   AlertSender
	threshold map[SystemEventType]EventSeverity
}

// AlertSender defines the interface for sending alerts.
type AlertSender interface {
	// SendAlert sends an alert for the given event
	SendAlert(ctx context.Context, event SystemEvent) error

	// GetSenderName returns the name of the alert sender
	GetSenderName() string
}

// NewAlertingWatcher creates a new alerting event watcher.
func NewAlertingWatcher(logger logging.Logger, name string, alerter AlertSender) *AlertingWatcher {
	// Default thresholds - only alert on warnings and above
	defaultThresholds := map[SystemEventType]EventSeverity{
		EventStewardDisconnected: SeverityWarning,
		EventStewardHealthChange: SeverityWarning,
		EventConfigurationFailed: SeverityError,
		EventConfigurationDrift:  SeverityWarning,
		EventSystemShutdown:      SeverityInfo,
		EventResourceAlert:       SeverityWarning,
		EventWorkflowFailed:      SeverityError,
	}

	return &AlertingWatcher{
		logger:    logger,
		name:      name,
		alerter:   alerter,
		threshold: defaultThresholds,
	}
}

// OnSystemEvent implements the SystemEventWatcher interface.
func (aw *AlertingWatcher) OnSystemEvent(event SystemEvent) {
	// Check if this event type should trigger an alert
	threshold, hasThreshold := aw.threshold[event.Type]
	if !hasThreshold {
		return
	}

	// Check if the event severity meets the threshold
	if !aw.shouldAlert(event.Severity, threshold) {
		return
	}

	// Send the alert
	ctx := context.Background()
	if event.CorrelationID != "" {
		ctx = context.WithValue(ctx, correlationIDKey, event.CorrelationID)
	}

	if err := aw.alerter.SendAlert(ctx, event); err != nil {
		aw.logger.ErrorCtx(ctx, "Failed to send alert",
			"event_id", event.ID,
			"event_type", event.Type,
			"alerter", aw.alerter.GetSenderName(),
			"error", err)
	} else {
		aw.logger.InfoCtx(ctx, "Alert sent",
			"event_id", event.ID,
			"event_type", event.Type,
			"severity", event.Severity,
			"alerter", aw.alerter.GetSenderName())
	}
}

// GetWatcherName implements the SystemEventWatcher interface.
func (aw *AlertingWatcher) GetWatcherName() string {
	return aw.name
}

// SetThreshold sets the alert threshold for a specific event type.
func (aw *AlertingWatcher) SetThreshold(eventType SystemEventType, severity EventSeverity) {
	aw.threshold[eventType] = severity
}

// shouldAlert determines if an alert should be sent based on severity levels.
func (aw *AlertingWatcher) shouldAlert(eventSeverity, threshold EventSeverity) bool {
	severityLevels := map[EventSeverity]int{
		SeverityInfo:     1,
		SeverityWarning:  2,
		SeverityError:    3,
		SeverityCritical: 4,
	}

	eventLevel, eventExists := severityLevels[eventSeverity]
	thresholdLevel, thresholdExists := severityLevels[threshold]

	if !eventExists || !thresholdExists {
		return false
	}

	return eventLevel >= thresholdLevel
}

// ConsoleAlerter is a simple alerter that sends alerts to the console.
// This is useful for development and testing.
type ConsoleAlerter struct {
	name   string
	logger logging.Logger
}

// NewConsoleAlerter creates a new console alerter.
func NewConsoleAlerter(logger logging.Logger, name string) *ConsoleAlerter {
	return &ConsoleAlerter{
		name:   name,
		logger: logger,
	}
}

// SendAlert implements the AlertSender interface.
func (ca *ConsoleAlerter) SendAlert(ctx context.Context, event SystemEvent) error {
	alertMessage := fmt.Sprintf("ALERT [%s]: %s from %s.%s - %s",
		event.Severity,
		event.Type,
		event.Source,
		event.Component,
		event.Data)

	ca.logger.WarnCtx(ctx, alertMessage,
		"alert_type", "console",
		"event_id", event.ID,
		"correlation_id", event.CorrelationID)

	return nil
}

// GetSenderName implements the AlertSender interface.
func (ca *ConsoleAlerter) GetSenderName() string {
	return ca.name
}
