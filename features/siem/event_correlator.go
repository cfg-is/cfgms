package siem

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// EventCorrelatorImpl implements event correlation across time windows for SIEM analysis.
// It maintains sliding windows of security events and applies correlation rules to detect
// patterns that span multiple events and timeframes.
type EventCorrelatorImpl struct {
	logger *logging.ModuleLogger

	// Correlation state
	correlationRules map[string]*CorrelationRule
	eventWindows     map[string]*EventWindow
	correlatedEvents map[string]*CorrelatedEvent
	mutex            sync.RWMutex

	// Configuration
	defaultWindow    time.Duration
	maxEventsPerWindow int
	cleanupInterval  time.Duration

	// Background processing
	stopChan    chan struct{}
	cleanupDone chan struct{}

	// Statistics
	totalCorrelations    int64
	totalEventsProcessed int64
	activeWindows        int64
	statsLock           sync.RWMutex
}

// EventWindow represents a sliding window of events for correlation
type EventWindow struct {
	ID         string
	RuleID     string
	Events     []*SecurityEvent
	StartTime  time.Time
	EndTime    time.Time
	LastUpdate time.Time
	TenantID   string
	GroupKey   string
	Metadata   map[string]interface{}
}

// NewEventCorrelator creates a new event correlator
func NewEventCorrelator(defaultWindow time.Duration) *EventCorrelatorImpl {
	logger := logging.ForModule("siem.event_correlator").WithField("component", "correlator")

	if defaultWindow == 0 {
		defaultWindow = 5 * time.Minute // Default correlation window
	}

	return &EventCorrelatorImpl{
		logger:             logger,
		correlationRules:   make(map[string]*CorrelationRule),
		eventWindows:       make(map[string]*EventWindow),
		correlatedEvents:   make(map[string]*CorrelatedEvent),
		defaultWindow:      defaultWindow,
		maxEventsPerWindow: 1000, // Prevent memory exhaustion
		cleanupInterval:    1 * time.Minute,
		stopChan:          make(chan struct{}),
		cleanupDone:       make(chan struct{}),
	}
}

// Start starts the event correlator background processes
func (ec *EventCorrelatorImpl) Start(ctx context.Context) error {
	ec.logger.InfoCtx(ctx, "Starting event correlator",
		"default_window", ec.defaultWindow.String(),
		"cleanup_interval", ec.cleanupInterval.String())

	// Start cleanup goroutine
	go ec.cleanupLoop(ctx)

	return nil
}

// Stop stops the event correlator
func (ec *EventCorrelatorImpl) Stop(ctx context.Context) error {
	ec.logger.InfoCtx(ctx, "Stopping event correlator")

	close(ec.stopChan)

	// Wait for cleanup to finish with timeout
	select {
	case <-ec.cleanupDone:
		ec.logger.InfoCtx(ctx, "Event correlator stopped gracefully")
	case <-time.After(10 * time.Second):
		ec.logger.WarnCtx(ctx, "Event correlator cleanup timeout")
	}

	return nil
}

// CorrelateEvents correlates security events within the specified time window
func (ec *EventCorrelatorImpl) CorrelateEvents(ctx context.Context, events []*SecurityEvent,
	window time.Duration) ([]*CorrelatedEvent, error) {

	if len(events) == 0 {
		return nil, nil
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := ec.logger.WithTenant(tenantID)

	logger.DebugCtx(ctx, "Correlating events",
		"event_count", len(events),
		"window", window.String())

	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	var correlatedEvents []*CorrelatedEvent

	// Update statistics
	ec.statsLock.Lock()
	ec.totalEventsProcessed += int64(len(events))
	ec.statsLock.Unlock()

	// Process each event for correlation
	for _, event := range events {
		if event == nil {
			continue
		}

		// Find applicable correlation rules
		applicableRules := ec.findApplicableRules(event)

		for _, rule := range applicableRules {
			// Add event to appropriate window
			windowKey := ec.buildWindowKey(rule, event)
			eventWindow := ec.getOrCreateWindow(windowKey, rule, event, window)

			// Add event to window
			if ec.addEventToWindow(eventWindow, event) {
				// Check if correlation conditions are met
				if correlatedEvent := ec.checkCorrelationConditions(eventWindow, rule); correlatedEvent != nil {
					correlatedEvents = append(correlatedEvents, correlatedEvent)

					// Store correlated event
					ec.correlatedEvents[correlatedEvent.ID] = correlatedEvent

					// Update statistics
					ec.statsLock.Lock()
					ec.totalCorrelations++
					ec.statsLock.Unlock()

					logger.InfoCtx(ctx, "Events correlated",
						"correlation_id", correlatedEvent.ID,
						"rule_id", correlatedEvent.RuleID,
						"event_count", len(correlatedEvent.Events),
						"severity", correlatedEvent.Severity)
				}
			}
		}
	}

	return correlatedEvents, nil
}

// AddCorrelationRule adds a new correlation rule
func (ec *EventCorrelatorImpl) AddCorrelationRule(rule *CorrelationRule) error {
	if rule == nil {
		return fmt.Errorf("correlation rule cannot be nil")
	}

	if rule.ID == "" {
		return fmt.Errorf("correlation rule ID cannot be empty")
	}

	if err := ec.validateCorrelationRule(rule); err != nil {
		return fmt.Errorf("invalid correlation rule: %w", err)
	}

	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	ec.correlationRules[rule.ID] = rule

	ec.logger.Info("Added correlation rule",
		"rule_id", rule.ID,
		"name", rule.Name,
		"event_types", rule.EventTypes,
		"time_window", rule.TimeWindow.String())

	return nil
}

// RemoveCorrelationRule removes a correlation rule
func (ec *EventCorrelatorImpl) RemoveCorrelationRule(ruleID string) error {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	if _, exists := ec.correlationRules[ruleID]; !exists {
		return fmt.Errorf("correlation rule '%s' not found", ruleID)
	}

	delete(ec.correlationRules, ruleID)

	// Clean up related windows
	for windowKey, window := range ec.eventWindows {
		if window.RuleID == ruleID {
			delete(ec.eventWindows, windowKey)
		}
	}

	ec.logger.Info("Removed correlation rule", "rule_id", ruleID)
	return nil
}

// GetActiveCorrelations returns currently active event correlations
func (ec *EventCorrelatorImpl) GetActiveCorrelations(ctx context.Context) ([]*CorrelatedEvent, error) {
	ec.mutex.RLock()
	defer ec.mutex.RUnlock()

	correlations := make([]*CorrelatedEvent, 0, len(ec.correlatedEvents))
	for _, correlation := range ec.correlatedEvents {
		// Return a copy to prevent external modification
		correlationCopy := *correlation
		correlationCopy.Events = make([]*SecurityEvent, len(correlation.Events))
		copy(correlationCopy.Events, correlation.Events)
		correlations = append(correlations, &correlationCopy)
	}

	return correlations, nil
}

// findApplicableRules finds correlation rules that apply to a given event
func (ec *EventCorrelatorImpl) findApplicableRules(event *SecurityEvent) []*CorrelationRule {
	var applicableRules []*CorrelationRule

	for _, rule := range ec.correlationRules {
		if !rule.Enabled {
			continue
		}

		// Check if event type matches
		if len(rule.EventTypes) > 0 {
			eventTypeMatch := false
			for _, eventType := range rule.EventTypes {
				if eventType == event.EventType {
					eventTypeMatch = true
					break
				}
			}
			if !eventTypeMatch {
				continue
			}
		}

		// Check additional conditions
		if ec.evaluateRuleConditions(rule, event) {
			applicableRules = append(applicableRules, rule)
		}
	}

	return applicableRules
}

// evaluateRuleConditions evaluates additional rule conditions
func (ec *EventCorrelatorImpl) evaluateRuleConditions(rule *CorrelationRule, event *SecurityEvent) bool {
	if len(rule.Conditions) == 0 {
		return true
	}

	for _, condition := range rule.Conditions {
		if !ec.evaluateCondition(condition, event) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single condition against an event
func (ec *EventCorrelatorImpl) evaluateCondition(condition *Condition, event *SecurityEvent) bool {
	var fieldValue interface{}

	// Get field value
	switch condition.Field {
	case "event_type":
		fieldValue = event.EventType
	case "severity":
		fieldValue = string(event.Severity)
	case "source":
		fieldValue = event.Source
	case "description":
		fieldValue = event.Description
	case "tenant_id":
		fieldValue = event.TenantID
	default:
		// Check custom fields
		var exists bool
		fieldValue, exists = event.Fields[condition.Field]
		if !exists {
			return false
		}
	}

	// Apply operator
	return ec.applyConditionOperator(condition.Operator, fieldValue, condition.Value, condition.CaseSensitive)
}

// applyConditionOperator applies a condition operator
func (ec *EventCorrelatorImpl) applyConditionOperator(operator string, fieldValue, conditionValue interface{}, caseSensitive bool) bool {
	fieldStr := fmt.Sprintf("%v", fieldValue)
	conditionStr := fmt.Sprintf("%v", conditionValue)

	if !caseSensitive {
		fieldStr = strings.ToLower(fieldStr)
		conditionStr = strings.ToLower(conditionStr)
	}

	switch operator {
	case "equals":
		return fieldStr == conditionStr
	case "not_equals":
		return fieldStr != conditionStr
	case "contains":
		return strings.Contains(fieldStr, conditionStr)
	case "not_contains":
		return !strings.Contains(fieldStr, conditionStr)
	case "starts_with":
		return strings.HasPrefix(fieldStr, conditionStr)
	case "ends_with":
		return strings.HasSuffix(fieldStr, conditionStr)
	default:
		return false
	}
}

// buildWindowKey builds a unique key for an event window
func (ec *EventCorrelatorImpl) buildWindowKey(rule *CorrelationRule, event *SecurityEvent) string {
	var keyParts []string

	// Add rule ID
	keyParts = append(keyParts, fmt.Sprintf("rule:%s", rule.ID))

	// Add tenant ID for isolation
	if event.TenantID != "" {
		keyParts = append(keyParts, fmt.Sprintf("tenant:%s", event.TenantID))
	}

	// Add group by fields
	for _, field := range rule.GroupBy {
		var value string
		switch field {
		case "event_type":
			value = event.EventType
		case "severity":
			value = string(event.Severity)
		case "source":
			value = event.Source
		case "tenant_id":
			value = event.TenantID
		default:
			if fieldValue, exists := event.Fields[field]; exists {
				value = fmt.Sprintf("%v", fieldValue)
			}
		}
		keyParts = append(keyParts, fmt.Sprintf("%s:%s", field, value))
	}

	return strings.Join(keyParts, "|")
}

// getOrCreateWindow gets or creates an event window
func (ec *EventCorrelatorImpl) getOrCreateWindow(windowKey string, rule *CorrelationRule,
	event *SecurityEvent, window time.Duration) *EventWindow {

	if existingWindow, exists := ec.eventWindows[windowKey]; exists {
		// Check if window is still valid
		windowDuration := window
		if rule.TimeWindow > 0 {
			windowDuration = rule.TimeWindow
		} else if ec.defaultWindow > 0 {
			windowDuration = ec.defaultWindow
		}

		if time.Since(existingWindow.StartTime) <= windowDuration {
			return existingWindow
		}
		// Window expired, will create new one
		delete(ec.eventWindows, windowKey)
	}

	// Create new window
	newWindow := &EventWindow{
		ID:         fmt.Sprintf("window_%s_%d", windowKey, time.Now().UnixNano()),
		RuleID:     rule.ID,
		Events:     make([]*SecurityEvent, 0),
		StartTime:  event.Timestamp,
		EndTime:    event.Timestamp.Add(window),
		LastUpdate: time.Now(),
		TenantID:   event.TenantID,
		GroupKey:   windowKey,
		Metadata:   make(map[string]interface{}),
	}

	ec.eventWindows[windowKey] = newWindow

	// Update statistics
	ec.statsLock.Lock()
	ec.activeWindows = int64(len(ec.eventWindows))
	ec.statsLock.Unlock()

	return newWindow
}

// addEventToWindow adds an event to a window
func (ec *EventCorrelatorImpl) addEventToWindow(window *EventWindow, event *SecurityEvent) bool {
	if len(window.Events) >= ec.maxEventsPerWindow {
		ec.logger.Warn("Event window at maximum capacity, dropping event",
			"window_id", window.ID,
			"max_events", ec.maxEventsPerWindow)
		return false
	}

	window.Events = append(window.Events, event)
	window.LastUpdate = time.Now()

	// Update window end time if necessary
	if event.Timestamp.After(window.EndTime) {
		rule := ec.correlationRules[window.RuleID]
		windowDuration := ec.defaultWindow
		if rule != nil && rule.TimeWindow > 0 {
			windowDuration = rule.TimeWindow
		}
		window.EndTime = event.Timestamp.Add(windowDuration)
	}

	return true
}

// checkCorrelationConditions checks if correlation conditions are met for a window
func (ec *EventCorrelatorImpl) checkCorrelationConditions(window *EventWindow, rule *CorrelationRule) *CorrelatedEvent {
	eventCount := len(window.Events)

	// Check minimum events requirement
	if rule.MinEvents > 0 && eventCount < rule.MinEvents {
		return nil
	}

	// Check maximum events limit
	if rule.MaxEvents > 0 && eventCount > rule.MaxEvents {
		return nil
	}

	// Correlation conditions met, create correlated event
	return ec.createCorrelatedEvent(window, rule)
}

// createCorrelatedEvent creates a correlated event from a window
func (ec *EventCorrelatorImpl) createCorrelatedEvent(window *EventWindow, rule *CorrelationRule) *CorrelatedEvent {
	// Sort events by timestamp
	sortedEvents := make([]*SecurityEvent, len(window.Events))
	copy(sortedEvents, window.Events)
	sort.Slice(sortedEvents, func(i, j int) bool {
		return sortedEvents[i].Timestamp.Before(sortedEvents[j].Timestamp)
	})

	// Determine severity (use highest severity)
	severity := SeverityInfo
	for _, event := range sortedEvents {
		if ec.severityLevel(event.Severity) > ec.severityLevel(severity) {
			severity = event.Severity
		}
	}

	// Generate description
	description := fmt.Sprintf("Correlated %d events matching rule '%s'", len(sortedEvents), rule.Name)

	// Create metadata
	metadata := map[string]interface{}{
		"rule_name":       rule.Name,
		"window_start":    window.StartTime,
		"window_end":      window.EndTime,
		"group_key":       window.GroupKey,
		"event_count":     len(sortedEvents),
		"correlation_time": time.Now(),
	}

	return &CorrelatedEvent{
		ID:          fmt.Sprintf("corr_%s_%d", rule.ID, time.Now().UnixNano()),
		RuleID:      rule.ID,
		Events:      sortedEvents,
		Timestamp:   time.Now(),
		WindowStart: window.StartTime,
		WindowEnd:   window.EndTime,
		Severity:    severity,
		Description: description,
		TenantID:    window.TenantID,
		Metadata:    metadata,
	}
}

// severityLevel returns a numeric level for severity comparison
func (ec *EventCorrelatorImpl) severityLevel(severity EventSeverity) int {
	switch severity {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// cleanupLoop runs periodic cleanup of expired windows and correlations
func (ec *EventCorrelatorImpl) cleanupLoop(ctx context.Context) {
	defer close(ec.cleanupDone)

	ticker := time.NewTicker(ec.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ec.stopChan:
			return
		case <-ticker.C:
			ec.performCleanup(ctx)
		}
	}
}

// performCleanup removes expired windows and old correlations
func (ec *EventCorrelatorImpl) performCleanup(ctx context.Context) {
	ec.mutex.Lock()
	defer ec.mutex.Unlock()

	now := time.Now()
	expiredWindows := 0
	expiredCorrelations := 0

	// Clean up expired windows
	for windowKey, window := range ec.eventWindows {
		if now.After(window.EndTime.Add(time.Minute)) { // Grace period
			delete(ec.eventWindows, windowKey)
			expiredWindows++
		}
	}

	// Clean up old correlations (keep for 1 hour)
	for corrID, correlation := range ec.correlatedEvents {
		if now.Sub(correlation.Timestamp) > 1*time.Hour {
			delete(ec.correlatedEvents, corrID)
			expiredCorrelations++
		}
	}

	// Update statistics
	ec.statsLock.Lock()
	ec.activeWindows = int64(len(ec.eventWindows))
	ec.statsLock.Unlock()

	if expiredWindows > 0 || expiredCorrelations > 0 {
		ec.logger.DebugCtx(ctx, "Cleanup completed",
			"expired_windows", expiredWindows,
			"expired_correlations", expiredCorrelations,
			"active_windows", len(ec.eventWindows),
			"active_correlations", len(ec.correlatedEvents))
	}
}

// validateCorrelationRule validates a correlation rule
func (ec *EventCorrelatorImpl) validateCorrelationRule(rule *CorrelationRule) error {
	if rule.TimeWindow <= 0 {
		return fmt.Errorf("time window must be greater than zero")
	}

	if rule.TimeWindow > 24*time.Hour {
		return fmt.Errorf("time window cannot exceed 24 hours")
	}

	if rule.MinEvents < 0 {
		return fmt.Errorf("min events cannot be negative")
	}

	if rule.MaxEvents < 0 {
		return fmt.Errorf("max events cannot be negative")
	}

	if rule.MaxEvents > 0 && rule.MinEvents > rule.MaxEvents {
		return fmt.Errorf("min events cannot be greater than max events")
	}

	return nil
}

// GetStatistics returns correlation statistics
func (ec *EventCorrelatorImpl) GetStatistics() map[string]interface{} {
	ec.statsLock.RLock()
	defer ec.statsLock.RUnlock()

	ec.mutex.RLock()
	defer ec.mutex.RUnlock()

	return map[string]interface{}{
		"total_correlations":     ec.totalCorrelations,
		"total_events_processed": ec.totalEventsProcessed,
		"active_windows":         ec.activeWindows,
		"active_correlations":    int64(len(ec.correlatedEvents)),
		"correlation_rules":      int64(len(ec.correlationRules)),
		"cleanup_interval":       ec.cleanupInterval.String(),
		"default_window":         ec.defaultWindow.String(),
		"max_events_per_window":  ec.maxEventsPerWindow,
	}
}