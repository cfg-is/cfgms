// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package trigger

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// LogEntry represents a log entry for SIEM analysis
type LogEntry struct {
	Timestamp time.Time              `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields"`
	Source    string                 `json:"source"`
	TenantID  string                 `json:"tenant_id,omitempty"`
}

// SIEMProcessor implements the SIEMIntegration interface
type SIEMProcessor struct {
	logger             *logging.ModuleLogger
	triggerManager     TriggerManager
	workflowTrigger    WorkflowTrigger
	siemTriggers       map[string]*Trigger
	aggregationData    map[string]*AggregationData
	triggerConditions  map[string][]*SIEMCondition
	mutex              sync.RWMutex
	running            bool
	stopChan           chan struct{}
	logBuffer          chan LogEntry
	bufferSize         int
	cleanupInterval    time.Duration
	aggregationWindows map[string]time.Time
}

// AggregationData holds aggregated data for SIEM analysis
type AggregationData struct {
	Count         int                `json:"count"`
	Sum           map[string]float64 `json:"sum"`
	Average       map[string]float64 `json:"average"`
	GroupedCounts map[string]int     `json:"grouped_counts"`
	LastUpdated   time.Time          `json:"last_updated"`
	WindowStart   time.Time          `json:"window_start"`
	Entries       []LogEntry         `json:"entries"`
	TriggerID     string             `json:"trigger_id"`
}

// NewSIEMProcessor creates a new SIEM integration processor
func NewSIEMProcessor(triggerManager TriggerManager, workflowTrigger WorkflowTrigger) *SIEMProcessor {
	logger := logging.ForModule("workflow.trigger.siem").WithField("component", "processor")

	return &SIEMProcessor{
		logger:             logger,
		triggerManager:     triggerManager,
		workflowTrigger:    workflowTrigger,
		siemTriggers:       make(map[string]*Trigger),
		aggregationData:    make(map[string]*AggregationData),
		triggerConditions:  make(map[string][]*SIEMCondition),
		stopChan:           make(chan struct{}),
		bufferSize:         10000,
		cleanupInterval:    5 * time.Minute,
		aggregationWindows: make(map[string]time.Time),
	}
}

// Start starts the SIEM integration processor
func (sp *SIEMProcessor) Start(ctx context.Context) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if sp.running {
		return fmt.Errorf("SIEM processor is already running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting SIEM processor",
		"buffer_size", sp.bufferSize,
		"cleanup_interval", sp.cleanupInterval.String())

	sp.logBuffer = make(chan LogEntry, sp.bufferSize)
	sp.running = true

	// Start log processing goroutine
	go sp.processLogEntries(ctx)

	// Start cleanup goroutine
	go sp.cleanupAggregationData(ctx)

	logger.InfoCtx(ctx, "SIEM processor started successfully")
	return nil
}

// Stop stops the SIEM integration processor
func (sp *SIEMProcessor) Stop(ctx context.Context) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if !sp.running {
		return fmt.Errorf("SIEM processor is not running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Stopping SIEM processor")

	sp.running = false

	// Close channels only if they haven't been closed already
	select {
	case <-sp.stopChan:
		// Channel already closed
	default:
		close(sp.stopChan)
	}

	// For logBuffer, we need a different approach since it's a buffered channel
	defer func() {
		if r := recover(); r != nil {
			// Channel was already closed, ignore the panic
			// This is expected behavior during shutdown
			_ = r // explicitly ignore the recovered value
		}
	}()
	close(sp.logBuffer)

	logger.InfoCtx(ctx, "SIEM processor stopped successfully")
	return nil
}

// RegisterSIEMTrigger registers a SIEM-based trigger
func (sp *SIEMProcessor) RegisterSIEMTrigger(ctx context.Context, trigger *Trigger) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	if trigger.Type != TriggerTypeSIEM || trigger.SIEM == nil {
		return fmt.Errorf("trigger %s is not a SIEM trigger", trigger.ID)
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Registering SIEM trigger",
		"trigger_id", trigger.ID,
		"event_types", trigger.SIEM.EventTypes,
		"window_size", trigger.SIEM.WindowSize.String())

	// Validate SIEM configuration
	if err := sp.validateSIEMConfig(trigger.SIEM); err != nil {
		logger.ErrorCtx(ctx, "Invalid SIEM configuration",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("invalid SIEM configuration: %w", err)
	}

	// Store trigger configuration
	sp.siemTriggers[trigger.ID] = trigger
	sp.triggerConditions[trigger.ID] = trigger.SIEM.Conditions

	// Initialize aggregation data
	sp.aggregationData[trigger.ID] = &AggregationData{
		Count:         0,
		Sum:           make(map[string]float64),
		Average:       make(map[string]float64),
		GroupedCounts: make(map[string]int),
		LastUpdated:   time.Now(),
		WindowStart:   time.Now(),
		Entries:       make([]LogEntry, 0),
		TriggerID:     trigger.ID,
	}

	logger.InfoCtx(ctx, "SIEM trigger registered successfully",
		"trigger_id", trigger.ID)

	return nil
}

// UnregisterSIEMTrigger removes a SIEM-based trigger
func (sp *SIEMProcessor) UnregisterSIEMTrigger(ctx context.Context, triggerID string) error {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	if _, exists := sp.siemTriggers[triggerID]; !exists {
		logger.WarnCtx(ctx, "Attempted to unregister non-existent SIEM trigger",
			"trigger_id", triggerID)
		return fmt.Errorf("SIEM trigger %s is not registered", triggerID)
	}

	delete(sp.siemTriggers, triggerID)
	delete(sp.triggerConditions, triggerID)
	delete(sp.aggregationData, triggerID)
	delete(sp.aggregationWindows, triggerID)

	logger.InfoCtx(ctx, "SIEM trigger unregistered successfully",
		"trigger_id", triggerID)

	return nil
}

// ProcessLogEntry processes a log entry for SIEM triggers
func (sp *SIEMProcessor) ProcessLogEntry(ctx context.Context, logEntry map[string]interface{}) error {
	if !sp.running {
		return fmt.Errorf("SIEM processor is not running")
	}

	// Convert map to LogEntry struct
	entry, err := sp.mapToLogEntry(logEntry)
	if err != nil {
		return fmt.Errorf("failed to convert log entry: %w", err)
	}

	// Send to buffer for processing
	select {
	case sp.logBuffer <- entry:
		return nil
	default:
		// Buffer is full, drop the log entry
		tenantID := logging.ExtractTenantFromContext(ctx)
		logger := sp.logger.WithTenant(tenantID)
		logger.WarnCtx(ctx, "Log buffer full, dropping log entry",
			"source", entry.Source,
			"message", entry.Message)
		return fmt.Errorf("log buffer full")
	}
}

// processLogEntries processes log entries from the buffer
func (sp *SIEMProcessor) processLogEntries(ctx context.Context) {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Started log entry processing loop")

	for {
		select {
		case <-ctx.Done():
			logger.InfoCtx(ctx, "Log entry processing stopped due to context cancellation")
			return
		case <-sp.stopChan:
			logger.InfoCtx(ctx, "Log entry processing stopped due to stop signal")
			return
		case entry, ok := <-sp.logBuffer:
			if !ok {
				logger.InfoCtx(ctx, "Log buffer closed, stopping processing")
				return
			}
			sp.processLogEntry(ctx, entry)
		}
	}
}

// processLogEntry processes a single log entry against all SIEM triggers
func (sp *SIEMProcessor) processLogEntry(ctx context.Context, entry LogEntry) {
	sp.mutex.RLock()
	triggers := make(map[string]*Trigger)
	for id, trigger := range sp.siemTriggers {
		triggers[id] = trigger
	}
	sp.mutex.RUnlock()

	for triggerID, trigger := range triggers {
		if !trigger.SIEM.Enabled {
			continue
		}

		// Check if log entry matches trigger's event types
		if !sp.matchesEventTypes(trigger.SIEM.EventTypes, entry) {
			continue
		}

		// Check if log entry matches trigger conditions
		if !sp.matchesConditions(trigger.SIEM.Conditions, entry) {
			continue
		}

		// Add to aggregation data
		sp.addToAggregation(triggerID, entry)

		// Check if threshold is met
		if sp.thresholdMet(triggerID, trigger.SIEM) {
			sp.fireTrigger(ctx, triggerID, trigger)
		}
	}
}

// matchesEventTypes checks if log entry matches any of the specified event types
func (sp *SIEMProcessor) matchesEventTypes(eventTypes []string, entry LogEntry) bool {
	if len(eventTypes) == 0 {
		return true // No filter means accept all
	}

	for _, eventType := range eventTypes {
		// Check against log level
		if strings.EqualFold(eventType, entry.Level) {
			return true
		}

		// Check against source
		if strings.EqualFold(eventType, entry.Source) {
			return true
		}

		// Check against message patterns
		if matched, _ := regexp.MatchString(eventType, entry.Message); matched {
			return true
		}

		// Check against custom fields
		if eventTypeField, exists := entry.Fields["event_type"]; exists {
			if eventTypeStr, ok := eventTypeField.(string); ok {
				if strings.EqualFold(eventType, eventTypeStr) {
					return true
				}
			}
		}
	}

	return false
}

// matchesConditions checks if log entry matches all specified conditions
func (sp *SIEMProcessor) matchesConditions(conditions []*SIEMCondition, entry LogEntry) bool {
	if len(conditions) == 0 {
		return true // No conditions means accept all
	}

	for _, condition := range conditions {
		if !sp.evaluateCondition(condition, entry) {
			return false
		}
	}

	return true
}

// evaluateCondition evaluates a single SIEM condition against a log entry
func (sp *SIEMProcessor) evaluateCondition(condition *SIEMCondition, entry LogEntry) bool {
	var fieldValue interface{}
	var exists bool

	// Get field value
	switch condition.Field {
	case "timestamp":
		fieldValue = entry.Timestamp
	case "level":
		fieldValue = entry.Level
	case "message":
		fieldValue = entry.Message
	case "source":
		fieldValue = entry.Source
	case "tenant_id":
		fieldValue = entry.TenantID
	default:
		// Handle dotted field notation (e.g., "fields.user_id")
		if strings.HasPrefix(condition.Field, "fields.") {
			fieldName := strings.TrimPrefix(condition.Field, "fields.")
			fieldValue, exists = entry.Fields[fieldName]
		} else {
			fieldValue, exists = entry.Fields[condition.Field]
		}
		if !exists && condition.Operator != SIEMOperatorNotExists {
			return false
		}
	}

	// Apply operator
	return sp.applyOperator(condition.Operator, fieldValue, condition.Value, condition.CaseSensitive)
}

// applyOperator applies a SIEM operator to compare field value with condition value
func (sp *SIEMProcessor) applyOperator(operator SIEMOperator, fieldValue, conditionValue interface{}, caseSensitive bool) bool {
	switch operator {
	case SIEMOperatorExists:
		return fieldValue != nil

	case SIEMOperatorNotExists:
		return fieldValue == nil

	case SIEMOperatorEquals:
		return sp.compareValues(fieldValue, conditionValue, caseSensitive) == 0

	case SIEMOperatorNotEquals:
		return sp.compareValues(fieldValue, conditionValue, caseSensitive) != 0

	case SIEMOperatorGreaterThan:
		return sp.compareValues(fieldValue, conditionValue, caseSensitive) > 0

	case SIEMOperatorLessThan:
		return sp.compareValues(fieldValue, conditionValue, caseSensitive) < 0

	case SIEMOperatorContains:
		fieldStr := sp.toString(fieldValue)
		conditionStr := sp.toString(conditionValue)
		if !caseSensitive {
			fieldStr = strings.ToLower(fieldStr)
			conditionStr = strings.ToLower(conditionStr)
		}
		return strings.Contains(fieldStr, conditionStr)

	case SIEMOperatorNotContains:
		fieldStr := sp.toString(fieldValue)
		conditionStr := sp.toString(conditionValue)
		if !caseSensitive {
			fieldStr = strings.ToLower(fieldStr)
			conditionStr = strings.ToLower(conditionStr)
		}
		return !strings.Contains(fieldStr, conditionStr)

	case SIEMOperatorStartsWith:
		fieldStr := sp.toString(fieldValue)
		conditionStr := sp.toString(conditionValue)
		if !caseSensitive {
			fieldStr = strings.ToLower(fieldStr)
			conditionStr = strings.ToLower(conditionStr)
		}
		return strings.HasPrefix(fieldStr, conditionStr)

	case SIEMOperatorEndsWith:
		fieldStr := sp.toString(fieldValue)
		conditionStr := sp.toString(conditionValue)
		if !caseSensitive {
			fieldStr = strings.ToLower(fieldStr)
			conditionStr = strings.ToLower(conditionStr)
		}
		return strings.HasSuffix(fieldStr, conditionStr)

	case SIEMOperatorRegex:
		fieldStr := sp.toString(fieldValue)
		pattern := sp.toString(conditionValue)
		flags := ""
		if !caseSensitive {
			flags = "(?i)"
		}
		matched, err := regexp.MatchString(flags+pattern, fieldStr)
		return err == nil && matched

	default:
		return false
	}
}

// compareValues compares two values considering their types
func (sp *SIEMProcessor) compareValues(a, b interface{}, caseSensitive bool) int {
	// Handle nil values
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}

	// Try numeric comparison first
	if aNum, aOk := sp.toFloat64(a); aOk {
		if bNum, bOk := sp.toFloat64(b); bOk {
			if aNum < bNum {
				return -1
			} else if aNum > bNum {
				return 1
			}
			return 0
		}
	}

	// Fall back to string comparison
	aStr := sp.toString(a)
	bStr := sp.toString(b)

	if !caseSensitive {
		aStr = strings.ToLower(aStr)
		bStr = strings.ToLower(bStr)
	}

	return strings.Compare(aStr, bStr)
}

// toString converts any value to string
func (sp *SIEMProcessor) toString(value interface{}) string {
	if value == nil {
		return ""
	}
	if str, ok := value.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", value)
}

// toFloat64 converts a value to float64 if possible
func (sp *SIEMProcessor) toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f, true
		}
	}
	return 0, false
}

// addToAggregation adds a log entry to aggregation data
func (sp *SIEMProcessor) addToAggregation(triggerID string, entry LogEntry) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	aggData, exists := sp.aggregationData[triggerID]
	if !exists {
		return
	}

	trigger := sp.siemTriggers[triggerID]
	if trigger == nil {
		return
	}

	// Check if we need to reset the window
	if time.Since(aggData.WindowStart) > trigger.SIEM.WindowSize {
		sp.resetAggregationWindow(triggerID)
		aggData = sp.aggregationData[triggerID]
	}

	// Add to count
	aggData.Count++

	// Add entry to entries list
	aggData.Entries = append(aggData.Entries, entry)

	// Update aggregation based on configuration
	if trigger.SIEM.Aggregation != nil {
		sp.updateAggregation(aggData, trigger.SIEM.Aggregation, entry)
	}

	aggData.LastUpdated = time.Now()
}

// updateAggregation updates aggregation data based on aggregation rules
func (sp *SIEMProcessor) updateAggregation(aggData *AggregationData, aggregation *SIEMAggregation, entry LogEntry) {
	// Handle grouping
	if len(aggregation.GroupBy) > 0 {
		groupKey := sp.buildGroupKey(aggregation.GroupBy, entry)
		aggData.GroupedCounts[groupKey]++
	}

	// Handle sum aggregation
	if len(aggregation.SumBy) > 0 {
		for _, field := range aggregation.SumBy {
			if value, exists := entry.Fields[field]; exists {
				if numValue, ok := sp.toFloat64(value); ok {
					aggData.Sum[field] += numValue
				}
			}
		}
	}

	// Handle average aggregation (calculated on the fly)
	if len(aggregation.AverageBy) > 0 {
		for _, field := range aggregation.AverageBy {
			if value, exists := entry.Fields[field]; exists {
				if numValue, ok := sp.toFloat64(value); ok {
					currentSum := aggData.Sum[field+"_sum"]
					currentCount := aggData.Sum[field+"_count"]
					aggData.Sum[field+"_sum"] = currentSum + numValue
					aggData.Sum[field+"_count"] = currentCount + 1
					aggData.Average[field] = aggData.Sum[field+"_sum"] / aggData.Sum[field+"_count"]
				}
			}
		}
	}
}

// buildGroupKey builds a group key from specified fields
func (sp *SIEMProcessor) buildGroupKey(groupBy []string, entry LogEntry) string {
	var keyParts []string

	for _, field := range groupBy {
		var value string
		switch field {
		case "level":
			value = entry.Level
		case "source":
			value = entry.Source
		case "tenant_id":
			value = entry.TenantID
		default:
			if fieldValue, exists := entry.Fields[field]; exists {
				value = sp.toString(fieldValue)
			}
		}
		keyParts = append(keyParts, fmt.Sprintf("%s:%s", field, value))
	}

	return strings.Join(keyParts, "|")
}

// thresholdMet checks if the trigger threshold has been met
func (sp *SIEMProcessor) thresholdMet(triggerID string, siemConfig *SIEMConfig) bool {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	aggData, exists := sp.aggregationData[triggerID]
	if !exists || siemConfig.Threshold == nil {
		return false
	}

	threshold := siemConfig.Threshold

	// Check count threshold
	if threshold.Count > 0 && aggData.Count >= threshold.Count {
		return true
	}

	// Check rate threshold (entries per minute)
	if threshold.Rate > 0 {
		duration := time.Since(aggData.WindowStart)
		if duration > 0 {
			rate := float64(aggData.Count) / duration.Minutes()
			if rate >= threshold.Rate {
				return true
			}
		}
	}

	// Check sum threshold
	if threshold.Sum > 0 {
		for _, sum := range aggData.Sum {
			if sum >= threshold.Sum {
				return true
			}
		}
	}

	// Check average threshold
	if threshold.Average > 0 {
		for _, avg := range aggData.Average {
			if avg >= threshold.Average {
				return true
			}
		}
	}

	return false
}

// fireTrigger fires a SIEM trigger
func (sp *SIEMProcessor) fireTrigger(ctx context.Context, triggerID string, trigger *Trigger) {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Firing SIEM trigger",
		"trigger_id", triggerID,
		"workflow_name", trigger.WorkflowName)

	// Get aggregation data
	sp.mutex.RLock()
	aggData := sp.aggregationData[triggerID]
	sp.mutex.RUnlock()

	// Prepare trigger data
	triggerData := map[string]interface{}{
		"trigger_type":      "siem",
		"trigger_id":        triggerID,
		"aggregation_count": aggData.Count,
		"window_start":      aggData.WindowStart,
		"window_end":        time.Now(),
		"log_entries":       aggData.Entries,
		"grouped_counts":    aggData.GroupedCounts,
		"sum_values":        aggData.Sum,
		"average_values":    aggData.Average,
	}

	// Merge with trigger variables
	for k, v := range trigger.Variables {
		triggerData[k] = v
	}

	// Execute workflow asynchronously
	go func() {
		execCtx := context.WithValue(context.Background(), TenantIDContextKey, tenantID)
		if trigger.Timeout > 0 {
			var cancel context.CancelFunc
			execCtx, cancel = context.WithTimeout(execCtx, trigger.Timeout)
			defer cancel()
		}

		execution, err := sp.workflowTrigger.TriggerWorkflow(execCtx, trigger, triggerData)
		if err != nil {
			logger.ErrorCtx(execCtx, "Failed to trigger workflow from SIEM",
				"trigger_id", triggerID,
				"workflow_name", trigger.WorkflowName,
				"error", err.Error())
			return
		}

		logger.InfoCtx(execCtx, "Workflow triggered successfully from SIEM",
			"trigger_id", triggerID,
			"workflow_name", trigger.WorkflowName,
			"execution_id", execution.ID)
	}()

	// Reset aggregation window after firing
	sp.mutex.Lock()
	sp.resetAggregationWindow(triggerID)
	sp.mutex.Unlock()
}

// resetAggregationWindow resets the aggregation window for a trigger
// Note: Caller must hold sp.mutex
func (sp *SIEMProcessor) resetAggregationWindow(triggerID string) {
	aggData := sp.aggregationData[triggerID]
	if aggData == nil {
		return
	}

	aggData.Count = 0
	aggData.Sum = make(map[string]float64)
	aggData.Average = make(map[string]float64)
	aggData.GroupedCounts = make(map[string]int)
	aggData.WindowStart = time.Now()
	aggData.Entries = make([]LogEntry, 0)
	aggData.LastUpdated = time.Now()
}

// cleanupAggregationData periodically cleans up old aggregation data
func (sp *SIEMProcessor) cleanupAggregationData(ctx context.Context) {
	ticker := time.NewTicker(sp.cleanupInterval)
	defer ticker.Stop()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := sp.logger.WithTenant(tenantID)

	for {
		select {
		case <-ctx.Done():
			return
		case <-sp.stopChan:
			return
		case <-ticker.C:
			sp.performCleanup(ctx, logger)
		}
	}
}

// performCleanup performs cleanup of old aggregation data
func (sp *SIEMProcessor) performCleanup(ctx context.Context, logger *logging.ModuleLogger) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()

	now := time.Now()
	cleaned := 0

	for triggerID, aggData := range sp.aggregationData {
		trigger := sp.siemTriggers[triggerID]
		if trigger == nil {
			continue
		}

		// Reset windows that are older than the configured window size
		if now.Sub(aggData.WindowStart) > trigger.SIEM.WindowSize {
			sp.resetAggregationWindow(triggerID)
			cleaned++
		}
	}

	if cleaned > 0 {
		logger.InfoCtx(ctx, "Cleaned up aggregation data",
			"cleaned_windows", cleaned)
	}
}

// validateSIEMConfig validates SIEM trigger configuration
func (sp *SIEMProcessor) validateSIEMConfig(config *SIEMConfig) error {
	if config.WindowSize <= 0 {
		return fmt.Errorf("window size must be greater than zero")
	}

	if config.WindowSize > 24*time.Hour {
		return fmt.Errorf("window_size cannot exceed 24 hours")
	}

	// Validate conditions
	for i, condition := range config.Conditions {
		if condition.Field == "" {
			return fmt.Errorf("condition %d: field is required", i)
		}
		if condition.Operator == "" {
			return fmt.Errorf("condition %d: operator is required", i)
		}
	}

	// Validate threshold
	if config.Threshold != nil {
		threshold := config.Threshold
		if threshold.Count <= 0 && threshold.Rate <= 0 && threshold.Sum <= 0 && threshold.Average <= 0 {
			return fmt.Errorf("at least one threshold value must be greater than 0")
		}
	}

	return nil
}

// mapToLogEntry converts a map to LogEntry struct
func (sp *SIEMProcessor) mapToLogEntry(logEntry map[string]interface{}) (LogEntry, error) {
	entry := LogEntry{
		Fields: make(map[string]interface{}),
	}

	// Extract timestamp
	if ts, exists := logEntry["timestamp"]; exists {
		if timestamp, ok := ts.(time.Time); ok {
			entry.Timestamp = timestamp
		} else if tsStr, ok := ts.(string); ok {
			if parsed, err := time.Parse(time.RFC3339, tsStr); err == nil {
				entry.Timestamp = parsed
			} else {
				// Return error for obviously invalid timestamp strings
				return LogEntry{}, fmt.Errorf("invalid timestamp format: %s", tsStr)
			}
		} else {
			entry.Timestamp = time.Now()
		}
	} else {
		entry.Timestamp = time.Now()
	}

	// Extract standard fields with validation
	if level, exists := logEntry["level"]; exists {
		// Validate level is a proper type (string or nil)
		if level != nil {
			if _, ok := level.(string); !ok {
				return LogEntry{}, fmt.Errorf("invalid level type: expected string, got %T", level)
			}
		}
		entry.Level = sp.toString(level)
	}

	if message, exists := logEntry["message"]; exists {
		entry.Message = sp.toString(message)
	}

	if source, exists := logEntry["source"]; exists {
		entry.Source = sp.toString(source)
	}

	if tenantID, exists := logEntry["tenant_id"]; exists {
		entry.TenantID = sp.toString(tenantID)
	}

	// Copy all other fields
	for k, v := range logEntry {
		if k != "timestamp" && k != "level" && k != "message" && k != "source" && k != "tenant_id" {
			if k == "fields" {
				// Special handling for nested fields
				if fieldsMap, ok := v.(map[string]interface{}); ok {
					for fieldKey, fieldValue := range fieldsMap {
						entry.Fields[fieldKey] = fieldValue
					}
				}
			} else {
				entry.Fields[k] = v
			}
		}
	}

	return entry, nil
}

// GetSIEMStatistics returns statistics for all SIEM triggers (for monitoring)
func (sp *SIEMProcessor) GetSIEMStatistics() map[string]*AggregationData {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	result := make(map[string]*AggregationData)
	for id, data := range sp.aggregationData {
		// Create a copy to avoid concurrent modification
		dataCopy := *data
		dataCopy.Entries = make([]LogEntry, len(data.Entries))
		copy(dataCopy.Entries, data.Entries)

		groupedCountsCopy := make(map[string]int)
		for k, v := range data.GroupedCounts {
			groupedCountsCopy[k] = v
		}
		dataCopy.GroupedCounts = groupedCountsCopy

		sumCopy := make(map[string]float64)
		for k, v := range data.Sum {
			sumCopy[k] = v
		}
		dataCopy.Sum = sumCopy

		avgCopy := make(map[string]float64)
		for k, v := range data.Average {
			avgCopy[k] = v
		}
		dataCopy.Average = avgCopy

		result[id] = &dataCopy
	}

	return result
}

// GetRegisteredSIEMTriggers returns all registered SIEM triggers (for monitoring)
func (sp *SIEMProcessor) GetRegisteredSIEMTriggers() map[string]*Trigger {
	sp.mutex.RLock()
	defer sp.mutex.RUnlock()

	result := make(map[string]*Trigger)
	for id, trigger := range sp.siemTriggers {
		result[id] = trigger
	}

	return result
}
