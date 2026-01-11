// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package siem

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/cfgis/cfgms/features/workflow/trigger"
	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/logging/interfaces"
)

// WorkflowIntegration handles integration between SIEM stream processing
// and the existing workflow trigger system for automated response workflows.
type WorkflowIntegration struct {
	logger          *logging.ModuleLogger
	triggerManager  trigger.TriggerManager
	workflowTrigger trigger.WorkflowTrigger

	// Configuration
	config WorkflowIntegrationConfig

	// Statistics
	workflowsTriggered  int64
	triggerFailures     int64
	lastTriggerTime     time.Time
	averageResponseTime time.Duration
}

// WorkflowIntegrationConfig defines configuration for SIEM workflow integration
type WorkflowIntegrationConfig struct {
	// Enable automated workflow triggering
	EnableWorkflowTriggers bool `json:"enable_workflow_triggers" yaml:"enable_workflow_triggers"`

	// Default workflow timeout
	DefaultTimeout time.Duration `json:"default_timeout" yaml:"default_timeout"`

	// Maximum concurrent workflow executions
	MaxConcurrentWorkflows int `json:"max_concurrent_workflows" yaml:"max_concurrent_workflows"`

	// Retry configuration
	RetryAttempts int           `json:"retry_attempts" yaml:"retry_attempts"`
	RetryDelay    time.Duration `json:"retry_delay" yaml:"retry_delay"`

	// Throttling configuration
	ThrottleLimit  int           `json:"throttle_limit" yaml:"throttle_limit"`   // Max triggers per minute
	ThrottleWindow time.Duration `json:"throttle_window" yaml:"throttle_window"` // Throttling window
}

// NewWorkflowIntegration creates a new SIEM workflow integration
func NewWorkflowIntegration(triggerManager trigger.TriggerManager,
	workflowTrigger trigger.WorkflowTrigger, config WorkflowIntegrationConfig) *WorkflowIntegration {

	logger := logging.ForModule("siem.workflow_integration").WithField("component", "integration")

	// Set defaults
	if config.DefaultTimeout == 0 {
		config.DefaultTimeout = 5 * time.Minute
	}
	if config.MaxConcurrentWorkflows == 0 {
		config.MaxConcurrentWorkflows = 10
	}
	if config.RetryAttempts == 0 {
		config.RetryAttempts = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.ThrottleLimit == 0 {
		config.ThrottleLimit = 100 // 100 triggers per minute
	}
	if config.ThrottleWindow == 0 {
		config.ThrottleWindow = 1 * time.Minute
	}

	return &WorkflowIntegration{
		logger:          logger,
		triggerManager:  triggerManager,
		workflowTrigger: workflowTrigger,
		config:          config,
	}
}

// ProcessSecurityEvent processes a security event and triggers workflows if configured
func (wi *WorkflowIntegration) ProcessSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	if !wi.config.EnableWorkflowTriggers {
		return nil
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wi.logger.WithTenant(tenantID)

	logger.DebugCtx(ctx, "Processing security event for workflow triggers",
		"event_id", event.ID,
		"event_type", event.EventType,
		"severity", event.Severity,
		"rule_id", event.RuleID)

	// Find applicable triggers based on event type and rule
	triggers, err := wi.findApplicableTriggers(ctx, event)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to find applicable triggers",
			"event_id", event.ID,
			"error", err.Error())
		return err
	}

	// Process each applicable trigger
	for _, triggerConfig := range triggers {
		if err := wi.executeTrigger(ctx, triggerConfig, event); err != nil {
			logger.ErrorCtx(ctx, "Failed to execute workflow trigger",
				"trigger_id", triggerConfig.ID,
				"event_id", event.ID,
				"error", err.Error())
			wi.triggerFailures++
		}
	}

	return nil
}

// ProcessCorrelatedEvent processes a correlated event and triggers workflows
func (wi *WorkflowIntegration) ProcessCorrelatedEvent(ctx context.Context, event *CorrelatedEvent) error {
	if !wi.config.EnableWorkflowTriggers {
		return nil
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := wi.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Processing correlated event for workflow triggers",
		"correlation_id", event.ID,
		"rule_id", event.RuleID,
		"event_count", len(event.Events),
		"severity", event.Severity)

	// Create SIEM trigger data for correlated event
	triggerData := map[string]interface{}{
		"trigger_type":      "siem_correlation",
		"correlation_id":    event.ID,
		"rule_id":           event.RuleID,
		"event_count":       len(event.Events),
		"severity":          string(event.Severity),
		"window_start":      event.WindowStart,
		"window_end":        event.WindowEnd,
		"description":       event.Description,
		"tenant_id":         event.TenantID,
		"correlated_events": wi.eventsToTriggerData(event.Events),
		"metadata":          event.Metadata,
	}

	// Find SIEM triggers for correlation events
	filter := &trigger.TriggerFilter{
		TenantID: event.TenantID,
		Type:     trigger.TriggerTypeSIEM,
	}

	triggers, err := wi.triggerManager.ListTriggers(ctx, filter)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to list SIEM triggers",
			"correlation_id", event.ID,
			"error", err.Error())
		return err
	}

	// Filter triggers that match correlation event
	for _, triggerConfig := range triggers {
		if wi.triggerMatchesCorrelation(triggerConfig, event) {
			if err := wi.executeCorrelationTrigger(ctx, triggerConfig, triggerData); err != nil {
				logger.ErrorCtx(ctx, "Failed to execute correlation trigger",
					"trigger_id", triggerConfig.ID,
					"correlation_id", event.ID,
					"error", err.Error())
				wi.triggerFailures++
			}
		}
	}

	return nil
}

// findApplicableTriggers finds workflow triggers applicable to a security event
func (wi *WorkflowIntegration) findApplicableTriggers(ctx context.Context, event *SecurityEvent) ([]*trigger.Trigger, error) {
	filter := &trigger.TriggerFilter{
		TenantID: event.TenantID,
		Type:     trigger.TriggerTypeSIEM,
	}

	triggers, err := wi.triggerManager.ListTriggers(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list triggers: %w", err)
	}

	var applicableTriggers []*trigger.Trigger
	for _, triggerConfig := range triggers {
		if wi.triggerMatchesEvent(triggerConfig, event) {
			applicableTriggers = append(applicableTriggers, triggerConfig)
		}
	}

	return applicableTriggers, nil
}

// triggerMatchesEvent checks if a trigger matches a security event
func (wi *WorkflowIntegration) triggerMatchesEvent(triggerConfig *trigger.Trigger, event *SecurityEvent) bool {
	if triggerConfig.SIEM == nil || !triggerConfig.SIEM.Enabled {
		return false
	}

	// Check event type match
	if len(triggerConfig.SIEM.EventTypes) > 0 {
		eventTypeMatch := false
		for _, eventType := range triggerConfig.SIEM.EventTypes {
			if eventType == event.EventType || eventType == "*" {
				eventTypeMatch = true
				break
			}
		}
		if !eventTypeMatch {
			return false
		}
	}

	// Check SIEM conditions
	for _, condition := range triggerConfig.SIEM.Conditions {
		if !wi.evaluateSIEMCondition(condition, event) {
			return false
		}
	}

	return true
}

// triggerMatchesCorrelation checks if a trigger matches a correlated event
func (wi *WorkflowIntegration) triggerMatchesCorrelation(triggerConfig *trigger.Trigger, event *CorrelatedEvent) bool {
	if triggerConfig.SIEM == nil || !triggerConfig.SIEM.Enabled {
		return false
	}

	// Check for correlation-specific event types
	if len(triggerConfig.SIEM.EventTypes) > 0 {
		for _, eventType := range triggerConfig.SIEM.EventTypes {
			if eventType == "correlation" || eventType == "*" {
				return true
			}
		}
		return false
	}

	return true
}

// evaluateSIEMCondition evaluates a SIEM condition against a security event
func (wi *WorkflowIntegration) evaluateSIEMCondition(condition *trigger.SIEMCondition, event *SecurityEvent) bool {
	var fieldValue interface{}

	// Get field value from event
	switch condition.Field {
	case "event_type":
		fieldValue = event.EventType
	case "severity":
		fieldValue = string(event.Severity)
	case "source":
		fieldValue = event.Source
	case "description":
		fieldValue = event.Description
	case "rule_id":
		fieldValue = event.RuleID
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

	// Apply SIEM operator (reuse existing logic from SIEM processor)
	return wi.applySIEMOperator(condition.Operator, fieldValue, condition.Value, condition.CaseSensitive)
}

// applySIEMOperator applies a SIEM operator for condition evaluation
func (wi *WorkflowIntegration) applySIEMOperator(operator trigger.SIEMOperator, fieldValue, conditionValue interface{}, caseSensitive bool) bool {
	// This mirrors the logic from the existing SIEM processor
	// We could refactor to share this logic, but keeping it here for now for clarity

	fieldStr := fmt.Sprintf("%v", fieldValue)
	conditionStr := fmt.Sprintf("%v", conditionValue)

	if !caseSensitive {
		fieldStr = strings.ToLower(fieldStr)
		conditionStr = strings.ToLower(conditionStr)
	}

	switch operator {
	case trigger.SIEMOperatorEquals:
		return fieldStr == conditionStr
	case trigger.SIEMOperatorNotEquals:
		return fieldStr != conditionStr
	case trigger.SIEMOperatorContains:
		return strings.Contains(fieldStr, conditionStr)
	case trigger.SIEMOperatorNotContains:
		return !strings.Contains(fieldStr, conditionStr)
	case trigger.SIEMOperatorStartsWith:
		return strings.HasPrefix(fieldStr, conditionStr)
	case trigger.SIEMOperatorEndsWith:
		return strings.HasSuffix(fieldStr, conditionStr)
	case trigger.SIEMOperatorExists:
		return fieldValue != nil
	case trigger.SIEMOperatorNotExists:
		return fieldValue == nil
	default:
		return false
	}
}

// executeTrigger executes a workflow trigger for a security event
func (wi *WorkflowIntegration) executeTrigger(ctx context.Context, triggerConfig *trigger.Trigger, event *SecurityEvent) error {
	startTime := time.Now()

	// Prepare trigger data
	triggerData := wi.securityEventToTriggerData(event)

	// Merge with trigger variables
	for k, v := range triggerConfig.Variables {
		triggerData[k] = v
	}

	// Set timeout
	var execCtx context.Context
	var cancel context.CancelFunc
	if triggerConfig.Timeout > 0 {
		execCtx, cancel = context.WithTimeout(ctx, triggerConfig.Timeout)
		defer cancel()
	} else {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, wi.config.DefaultTimeout)
		defer cancel()
	}

	// Execute workflow with retry
	var lastErr error
	for attempt := 0; attempt <= wi.config.RetryAttempts; attempt++ {
		execution, err := wi.workflowTrigger.TriggerWorkflow(execCtx, triggerConfig, triggerData)
		if err == nil {
			wi.workflowsTriggered++
			wi.lastTriggerTime = time.Now()
			wi.updateAverageResponseTime(time.Since(startTime))

			wi.logger.InfoCtx(ctx, "Workflow triggered successfully from SIEM event",
				"trigger_id", triggerConfig.ID,
				"workflow_name", triggerConfig.WorkflowName,
				"execution_id", execution.ID,
				"event_id", event.ID,
				"attempt", attempt+1)
			return nil
		}

		lastErr = err

		// Don't retry on last attempt
		if attempt < wi.config.RetryAttempts {
			wi.logger.WarnCtx(ctx, "Workflow trigger attempt failed, retrying",
				"trigger_id", triggerConfig.ID,
				"event_id", event.ID,
				"attempt", attempt+1,
				"error", err.Error(),
				"retry_delay", wi.config.RetryDelay)

			time.Sleep(wi.config.RetryDelay)
		}
	}

	return fmt.Errorf("all trigger attempts failed: %w", lastErr)
}

// executeCorrelationTrigger executes a workflow trigger for a correlated event
func (wi *WorkflowIntegration) executeCorrelationTrigger(ctx context.Context, triggerConfig *trigger.Trigger, triggerData map[string]interface{}) error {
	// Set timeout
	execCtx := ctx
	if triggerConfig.Timeout > 0 {
		var cancel context.CancelFunc
		execCtx, cancel = context.WithTimeout(ctx, triggerConfig.Timeout)
		defer cancel()
	}

	execution, err := wi.workflowTrigger.TriggerWorkflow(execCtx, triggerConfig, triggerData)
	if err != nil {
		return fmt.Errorf("failed to trigger correlation workflow: %w", err)
	}

	wi.workflowsTriggered++
	wi.lastTriggerTime = time.Now()

	wi.logger.InfoCtx(ctx, "Correlation workflow triggered successfully",
		"trigger_id", triggerConfig.ID,
		"workflow_name", triggerConfig.WorkflowName,
		"execution_id", execution.ID,
		"correlation_id", triggerData["correlation_id"])

	return nil
}

// securityEventToTriggerData converts a security event to trigger data
func (wi *WorkflowIntegration) securityEventToTriggerData(event *SecurityEvent) map[string]interface{} {
	return map[string]interface{}{
		"trigger_type": "siem_event",
		"event_id":     event.ID,
		"event_type":   event.EventType,
		"severity":     string(event.Severity),
		"source":       event.Source,
		"description":  event.Description,
		"rule_id":      event.RuleID,
		"tenant_id":    event.TenantID,
		"timestamp":    event.Timestamp,
		"fields":       event.Fields,
		"raw_log":      wi.logEntryToMap(event.RawLog),
	}
}

// eventsToTriggerData converts security events to trigger data format
func (wi *WorkflowIntegration) eventsToTriggerData(events []*SecurityEvent) []map[string]interface{} {
	result := make([]map[string]interface{}, len(events))
	for i, event := range events {
		result[i] = wi.securityEventToTriggerData(event)
	}
	return result
}

// logEntryToMap converts a log entry to a map for trigger data
func (wi *WorkflowIntegration) logEntryToMap(entry interfaces.LogEntry) map[string]interface{} {
	return map[string]interface{}{
		"timestamp":      entry.Timestamp,
		"level":          entry.Level,
		"message":        entry.Message,
		"service_name":   entry.ServiceName,
		"component":      entry.Component,
		"tenant_id":      entry.TenantID,
		"session_id":     entry.SessionID,
		"correlation_id": entry.CorrelationID,
		"hostname":       entry.Hostname,
		"app_name":       entry.AppName,
		"fields":         entry.Fields,
	}
}

// updateAverageResponseTime updates the average response time metric
func (wi *WorkflowIntegration) updateAverageResponseTime(responseTime time.Duration) {
	// Simple moving average calculation
	if wi.averageResponseTime == 0 {
		wi.averageResponseTime = responseTime
	} else {
		// Weight new samples at 10%
		wi.averageResponseTime = time.Duration(
			0.9*float64(wi.averageResponseTime) + 0.1*float64(responseTime))
	}
}

// GetStatistics returns workflow integration statistics
func (wi *WorkflowIntegration) GetStatistics() map[string]interface{} {
	return map[string]interface{}{
		"workflows_triggered":      wi.workflowsTriggered,
		"trigger_failures":         wi.triggerFailures,
		"last_trigger_time":        wi.lastTriggerTime,
		"average_response_time":    wi.averageResponseTime.String(),
		"enable_workflow_triggers": wi.config.EnableWorkflowTriggers,
		"max_concurrent_workflows": wi.config.MaxConcurrentWorkflows,
		"retry_attempts":           wi.config.RetryAttempts,
		"throttle_limit":           wi.config.ThrottleLimit,
	}
}
