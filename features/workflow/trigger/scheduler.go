// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cfgis/cfgms/pkg/logging"
)

// CronScheduler implements the Scheduler interface for cron-based scheduling
type CronScheduler struct {
	logger            *logging.ModuleLogger
	triggerManager    TriggerManager
	workflowTrigger   WorkflowTrigger
	scheduledTriggers map[string]*scheduledTrigger
	mutex             sync.RWMutex
	running           bool
	stopChan          chan struct{}
	tickerInterval    time.Duration
}

// scheduledTrigger represents a scheduled trigger with its next execution time
type scheduledTrigger struct {
	trigger      *Trigger
	nextRun      time.Time
	cronSchedule *CronSchedule
	enabled      bool
}

// CronSchedule represents a parsed cron expression
type CronSchedule struct {
	second   CronField
	minute   CronField
	hour     CronField
	day      CronField
	month    CronField
	weekday  CronField
	timezone *time.Location
}

// CronField represents a single field in a cron expression
type CronField struct {
	values   []int
	wildcard bool
	step     int
	rangeMin int
	rangeMax int
}

// NewCronScheduler creates a new cron-based scheduler
func NewCronScheduler(triggerManager TriggerManager, workflowTrigger WorkflowTrigger) *CronScheduler {
	logger := logging.ForModule("workflow.trigger.scheduler").WithField("component", "cron_scheduler")

	return &CronScheduler{
		logger:            logger,
		triggerManager:    triggerManager,
		workflowTrigger:   workflowTrigger,
		scheduledTriggers: make(map[string]*scheduledTrigger),
		stopChan:          make(chan struct{}),
		tickerInterval:    time.Minute, // Check every minute for due executions
	}
}

// SetTickerInterval sets the scheduler check interval (useful for testing)
func (cs *CronScheduler) SetTickerInterval(interval time.Duration) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.tickerInterval = interval
}

// Start starts the cron scheduler
func (cs *CronScheduler) Start(ctx context.Context) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if cs.running {
		return fmt.Errorf("scheduler is already running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting cron scheduler")

	cs.running = true
	cs.stopChan = make(chan struct{}) // Reinitialize for restartability after Stop()
	go cs.schedulerLoop(ctx)

	logger.InfoCtx(ctx, "Cron scheduler started successfully")
	return nil
}

// Stop stops the cron scheduler
func (cs *CronScheduler) Stop(ctx context.Context) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if !cs.running {
		return fmt.Errorf("scheduler is not running")
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Stopping cron scheduler")

	cs.running = false
	close(cs.stopChan)

	logger.InfoCtx(ctx, "Cron scheduler stopped successfully")
	return nil
}

// ScheduleWorkflow schedules a workflow execution based on trigger configuration
func (cs *CronScheduler) ScheduleWorkflow(ctx context.Context, trigger *Trigger) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if trigger.Type != TriggerTypeSchedule || trigger.Schedule == nil {
		return fmt.Errorf("trigger %s is not a schedule trigger", trigger.ID)
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Scheduling workflow trigger",
		"trigger_id", trigger.ID,
		"workflow_name", trigger.WorkflowName,
		"cron_expression", trigger.Schedule.CronExpression)

	// Parse cron expression
	cronSchedule, err := cs.parseCronExpression(trigger.Schedule.CronExpression, trigger.Schedule.Timezone)
	if err != nil {
		logger.ErrorCtx(ctx, "Failed to parse cron expression",
			"trigger_id", trigger.ID,
			"cron_expression", trigger.Schedule.CronExpression,
			"error", err.Error())
		return fmt.Errorf("invalid cron expression: %w", err)
	}

	// Calculate next execution time
	now := time.Now()
	if cronSchedule.timezone != nil {
		now = now.In(cronSchedule.timezone)
	}

	nextRun := cs.calculateNextRun(cronSchedule, now)

	// Apply jitter if configured using cryptographically secure random
	if trigger.Schedule.Jitter > 0 {
		// Generate secure random jitter
		randBytes := make([]byte, 4)
		if _, err := rand.Read(randBytes); err != nil {
			// Fallback: no jitter if crypto/rand fails
			cs.logger.Warn("Failed to generate secure random for jitter, skipping jitter", "error", err)
		} else {
			// Convert to positive int within jitter range
			randValue := int(randBytes[0])<<24 | int(randBytes[1])<<16 | int(randBytes[2])<<8 | int(randBytes[3])
			if randValue < 0 {
				randValue = -randValue
			}
			jitterSeconds := randValue % trigger.Schedule.Jitter
			jitter := time.Duration(jitterSeconds) * time.Second
			nextRun = nextRun.Add(jitter)
		}
	}

	// Create scheduled trigger
	scheduledTrig := &scheduledTrigger{
		trigger:      trigger,
		nextRun:      nextRun,
		cronSchedule: cronSchedule,
		enabled:      trigger.Schedule.Enabled,
	}

	cs.scheduledTriggers[trigger.ID] = scheduledTrig

	logger.InfoCtx(ctx, "Workflow trigger scheduled successfully",
		"trigger_id", trigger.ID,
		"next_run", nextRun.Format(time.RFC3339),
		"timezone", cronSchedule.timezone.String())

	return nil
}

// UnscheduleWorkflow removes a scheduled workflow
func (cs *CronScheduler) UnscheduleWorkflow(ctx context.Context, triggerID string) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	if _, exists := cs.scheduledTriggers[triggerID]; !exists {
		logger.WarnCtx(ctx, "Attempted to unschedule non-existent trigger",
			"trigger_id", triggerID)
		return fmt.Errorf("trigger %s is not scheduled", triggerID)
	}

	delete(cs.scheduledTriggers, triggerID)

	logger.InfoCtx(ctx, "Workflow trigger unscheduled successfully",
		"trigger_id", triggerID)

	return nil
}

// schedulerLoop is the main scheduler loop that checks for due executions
func (cs *CronScheduler) schedulerLoop(ctx context.Context) {
	ticker := time.NewTicker(cs.tickerInterval)
	defer ticker.Stop()

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Scheduler loop started",
		"check_interval", cs.tickerInterval.String())

	for {
		select {
		case <-ctx.Done():
			logger.InfoCtx(ctx, "Scheduler loop stopped due to context cancellation")
			return
		case <-cs.stopChan:
			logger.InfoCtx(ctx, "Scheduler loop stopped due to stop signal")
			return
		case now := <-ticker.C:
			cs.checkAndExecuteDueTriggers(ctx, now)
		}
	}
}

// checkAndExecuteDueTriggers checks for due triggers and executes them
func (cs *CronScheduler) checkAndExecuteDueTriggers(ctx context.Context, now time.Time) {
	cs.mutex.RLock()
	dueTriggers := make([]*scheduledTrigger, 0)

	for _, scheduled := range cs.scheduledTriggers {
		if scheduled.enabled && scheduled.nextRun.Before(now) || scheduled.nextRun.Equal(now) {
			dueTriggers = append(dueTriggers, scheduled)
		}
	}
	cs.mutex.RUnlock()

	if len(dueTriggers) == 0 {
		return
	}

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Found due triggers for execution",
		"count", len(dueTriggers),
		"check_time", now.Format(time.RFC3339))

	for _, scheduled := range dueTriggers {
		cs.executeDueTrigger(ctx, scheduled, now)
	}
}

// executeDueTrigger executes a single due trigger
func (cs *CronScheduler) executeDueTrigger(ctx context.Context, scheduled *scheduledTrigger, now time.Time) {
	trigger := scheduled.trigger

	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Executing scheduled trigger",
		"trigger_id", trigger.ID,
		"workflow_name", trigger.WorkflowName,
		"scheduled_time", scheduled.nextRun.Format(time.RFC3339),
		"actual_time", now.Format(time.RFC3339))

	// Check if trigger should still run (max runs limit)
	if trigger.Schedule.MaxRuns > 0 && trigger.Schedule.CurrentRuns >= trigger.Schedule.MaxRuns {
		logger.InfoCtx(ctx, "Trigger has reached maximum runs limit",
			"trigger_id", trigger.ID,
			"current_runs", trigger.Schedule.CurrentRuns,
			"max_runs", trigger.Schedule.MaxRuns)

		// Disable the trigger
		cs.disableTrigger(trigger.ID)
		return
	}

	// Check if trigger is within valid time window
	if !cs.isWithinTimeWindow(trigger.Schedule, now) {
		logger.InfoCtx(ctx, "Trigger execution outside valid time window",
			"trigger_id", trigger.ID,
			"current_time", now.Format(time.RFC3339))

		// Calculate next run and continue
		scheduled.nextRun = cs.calculateNextRun(scheduled.cronSchedule, now)
		return
	}

	// Prepare trigger data
	triggerData := map[string]interface{}{
		"trigger_type":    "schedule",
		"trigger_id":      trigger.ID,
		"scheduled_time":  scheduled.nextRun,
		"execution_time":  now,
		"cron_expression": trigger.Schedule.CronExpression,
	}

	// Execute the workflow
	go func() {
		execCtx := context.WithValue(context.Background(), TenantIDContextKey, tenantID)
		if trigger.Timeout > 0 {
			var cancel context.CancelFunc
			execCtx, cancel = context.WithTimeout(execCtx, trigger.Timeout)
			defer cancel()
		}

		execution, err := cs.workflowTrigger.TriggerWorkflow(execCtx, trigger, triggerData)
		if err != nil {
			logger.ErrorCtx(execCtx, "Failed to trigger workflow",
				"trigger_id", trigger.ID,
				"workflow_name", trigger.WorkflowName,
				"error", err.Error())

			// Handle trigger error based on error handling configuration
			cs.handleTriggerError(execCtx, trigger, err)
			return
		}

		logger.InfoCtx(execCtx, "Workflow triggered successfully",
			"trigger_id", trigger.ID,
			"workflow_name", trigger.WorkflowName,
			"execution_id", execution.ID)

		// Update trigger statistics
		cs.updateTriggerStatistics(trigger.ID)
	}()

	// Calculate next run time
	scheduled.nextRun = cs.calculateNextRun(scheduled.cronSchedule, now)

	logger.InfoCtx(ctx, "Next execution scheduled",
		"trigger_id", trigger.ID,
		"next_run", scheduled.nextRun.Format(time.RFC3339))
}

// parseCronExpression parses a cron expression into a CronSchedule
func (cs *CronScheduler) parseCronExpression(expression, timezone string) (*CronSchedule, error) {
	// Split the cron expression
	fields := strings.Fields(strings.TrimSpace(expression))

	// Support both 5-field (minute hour day month weekday) and 6-field (second minute hour day month weekday) formats
	var cronFields []string
	if len(fields) == 5 {
		// Add seconds field (0) for 5-field format
		cronFields = append([]string{"0"}, fields...)
	} else if len(fields) == 6 {
		cronFields = fields
	} else {
		return nil, fmt.Errorf("invalid cron expression: expected 5 or 6 fields, got %d", len(fields))
	}

	// Parse timezone
	var tz *time.Location
	var err error
	if timezone == "" {
		tz = time.UTC
	} else {
		tz, err = time.LoadLocation(timezone)
		if err != nil {
			return nil, fmt.Errorf("invalid timezone %s: %w", timezone, err)
		}
	}

	// Parse each field
	second, err := cs.parseCronField(cronFields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("invalid second field: %w", err)
	}

	minute, err := cs.parseCronField(cronFields[1], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("invalid minute field: %w", err)
	}

	hour, err := cs.parseCronField(cronFields[2], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("invalid hour field: %w", err)
	}

	day, err := cs.parseCronField(cronFields[3], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("invalid day field: %w", err)
	}

	month, err := cs.parseCronField(cronFields[4], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("invalid month field: %w", err)
	}

	weekday, err := cs.parseCronField(cronFields[5], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("invalid weekday field: %w", err)
	}

	return &CronSchedule{
		second:   second,
		minute:   minute,
		hour:     hour,
		day:      day,
		month:    month,
		weekday:  weekday,
		timezone: tz,
	}, nil
}

// parseCronField parses a single cron field
func (cs *CronScheduler) parseCronField(field string, min, max int) (CronField, error) {
	if field == "*" {
		return CronField{wildcard: true, rangeMin: min, rangeMax: max}, nil
	}

	// Handle step values (e.g., */5, 1-10/2)
	parts := strings.Split(field, "/")
	var step = 1
	var rangeExpr = parts[0]

	if len(parts) == 2 {
		var err error
		step, err = strconv.Atoi(parts[1])
		if err != nil || step <= 0 {
			return CronField{}, fmt.Errorf("invalid step value: %s", parts[1])
		}
	} else if len(parts) > 2 {
		return CronField{}, fmt.Errorf("invalid field format: %s", field)
	}

	var values []int

	if rangeExpr == "*" {
		// Generate all values in range with step
		for i := min; i <= max; i += step {
			values = append(values, i)
		}
		return CronField{values: values, step: step, rangeMin: min, rangeMax: max}, nil
	}

	// Handle ranges (e.g., 1-5) and lists (e.g., 1,3,5)
	items := strings.Split(rangeExpr, ",")
	for _, item := range items {
		if strings.Contains(item, "-") {
			// Range
			rangeParts := strings.Split(item, "-")
			if len(rangeParts) != 2 {
				return CronField{}, fmt.Errorf("invalid range format: %s", item)
			}

			start, err := strconv.Atoi(rangeParts[0])
			if err != nil {
				return CronField{}, fmt.Errorf("invalid range start: %s", rangeParts[0])
			}

			end, err := strconv.Atoi(rangeParts[1])
			if err != nil {
				return CronField{}, fmt.Errorf("invalid range end: %s", rangeParts[1])
			}

			if start < min || end > max || start > end {
				return CronField{}, fmt.Errorf("range %d-%d is outside valid range %d-%d", start, end, min, max)
			}

			for i := start; i <= end; i += step {
				values = append(values, i)
			}
		} else {
			// Single value
			value, err := strconv.Atoi(item)
			if err != nil {
				return CronField{}, fmt.Errorf("invalid value: %s", item)
			}

			if value < min || value > max {
				return CronField{}, fmt.Errorf("value %d is outside valid range %d-%d", value, min, max)
			}

			values = append(values, value)
		}
	}

	return CronField{values: values, step: step, rangeMin: min, rangeMax: max}, nil
}

// calculateNextRun calculates the next execution time for a cron schedule
func (cs *CronScheduler) calculateNextRun(schedule *CronSchedule, from time.Time) time.Time {
	// Check if this is a seconds-level cron (has specific seconds defined)
	hasSecondsLevel := !schedule.second.wildcard || schedule.second.step > 1

	var next time.Time
	var increment time.Duration
	var maxAttempts int

	if hasSecondsLevel {
		// For second-level cron, start from the next second
		next = from.In(schedule.timezone).Truncate(time.Second).Add(time.Second)
		increment = time.Second
		maxAttempts = 366 * 24 * 60 * 60 // Max one year of seconds
	} else {
		// For minute-level cron, start from the next minute
		next = from.In(schedule.timezone).Truncate(time.Minute).Add(time.Minute)
		increment = time.Minute
		maxAttempts = 366 * 24 * 60 // Max one year of minutes
	}

	// Find the next matching time
	for attempts := 0; attempts < maxAttempts; attempts++ {
		if cs.timeMatches(schedule, next) {
			return next
		}
		next = next.Add(increment)
	}

	// Fallback: if no match found, schedule for next hour
	return from.Add(time.Hour)
}

// timeMatches checks if a time matches the cron schedule
func (cs *CronScheduler) timeMatches(schedule *CronSchedule, t time.Time) bool {
	return cs.fieldMatches(schedule.second, t.Second()) &&
		cs.fieldMatches(schedule.minute, t.Minute()) &&
		cs.fieldMatches(schedule.hour, t.Hour()) &&
		cs.fieldMatches(schedule.day, t.Day()) &&
		cs.fieldMatches(schedule.month, int(t.Month())) &&
		cs.fieldMatches(schedule.weekday, int(t.Weekday()))
}

// fieldMatches checks if a value matches a cron field
func (cs *CronScheduler) fieldMatches(field CronField, value int) bool {
	if field.wildcard {
		return true
	}

	for _, v := range field.values {
		if v == value {
			return true
		}
	}

	return false
}

// isWithinTimeWindow checks if the current time is within the trigger's valid time window
func (cs *CronScheduler) isWithinTimeWindow(schedule *ScheduleConfig, now time.Time) bool {
	if schedule.StartTime != nil && now.Before(*schedule.StartTime) {
		return false
	}

	if schedule.EndTime != nil && now.After(*schedule.EndTime) {
		return false
	}

	return true
}

// disableTrigger disables a trigger
func (cs *CronScheduler) disableTrigger(triggerID string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if scheduled, exists := cs.scheduledTriggers[triggerID]; exists {
		scheduled.enabled = false
	}
}

// updateTriggerStatistics updates execution statistics for a trigger
func (cs *CronScheduler) updateTriggerStatistics(triggerID string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if scheduled, exists := cs.scheduledTriggers[triggerID]; exists {
		scheduled.trigger.Schedule.CurrentRuns++
		scheduled.trigger.Schedule.LastExecution = &time.Time{}
		*scheduled.trigger.Schedule.LastExecution = time.Now()
		scheduled.trigger.Schedule.NextExecution = &scheduled.nextRun
	}
}

// handleTriggerError handles errors that occur during trigger execution
func (cs *CronScheduler) handleTriggerError(ctx context.Context, trigger *Trigger, err error) {
	tenantID := logging.ExtractTenantFromContext(ctx)
	logger := cs.logger.WithTenant(tenantID)

	if trigger.ErrorHandling == nil {
		logger.ErrorCtx(ctx, "Trigger error with no error handling configured",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return
	}

	// Increment consecutive failure count
	trigger.ErrorHandling.CurrentConsecutiveFailures++

	logger.ErrorCtx(ctx, "Handling trigger error",
		"trigger_id", trigger.ID,
		"consecutive_failures", trigger.ErrorHandling.CurrentConsecutiveFailures,
		"max_failures", trigger.ErrorHandling.MaxConsecutiveFailures,
		"action", string(trigger.ErrorHandling.OnError),
		"error", err.Error())

	// Check if we should disable the trigger
	if trigger.ErrorHandling.MaxConsecutiveFailures > 0 &&
		trigger.ErrorHandling.CurrentConsecutiveFailures >= trigger.ErrorHandling.MaxConsecutiveFailures {

		logger.WarnCtx(ctx, "Disabling trigger due to consecutive failures",
			"trigger_id", trigger.ID,
			"consecutive_failures", trigger.ErrorHandling.CurrentConsecutiveFailures)

		cs.disableTrigger(trigger.ID)
		return
	}

	// Handle based on configured action
	switch trigger.ErrorHandling.OnError {
	case TriggerErrorActionPause:
		logger.InfoCtx(ctx, "Pausing trigger due to error",
			"trigger_id", trigger.ID)
		cs.disableTrigger(trigger.ID)

	case TriggerErrorActionDisable:
		logger.InfoCtx(ctx, "Disabling trigger due to error",
			"trigger_id", trigger.ID)
		cs.disableTrigger(trigger.ID)

	case TriggerErrorActionNotify:
		// TODO: Implement notification system integration
		logger.InfoCtx(ctx, "Sending error notification for trigger",
			"trigger_id", trigger.ID,
			"channels", trigger.ErrorHandling.NotificationChannels)

	case TriggerErrorActionContinue:
		logger.InfoCtx(ctx, "Continuing trigger operation despite error",
			"trigger_id", trigger.ID)
	}
}

// GetScheduledTriggers returns a copy of all scheduled triggers (for testing/monitoring)
func (cs *CronScheduler) GetScheduledTriggers() map[string]*Trigger {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	result := make(map[string]*Trigger)
	for id, scheduled := range cs.scheduledTriggers {
		result[id] = scheduled.trigger
	}

	return result
}

// GetNextExecutionTime returns the next execution time for a trigger (for testing/monitoring)
func (cs *CronScheduler) GetNextExecutionTime(triggerID string) (*time.Time, error) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	scheduled, exists := cs.scheduledTriggers[triggerID]
	if !exists {
		return nil, fmt.Errorf("trigger %s is not scheduled", triggerID)
	}

	return &scheduled.nextRun, nil
}
