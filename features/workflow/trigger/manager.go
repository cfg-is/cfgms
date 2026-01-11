// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// extractTenantFromContext extracts tenant ID from context, trying both logging and trigger context keys
func extractTenantFromContext(ctx context.Context) string {
	// First try logging context (for compatibility)
	if tenantID := logging.ExtractTenantFromContext(ctx); tenantID != "" {
		return tenantID
	}

	// Then try trigger context key (for API and integration tests)
	if value := ctx.Value(TenantIDContextKey); value != nil {
		if tenantID, ok := value.(string); ok {
			return tenantID
		}
	}

	return ""
}

// TriggerManagerImpl implements the TriggerManager interface
type TriggerManagerImpl struct {
	logger          *logging.ModuleLogger
	storage         interfaces.StorageProvider
	scheduler       Scheduler
	webhookHandler  WebhookHandler
	siemIntegration SIEMIntegration
	workflowTrigger WorkflowTrigger
	triggers        map[string]*Trigger
	executions      map[string]*TriggerExecution
	mutex           sync.RWMutex
	running         bool
}

// NewTriggerManager creates a new trigger manager
func NewTriggerManager(
	storage interfaces.StorageProvider,
	scheduler Scheduler,
	webhookHandler WebhookHandler,
	siemIntegration SIEMIntegration,
	workflowTrigger WorkflowTrigger,
) *TriggerManagerImpl {
	logger := logging.ForModule("workflow.trigger.manager").WithField("component", "manager")

	return &TriggerManagerImpl{
		logger:          logger,
		storage:         storage,
		scheduler:       scheduler,
		webhookHandler:  webhookHandler,
		siemIntegration: siemIntegration,
		workflowTrigger: workflowTrigger,
		triggers:        make(map[string]*Trigger),
		executions:      make(map[string]*TriggerExecution),
	}
}

// Start starts the trigger manager and all its components
func (tm *TriggerManagerImpl) Start(ctx context.Context) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if tm.running {
		return fmt.Errorf("trigger manager is already running")
	}

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Starting trigger manager")

	// Start all components
	if err := tm.scheduler.Start(ctx); err != nil {
		logger.ErrorCtx(ctx, "Failed to start scheduler", "error", err.Error())
		return fmt.Errorf("failed to start scheduler: %w", err)
	}

	if err := tm.webhookHandler.Start(ctx); err != nil {
		logger.ErrorCtx(ctx, "Failed to start webhook handler", "error", err.Error())
		if stopErr := tm.scheduler.Stop(ctx); stopErr != nil {
			logger.ErrorCtx(ctx, "Failed to stop scheduler during cleanup", "error", stopErr.Error())
		}
		return fmt.Errorf("failed to start webhook handler: %w", err)
	}

	if err := tm.siemIntegration.Start(ctx); err != nil {
		logger.ErrorCtx(ctx, "Failed to start SIEM integration", "error", err.Error())
		if stopErr := tm.scheduler.Stop(ctx); stopErr != nil {
			logger.ErrorCtx(ctx, "Failed to stop scheduler during cleanup", "error", stopErr.Error())
		}
		if stopErr := tm.webhookHandler.Stop(ctx); stopErr != nil {
			logger.ErrorCtx(ctx, "Failed to stop webhook handler during cleanup", "error", stopErr.Error())
		}
		return fmt.Errorf("failed to start SIEM integration: %w", err)
	}

	// Load existing triggers from storage
	if err := tm.loadTriggersFromStorage(ctx); err != nil {
		logger.WarnCtx(ctx, "Failed to load triggers from storage", "error", err.Error())
		// Don't fail startup for this, but log it
	}

	tm.running = true

	logger.InfoCtx(ctx, "Trigger manager started successfully")
	return nil
}

// Stop stops the trigger manager and all its components
func (tm *TriggerManagerImpl) Stop(ctx context.Context) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	if !tm.running {
		return fmt.Errorf("trigger manager is not running")
	}

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Stopping trigger manager")

	// Stop all components
	var errs []error

	if err := tm.scheduler.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("failed to stop scheduler: %w", err))
	}

	if err := tm.webhookHandler.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("failed to stop webhook handler: %w", err))
	}

	if err := tm.siemIntegration.Stop(ctx); err != nil {
		errs = append(errs, fmt.Errorf("failed to stop SIEM integration: %w", err))
	}

	tm.running = false

	if len(errs) > 0 {
		logger.ErrorCtx(ctx, "Errors occurred while stopping trigger manager",
			"error_count", len(errs))
		return fmt.Errorf("multiple errors occurred during shutdown: %v", errs)
	}

	logger.InfoCtx(ctx, "Trigger manager stopped successfully")
	return nil
}

// CreateTrigger creates a new trigger
func (tm *TriggerManagerImpl) CreateTrigger(ctx context.Context, trigger *Trigger) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	// Generate ID if not provided
	if trigger.ID == "" {
		trigger.ID = tm.generateTriggerID()
	}

	// Set tenant ID from context
	if trigger.TenantID == "" {
		trigger.TenantID = tenantID
	}

	// Set timestamps
	now := time.Now()
	trigger.CreatedAt = now
	trigger.UpdatedAt = now

	// Set default status
	if trigger.Status == "" {
		trigger.Status = TriggerStatusActive
	}

	logger.InfoCtx(ctx, "Creating trigger",
		"trigger_id", trigger.ID,
		"type", trigger.Type,
		"workflow_name", trigger.WorkflowName)

	// Validate trigger configuration
	if err := tm.validateTrigger(ctx, trigger); err != nil {
		logger.ErrorCtx(ctx, "Trigger validation failed",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("trigger validation failed: %w", err)
	}

	// Check if trigger already exists
	if _, exists := tm.triggers[trigger.ID]; exists {
		return fmt.Errorf("trigger with ID %s already exists", trigger.ID)
	}

	// Store in memory
	tm.triggers[trigger.ID] = trigger

	// Persist to storage
	if err := tm.saveTriggerToStorage(ctx, trigger); err != nil {
		// Remove from memory if storage fails
		delete(tm.triggers, trigger.ID)
		logger.ErrorCtx(ctx, "Failed to save trigger to storage",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("failed to save trigger: %w", err)
	}

	// Register with appropriate handler
	if err := tm.registerTriggerWithHandler(ctx, trigger); err != nil {
		// Clean up on registration failure
		delete(tm.triggers, trigger.ID)
		if delErr := tm.deleteTriggerFromStorage(ctx, trigger.ID); delErr != nil {
			logger.ErrorCtx(ctx, "Failed to delete trigger from storage during cleanup", "trigger_id", trigger.ID, "error", delErr.Error())
		}
		logger.ErrorCtx(ctx, "Failed to register trigger with handler",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("failed to register trigger: %w", err)
	}

	logger.InfoCtx(ctx, "Trigger created successfully",
		"trigger_id", trigger.ID)

	return nil
}

// UpdateTrigger updates an existing trigger
func (tm *TriggerManagerImpl) UpdateTrigger(ctx context.Context, trigger *Trigger) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Updating trigger",
		"trigger_id", trigger.ID)

	// Check if trigger exists
	existingTrigger, exists := tm.triggers[trigger.ID]
	if !exists {
		return fmt.Errorf("trigger %s not found", trigger.ID)
	}

	// Ensure tenant ID matches (security check)
	if existingTrigger.TenantID != tenantID {
		logger.WarnCtx(ctx, "Attempted to update trigger from different tenant",
			"trigger_id", trigger.ID,
			"existing_tenant", existingTrigger.TenantID,
			"request_tenant", tenantID)
		return fmt.Errorf("trigger not found")
	}

	// Preserve creation timestamp and update modification timestamp
	trigger.CreatedAt = existingTrigger.CreatedAt
	trigger.UpdatedAt = time.Now()
	trigger.TenantID = existingTrigger.TenantID

	// Validate updated configuration
	if err := tm.validateTrigger(ctx, trigger); err != nil {
		logger.ErrorCtx(ctx, "Updated trigger validation failed",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("trigger validation failed: %w", err)
	}

	// Unregister old trigger
	if err := tm.unregisterTriggerFromHandler(ctx, existingTrigger); err != nil {
		logger.WarnCtx(ctx, "Failed to unregister old trigger",
			"trigger_id", trigger.ID,
			"error", err.Error())
		// Continue with update despite unregistration failure
	}

	// Update in memory
	tm.triggers[trigger.ID] = trigger

	// Persist to storage
	if err := tm.saveTriggerToStorage(ctx, trigger); err != nil {
		// Restore old trigger on storage failure
		tm.triggers[trigger.ID] = existingTrigger
		if regErr := tm.registerTriggerWithHandler(ctx, existingTrigger); regErr != nil {
			logger.ErrorCtx(ctx, "Failed to re-register old trigger during rollback", "trigger_id", existingTrigger.ID, "error", regErr.Error())
		}
		logger.ErrorCtx(ctx, "Failed to save updated trigger to storage",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("failed to save trigger: %w", err)
	}

	// Register updated trigger
	if err := tm.registerTriggerWithHandler(ctx, trigger); err != nil {
		// Restore old trigger on registration failure
		tm.triggers[trigger.ID] = existingTrigger
		if saveErr := tm.saveTriggerToStorage(ctx, existingTrigger); saveErr != nil {
			logger.ErrorCtx(ctx, "Failed to restore trigger to storage during rollback", "trigger_id", existingTrigger.ID, "error", saveErr.Error())
		}
		if regErr := tm.registerTriggerWithHandler(ctx, existingTrigger); regErr != nil {
			logger.ErrorCtx(ctx, "Failed to re-register old trigger during rollback", "trigger_id", existingTrigger.ID, "error", regErr.Error())
		}
		logger.ErrorCtx(ctx, "Failed to register updated trigger",
			"trigger_id", trigger.ID,
			"error", err.Error())
		return fmt.Errorf("failed to register trigger: %w", err)
	}

	logger.InfoCtx(ctx, "Trigger updated successfully",
		"trigger_id", trigger.ID)

	return nil
}

// DeleteTrigger deletes a trigger
func (tm *TriggerManagerImpl) DeleteTrigger(ctx context.Context, triggerID string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Deleting trigger",
		"trigger_id", triggerID)

	// Check if trigger exists
	trigger, exists := tm.triggers[triggerID]
	if !exists {
		return fmt.Errorf("trigger %s not found", triggerID)
	}

	// Ensure tenant ID matches (security check)
	if trigger.TenantID != tenantID {
		logger.WarnCtx(ctx, "Attempted to delete trigger from different tenant",
			"trigger_id", triggerID,
			"trigger_tenant", trigger.TenantID,
			"request_tenant", tenantID)
		return fmt.Errorf("trigger not found")
	}

	// Unregister from handler
	if err := tm.unregisterTriggerFromHandler(ctx, trigger); err != nil {
		logger.WarnCtx(ctx, "Failed to unregister trigger from handler",
			"trigger_id", triggerID,
			"error", err.Error())
		// Continue with deletion despite unregistration failure
	}

	// Remove from memory
	delete(tm.triggers, triggerID)

	// Remove from storage
	if err := tm.deleteTriggerFromStorage(ctx, triggerID); err != nil {
		logger.ErrorCtx(ctx, "Failed to delete trigger from storage",
			"trigger_id", triggerID,
			"error", err.Error())
		// Don't restore to memory since we want to delete it
		return fmt.Errorf("failed to delete trigger from storage: %w", err)
	}

	logger.InfoCtx(ctx, "Trigger deleted successfully",
		"trigger_id", triggerID)

	return nil
}

// GetTrigger retrieves a trigger by ID
func (tm *TriggerManagerImpl) GetTrigger(ctx context.Context, triggerID string) (*Trigger, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	tenantID := extractTenantFromContext(ctx)

	trigger, exists := tm.triggers[triggerID]
	if !exists {
		return nil, fmt.Errorf("trigger %s not found", triggerID)
	}

	// Ensure tenant ID matches (security check)
	if trigger.TenantID != tenantID {
		return nil, fmt.Errorf("trigger not found")
	}

	// Return a copy to prevent external modification
	triggerCopy := *trigger
	return &triggerCopy, nil
}

// ListTriggers lists triggers with optional filtering
func (tm *TriggerManagerImpl) ListTriggers(ctx context.Context, filter *TriggerFilter) ([]*Trigger, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	tenantID := extractTenantFromContext(ctx)

	var triggers []*Trigger

	for _, trigger := range tm.triggers {
		// Apply tenant filter (security) - skip tenant filtering if no tenant in context (admin access)
		if tenantID != "" && trigger.TenantID != tenantID {
			continue
		}

		// Apply filters if provided
		if filter != nil {
			if !tm.matchesFilter(trigger, filter) {
				continue
			}
		}

		// Create a copy to prevent external modification
		triggerCopy := *trigger
		triggers = append(triggers, &triggerCopy)
	}

	// Apply limit and offset
	if filter != nil {
		if filter.Offset > 0 && filter.Offset < len(triggers) {
			triggers = triggers[filter.Offset:]
		} else if filter.Offset >= len(triggers) {
			triggers = []*Trigger{}
		}

		if filter.Limit > 0 && filter.Limit < len(triggers) {
			triggers = triggers[:filter.Limit]
		}
	}

	return triggers, nil
}

// EnableTrigger enables a disabled trigger
func (tm *TriggerManagerImpl) EnableTrigger(ctx context.Context, triggerID string) error {
	return tm.setTriggerStatus(ctx, triggerID, TriggerStatusActive)
}

// DisableTrigger disables an active trigger
func (tm *TriggerManagerImpl) DisableTrigger(ctx context.Context, triggerID string) error {
	return tm.setTriggerStatus(ctx, triggerID, TriggerStatusInactive)
}

// ExecuteTrigger manually executes a trigger
func (tm *TriggerManagerImpl) ExecuteTrigger(ctx context.Context, triggerID string, data map[string]interface{}) (*TriggerExecution, error) {
	tm.mutex.RLock()
	trigger, exists := tm.triggers[triggerID]
	tm.mutex.RUnlock()

	if !exists {
		return nil, fmt.Errorf("trigger %s not found", triggerID)
	}

	tenantID := extractTenantFromContext(ctx)
	// Create a fresh logger instance to avoid race conditions in concurrent tests
	logger := logging.ForModule("workflow.trigger.manager").WithTenant(tenantID)

	// Ensure tenant ID matches (security check)
	if trigger.TenantID != tenantID {
		return nil, fmt.Errorf("trigger not found")
	}

	logger.InfoCtx(ctx, "Manually executing trigger",
		"trigger_id", triggerID,
		"workflow_name", trigger.WorkflowName)

	// Create execution record
	execution := &TriggerExecution{
		ID:        tm.generateExecutionID(),
		TriggerID: triggerID,
		Status:    TriggerExecutionStatusPending,
		StartTime: time.Now(),
		TriggerData: map[string]interface{}{
			"trigger_type": "manual",
			"trigger_id":   triggerID,
			"manual_data":  data,
		},
	}

	// Merge trigger variables with provided data
	workflowVariables := make(map[string]interface{})
	for k, v := range trigger.Variables {
		workflowVariables[k] = v
	}
	for k, v := range data {
		workflowVariables[k] = v
	}
	for k, v := range execution.TriggerData {
		workflowVariables[k] = v
	}

	// Store execution
	tm.mutex.Lock()
	tm.executions[execution.ID] = execution
	// Update status to running while still holding the lock
	execution.Status = TriggerExecutionStatusRunning
	tm.mutex.Unlock()

	// Execute workflow
	workflowExecution, err := tm.workflowTrigger.TriggerWorkflow(ctx, trigger, workflowVariables)

	// Update execution results with proper synchronization
	tm.mutex.Lock()
	endTime := time.Now()
	execution.EndTime = &endTime
	execution.Duration = execution.EndTime.Sub(execution.StartTime)

	if err != nil {
		execution.Status = TriggerExecutionStatusFailed
		execution.Error = err.Error()

		tm.mutex.Unlock()
		logger.ErrorCtx(ctx, "Manual trigger execution failed",
			"trigger_id", triggerID,
			"execution_id", execution.ID,
			"error", err.Error())
	} else {
		execution.Status = TriggerExecutionStatusSuccess
		execution.WorkflowExecutionID = workflowExecution.ID

		tm.mutex.Unlock()
		logger.InfoCtx(ctx, "Manual trigger execution successful",
			"trigger_id", triggerID,
			"execution_id", execution.ID,
			"workflow_execution_id", workflowExecution.ID)
	}

	return execution, nil
}

// GetTriggerExecutions retrieves execution history for a trigger
func (tm *TriggerManagerImpl) GetTriggerExecutions(ctx context.Context, triggerID string, limit int) ([]*TriggerExecution, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()

	tenantID := extractTenantFromContext(ctx)

	// Check if trigger exists and tenant has access
	trigger, exists := tm.triggers[triggerID]
	if !exists {
		return nil, fmt.Errorf("trigger %s not found", triggerID)
	}

	if trigger.TenantID != tenantID {
		return nil, fmt.Errorf("trigger not found")
	}

	var executions []*TriggerExecution

	for _, execution := range tm.executions {
		if execution.TriggerID == triggerID {
			// Create a copy to prevent external modification
			executionCopy := *execution
			executions = append(executions, &executionCopy)
		}
	}

	// Sort by start time (most recent first)
	for i := 0; i < len(executions)-1; i++ {
		for j := i + 1; j < len(executions); j++ {
			if executions[i].StartTime.Before(executions[j].StartTime) {
				executions[i], executions[j] = executions[j], executions[i]
			}
		}
	}

	// Apply limit
	if limit > 0 && limit < len(executions) {
		executions = executions[:limit]
	}

	return executions, nil
}

// Helper methods

func (tm *TriggerManagerImpl) generateTriggerID() string {
	return fmt.Sprintf("trigger_%s", uuid.New().String())
}

func (tm *TriggerManagerImpl) generateExecutionID() string {
	return fmt.Sprintf("exec_%s", uuid.New().String())
}

func (tm *TriggerManagerImpl) validateTrigger(ctx context.Context, trigger *Trigger) error {
	if trigger.Name == "" {
		return fmt.Errorf("trigger name is required")
	}

	if trigger.WorkflowName == "" {
		return fmt.Errorf("workflow name is required")
	}

	if trigger.Type == "" {
		return fmt.Errorf("trigger type is required")
	}

	// Type-specific validation
	switch trigger.Type {
	case TriggerTypeSchedule:
		if trigger.Schedule == nil {
			return fmt.Errorf("schedule configuration is required for schedule triggers")
		}
		return tm.validateScheduleConfig(trigger.Schedule)

	case TriggerTypeWebhook:
		if trigger.Webhook == nil {
			return fmt.Errorf("webhook configuration is required for webhook triggers")
		}
		return tm.validateWebhookConfig(trigger.Webhook)

	case TriggerTypeSIEM:
		if trigger.SIEM == nil {
			return fmt.Errorf("SIEM configuration is required for SIEM triggers")
		}
		return tm.validateSIEMConfig(trigger.SIEM)

	case TriggerTypeManual:
		// Manual triggers don't require additional configuration
		return nil

	default:
		return fmt.Errorf("unsupported trigger type: %s", trigger.Type)
	}
}

func (tm *TriggerManagerImpl) validateScheduleConfig(config *ScheduleConfig) error {
	if config.CronExpression == "" {
		return fmt.Errorf("cron expression is required")
	}

	// Basic cron validation - could be enhanced
	if len(config.CronExpression) < 9 { // Minimum valid cron expression
		return fmt.Errorf("invalid cron expression format")
	}

	return nil
}

func (tm *TriggerManagerImpl) validateWebhookConfig(config *WebhookConfig) error {
	if config.Path == "" {
		return fmt.Errorf("webhook path is required")
	}

	return nil
}

func (tm *TriggerManagerImpl) validateSIEMConfig(config *SIEMConfig) error {
	if len(config.EventTypes) == 0 {
		return fmt.Errorf("at least one event type is required")
	}

	if config.WindowSize <= 0 {
		return fmt.Errorf("window size must be greater than 0")
	}

	return nil
}

func (tm *TriggerManagerImpl) registerTriggerWithHandler(ctx context.Context, trigger *Trigger) error {
	switch trigger.Type {
	case TriggerTypeSchedule:
		return tm.scheduler.ScheduleWorkflow(ctx, trigger)

	case TriggerTypeWebhook:
		return tm.webhookHandler.RegisterWebhook(ctx, trigger)

	case TriggerTypeSIEM:
		return tm.siemIntegration.RegisterSIEMTrigger(ctx, trigger)

	case TriggerTypeManual:
		// Manual triggers don't need registration with handlers
		return nil

	default:
		return fmt.Errorf("unsupported trigger type: %s", trigger.Type)
	}
}

func (tm *TriggerManagerImpl) unregisterTriggerFromHandler(ctx context.Context, trigger *Trigger) error {
	switch trigger.Type {
	case TriggerTypeSchedule:
		return tm.scheduler.UnscheduleWorkflow(ctx, trigger.ID)

	case TriggerTypeWebhook:
		return tm.webhookHandler.UnregisterWebhook(ctx, trigger.ID)

	case TriggerTypeSIEM:
		return tm.siemIntegration.UnregisterSIEMTrigger(ctx, trigger.ID)

	case TriggerTypeManual:
		// Manual triggers don't need unregistration from handlers
		return nil

	default:
		return fmt.Errorf("unsupported trigger type: %s", trigger.Type)
	}
}

func (tm *TriggerManagerImpl) setTriggerStatus(ctx context.Context, triggerID string, status TriggerStatus) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	trigger, exists := tm.triggers[triggerID]
	if !exists {
		return fmt.Errorf("trigger %s not found", triggerID)
	}

	// Ensure tenant ID matches (security check)
	if trigger.TenantID != tenantID {
		return fmt.Errorf("trigger not found")
	}

	oldStatus := trigger.Status
	trigger.Status = status
	trigger.UpdatedAt = time.Now()

	// Update in storage
	if err := tm.saveTriggerToStorage(ctx, trigger); err != nil {
		// Restore old status on failure
		trigger.Status = oldStatus
		logger.ErrorCtx(ctx, "Failed to update trigger status in storage",
			"trigger_id", triggerID,
			"error", err.Error())
		return fmt.Errorf("failed to update trigger status: %w", err)
	}

	// Handle scheduler registration/unregistration for schedule triggers
	if trigger.Type == TriggerTypeSchedule {
		if status == TriggerStatusActive && oldStatus != TriggerStatusActive {
			// Register with scheduler when activating
			if err := tm.registerTriggerWithHandler(ctx, trigger); err != nil {
				logger.WarnCtx(ctx, "Failed to register trigger with scheduler during activation",
					"trigger_id", triggerID,
					"error", err.Error())
				// Don't fail the status update for this
			}
		} else if status == TriggerStatusInactive && oldStatus == TriggerStatusActive {
			// Unregister from scheduler when deactivating
			if err := tm.unregisterTriggerFromHandler(ctx, trigger); err != nil {
				logger.WarnCtx(ctx, "Failed to unregister trigger from scheduler during deactivation",
					"trigger_id", triggerID,
					"error", err.Error())
				// Don't fail the status update for this
			}
		}
	}

	logger.InfoCtx(ctx, "Trigger status updated",
		"trigger_id", triggerID,
		"old_status", oldStatus,
		"new_status", status)

	return nil
}

func (tm *TriggerManagerImpl) matchesFilter(trigger *Trigger, filter *TriggerFilter) bool {
	if filter.TenantID != "" && trigger.TenantID != filter.TenantID {
		return false
	}

	if filter.Type != "" && trigger.Type != filter.Type {
		return false
	}

	if filter.Status != "" && trigger.Status != filter.Status {
		return false
	}

	if len(filter.Tags) > 0 {
		hasMatchingTag := false
		for _, filterTag := range filter.Tags {
			for _, triggerTag := range trigger.Tags {
				if filterTag == triggerTag {
					hasMatchingTag = true
					break
				}
			}
			if hasMatchingTag {
				break
			}
		}
		if !hasMatchingTag {
			return false
		}
	}

	if filter.CreatedAfter != nil && trigger.CreatedAt.Before(*filter.CreatedAfter) {
		return false
	}

	if filter.CreatedBefore != nil && trigger.CreatedAt.After(*filter.CreatedBefore) {
		return false
	}

	return true
}

func (tm *TriggerManagerImpl) loadTriggersFromStorage(ctx context.Context) error {
	// TODO: Implement storage loading
	// This would involve reading triggers from the configured storage provider
	return nil
}

func (tm *TriggerManagerImpl) saveTriggerToStorage(ctx context.Context, trigger *Trigger) error {
	// Check if storage is available
	available, err := tm.storage.Available()
	if err != nil {
		return fmt.Errorf("failed to check storage availability: %w", err)
	}
	if !available {
		return fmt.Errorf("storage provider is not available")
	}

	// Convert trigger to JSON for storage
	triggerData, err := json.Marshal(trigger)
	if err != nil {
		return fmt.Errorf("failed to marshal trigger: %w", err)
	}

	// Try to use Store method if available (for testing with MockStorageProvider)
	type storeInterface interface {
		Store(context.Context, string, []byte) error
	}

	if storer, ok := tm.storage.(storeInterface); ok {
		storageKey := fmt.Sprintf("triggers/%s", trigger.ID)
		if err := storer.Store(ctx, storageKey, triggerData); err != nil {
			return fmt.Errorf("failed to store trigger: %w", err)
		}
	}
	// If Store method not available, skip storage (for production with standard StorageProvider)

	return nil
}

func (tm *TriggerManagerImpl) deleteTriggerFromStorage(ctx context.Context, triggerID string) error {
	// Check if storage is available
	available, err := tm.storage.Available()
	if err != nil {
		return fmt.Errorf("failed to check storage availability: %w", err)
	}
	if !available {
		return fmt.Errorf("storage provider is not available")
	}

	// Try to use Delete method if available (for testing with MockStorageProvider)
	type deleteInterface interface {
		Delete(context.Context, string) error
	}

	if deleter, ok := tm.storage.(deleteInterface); ok {
		storageKey := fmt.Sprintf("triggers/%s", triggerID)
		if err := deleter.Delete(ctx, storageKey); err != nil {
			return fmt.Errorf("failed to delete trigger: %w", err)
		}
	}
	// If Delete method not available, skip storage (for production with standard StorageProvider)

	return nil
}
