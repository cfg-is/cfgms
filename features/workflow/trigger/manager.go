// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/cfgis/cfgms/pkg/ctxkeys"
	"github.com/cfgis/cfgms/pkg/lease"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// extractTenantFromContext reads the authenticated tenant from ctxkeys.TenantID,
// the single canonical context key the authentication middleware sets (Issue
// #4326). Every trigger authorization decision (CreateTrigger, ListTriggers,
// GetTrigger, UpdateTrigger, DeleteTrigger, ExecuteTrigger) reads the tenant
// through this helper — never through logging.ExtractTenantFromContext, a
// logging-only accessor that reads a different context key the middleware never
// writes and therefore always returned "".
func extractTenantFromContext(ctx context.Context) string {
	if tenantID, ok := ctx.Value(ctxkeys.TenantID).(string); ok {
		return tenantID
	}
	return ""
}

// StoreRequirements declares the storage stores required by the workflow-trigger subsystem.
// Collected by collectActiveStorageRequirements in features/controller/server and validated
// at startup via interfaces.ValidateStorageRequirements — a missing TriggerStore fails
// closed rather than silently degrading trigger persistence when a provider cannot supply it.
var StoreRequirements = []interfaces.StoreRequirement{
	{Subsystem: "workflow-trigger", Store: interfaces.StoreNameTrigger, Severity: interfaces.RequirementRequired},
}

// TriggerManagerImpl implements the TriggerManager interface
type TriggerManagerImpl struct {
	logger          *logging.ModuleLogger
	storage         interfaces.StorageProvider
	triggerStore    business.TriggerStore
	secretStore     secretsif.SecretStore
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
	secretStore secretsif.SecretStore,
) *TriggerManagerImpl {
	logger := logging.ForModule("workflow.trigger.manager").WithField("component", "manager")

	var triggerStore business.TriggerStore
	if storage != nil {
		ts, err := storage.CreateTriggerStore(nil)
		if err != nil {
			if !errors.Is(err, business.ErrNotSupported) {
				logger.Warn("failed to initialize trigger store", "error", err.Error())
			}
			// ErrNotSupported: provider does not implement trigger persistence — silent skip
		} else {
			triggerStore = ts
		}
	}

	return &TriggerManagerImpl{
		logger:          logger,
		storage:         storage,
		triggerStore:    triggerStore,
		secretStore:     secretStore,
		scheduler:       scheduler,
		webhookHandler:  webhookHandler,
		siemIntegration: siemIntegration,
		workflowTrigger: workflowTrigger,
		triggers:        make(map[string]*Trigger),
		executions:      make(map[string]*TriggerExecution),
	}
}

// leaseJobSetter is implemented by Scheduler implementations that support a
// cluster-singleton lease claim (ADR-031 Decision 4) — currently CronScheduler
// only. Type-asserted rather than added to the Scheduler interface so test
// doubles that implement Scheduler without lease support are unaffected.
type leaseJobSetter interface {
	SetLeaseJob(job lease.SingletonJob)
}

// SetSchedulerLease wires the cluster-singleton lease claim the scheduler's
// due-trigger check runs behind, if the configured Scheduler supports one. A
// scheduler that does not (e.g. a test double) makes this a no-op.
func (tm *TriggerManagerImpl) SetSchedulerLease(job lease.SingletonJob) {
	if setter, ok := tm.scheduler.(leaseJobSetter); ok {
		setter.SetLeaseJob(job)
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

// triggerCredentialRef names a trigger credential within its tenant's secrets
// (Issue #4641). The tenant is not part of the name: the credential is stored
// with the trigger's tenant, and a tenant ID may itself contain "/", which in
// the name would make the combined "<tenant>/<ref>" key ambiguous.
func triggerCredentialRef(triggerID, kind string) string {
	return "trigger-" + triggerID + "-" + kind
}

// validateTriggerID refuses a trigger ID that could not be used safely as part
// of a secret name or a path: one containing a path separator or "..".
func validateTriggerID(id string) error {
	if strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return fmt.Errorf("invalid trigger id %q: must not contain '/', '\\' or '..'", id)
	}
	return nil
}

// triggerSecretKey is the secret-store key a trigger credential is read and
// deleted by: the credential is stored with the trigger's tenant, and the secret
// store addresses tenant-owned secrets as "<tenant_id>/<key>" (Issue #4641). A
// bare ref is refused by the store, so credentials could never be recovered on
// reload (the trigger was skipped) or cleaned up on delete.
func triggerSecretKey(tenantID, ref string) string {
	return tenantID + "/" + ref
}

// SetPersistence gives the manager the durable trigger store and the secret
// store for trigger credentials (Issue #4641). The controller passes the storage
// manager's trigger store — a StorageProvider such as flatfile may not implement
// one, and without a store triggers live in memory only and are lost on restart.
// Call before Start, which reloads every tenant's triggers from the store.
func (tm *TriggerManagerImpl) SetPersistence(triggerStore business.TriggerStore, secretStore secretsif.SecretStore) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	tm.triggerStore = triggerStore
	tm.secretStore = secretStore
}

// CreateTrigger creates a new trigger
func (tm *TriggerManagerImpl) CreateTrigger(ctx context.Context, trigger *Trigger) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	if tenantID == "" {
		return fmt.Errorf("tenant context required to create a trigger")
	}
	logger := tm.logger.WithTenant(tenantID)

	// Generate ID if not provided
	if trigger.ID == "" {
		trigger.ID = tm.generateTriggerID()
	}
	if err := validateTriggerID(trigger.ID); err != nil {
		return err
	}

	// The tenant always comes from the authenticated context, never from the
	// caller-supplied trigger body (Issue #4326) — otherwise a request body could
	// name any tenant and create a trigger outside the caller's own tenant.
	trigger.TenantID = tenantID

	// Set timestamps
	now := time.Now()
	trigger.CreatedAt = now
	trigger.UpdatedAt = now

	// Set default status
	if trigger.Status == "" {
		trigger.Status = TriggerStatusActive
	}

	logger.InfoCtx(ctx, "Creating trigger",
		"trigger_id", logging.SanitizeLogValue(trigger.ID),
		"type", logging.SanitizeLogValue(string(trigger.Type)),
		"workflow_name", logging.SanitizeLogValue(trigger.WorkflowName))

	// Validate trigger configuration
	if err := tm.validateTrigger(ctx, trigger); err != nil {
		logger.ErrorCtx(ctx, "Trigger validation failed",
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
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
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("failed to save trigger: %w", err)
	}

	// Register with appropriate handler
	if err := tm.registerTriggerWithHandler(ctx, trigger); err != nil {
		// Clean up on registration failure
		delete(tm.triggers, trigger.ID)
		if delErr := tm.deleteTriggerFromStorage(ctx, trigger.ID); delErr != nil {
			logger.ErrorCtx(ctx, "Failed to delete trigger from storage during cleanup", "trigger_id", logging.SanitizeLogValue(trigger.ID), "error", logging.SanitizeLogValue(delErr.Error()))
		}
		logger.ErrorCtx(ctx, "Failed to register trigger with handler",
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("failed to register trigger: %w", err)
	}

	logger.InfoCtx(ctx, "Trigger created successfully",
		"trigger_id", logging.SanitizeLogValue(trigger.ID))

	return nil
}

// UpdateTrigger updates an existing trigger
func (tm *TriggerManagerImpl) UpdateTrigger(ctx context.Context, trigger *Trigger) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Updating trigger",
		"trigger_id", logging.SanitizeLogValue(trigger.ID))

	// Check if trigger exists
	existingTrigger, exists := tm.triggers[trigger.ID]
	if !exists {
		return fmt.Errorf("trigger %s not found", trigger.ID)
	}

	// Ensure tenant ID matches (security check)
	if existingTrigger.TenantID != tenantID {
		logger.WarnCtx(ctx, "Attempted to update trigger from different tenant",
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
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
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("trigger validation failed: %w", err)
	}

	// Unregister old trigger
	if err := tm.unregisterTriggerFromHandler(ctx, existingTrigger); err != nil {
		logger.WarnCtx(ctx, "Failed to unregister old trigger",
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		// Continue with update despite unregistration failure
	}

	// Update in memory
	tm.triggers[trigger.ID] = trigger

	// Persist to storage
	if err := tm.saveTriggerToStorage(ctx, trigger); err != nil {
		// Restore old trigger on storage failure
		tm.triggers[trigger.ID] = existingTrigger
		if regErr := tm.registerTriggerWithHandler(ctx, existingTrigger); regErr != nil {
			logger.ErrorCtx(ctx, "Failed to re-register old trigger during rollback", "trigger_id", existingTrigger.ID, "error", logging.SanitizeLogValue(regErr.Error()))
		}
		logger.ErrorCtx(ctx, "Failed to save updated trigger to storage",
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("failed to save trigger: %w", err)
	}

	// Register updated trigger
	if err := tm.registerTriggerWithHandler(ctx, trigger); err != nil {
		// Restore old trigger on registration failure
		tm.triggers[trigger.ID] = existingTrigger
		if saveErr := tm.saveTriggerToStorage(ctx, existingTrigger); saveErr != nil {
			logger.ErrorCtx(ctx, "Failed to restore trigger to storage during rollback", "trigger_id", existingTrigger.ID, "error", logging.SanitizeLogValue(saveErr.Error()))
		}
		if regErr := tm.registerTriggerWithHandler(ctx, existingTrigger); regErr != nil {
			logger.ErrorCtx(ctx, "Failed to re-register old trigger during rollback", "trigger_id", existingTrigger.ID, "error", logging.SanitizeLogValue(regErr.Error()))
		}
		logger.ErrorCtx(ctx, "Failed to register updated trigger",
			"trigger_id", logging.SanitizeLogValue(trigger.ID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("failed to register trigger: %w", err)
	}

	logger.InfoCtx(ctx, "Trigger updated successfully",
		"trigger_id", logging.SanitizeLogValue(trigger.ID))

	return nil
}

// DeleteTrigger deletes a trigger
func (tm *TriggerManagerImpl) DeleteTrigger(ctx context.Context, triggerID string) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()

	tenantID := extractTenantFromContext(ctx)
	logger := tm.logger.WithTenant(tenantID)

	logger.InfoCtx(ctx, "Deleting trigger",
		"trigger_id", logging.SanitizeLogValue(triggerID))

	// Check if trigger exists
	trigger, exists := tm.triggers[triggerID]
	if !exists {
		return fmt.Errorf("trigger %s not found", triggerID)
	}

	// Ensure tenant ID matches (security check)
	if trigger.TenantID != tenantID {
		logger.WarnCtx(ctx, "Attempted to delete trigger from different tenant",
			"trigger_id", logging.SanitizeLogValue(triggerID),
			"trigger_tenant", trigger.TenantID,
			"request_tenant", tenantID)
		return fmt.Errorf("trigger not found")
	}

	// Unregister from handler
	if err := tm.unregisterTriggerFromHandler(ctx, trigger); err != nil {
		logger.WarnCtx(ctx, "Failed to unregister trigger from handler",
			"trigger_id", logging.SanitizeLogValue(triggerID),
			"error", logging.SanitizeLogValue(err.Error()))
		// Continue with deletion despite unregistration failure
	}

	// Remove from memory
	delete(tm.triggers, triggerID)

	// Remove from storage
	if err := tm.deleteTriggerFromStorage(ctx, triggerID); err != nil {
		logger.ErrorCtx(ctx, "Failed to delete trigger from storage",
			"trigger_id", logging.SanitizeLogValue(triggerID),
			"error", logging.SanitizeLogValue(err.Error()))
		// Don't restore to memory since we want to delete it
		return fmt.Errorf("failed to delete trigger from storage: %w", err)
	}

	logger.InfoCtx(ctx, "Trigger deleted successfully",
		"trigger_id", logging.SanitizeLogValue(triggerID))

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
	if tenantID == "" {
		return nil, fmt.Errorf("tenant context required to list triggers")
	}

	triggers := make([]*Trigger, 0)

	for _, trigger := range tm.triggers {
		// Apply tenant filter (security): an absent tenant is refused above, never
		// treated as admin access to every tenant's triggers (Issue #4326).
		if trigger.TenantID != tenantID {
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
		"trigger_id", logging.SanitizeLogValue(triggerID),
		"workflow_name", logging.SanitizeLogValue(trigger.WorkflowName))

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
			"trigger_id", logging.SanitizeLogValue(triggerID),
			"execution_id", logging.SanitizeLogValue(execution.ID),
			"error", logging.SanitizeLogValue(err.Error()))
	} else {
		execution.Status = TriggerExecutionStatusSuccess
		execution.WorkflowExecutionID = workflowExecution.ID

		tm.mutex.Unlock()
		logger.InfoCtx(ctx, "Manual trigger execution successful",
			"trigger_id", logging.SanitizeLogValue(triggerID),
			"execution_id", logging.SanitizeLogValue(execution.ID),
			"workflow_execution_id", logging.SanitizeLogValue(workflowExecution.ID))
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
		if tm.scheduler == nil {
			return fmt.Errorf("no scheduler to register trigger %s with", trigger.ID)
		}
		return tm.scheduler.ScheduleWorkflow(ctx, trigger)

	case TriggerTypeWebhook:
		if tm.webhookHandler == nil {
			return fmt.Errorf("no webhook handler to register trigger %s with", trigger.ID)
		}
		return tm.webhookHandler.RegisterWebhook(ctx, trigger)

	case TriggerTypeSIEM:
		if tm.siemIntegration == nil {
			return fmt.Errorf("no SIEM integration to register trigger %s with", trigger.ID)
		}
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
			"trigger_id", logging.SanitizeLogValue(triggerID),
			"error", logging.SanitizeLogValue(err.Error()))
		return fmt.Errorf("failed to update trigger status: %w", err)
	}

	// Handle scheduler registration/unregistration for schedule triggers
	if trigger.Type == TriggerTypeSchedule {
		if status == TriggerStatusActive && oldStatus != TriggerStatusActive {
			// Register with scheduler when activating
			if err := tm.registerTriggerWithHandler(ctx, trigger); err != nil {
				logger.WarnCtx(ctx, "Failed to register trigger with scheduler during activation",
					"trigger_id", logging.SanitizeLogValue(triggerID),
					"error", logging.SanitizeLogValue(err.Error()))
				// Don't fail the status update for this
			}
		} else if status == TriggerStatusInactive && oldStatus == TriggerStatusActive {
			// Unregister from scheduler when deactivating
			if err := tm.unregisterTriggerFromHandler(ctx, trigger); err != nil {
				logger.WarnCtx(ctx, "Failed to unregister trigger from scheduler during deactivation",
					"trigger_id", logging.SanitizeLogValue(triggerID),
					"error", logging.SanitizeLogValue(err.Error()))
				// Don't fail the status update for this
			}
		}
	}

	logger.InfoCtx(ctx, "Trigger status updated",
		"trigger_id", logging.SanitizeLogValue(triggerID),
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
	if tm.triggerStore == nil {
		return nil
	}

	tenantID := extractTenantFromContext(ctx)
	records, err := tm.triggerStore.ListTriggers(ctx, business.TriggerStoreFilter{TenantID: tenantID})
	if err != nil {
		return fmt.Errorf("failed to list triggers from storage: %w", err)
	}

	for _, record := range records {
		trigger, restoreErr := tm.restoreTriggerFromRecord(ctx, record)
		if restoreErr != nil {
			// Degraded load: skip trigger whose creds cannot be recovered; warn already emitted inside.
			continue
		}
		// A restored trigger must fire, not just be listed: re-register every
		// active trigger with its scheduler / webhook / SIEM handler (Issue
		// #4641). One that cannot be registered is marked errored rather than
		// shown as active while nothing would ever run it.
		if trigger.Status == TriggerStatusActive {
			if regErr := tm.registerTriggerWithHandler(ctx, trigger); regErr != nil {
				tm.logger.WarnCtx(ctx, "failed to register restored trigger",
					"trigger_id", logging.SanitizeLogValue(record.ID), "error", logging.SanitizeLogValue(regErr.Error()))
				trigger.Status = TriggerStatusError
			}
		}
		tm.triggers[record.ID] = trigger
	}

	return nil
}

func (tm *TriggerManagerImpl) saveTriggerToStorage(ctx context.Context, trigger *Trigger) error {
	if tm.triggerStore == nil {
		return nil
	}

	record := &business.TriggerRecord{
		ID:           trigger.ID,
		TenantID:     trigger.TenantID,
		Name:         trigger.Name,
		Type:         string(trigger.Type),
		Status:       string(trigger.Status),
		WorkflowName: trigger.WorkflowName,
		CreatedAt:    trigger.CreatedAt,
		UpdatedAt:    trigger.UpdatedAt,
	}

	if trigger.Webhook != nil {
		record.WebhookPath = trigger.Webhook.Path
		record.WebhookMethod = trigger.Webhook.Method

		if trigger.Webhook.Authentication != nil {
			auth := trigger.Webhook.Authentication

			if auth.BearerToken != "" {
				if tm.secretStore == nil {
					return fmt.Errorf("secret store required to persist trigger credentials")
				}
				refKey := triggerCredentialRef(trigger.ID, "bearer")
				if err := tm.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
					Key:      refKey,
					Value:    auth.BearerToken,
					TenantID: trigger.TenantID,
				}); err != nil {
					return fmt.Errorf("failed to store bearer token: %w", err)
				}
				record.BearerTokenRef = refKey
			}

			if auth.Secret != "" {
				if tm.secretStore == nil {
					return fmt.Errorf("secret store required to persist trigger credentials")
				}
				refKey := triggerCredentialRef(trigger.ID, "hmac-secret")
				if err := tm.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
					Key:      refKey,
					Value:    auth.Secret,
					TenantID: trigger.TenantID,
				}); err != nil {
					return fmt.Errorf("failed to store hmac secret: %w", err)
				}
				record.HMACSecretRef = refKey
			}

			if auth.APIKey != "" {
				if tm.secretStore == nil {
					return fmt.Errorf("secret store required to persist trigger credentials")
				}
				refKey := triggerCredentialRef(trigger.ID, "api-key")
				if err := tm.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
					Key:      refKey,
					Value:    auth.APIKey,
					TenantID: trigger.TenantID,
				}); err != nil {
					return fmt.Errorf("failed to store api key: %w", err)
				}
				record.APIKeyRef = refKey
			}

			if auth.BasicAuth != nil {
				if auth.BasicAuth.Username != "" {
					if tm.secretStore == nil {
						return fmt.Errorf("secret store required to persist trigger credentials")
					}
					refKey := triggerCredentialRef(trigger.ID, "basic-user")
					if err := tm.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
						Key:      refKey,
						Value:    auth.BasicAuth.Username,
						TenantID: trigger.TenantID,
					}); err != nil {
						return fmt.Errorf("failed to store basic username: %w", err)
					}
					record.BasicUsernameRef = refKey
				}

				if auth.BasicAuth.Password != "" {
					if tm.secretStore == nil {
						return fmt.Errorf("secret store required to persist trigger credentials")
					}
					refKey := triggerCredentialRef(trigger.ID, "basic-pass")
					if err := tm.secretStore.StoreSecret(ctx, &secretsif.SecretRequest{
						Key:      refKey,
						Value:    auth.BasicAuth.Password,
						TenantID: trigger.TenantID,
					}); err != nil {
						return fmt.Errorf("failed to store basic password: %w", err)
					}
					record.BasicPasswordRef = refKey
				}
			}
		}

	}

	configBytes, err := marshalTriggerConfig(trigger)
	if err != nil {
		return err
	}
	record.ConfigPayload = configBytes

	return tm.triggerStore.StoreTrigger(ctx, record)
}

func (tm *TriggerManagerImpl) deleteTriggerFromStorage(ctx context.Context, triggerID string) error {
	if tm.triggerStore == nil {
		return nil
	}

	// Retrieve the record first so we know which secret refs to clean up.
	record, err := tm.triggerStore.GetTrigger(ctx, triggerID)
	if err != nil {
		if errors.Is(err, business.ErrTriggerNotFound) {
			// Already gone — treat as success (trigger may never have been persisted).
			return nil
		}
		return fmt.Errorf("failed to fetch trigger record for deletion: %w", err)
	}

	if err := tm.triggerStore.DeleteTrigger(ctx, triggerID); err != nil && !errors.Is(err, business.ErrTriggerNotFound) {
		return fmt.Errorf("failed to delete trigger from store: %w", err)
	}

	// Clean up secret refs; partial failure is non-critical (trigger record already deleted).
	if tm.secretStore != nil {
		for _, refKey := range []string{
			record.BearerTokenRef,
			record.HMACSecretRef,
			record.APIKeyRef,
			record.BasicUsernameRef,
			record.BasicPasswordRef,
		} {
			if refKey == "" {
				continue
			}
			if delErr := tm.secretStore.DeleteSecret(ctx, triggerSecretKey(record.TenantID, refKey)); delErr != nil {
				tm.logger.Warn("failed to clean up secret ref", "ref", logging.SanitizeLogValue(refKey), "error", logging.SanitizeLogValue(delErr.Error()))
			}
		}
	}

	return nil
}

// triggerConfigPayloadVersion marks a ConfigPayload holding the whole trigger
// configuration (Issue #4641). Payloads without it hold only a webhook config —
// the format written before schedule and SIEM configuration were persisted.
const triggerConfigPayloadVersion = 2

type triggerConfigPayload struct {
	Version int      `json:"v"`
	Trigger *Trigger `json:"trigger"`
}

// marshalTriggerConfig serializes trigger's configuration for every trigger
// type, with webhook credentials zeroed — they live in the secret store, and the
// record holds only references to them.
func marshalTriggerConfig(trigger *Trigger) ([]byte, error) {
	clone := *trigger
	if clone.Webhook != nil {
		webhook := *clone.Webhook
		if webhook.Authentication != nil {
			// Keep the non-secret authentication settings (type, header names) —
			// without the type a restored webhook rejects every request — and
			// clear every credential value.
			auth := *webhook.Authentication
			auth.Secret = ""
			auth.APIKey = ""
			auth.BearerToken = ""
			auth.BasicAuth = nil
			webhook.Authentication = &auth
		}
		clone.Webhook = &webhook
	}
	data, err := json.Marshal(triggerConfigPayload{Version: triggerConfigPayloadVersion, Trigger: &clone})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal trigger config: %w", err)
	}
	return data, nil
}

// applyTriggerConfig restores trigger's configuration from payload and returns
// its webhook config (nil when it has none) for credential restoration.
// Identity, status and timestamps come from the record columns, never the payload.
func applyTriggerConfig(trigger *Trigger, payload []byte) (*WebhookConfig, error) {
	var envelope triggerConfigPayload
	if err := json.Unmarshal(payload, &envelope); err == nil && envelope.Version == triggerConfigPayloadVersion && envelope.Trigger != nil {
		stored := envelope.Trigger
		trigger.Description = stored.Description
		trigger.Variables = stored.Variables
		trigger.Schedule = stored.Schedule
		trigger.SIEM = stored.SIEM
		trigger.Timeout = stored.Timeout
		trigger.Concurrency = stored.Concurrency
		trigger.Conditions = stored.Conditions
		return stored.Webhook, nil
	}
	var webhook WebhookConfig
	if err := json.Unmarshal(payload, &webhook); err != nil {
		return nil, err
	}
	return &webhook, nil
}

// restoreTriggerFromRecord reconstructs a Trigger from a stored TriggerRecord, recovering
// credential values from the secretStore. Returns an error (and emits a WARN log) for any
// ref that cannot be resolved; callers should skip the trigger on error (degraded load).
func (tm *TriggerManagerImpl) restoreTriggerFromRecord(ctx context.Context, record *business.TriggerRecord) (*Trigger, error) {
	trigger := &Trigger{
		ID:           record.ID,
		TenantID:     record.TenantID,
		Name:         record.Name,
		Type:         TriggerType(record.Type),
		Status:       TriggerStatus(record.Status),
		WorkflowName: record.WorkflowName,
		CreatedAt:    record.CreatedAt,
		UpdatedAt:    record.UpdatedAt,
	}

	if len(record.ConfigPayload) == 0 {
		return trigger, nil
	}

	webhookConfig, err := applyTriggerConfig(trigger, record.ConfigPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal config payload for trigger %s: %w", record.ID, err)
	}

	hasRefs := record.BearerTokenRef != "" || record.HMACSecretRef != "" || record.APIKeyRef != "" ||
		record.BasicUsernameRef != "" || record.BasicPasswordRef != ""
	if hasRefs && tm.secretStore == nil {
		return nil, fmt.Errorf("trigger %s has credential refs but no secret store is configured", record.ID)
	}

	// Start from the persisted non-secret authentication settings and add the
	// credential values recovered from the secret store.
	auth := &WebhookAuth{}
	if webhookConfig != nil && webhookConfig.Authentication != nil {
		stored := *webhookConfig.Authentication
		auth = &stored
	}
	hasAuth := false

	if record.BearerTokenRef != "" {
		secret, err := tm.secretStore.GetSecret(ctx, triggerSecretKey(record.TenantID, record.BearerTokenRef))
		if err != nil {
			tm.logger.WarnCtx(ctx, "failed to restore trigger credential",
				"trigger_id", logging.SanitizeLogValue(record.ID), "ref", logging.SanitizeLogValue(record.BearerTokenRef), "error", logging.SanitizeLogValue(err.Error()))
			return nil, fmt.Errorf("failed to get bearer token for trigger %s: %w", record.ID, err)
		}
		auth.BearerToken = secret.Value
		hasAuth = true
	}

	if record.HMACSecretRef != "" {
		secret, err := tm.secretStore.GetSecret(ctx, triggerSecretKey(record.TenantID, record.HMACSecretRef))
		if err != nil {
			tm.logger.WarnCtx(ctx, "failed to restore trigger credential",
				"trigger_id", logging.SanitizeLogValue(record.ID), "ref", logging.SanitizeLogValue(record.HMACSecretRef), "error", logging.SanitizeLogValue(err.Error()))
			return nil, fmt.Errorf("failed to get hmac secret for trigger %s: %w", record.ID, err)
		}
		auth.Secret = secret.Value
		hasAuth = true
	}

	if record.APIKeyRef != "" {
		secret, err := tm.secretStore.GetSecret(ctx, triggerSecretKey(record.TenantID, record.APIKeyRef))
		if err != nil {
			tm.logger.WarnCtx(ctx, "failed to restore trigger credential",
				"trigger_id", logging.SanitizeLogValue(record.ID), "ref", logging.SanitizeLogValue(record.APIKeyRef), "error", logging.SanitizeLogValue(err.Error()))
			return nil, fmt.Errorf("failed to get api key for trigger %s: %w", record.ID, err)
		}
		auth.APIKey = secret.Value
		hasAuth = true
	}

	if record.BasicUsernameRef != "" || record.BasicPasswordRef != "" {
		auth.BasicAuth = &BasicAuth{}

		if record.BasicUsernameRef != "" {
			secret, err := tm.secretStore.GetSecret(ctx, triggerSecretKey(record.TenantID, record.BasicUsernameRef))
			if err != nil {
				tm.logger.WarnCtx(ctx, "failed to restore trigger credential",
					"trigger_id", logging.SanitizeLogValue(record.ID), "ref", logging.SanitizeLogValue(record.BasicUsernameRef), "error", logging.SanitizeLogValue(err.Error()))
				return nil, fmt.Errorf("failed to get basic username for trigger %s: %w", record.ID, err)
			}
			auth.BasicAuth.Username = secret.Value
			hasAuth = true
		}

		if record.BasicPasswordRef != "" {
			secret, err := tm.secretStore.GetSecret(ctx, triggerSecretKey(record.TenantID, record.BasicPasswordRef))
			if err != nil {
				tm.logger.WarnCtx(ctx, "failed to restore trigger credential",
					"trigger_id", logging.SanitizeLogValue(record.ID), "ref", logging.SanitizeLogValue(record.BasicPasswordRef), "error", logging.SanitizeLogValue(err.Error()))
				return nil, fmt.Errorf("failed to get basic password for trigger %s: %w", record.ID, err)
			}
			auth.BasicAuth.Password = secret.Value
			hasAuth = true
		}
	}

	if hasAuth {
		if webhookConfig == nil {
			return nil, fmt.Errorf("trigger %s has webhook credentials but no webhook config", record.ID)
		}
		webhookConfig.Authentication = auth
	}
	trigger.Webhook = webhookConfig

	return trigger, nil
}
