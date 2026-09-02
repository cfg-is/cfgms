// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
)

// triggerHarness wires a TriggerManagerImpl to the real trigger-system components:
// TestStorageProvider (a real StorageProvider backed by an in-memory TriggerStore),
// the production CronScheduler, HTTPWebhookHandler and SIEMProcessor, the real
// TestWorkflowTrigger and the in-memory SecretStore. Tests assert on the observable
// state of those components rather than on recorded interactions.
type triggerHarness struct {
	manager         *TriggerManagerImpl
	storage         *TestStorageProvider
	scheduler       *CronScheduler
	webhookHandler  *HTTPWebhookHandler
	siemProcessor   *SIEMProcessor
	workflowTrigger *TestWorkflowTrigger
	triggerStore    *inMemoryTriggerStore
	secretStore     *inMemorySecretStore
}

// newTriggerHarness builds a fully wired trigger manager from real components.
func newTriggerHarness(t *testing.T) *triggerHarness {
	t.Helper()

	storage := NewTestStorageProvider()
	workflowTrigger := NewTestWorkflowTrigger()
	secretStore := newInMemorySecretStore()

	// Components need the manager and the manager needs the components, so the
	// manager is constructed first and the components are attached afterwards
	// (same wiring order the controller factory uses).
	manager := NewTriggerManager(storage, nil, nil, nil, workflowTrigger, secretStore)

	scheduler := NewCronScheduler(manager, workflowTrigger)
	// These tests assert scheduling state, not fired executions: a long tick keeps
	// the scheduler loop from executing triggers concurrently with the assertions.
	scheduler.SetTickerInterval(time.Hour)
	webhookHandler := NewHTTPWebhookHandler(manager, workflowTrigger, "127.0.0.1", 0)
	siemProcessor := NewSIEMProcessor(manager, workflowTrigger)

	manager.scheduler = scheduler
	manager.webhookHandler = webhookHandler
	manager.siemIntegration = siemProcessor

	triggerStore, ok := manager.triggerStore.(*inMemoryTriggerStore)
	require.True(t, ok, "NewTriggerManager must build a TriggerStore from the storage provider")

	t.Cleanup(func() {
		manager.mutex.RLock()
		running := manager.running
		manager.mutex.RUnlock()
		if running {
			require.NoError(t, manager.Stop(context.Background()))
		}
	})

	return &triggerHarness{
		manager:         manager,
		storage:         storage,
		scheduler:       scheduler,
		webhookHandler:  webhookHandler,
		siemProcessor:   siemProcessor,
		workflowTrigger: workflowTrigger,
		triggerStore:    triggerStore,
		secretStore:     secretStore,
	}
}

func TestTriggerManagerImpl_NewTriggerManager(t *testing.T) {
	h := newTriggerHarness(t)

	require.NotNil(t, h.manager)
	assert.Same(t, h.storage, h.manager.storage)
	assert.Same(t, h.scheduler, h.manager.scheduler)
	assert.Same(t, h.webhookHandler, h.manager.webhookHandler)
	assert.Same(t, h.siemProcessor, h.manager.siemIntegration)
	assert.Same(t, h.workflowTrigger, h.manager.workflowTrigger)
	assert.Same(t, h.secretStore, h.manager.secretStore)
	assert.NotNil(t, h.manager.triggers)
	assert.NotNil(t, h.manager.executions)
	assert.False(t, h.manager.running)

	// The manager must derive its TriggerStore from the storage provider.
	assert.NotNil(t, h.manager.triggerStore)
}

func TestTriggerManagerImpl_StartStop(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := context.Background()

	require.NoError(t, h.manager.Start(ctx))
	assert.True(t, h.manager.running)

	// Each real component must now be running: starting one directly reports it.
	assert.Error(t, h.scheduler.Start(ctx), "scheduler must already be running")
	assert.Error(t, h.webhookHandler.Start(ctx), "webhook handler must already be running")
	assert.Error(t, h.siemProcessor.Start(ctx), "SIEM processor must already be running")

	// The running SIEM processor accepts log entries; a stopped one rejects them.
	require.NoError(t, h.siemProcessor.ProcessLogEntry(ctx, map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     "info",
		"message":   "startup probe",
		"source":    "manager-test",
	}))

	// Double start (should fail)
	err := h.manager.Start(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trigger manager is already running")

	require.NoError(t, h.manager.Stop(ctx))
	assert.False(t, h.manager.running)

	// Each real component must now be stopped.
	assert.Error(t, h.scheduler.Stop(ctx), "scheduler must already be stopped")
	assert.Error(t, h.webhookHandler.Stop(ctx), "webhook handler must already be stopped")
	assert.Error(t, h.siemProcessor.Stop(ctx), "SIEM processor must already be stopped")
	assert.Error(t, h.siemProcessor.ProcessLogEntry(ctx, map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"level":     "info",
		"message":   "shutdown probe",
		"source":    "manager-test",
	}), "stopped SIEM processor must reject log entries")

	// Double stop (should fail)
	err = h.manager.Stop(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trigger manager is not running")
}

func TestTriggerManagerImpl_CreateTrigger(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := context.Background()

	tests := []struct {
		name        string
		trigger     *Trigger
		expectError bool
		errorMsg    string
		verify      func(t *testing.T)
	}{
		{
			name: "create schedule trigger",
			trigger: &Trigger{
				ID:           "schedule-1",
				Name:         "Daily Backup",
				Type:         TriggerTypeSchedule,
				Status:       TriggerStatusActive,
				TenantID:     "tenant-123",
				WorkflowName: "backup-workflow",
				Schedule: &ScheduleConfig{
					CronExpression: "0 2 * * *",
					Enabled:        true,
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			expectError: false,
			verify: func(t *testing.T) {
				scheduled := h.scheduler.GetScheduledTriggers()
				require.Contains(t, scheduled, "schedule-1", "schedule trigger must be registered with the scheduler")
				assert.Equal(t, "backup-workflow", scheduled["schedule-1"].WorkflowName)

				next, err := h.scheduler.GetNextExecutionTime("schedule-1")
				require.NoError(t, err)
				assert.False(t, next.IsZero(), "scheduler must compute a next execution time")
			},
		},
		{
			name: "create webhook trigger",
			trigger: &Trigger{
				ID:           "webhook-1",
				Name:         "API Integration",
				Type:         TriggerTypeWebhook,
				Status:       TriggerStatusActive,
				TenantID:     "tenant-123",
				WorkflowName: "api-workflow",
				Webhook: &WebhookConfig{
					Path:    "/webhook/api",
					Method:  []string{"POST"},
					Enabled: true,
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			expectError: false,
			verify: func(t *testing.T) {
				registered := h.webhookHandler.GetRegisteredWebhooks()
				require.Contains(t, registered, "webhook-1", "webhook trigger must be registered with the webhook handler")
				assert.Equal(t, "/webhook/api", registered["webhook-1"].Webhook.Path)
			},
		},
		{
			name: "create SIEM trigger",
			trigger: &Trigger{
				ID:           "siem-1",
				Name:         "Security Alert",
				Type:         TriggerTypeSIEM,
				Status:       TriggerStatusActive,
				TenantID:     "tenant-123",
				WorkflowName: "security-workflow",
				SIEM: &SIEMConfig{
					EventTypes: []string{"auth_failure"},
					WindowSize: 5 * time.Minute,
					Enabled:    true,
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			},
			expectError: false,
			verify: func(t *testing.T) {
				registered := h.siemProcessor.GetRegisteredSIEMTriggers()
				require.Contains(t, registered, "siem-1", "SIEM trigger must be registered with the SIEM processor")
				assert.Equal(t, []string{"auth_failure"}, registered["siem-1"].SIEM.EventTypes)
			},
		},
		{
			name: "trigger with empty ID",
			trigger: &Trigger{
				ID:           "",
				Name:         "Test Trigger",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			expectError: true,
			errorMsg:    "schedule configuration is required for schedule triggers",
		},
		{
			name: "trigger with empty workflow name",
			trigger: &Trigger{
				ID:           "test-1",
				Name:         "Test Trigger",
				Type:         TriggerTypeSchedule,
				WorkflowName: "",
			},
			expectError: true,
			errorMsg:    "workflow name is required",
		},
		{
			name: "invalid trigger type",
			trigger: &Trigger{
				ID:           "invalid-1",
				Name:         "Invalid Trigger",
				Type:         TriggerType("invalid"),
				WorkflowName: "test-workflow",
			},
			expectError: true,
			errorMsg:    "unsupported trigger type",
		},
		{
			name: "trigger persisted to trigger store",
			trigger: &Trigger{
				ID:           "storage-test-1",
				Name:         "Storage Test",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
				Schedule: &ScheduleConfig{
					CronExpression: "0 2 * * *",
					Enabled:        true,
				},
			},
			expectError: false,
			verify: func(t *testing.T) {
				record, err := h.triggerStore.GetTrigger(ctx, "storage-test-1")
				require.NoError(t, err, "trigger must be persisted to the trigger store")
				assert.Equal(t, "Storage Test", record.Name)
				assert.Equal(t, string(TriggerTypeSchedule), record.Type)
				assert.Equal(t, "test-workflow", record.WorkflowName)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.manager.CreateTrigger(ctx, tt.trigger)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			require.NoError(t, err)
			assert.Contains(t, h.manager.triggers, tt.trigger.ID)
			assert.Equal(t, tt.trigger, h.manager.triggers[tt.trigger.ID])
			if tt.verify != nil {
				tt.verify(t)
			}
		})
	}
}

func TestTriggerManagerImpl_UpdateTrigger(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := logging.WithTenant(context.Background(), "tenant-123")

	existingTrigger := &Trigger{
		ID:           "schedule-1",
		Name:         "Daily Backup",
		Type:         TriggerTypeSchedule,
		Status:       TriggerStatusActive,
		TenantID:     "tenant-123",
		WorkflowName: "backup-workflow",
		Schedule: &ScheduleConfig{
			CronExpression: "0 2 * * *",
			Enabled:        true,
		},
	}
	require.NoError(t, h.manager.CreateTrigger(ctx, existingTrigger))

	tests := []struct {
		name        string
		trigger     *Trigger
		expectError bool
		errorMsg    string
		verify      func(t *testing.T)
	}{
		{
			name: "update existing trigger",
			trigger: &Trigger{
				ID:           "schedule-1",
				Name:         "Daily Backup Updated",
				Type:         TriggerTypeSchedule,
				Status:       TriggerStatusActive,
				TenantID:     "tenant-123",
				WorkflowName: "backup-workflow-v2",
				Schedule: &ScheduleConfig{
					CronExpression: "0 3 * * *", // Changed time
					Enabled:        true,
				},
			},
			expectError: false,
			verify: func(t *testing.T) {
				// The scheduler must hold the re-registered trigger with the new cron.
				scheduled := h.scheduler.GetScheduledTriggers()
				require.Contains(t, scheduled, "schedule-1")
				assert.Equal(t, "0 3 * * *", scheduled["schedule-1"].Schedule.CronExpression)
				assert.Equal(t, "backup-workflow-v2", scheduled["schedule-1"].WorkflowName)

				record, err := h.triggerStore.GetTrigger(ctx, "schedule-1")
				require.NoError(t, err)
				assert.Equal(t, "Daily Backup Updated", record.Name)
				assert.Equal(t, "backup-workflow-v2", record.WorkflowName)
			},
		},
		{
			name: "update non-existent trigger",
			trigger: &Trigger{
				ID:           "non-existent",
				Name:         "Non-existent",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			expectError: true,
			errorMsg:    "trigger non-existent not found",
		},
		{
			name: "update with validation error",
			trigger: &Trigger{
				ID:           "schedule-1",
				Name:         "Invalid Update",
				Type:         TriggerTypeSchedule,
				WorkflowName: "invalid-workflow",
				Schedule: &ScheduleConfig{
					CronExpression: "", // Empty cron expression will fail validation
					Enabled:        true,
				},
			},
			expectError: true,
			errorMsg:    "cron expression is required",
			verify: func(t *testing.T) {
				// Rejected update must leave the previously stored trigger intact.
				assert.Equal(t, "Daily Backup Updated", h.manager.triggers["schedule-1"].Name)
				scheduled := h.scheduler.GetScheduledTriggers()
				require.Contains(t, scheduled, "schedule-1")
				assert.Equal(t, "0 3 * * *", scheduled["schedule-1"].Schedule.CronExpression)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.manager.UpdateTrigger(ctx, tt.trigger)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				updatedTrigger := h.manager.triggers[tt.trigger.ID]
				assert.Equal(t, tt.trigger.Name, updatedTrigger.Name)
				assert.Equal(t, tt.trigger.WorkflowName, updatedTrigger.WorkflowName)
			}

			if tt.verify != nil {
				tt.verify(t)
			}
		})
	}
}

func TestTriggerManagerImpl_DeleteTrigger(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := logging.WithTenant(context.Background(), "tenant-123")

	scheduleTrigger := &Trigger{
		ID:           "schedule-1",
		Name:         "Schedule Delete",
		Type:         TriggerTypeSchedule,
		TenantID:     "tenant-123",
		WorkflowName: "schedule-workflow",
		Schedule: &ScheduleConfig{
			CronExpression: "0 2 * * *",
			Enabled:        true,
		},
	}
	webhookTrigger := &Trigger{
		ID:           "webhook-1",
		Name:         "Webhook Delete",
		Type:         TriggerTypeWebhook,
		TenantID:     "tenant-123",
		WorkflowName: "webhook-workflow",
		Webhook: &WebhookConfig{
			Path:    "/webhook/test",
			Enabled: true,
		},
	}
	siemTrigger := &Trigger{
		ID:           "siem-1",
		Name:         "SIEM Delete",
		Type:         TriggerTypeSIEM,
		TenantID:     "tenant-123",
		WorkflowName: "siem-workflow",
		SIEM: &SIEMConfig{
			EventTypes: []string{"error"},
			WindowSize: 5 * time.Minute,
			Enabled:    true,
		},
	}

	tests := []struct {
		name        string
		triggerID   string
		trigger     *Trigger
		expectError bool
		errorMsg    string
		verify      func(t *testing.T)
	}{
		{
			name:      "delete schedule trigger",
			triggerID: "schedule-1",
			trigger:   scheduleTrigger,
			verify: func(t *testing.T) {
				assert.NotContains(t, h.scheduler.GetScheduledTriggers(), "schedule-1",
					"deleted schedule trigger must be unscheduled")
			},
		},
		{
			name:      "delete webhook trigger",
			triggerID: "webhook-1",
			trigger:   webhookTrigger,
			verify: func(t *testing.T) {
				assert.NotContains(t, h.webhookHandler.GetRegisteredWebhooks(), "webhook-1",
					"deleted webhook trigger must be unregistered")
			},
		},
		{
			name:      "delete SIEM trigger",
			triggerID: "siem-1",
			trigger:   siemTrigger,
			verify: func(t *testing.T) {
				assert.NotContains(t, h.siemProcessor.GetRegisteredSIEMTriggers(), "siem-1",
					"deleted SIEM trigger must be unregistered")
			},
		},
		{
			name:        "delete non-existent trigger",
			triggerID:   "non-existent",
			expectError: true,
			errorMsg:    "trigger non-existent not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.trigger != nil {
				require.NoError(t, h.manager.CreateTrigger(ctx, tt.trigger))
			}

			err := h.manager.DeleteTrigger(ctx, tt.triggerID)

			if tt.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				return
			}

			require.NoError(t, err)
			assert.NotContains(t, h.manager.triggers, tt.triggerID)

			_, storeErr := h.triggerStore.GetTrigger(ctx, tt.triggerID)
			assert.ErrorIs(t, storeErr, business.ErrTriggerNotFound,
				"deleted trigger must be removed from the trigger store")

			if tt.verify != nil {
				tt.verify(t)
			}
		})
	}
}

func TestTriggerManagerImpl_GetTrigger(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := context.Background()

	trigger := &Trigger{
		ID:           "test-1",
		Name:         "Test Trigger",
		Type:         TriggerTypeManual,
		WorkflowName: "test-workflow",
	}
	require.NoError(t, h.manager.CreateTrigger(ctx, trigger))

	tests := []struct {
		name        string
		triggerID   string
		expected    *Trigger
		expectError bool
		errorMsg    string
	}{
		{
			name:        "get existing trigger",
			triggerID:   "test-1",
			expected:    trigger,
			expectError: false,
		},
		{
			name:        "get non-existent trigger",
			triggerID:   "non-existent",
			expected:    nil,
			expectError: true,
			errorMsg:    "trigger non-existent not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := h.manager.GetTrigger(ctx, tt.triggerID)

			if tt.expectError {
				require.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTriggerManagerImpl_ListTriggers(t *testing.T) {
	h := newTriggerHarness(t)

	// Triggers are created through the manager for each tenant so the filter runs
	// against state produced by the real create path.
	triggers := []*Trigger{
		{
			ID:           "schedule-1",
			Name:         "Schedule Trigger",
			Type:         TriggerTypeManual,
			Status:       TriggerStatusActive,
			TenantID:     "tenant-123",
			WorkflowName: "schedule-workflow",
			Tags:         []string{"backup", "daily"},
		},
		{
			ID:           "webhook-1",
			Name:         "Webhook Trigger",
			Type:         TriggerTypeWebhook,
			Status:       TriggerStatusActive,
			TenantID:     "tenant-123",
			WorkflowName: "webhook-workflow",
			Tags:         []string{"api", "integration"},
			Webhook: &WebhookConfig{
				Path:    "/webhook/list",
				Enabled: true,
			},
		},
		{
			ID:           "siem-1",
			Name:         "SIEM Trigger",
			Type:         TriggerTypeSIEM,
			Status:       TriggerStatusInactive,
			TenantID:     "tenant-456",
			WorkflowName: "siem-workflow",
			Tags:         []string{"security", "monitoring"},
			SIEM: &SIEMConfig{
				EventTypes: []string{"error"},
				WindowSize: time.Minute,
				Enabled:    true,
			},
		},
	}

	for _, trigger := range triggers {
		tenantCtx := logging.WithTenant(context.Background(), trigger.TenantID)
		require.NoError(t, h.manager.CreateTrigger(tenantCtx, trigger))
	}

	// Use background context (no tenant = admin access to see all triggers)
	ctx := context.Background()

	tests := []struct {
		name        string
		filter      *TriggerFilter
		expectedLen int
		expectedIDs []string
		expectError bool
	}{
		{
			name:        "list all triggers",
			filter:      &TriggerFilter{},
			expectedLen: 3,
			expectedIDs: []string{"schedule-1", "webhook-1", "siem-1"},
		},
		{
			name: "filter by tenant",
			filter: &TriggerFilter{
				TenantID: "tenant-123",
			},
			expectedLen: 2,
			expectedIDs: []string{"schedule-1", "webhook-1"},
		},
		{
			name: "filter by type",
			filter: &TriggerFilter{
				Type: TriggerTypeWebhook,
			},
			expectedLen: 1,
			expectedIDs: []string{"webhook-1"},
		},
		{
			name: "filter by status",
			filter: &TriggerFilter{
				Status: TriggerStatusActive,
			},
			expectedLen: 2,
			expectedIDs: []string{"schedule-1", "webhook-1"},
		},
		{
			name: "filter by tags",
			filter: &TriggerFilter{
				Tags: []string{"security"},
			},
			expectedLen: 1,
			expectedIDs: []string{"siem-1"},
		},
		{
			name: "filter with limit",
			filter: &TriggerFilter{
				Limit: 2,
			},
			expectedLen: 2,
		},
		{
			name: "filter with no matches",
			filter: &TriggerFilter{
				TenantID: "non-existent-tenant",
			},
			expectedLen: 0,
			expectedIDs: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := h.manager.ListTriggers(ctx, tt.filter)

			if tt.expectError {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, result, tt.expectedLen)

			if tt.expectedIDs != nil {
				actualIDs := make([]string, len(result))
				for i, trigger := range result {
					actualIDs[i] = trigger.ID
				}
				assert.ElementsMatch(t, tt.expectedIDs, actualIDs)
			}
		})
	}
}

func TestTriggerManagerImpl_EnableDisableTrigger(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := context.Background()

	trigger := &Trigger{
		ID:           "test-1",
		Name:         "Enable Disable Trigger",
		Type:         TriggerTypeSchedule,
		Status:       TriggerStatusActive,
		WorkflowName: "test-workflow",
		Schedule: &ScheduleConfig{
			CronExpression: "0 2 * * *",
			Enabled:        true,
		},
	}
	require.NoError(t, h.manager.CreateTrigger(ctx, trigger))
	require.Contains(t, h.scheduler.GetScheduledTriggers(), "test-1")

	t.Run("disable trigger", func(t *testing.T) {
		require.NoError(t, h.manager.DisableTrigger(ctx, "test-1"))
		assert.Equal(t, TriggerStatusInactive, trigger.Status)
		assert.NotContains(t, h.scheduler.GetScheduledTriggers(), "test-1",
			"disabled trigger must be removed from the scheduler")

		record, err := h.triggerStore.GetTrigger(ctx, "test-1")
		require.NoError(t, err)
		assert.Equal(t, string(TriggerStatusInactive), record.Status)
	})

	t.Run("enable trigger", func(t *testing.T) {
		require.NoError(t, h.manager.EnableTrigger(ctx, "test-1"))
		assert.Equal(t, TriggerStatusActive, trigger.Status)
		assert.Contains(t, h.scheduler.GetScheduledTriggers(), "test-1",
			"enabled trigger must be re-registered with the scheduler")

		record, err := h.triggerStore.GetTrigger(ctx, "test-1")
		require.NoError(t, err)
		assert.Equal(t, string(TriggerStatusActive), record.Status)
	})

	t.Run("enable non-existent trigger", func(t *testing.T) {
		err := h.manager.EnableTrigger(ctx, "non-existent")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trigger non-existent not found")
	})
}

func TestTriggerManagerImpl_ExecuteTrigger(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := context.Background()

	trigger := &Trigger{
		ID:           "test-1",
		Name:         "Manual Trigger",
		Type:         TriggerTypeManual,
		Status:       TriggerStatusActive,
		WorkflowName: "test-workflow",
	}
	require.NoError(t, h.manager.CreateTrigger(ctx, trigger))

	triggerData := map[string]interface{}{
		"manual_execution": true,
		"user_id":          "user-123",
	}

	execution, err := h.manager.ExecuteTrigger(ctx, "test-1", triggerData)

	require.NoError(t, err)
	require.NotNil(t, execution)
	assert.Equal(t, "test-1", execution.TriggerID)
	assert.Equal(t, TriggerExecutionStatusSuccess, execution.Status)

	// The real workflow trigger recorded exactly one execution, and the manager
	// linked the trigger execution to that workflow execution ID.
	workflowExecutions := h.workflowTrigger.GetExecutions()
	require.Len(t, workflowExecutions, 1)
	assert.Equal(t, "test-workflow", workflowExecutions[0].WorkflowName)
	assert.Equal(t, workflowExecutions[0].ID, execution.WorkflowExecutionID)

	// Verify execution is stored
	assert.Contains(t, h.manager.executions, execution.ID)
}

func TestTriggerManagerImpl_ExecuteTriggerFailure(t *testing.T) {
	h := newTriggerHarness(t)
	ctx := context.Background()

	trigger := &Trigger{
		ID:           "test-fail",
		Name:         "Failing Manual Trigger",
		Type:         TriggerTypeManual,
		Status:       TriggerStatusActive,
		WorkflowName: "failing-workflow",
	}
	require.NoError(t, h.manager.CreateTrigger(ctx, trigger))

	// The real workflow trigger fails the next execution.
	h.workflowTrigger.SetFailNext(true)

	execution, err := h.manager.ExecuteTrigger(ctx, "test-fail", nil)

	require.NoError(t, err, "a failing workflow must not fail the trigger execution call")
	require.NotNil(t, execution)
	assert.Equal(t, TriggerExecutionStatusFailed, execution.Status)
	assert.NotEmpty(t, execution.Error)
	assert.Empty(t, execution.WorkflowExecutionID)
}
func TestTriggerManagerImpl_NilStoragePersistence(t *testing.T) {
	// When storage is nil (e.g. composite OSS manager where GetProvider returns nil),
	// save and delete should be no-ops, not panics.
	manager := &TriggerManagerImpl{
		storage:    nil,
		triggers:   make(map[string]*Trigger),
		executions: make(map[string]*TriggerExecution),
		logger:     logging.ForModule("workflow.trigger.manager.test"),
	}

	ctx := context.Background()
	trigger := &Trigger{ID: "t-nil-storage", Name: "nil-storage-trigger"}

	t.Run("saveTriggerToStorage returns nil when storage is nil", func(t *testing.T) {
		err := manager.saveTriggerToStorage(ctx, trigger)
		assert.NoError(t, err, "saveTriggerToStorage must not error when storage is nil")
	})

	t.Run("deleteTriggerFromStorage returns nil when storage is nil", func(t *testing.T) {
		err := manager.deleteTriggerFromStorage(ctx, trigger.ID)
		assert.NoError(t, err, "deleteTriggerFromStorage must not error when storage is nil")
	})
}

func TestTriggerManagerSaveRejectsCredentialsWithoutSecretStore(t *testing.T) {
	ts := newInMemoryTriggerStore()
	ctx := contextWithTenant("tenant-test")

	mgr := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: ts,
		secretStore:  nil,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}

	tests := []struct {
		name    string
		trigger *Trigger
	}{
		{
			name: "bearer token requires secret store",
			trigger: &Trigger{
				ID: "t-cred", TenantID: "tenant-test", Name: "n", Type: TriggerTypeWebhook,
				Status: TriggerStatusActive, WorkflowName: "wf",
				Webhook: &WebhookConfig{Path: "/x", Authentication: &WebhookAuth{BearerToken: "tok"}},
			},
		},
		{
			name: "hmac secret requires secret store",
			trigger: &Trigger{
				ID: "t-cred", TenantID: "tenant-test", Name: "n", Type: TriggerTypeWebhook,
				Status: TriggerStatusActive, WorkflowName: "wf",
				Webhook: &WebhookConfig{Path: "/x", Authentication: &WebhookAuth{Secret: "hmac"}},
			},
		},
		{
			name: "api key requires secret store",
			trigger: &Trigger{
				ID: "t-cred", TenantID: "tenant-test", Name: "n", Type: TriggerTypeWebhook,
				Status: TriggerStatusActive, WorkflowName: "wf",
				Webhook: &WebhookConfig{Path: "/x", Authentication: &WebhookAuth{APIKey: "key"}},
			},
		},
		{
			name: "basic username requires secret store",
			trigger: &Trigger{
				ID: "t-cred", TenantID: "tenant-test", Name: "n", Type: TriggerTypeWebhook,
				Status: TriggerStatusActive, WorkflowName: "wf",
				Webhook: &WebhookConfig{Path: "/x", Authentication: &WebhookAuth{BasicAuth: &BasicAuth{Username: "u"}}},
			},
		},
		{
			name: "basic password requires secret store",
			trigger: &Trigger{
				ID: "t-cred", TenantID: "tenant-test", Name: "n", Type: TriggerTypeWebhook,
				Status: TriggerStatusActive, WorkflowName: "wf",
				Webhook: &WebhookConfig{Path: "/x", Authentication: &WebhookAuth{BasicAuth: &BasicAuth{Password: "p"}}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.saveTriggerToStorage(ctx, tt.trigger)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "secret store required to persist trigger credentials")
		})
	}
}

// ---------------------------------------------------------------------------
// In-memory test helpers for persistence tests
// ---------------------------------------------------------------------------

// inMemoryTriggerStore is a thread-safe in-memory TriggerStore for testing.
type inMemoryTriggerStore struct {
	mu      sync.RWMutex
	records map[string]*business.TriggerRecord
}

func newInMemoryTriggerStore() *inMemoryTriggerStore {
	return &inMemoryTriggerStore{records: make(map[string]*business.TriggerRecord)}
}

func (s *inMemoryTriggerStore) StoreTrigger(_ context.Context, record *business.TriggerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.ID] = record
	return nil
}

func (s *inMemoryTriggerStore) GetTrigger(_ context.Context, id string) (*business.TriggerRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[id]
	if !ok {
		return nil, business.ErrTriggerNotFound
	}
	return r, nil
}

func (s *inMemoryTriggerStore) DeleteTrigger(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		return business.ErrTriggerNotFound
	}
	delete(s.records, id)
	return nil
}

func (s *inMemoryTriggerStore) ListTriggers(_ context.Context, filter business.TriggerStoreFilter) ([]*business.TriggerRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*business.TriggerRecord
	for _, r := range s.records {
		if filter.TenantID != "" && r.TenantID != filter.TenantID {
			continue
		}
		result = append(result, r)
	}
	return result, nil
}

func (s *inMemoryTriggerStore) Close() error { return nil }

// inMemorySecretStore is a thread-safe in-memory SecretStore for testing.
type inMemorySecretStore struct {
	mu      sync.RWMutex
	secrets map[string]string // key → plaintext value
}

func newInMemorySecretStore() *inMemorySecretStore {
	return &inMemorySecretStore{secrets: make(map[string]string)}
}

func (s *inMemorySecretStore) StoreSecret(_ context.Context, req *secretsif.SecretRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return nil
}

func (s *inMemorySecretStore) GetSecret(_ context.Context, key string) (*secretsif.Secret, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.secrets[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secretsif.ErrSecretNotFound, key)
	}
	return &secretsif.Secret{Key: key, Value: v}, nil
}

func (s *inMemorySecretStore) CompareAndSwapSecret(_ context.Context, _ string, _ int, req *secretsif.SecretRequest) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.secrets[req.Key] = req.Value
	return 1, true, nil
}

func (s *inMemorySecretStore) DeleteSecret(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.secrets[key]; !ok {
		return fmt.Errorf("%w: %s", secretsif.ErrSecretNotFound, key)
	}
	delete(s.secrets, key)
	return nil
}

func (s *inMemorySecretStore) ListSecrets(_ context.Context, _ *secretsif.SecretFilter) ([]*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *inMemorySecretStore) GetSecrets(_ context.Context, keys []string) (map[string]*secretsif.Secret, error) {
	result := make(map[string]*secretsif.Secret)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, k := range keys {
		if v, ok := s.secrets[k]; ok {
			result[k] = &secretsif.Secret{Key: k, Value: v}
		}
	}
	return result, nil
}
func (s *inMemorySecretStore) StoreSecrets(ctx context.Context, secrets map[string]*secretsif.SecretRequest) error {
	for _, req := range secrets {
		if err := s.StoreSecret(ctx, req); err != nil {
			return err
		}
	}
	return nil
}
func (s *inMemorySecretStore) GetSecretVersion(_ context.Context, _ string, _ int) (*secretsif.Secret, error) {
	return nil, errors.New("versioning not supported")
}
func (s *inMemorySecretStore) ListSecretVersions(_ context.Context, _ string) ([]*secretsif.SecretVersion, error) {
	return nil, nil
}
func (s *inMemorySecretStore) GetSecretMetadata(_ context.Context, _ string) (*secretsif.SecretMetadata, error) {
	return nil, nil
}
func (s *inMemorySecretStore) UpdateSecretMetadata(_ context.Context, _ string, _ map[string]string) error {
	return nil
}
func (s *inMemorySecretStore) RotateSecret(_ context.Context, _ string, _ string) error { return nil }
func (s *inMemorySecretStore) ExpireSecret(_ context.Context, _ string) error           { return nil }
func (s *inMemorySecretStore) HealthCheck(_ context.Context) error                      { return nil }
func (s *inMemorySecretStore) Close() error                                             { return nil }

// newManagerWithPersistence creates a TriggerManagerImpl wired to real in-memory
// TriggerStore and SecretStore. Used by persistence-focused tests.
func newManagerWithPersistence(tenantID string) (*TriggerManagerImpl, *inMemoryTriggerStore, *inMemorySecretStore) {
	ts := newInMemoryTriggerStore()
	ss := newInMemorySecretStore()
	mgr := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: ts,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}
	return mgr, ts, ss
}

// contextWithTenant returns a context carrying the given tenant ID via the trigger package key.
func contextWithTenant(tenantID string) context.Context {
	return context.WithValue(context.Background(), TenantIDContextKey, tenantID)
}

// ---------------------------------------------------------------------------
// Required persistence tests
// ---------------------------------------------------------------------------

func TestTriggerManagerSaveRedactsAllCredentials(t *testing.T) {
	mgr, ts, _ := newManagerWithPersistence("tenant-save")
	ctx := contextWithTenant("tenant-save")

	trigger := &Trigger{
		ID:           "t-redact",
		TenantID:     "tenant-save",
		Name:         "Redact Test",
		Type:         TriggerTypeWebhook,
		Status:       TriggerStatusActive,
		WorkflowName: "wf",
		Webhook: &WebhookConfig{
			Path: "/test",
			Authentication: &WebhookAuth{
				BearerToken: "secret-bearer",
				Secret:      "secret-hmac",
				APIKey:      "secret-apikey",
				BasicAuth: &BasicAuth{
					Username: "secret-user",
					Password: "secret-pass",
				},
			},
		},
	}

	require.NoError(t, mgr.saveTriggerToStorage(ctx, trigger))

	record, err := ts.GetTrigger(ctx, "t-redact")
	require.NoError(t, err)

	// Verify all five ref fields are populated.
	assert.NotEmpty(t, record.BearerTokenRef, "BearerTokenRef must be set")
	assert.NotEmpty(t, record.HMACSecretRef, "HMACSecretRef must be set")
	assert.NotEmpty(t, record.APIKeyRef, "APIKeyRef must be set")
	assert.NotEmpty(t, record.BasicUsernameRef, "BasicUsernameRef must be set")
	assert.NotEmpty(t, record.BasicPasswordRef, "BasicPasswordRef must be set")

	// Verify NO plaintext credential appears in ConfigPayload.
	for _, plaintext := range []string{"secret-bearer", "secret-hmac", "secret-apikey", "secret-user", "secret-pass"} {
		assert.NotContains(t, string(record.ConfigPayload), plaintext,
			"plaintext credential %q must not appear in ConfigPayload", plaintext)
	}

	// Verify the *Ref fields themselves do NOT hold the plaintext values.
	for _, refField := range []string{
		record.BearerTokenRef, record.HMACSecretRef, record.APIKeyRef,
		record.BasicUsernameRef, record.BasicPasswordRef,
	} {
		for _, plaintext := range []string{"secret-bearer", "secret-hmac", "secret-apikey", "secret-user", "secret-pass"} {
			assert.NotEqual(t, plaintext, refField,
				"ref field %q must not equal plaintext credential %q", refField, plaintext)
		}
	}
}

func TestTriggerManagerPersistenceRoundTrip(t *testing.T) {
	// Save a trigger with full credentials, then simulate manager restart
	// by creating a fresh manager pointing at the same stores.
	ts := newInMemoryTriggerStore()
	ss := newInMemorySecretStore()

	ctx := contextWithTenant("tenant-rt")

	save := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: ts,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}

	original := &Trigger{
		ID:           "t-rt",
		TenantID:     "tenant-rt",
		Name:         "Round Trip",
		Type:         TriggerTypeWebhook,
		Status:       TriggerStatusActive,
		WorkflowName: "wf-rt",
		CreatedAt:    time.Now().Truncate(time.Second),
		UpdatedAt:    time.Now().Truncate(time.Second),
		Webhook: &WebhookConfig{
			Path:   "/rt",
			Method: []string{"POST"},
			Authentication: &WebhookAuth{
				BearerToken: "rt-bearer",
				Secret:      "rt-hmac",
				APIKey:      "rt-apikey",
				BasicAuth: &BasicAuth{
					Username: "rt-user",
					Password: "rt-pass",
				},
			},
		},
	}
	require.NoError(t, save.saveTriggerToStorage(ctx, original))

	// Fresh manager (simulates restart) — same backing stores.
	load := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: ts,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}
	require.NoError(t, load.loadTriggersFromStorage(ctx))

	got, ok := load.triggers["t-rt"]
	require.True(t, ok, "trigger must be present after load")
	require.NotNil(t, got.Webhook)
	require.NotNil(t, got.Webhook.Authentication)

	auth := got.Webhook.Authentication
	assert.Equal(t, "rt-bearer", auth.BearerToken)
	assert.Equal(t, "rt-hmac", auth.Secret)
	assert.Equal(t, "rt-apikey", auth.APIKey)
	require.NotNil(t, auth.BasicAuth)
	assert.Equal(t, "rt-user", auth.BasicAuth.Username)
	assert.Equal(t, "rt-pass", auth.BasicAuth.Password)
}

func TestTriggerSecretKeyTenantIsolation(t *testing.T) {
	// Two managers sharing one secret store but different tenants.
	// A secret written by tenant A must not be readable via tenant B's key namespace.
	ss := newInMemorySecretStore()
	tsA := newInMemoryTriggerStore()
	tsB := newInMemoryTriggerStore()

	ctxA := contextWithTenant("tenant-A")
	ctxB := contextWithTenant("tenant-B")

	mgrA := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: tsA,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}
	mgrB := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: tsB,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}

	trigA := &Trigger{
		ID:           "t-iso",
		TenantID:     "tenant-A",
		Name:         "Isolation A",
		Type:         TriggerTypeWebhook,
		Status:       TriggerStatusActive,
		WorkflowName: "wf",
		Webhook: &WebhookConfig{
			Path:           "/iso",
			Authentication: &WebhookAuth{BearerToken: "secret-A"},
		},
	}
	require.NoError(t, mgrA.saveTriggerToStorage(ctxA, trigA))

	// The secret is stored under the tenant-A key; tenant-B's key for the same
	// trigger ID and field must not exist.
	keyA := fmt.Sprintf("trigger-%s-%s-bearer", "tenant-A", "t-iso")
	keyB := fmt.Sprintf("trigger-%s-%s-bearer", "tenant-B", "t-iso")

	secretA, err := ss.GetSecret(ctxA, keyA)
	require.NoError(t, err, "tenant-A secret must be retrievable")
	assert.Equal(t, "secret-A", secretA.Value)

	_, err = ss.GetSecret(ctxB, keyB)
	assert.ErrorIs(t, err, secretsif.ErrSecretNotFound,
		"tenant-B must not be able to retrieve tenant-A's secret via its own key namespace")

	// Also verify mgrB cannot load the trigger (it uses a separate tsB store).
	require.NoError(t, mgrB.loadTriggersFromStorage(ctxB))
	_, ok := mgrB.triggers["t-iso"]
	assert.False(t, ok, "mgrB must not see tenant-A's trigger")
}

func TestTriggerManagerDegradedLoad(t *testing.T) {
	ts := newInMemoryTriggerStore()
	ss := newInMemorySecretStore()
	ctx := contextWithTenant("tenant-dg")

	// Populate store directly: two valid triggers + one with a deleted bearer ref.
	validBearer1 := "trigger-tenant-dg-t-ok1-bearer"
	validBearer2 := "trigger-tenant-dg-t-ok2-bearer"
	brokenBearer := "trigger-tenant-dg-t-broken-bearer"

	require.NoError(t, ss.StoreSecret(ctx, &secretsif.SecretRequest{Key: validBearer1, Value: "v1", TenantID: "tenant-dg"}))
	require.NoError(t, ss.StoreSecret(ctx, &secretsif.SecretRequest{Key: validBearer2, Value: "v2", TenantID: "tenant-dg"}))
	// Deliberately do NOT store brokenBearer so GetSecret will return ErrSecretNotFound.

	for _, rec := range []*business.TriggerRecord{
		{ID: "t-ok1", TenantID: "tenant-dg", Name: "OK1", Type: string(TriggerTypeWebhook), Status: string(TriggerStatusActive), WorkflowName: "wf", BearerTokenRef: validBearer1, ConfigPayload: []byte(`{"path":"/ok1"}`)},
		{ID: "t-ok2", TenantID: "tenant-dg", Name: "OK2", Type: string(TriggerTypeWebhook), Status: string(TriggerStatusActive), WorkflowName: "wf", BearerTokenRef: validBearer2, ConfigPayload: []byte(`{"path":"/ok2"}`)},
		{ID: "t-broken", TenantID: "tenant-dg", Name: "Broken", Type: string(TriggerTypeWebhook), Status: string(TriggerStatusActive), WorkflowName: "wf", BearerTokenRef: brokenBearer, ConfigPayload: []byte(`{"path":"/broken"}`)},
	} {
		require.NoError(t, ts.StoreTrigger(ctx, rec))
	}

	mgr := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: ts,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}

	require.NoError(t, mgr.loadTriggersFromStorage(ctx))

	// Two valid triggers must be present; the broken one must be absent.
	assert.Contains(t, mgr.triggers, "t-ok1", "t-ok1 must be loaded")
	assert.Contains(t, mgr.triggers, "t-ok2", "t-ok2 must be loaded")
	assert.NotContains(t, mgr.triggers, "t-broken", "t-broken must be skipped")

	// Absence of "t-broken" proves the degraded-load path (WarnCtx + skip) was taken.
	assert.NotContains(t, mgr.triggers, "t-broken", "broken ref must cause trigger to be skipped")
}

func TestTriggerDeleteCleansSecrets(t *testing.T) {
	ts := newInMemoryTriggerStore()
	ss := newInMemorySecretStore()
	ctx := contextWithTenant("tenant-del")

	mgr := &TriggerManagerImpl{
		logger:       logging.ForModule("workflow.trigger.manager.test"),
		triggerStore: ts,
		secretStore:  ss,
		triggers:     make(map[string]*Trigger),
		executions:   make(map[string]*TriggerExecution),
	}

	trigger := &Trigger{
		ID:           "t-del",
		TenantID:     "tenant-del",
		Name:         "Delete Test",
		Type:         TriggerTypeWebhook,
		Status:       TriggerStatusActive,
		WorkflowName: "wf",
		Webhook: &WebhookConfig{
			Path: "/del",
			Authentication: &WebhookAuth{
				BearerToken: "del-bearer",
				Secret:      "del-hmac",
				APIKey:      "del-apikey",
				BasicAuth:   &BasicAuth{Username: "del-user", Password: "del-pass"},
			},
		},
	}

	require.NoError(t, mgr.saveTriggerToStorage(ctx, trigger))

	// Verify secrets were stored.
	refKeys := []string{
		"trigger-tenant-del-t-del-bearer",
		"trigger-tenant-del-t-del-hmac-secret",
		"trigger-tenant-del-t-del-api-key",
		"trigger-tenant-del-t-del-basic-user",
		"trigger-tenant-del-t-del-basic-pass",
	}
	for _, k := range refKeys {
		_, err := ss.GetSecret(ctx, k)
		require.NoError(t, err, "secret %q must exist before delete", k)
	}

	require.NoError(t, mgr.deleteTriggerFromStorage(ctx, "t-del"))

	// After deletion, all five secret refs must be gone.
	for _, k := range refKeys {
		_, err := ss.GetSecret(ctx, k)
		assert.ErrorIs(t, err, secretsif.ErrSecretNotFound,
			"secret %q must be removed after trigger deletion", k)
	}

	// Partial-delete error: if one DeleteSecret call fails the rest are still attempted.
	// Simulate by pre-deleting one ref and re-calling deleteTriggerFromStorage on a
	// fresh record with all refs populated (the method logs WARN and continues).
	rec := &business.TriggerRecord{
		ID:               "t-del-partial",
		TenantID:         "tenant-del",
		BearerTokenRef:   "partial-bearer",
		HMACSecretRef:    "partial-hmac",
		APIKeyRef:        "partial-api",
		BasicUsernameRef: "partial-user",
		BasicPasswordRef: "partial-pass",
	}
	require.NoError(t, ts.StoreTrigger(ctx, rec))
	// Only store some of the secrets (simulates partially-missing refs).
	require.NoError(t, ss.StoreSecret(ctx, &secretsif.SecretRequest{Key: "partial-bearer", Value: "x", TenantID: "tenant-del"}))
	require.NoError(t, ss.StoreSecret(ctx, &secretsif.SecretRequest{Key: "partial-hmac", Value: "x", TenantID: "tenant-del"}))
	// partial-api, partial-user, partial-pass are intentionally absent.

	// deleteTriggerFromStorage must succeed even with missing secret refs (WARN + continue).
	err := mgr.deleteTriggerFromStorage(ctx, "t-del-partial")
	assert.NoError(t, err, "deleteTriggerFromStorage must not fail on missing secret refs")
}

// ---------------------------------------------------------------------------
// Store requirement declaration tests (Issue #3493)
// ---------------------------------------------------------------------------

// decliningTriggerProvider is a purpose-built StorageProvider that returns
// ErrNotSupported for CreateTriggerStore while delegating every other method
// to TestStorageProvider. It is a real provider that cannot supply workflow
// trigger persistence — the condition StoreRequirements exists to catch at startup.
type decliningTriggerProvider struct {
	*TestStorageProvider
}

func (p *decliningTriggerProvider) Name() string { return "test-declining-trigger" }

func (p *decliningTriggerProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return nil, business.ErrNotSupported
}

// clusterTriggerStoreConfig returns the database-provider configuration used by the
// cluster-shape subtest, built from the same CFGMS_TEST_DB_* environment variables the
// database provider's own tests use so it targets the CI Postgres service when one is
// present and fails to connect (rather than failing to parse) when one is not.
func clusterTriggerStoreConfig() map[string]interface{} {
	port := "5432"
	if v := os.Getenv("CFGMS_TEST_DB_PORT"); v != "" {
		port = v
	}
	dbName := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_NAME"); v != "" {
		dbName = v
	}
	dbUser := "cfgms_test"
	if v := os.Getenv("CFGMS_TEST_DB_USER"); v != "" {
		dbUser = v
	}
	dsn := fmt.Sprintf("host=localhost port=%s dbname=%s user=%s password=%s sslmode=disable",
		port, dbName, dbUser, os.Getenv("CFGMS_TEST_DB_PASSWORD"))
	return map[string]interface{}{"dsn": dsn}
}

// TestStoreRequirements_TriggerStoreAvailable_PassesValidation verifies that a
// controller composed with workflow-trigger enabled and TriggerStore available
// starts cleanly — in both the OSS (flatfile+SQLite) and database-provider shapes.
// Both shapes supply TriggerStore (#3402 shipped it on the database provider),
// so both must pass ValidateStorageRequirements with StoreRequirements.
//
// Each subtest builds its own StorageManager from the real provider registry for
// the shape it names: two distinct compositions, not one object validated twice.
func TestStoreRequirements_TriggerStoreAvailable_PassesValidation(t *testing.T) {
	t.Run("OSS shape", func(t *testing.T) {
		// The production OSS composition entry point: real flatfile provider for
		// config/audit/steward, real SQLite provider for business stores.
		sm, err := interfaces.CreateOSSStorageManager(t.TempDir(), filepath.Join(t.TempDir(), "triggers.db"))
		require.NoError(t, err, "OSS composition (flatfile + SQLite) must succeed")
		t.Cleanup(func() { _ = sm.Close() })

		require.True(t, sm.HasStore(interfaces.StoreNameTrigger),
			"the OSS shape must supply TriggerStore — without it the assertion below is vacuous")
		require.NoError(t, interfaces.ValidateStorageRequirements(sm, StoreRequirements),
			"OSS controller with TriggerStore available must start cleanly")
	})

	t.Run("database shape", func(t *testing.T) {
		provider, err := interfaces.GetStorageProvider("database")
		require.NoError(t, err, "the database provider backing the cluster shape must be registered")

		ts, createErr := provider.CreateTriggerStore(clusterTriggerStoreConfig())
		// ErrNotSupported is the one outcome that reaches this gate: CreateClusterStorageManager
		// translates it into a nil triggerStore field, and a nil field is the only input that
		// makes ValidateStorageRequirements fail. Any other error aborts composition earlier.
		// This assertion holds with or without a reachable Postgres, so the cluster shape's
		// capability (#3402) is checked on every run, not only in the integration lane.
		require.False(t, errors.Is(createErr, business.ErrNotSupported),
			"the database provider must not decline TriggerStore — a declined store makes every cluster-mode controller fail this startup gate")
		if createErr != nil {
			// No Postgres reachable: a deployment condition, not a capability gap. The
			// live composition below runs wherever the Postgres service exists.
			t.Logf("no reachable Postgres for the live cluster composition (%v); capability assertion above still applied", createErr)
			return
		}
		if c, ok := ts.(interface{ Close() error }); ok {
			_ = c.Close()
		}

		// Postgres is present: compose the real cluster StorageManager — a second,
		// database-provider-backed manager distinct from the OSS one above.
		sm, err := interfaces.CreateClusterStorageManager(
			clusterTriggerStoreConfig()["dsn"].(string),
			"test-hmac-key-for-workflow-trigger-requirement-tests-only",
			nil,
		)
		require.NoError(t, err, "cluster composition against the database provider must succeed")
		t.Cleanup(func() { _ = sm.Close() })

		require.Equal(t, "database", sm.GetProviderName(),
			"the cluster shape must be backed by the database provider, not flatfile or SQLite")
		require.True(t, sm.HasStore(interfaces.StoreNameTrigger),
			"the database shape must supply TriggerStore — without it the assertion below is vacuous")
		require.NoError(t, interfaces.ValidateStorageRequirements(sm, StoreRequirements),
			"database-provider controller with TriggerStore available must start cleanly")
	})
}

// TestStoreRequirements_TriggerStoreDeclined_FailsStartup verifies that a controller
// composed with workflow-trigger enabled but a provider that declines TriggerStore
// fails startup with an error naming the workflow-trigger subsystem. The declining
// condition is produced by a purpose-built test provider (not a mock) so the
// test exercises the same code path as a real composition failure.
func TestStoreRequirements_TriggerStoreDeclined_FailsStartup(t *testing.T) {
	p := &decliningTriggerProvider{TestStorageProvider: NewTestStorageProvider()}
	ts, declineErr := p.CreateTriggerStore(nil)
	require.True(t, errors.Is(declineErr, business.ErrNotSupported),
		"declining provider must return ErrNotSupported for CreateTriggerStore")
	require.Nil(t, ts)

	// Compose a StorageManager as production code does: ErrNotSupported → nil TriggerStore field.
	sm := interfaces.NewStorageManagerFromStores(
		nil, nil, nil, nil, nil, nil, nil, nil, nil, ts, nil,
	)

	err := interfaces.ValidateStorageRequirements(sm, StoreRequirements)
	require.Error(t, err,
		"workflow-trigger's required TriggerStore must block startup when the provider declines it")
	assert.Contains(t, err.Error(), "workflow-trigger",
		"error must name the declaring subsystem")
	assert.Contains(t, err.Error(), string(interfaces.StoreNameTrigger),
		"error must name the missing store")
}
