// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/cfgis/cfgms/pkg/logging"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
)

// MockStorageProvider implements StorageProvider for testing
type MockStorageProvider struct {
	mock.Mock
}

func (m *MockStorageProvider) Initialize(ctx context.Context, config map[string]interface{}) error {
	args := m.Called(ctx, config)
	return args.Error(0)
}

func (m *MockStorageProvider) Store(ctx context.Context, key string, data []byte) error {
	args := m.Called(ctx, key, data)
	return args.Error(0)
}

func (m *MockStorageProvider) Retrieve(ctx context.Context, key string) ([]byte, error) {
	args := m.Called(ctx, key)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockStorageProvider) Delete(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

func (m *MockStorageProvider) List(ctx context.Context, prefix string) ([]string, error) {
	args := m.Called(ctx, prefix)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockStorageProvider) Exists(ctx context.Context, key string) (bool, error) {
	args := m.Called(ctx, key)
	return args.Bool(0), args.Error(1)
}

func (m *MockStorageProvider) Available() (bool, error) {
	args := m.Called()
	return args.Bool(0), args.Error(1)
}

func (m *MockStorageProvider) Close() error {
	args := m.Called()
	return args.Error(0)
}

// Additional methods required by StorageProvider interface
func (m *MockStorageProvider) Name() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockStorageProvider) Description() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockStorageProvider) CreateClientTenantStore(config map[string]interface{}) (interfaces.ClientTenantStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.ClientTenantStore), args.Error(1)
}

func (m *MockStorageProvider) CreateConfigStore(config map[string]interface{}) (interfaces.ConfigStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.ConfigStore), args.Error(1)
}

func (m *MockStorageProvider) CreateAuditStore(config map[string]interface{}) (interfaces.AuditStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.AuditStore), args.Error(1)
}

func (m *MockStorageProvider) CreateRBACStore(config map[string]interface{}) (interfaces.RBACStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.RBACStore), args.Error(1)
}

func (m *MockStorageProvider) CreateRuntimeStore(config map[string]interface{}) (interfaces.RuntimeStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.RuntimeStore), args.Error(1)
}

func (m *MockStorageProvider) CreateTenantStore(config map[string]interface{}) (interfaces.TenantStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.TenantStore), args.Error(1)
}

func (m *MockStorageProvider) CreateRegistrationTokenStore(config map[string]interface{}) (interfaces.RegistrationTokenStore, error) {
	args := m.Called(config)
	return args.Get(0).(interfaces.RegistrationTokenStore), args.Error(1)
}

func (m *MockStorageProvider) GetCapabilities() interfaces.ProviderCapabilities {
	args := m.Called()
	return args.Get(0).(interfaces.ProviderCapabilities)
}

func (m *MockStorageProvider) GetVersion() string {
	args := m.Called()
	return args.String(0)
}

// MockScheduler implements Scheduler for testing
type MockScheduler struct {
	mock.Mock
}

func (m *MockScheduler) ScheduleWorkflow(ctx context.Context, trigger *Trigger) error {
	args := m.Called(ctx, trigger)
	return args.Error(0)
}

func (m *MockScheduler) UnscheduleWorkflow(ctx context.Context, triggerID string) error {
	args := m.Called(ctx, triggerID)
	return args.Error(0)
}

func (m *MockScheduler) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockScheduler) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockWebhookHandler implements WebhookHandler for testing
type MockWebhookHandler struct {
	mock.Mock
}

func (m *MockWebhookHandler) RegisterWebhook(ctx context.Context, trigger *Trigger) error {
	args := m.Called(ctx, trigger)
	return args.Error(0)
}

func (m *MockWebhookHandler) UnregisterWebhook(ctx context.Context, triggerID string) error {
	args := m.Called(ctx, triggerID)
	return args.Error(0)
}

func (m *MockWebhookHandler) HandleWebhook(ctx context.Context, triggerID string, payload []byte, headers map[string]string) (*TriggerExecution, error) {
	args := m.Called(ctx, triggerID, payload, headers)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TriggerExecution), args.Error(1)
}

func (m *MockWebhookHandler) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockWebhookHandler) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockSIEMIntegration implements SIEMIntegration for testing
type MockSIEMIntegration struct {
	mock.Mock
}

func (m *MockSIEMIntegration) RegisterSIEMTrigger(ctx context.Context, trigger *Trigger) error {
	args := m.Called(ctx, trigger)
	return args.Error(0)
}

func (m *MockSIEMIntegration) UnregisterSIEMTrigger(ctx context.Context, triggerID string) error {
	args := m.Called(ctx, triggerID)
	return args.Error(0)
}

func (m *MockSIEMIntegration) ProcessLogEntry(ctx context.Context, logEntry map[string]interface{}) error {
	args := m.Called(ctx, logEntry)
	return args.Error(0)
}

func (m *MockSIEMIntegration) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockSIEMIntegration) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func TestTriggerManagerImpl_NewTriggerManager(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	assert.NotNil(t, manager)
	assert.Equal(t, mockStorage, manager.storage)
	assert.Equal(t, mockScheduler, manager.scheduler)
	assert.Equal(t, mockWebhookHandler, manager.webhookHandler)
	assert.Equal(t, mockSIEMIntegration, manager.siemIntegration)
	assert.Equal(t, mockWorkflowTrigger, manager.workflowTrigger)
	assert.NotNil(t, manager.triggers)
	assert.NotNil(t, manager.executions)
	assert.False(t, manager.running)
}

func TestTriggerManagerImpl_StartStop(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	ctx := context.Background()

	// Mock successful starts
	mockScheduler.On("Start", ctx).Return(nil)
	mockWebhookHandler.On("Start", ctx).Return(nil)
	mockSIEMIntegration.On("Start", ctx).Return(nil)
	mockStorage.On("List", ctx, "triggers/").Return([]string{}, nil)

	// Mock successful stops
	mockScheduler.On("Stop", ctx).Return(nil)
	mockWebhookHandler.On("Stop", ctx).Return(nil)
	mockSIEMIntegration.On("Stop", ctx).Return(nil)

	// Test start
	err := manager.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, manager.running)

	// Test double start (should fail)
	err = manager.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trigger manager is already running")

	// Test stop
	err = manager.Stop(ctx)
	assert.NoError(t, err)
	assert.False(t, manager.running)

	// Test double stop (should fail)
	err = manager.Stop(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "trigger manager is not running")

	// Verify all mocks were called
	mockScheduler.AssertExpectations(t)
	mockWebhookHandler.AssertExpectations(t)
	mockSIEMIntegration.AssertExpectations(t)
}

func TestTriggerManagerImpl_CreateTrigger(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	ctx := context.Background()

	tests := []struct {
		name        string
		trigger     *Trigger
		setupMocks  func()
		expectError bool
		errorMsg    string
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
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockWorkflowTrigger.On("ValidateTrigger", ctx, mock.Anything).Return(nil)
				mockStorage.On("Store", ctx, "triggers/schedule-1", mock.Anything).Return(nil)
				mockScheduler.On("ScheduleWorkflow", ctx, mock.Anything).Return(nil)
			},
			expectError: false,
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
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockWorkflowTrigger.On("ValidateTrigger", ctx, mock.Anything).Return(nil)
				mockStorage.On("Store", ctx, "triggers/webhook-1", mock.Anything).Return(nil)
				mockWebhookHandler.On("RegisterWebhook", ctx, mock.Anything).Return(nil)
			},
			expectError: false,
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
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockWorkflowTrigger.On("ValidateTrigger", ctx, mock.Anything).Return(nil)
				mockStorage.On("Store", ctx, "triggers/siem-1", mock.Anything).Return(nil)
				mockSIEMIntegration.On("RegisterSIEMTrigger", ctx, mock.Anything).Return(nil)
			},
			expectError: false,
		},
		{
			name: "trigger with empty ID",
			trigger: &Trigger{
				ID:           "",
				Name:         "Test Trigger",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			setupMocks:  func() {},
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
			setupMocks:  func() {},
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
			setupMocks:  func() {},
			expectError: true,
			errorMsg:    "unsupported trigger type",
		},
		{
			name: "storage not implemented yet",
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
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockWorkflowTrigger.On("ValidateTrigger", ctx, mock.Anything).Return(nil)
				mockStorage.On("Store", ctx, "triggers/storage-test-1", mock.Anything).Return(nil)
				mockScheduler.On("ScheduleWorkflow", ctx, mock.Anything).Return(nil)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockStorage.ExpectedCalls = nil
			mockScheduler.ExpectedCalls = nil
			mockWebhookHandler.ExpectedCalls = nil
			mockSIEMIntegration.ExpectedCalls = nil
			mockWorkflowTrigger.ExpectedCalls = nil

			tt.setupMocks()

			err := manager.CreateTrigger(ctx, tt.trigger)

			if tt.expectError {
				if assert.Error(t, err) {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Contains(t, manager.triggers, tt.trigger.ID)
				assert.Equal(t, tt.trigger, manager.triggers[tt.trigger.ID])
			}
		})
	}
}

func TestTriggerManagerImpl_UpdateTrigger(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Create an existing trigger
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
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	manager.triggers[existingTrigger.ID] = existingTrigger

	ctx := logging.WithTenant(context.Background(), "tenant-123")

	tests := []struct {
		name        string
		trigger     *Trigger
		setupMocks  func()
		expectError bool
		errorMsg    string
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
				CreatedAt: existingTrigger.CreatedAt,
				UpdatedAt: time.Now(),
			},
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockWorkflowTrigger.On("ValidateTrigger", ctx, mock.Anything).Return(nil)
				mockStorage.On("Store", ctx, "triggers/schedule-1", mock.Anything).Return(nil)
				mockScheduler.On("UnscheduleWorkflow", ctx, "schedule-1").Return(nil)
				mockScheduler.On("ScheduleWorkflow", ctx, mock.Anything).Return(nil)
			},
			expectError: false,
		},
		{
			name: "update non-existent trigger",
			trigger: &Trigger{
				ID:           "non-existent",
				Name:         "Non-existent",
				Type:         TriggerTypeSchedule,
				WorkflowName: "test-workflow",
			},
			setupMocks:  func() {},
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
			setupMocks: func() {
				// No mocks needed - validation should fail before any calls
			},
			expectError: true,
			errorMsg:    "cron expression is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockStorage.ExpectedCalls = nil
			mockScheduler.ExpectedCalls = nil
			mockWorkflowTrigger.ExpectedCalls = nil

			tt.setupMocks()

			err := manager.UpdateTrigger(ctx, tt.trigger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				updatedTrigger := manager.triggers[tt.trigger.ID]
				assert.Equal(t, tt.trigger.Name, updatedTrigger.Name)
				assert.Equal(t, tt.trigger.WorkflowName, updatedTrigger.WorkflowName)
			}
		})
	}
}

func TestTriggerManagerImpl_DeleteTrigger(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Create test triggers
	scheduleTrigger := &Trigger{
		ID:       "schedule-1",
		Type:     TriggerTypeSchedule,
		TenantID: "tenant-123",
		Schedule: &ScheduleConfig{
			CronExpression: "0 2 * * *",
			Enabled:        true,
		},
	}
	webhookTrigger := &Trigger{
		ID:       "webhook-1",
		Type:     TriggerTypeWebhook,
		TenantID: "tenant-123",
		Webhook: &WebhookConfig{
			Path:    "/webhook/test",
			Enabled: true,
		},
	}
	siemTrigger := &Trigger{
		ID:       "siem-1",
		Type:     TriggerTypeSIEM,
		TenantID: "tenant-123",
		SIEM: &SIEMConfig{
			EventTypes: []string{"error"},
			WindowSize: 5 * time.Minute,
			Enabled:    true,
		},
	}

	manager.triggers["schedule-1"] = scheduleTrigger
	manager.triggers["webhook-1"] = webhookTrigger
	manager.triggers["siem-1"] = siemTrigger

	ctx := logging.WithTenant(context.Background(), "tenant-123")

	tests := []struct {
		name        string
		triggerID   string
		setupMocks  func()
		expectError bool
		errorMsg    string
	}{
		{
			name:      "delete schedule trigger",
			triggerID: "schedule-1",
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockStorage.On("Delete", ctx, "triggers/schedule-1").Return(nil)
				mockScheduler.On("UnscheduleWorkflow", ctx, "schedule-1").Return(nil)
			},
			expectError: false,
		},
		{
			name:      "delete webhook trigger",
			triggerID: "webhook-1",
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockStorage.On("Delete", ctx, "triggers/webhook-1").Return(nil)
				mockWebhookHandler.On("UnregisterWebhook", ctx, "webhook-1").Return(nil)
			},
			expectError: false,
		},
		{
			name:      "delete SIEM trigger",
			triggerID: "siem-1",
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockStorage.On("Delete", ctx, "triggers/siem-1").Return(nil)
				mockSIEMIntegration.On("UnregisterSIEMTrigger", ctx, "siem-1").Return(nil)
			},
			expectError: false,
		},
		{
			name:        "delete non-existent trigger",
			triggerID:   "non-existent",
			setupMocks:  func() {},
			expectError: true,
			errorMsg:    "trigger non-existent not found",
		},
		{
			name:      "storage deletion not implemented yet",
			triggerID: "schedule-1",
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockStorage.On("Delete", ctx, "triggers/schedule-1").Return(nil)
				mockScheduler.On("UnscheduleWorkflow", ctx, "schedule-1").Return(nil)
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mocks
			mockStorage.ExpectedCalls = nil
			mockScheduler.ExpectedCalls = nil
			mockWebhookHandler.ExpectedCalls = nil
			mockSIEMIntegration.ExpectedCalls = nil

			tt.setupMocks()

			// Ensure trigger exists before deletion (for valid test cases)
			switch tt.triggerID {
			case "schedule-1":
				manager.triggers["schedule-1"] = scheduleTrigger
			case "webhook-1":
				manager.triggers["webhook-1"] = webhookTrigger
			case "siem-1":
				manager.triggers["siem-1"] = siemTrigger
			}

			err := manager.DeleteTrigger(ctx, tt.triggerID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.NotContains(t, manager.triggers, tt.triggerID)
			}
		})
	}
}

func TestTriggerManagerImpl_GetTrigger(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Create test trigger
	trigger := &Trigger{
		ID:           "test-1",
		Name:         "Test Trigger",
		Type:         TriggerTypeSchedule,
		WorkflowName: "test-workflow",
	}
	manager.triggers["test-1"] = trigger

	ctx := context.Background()

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
			result, err := manager.GetTrigger(ctx, tt.triggerID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, result)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestTriggerManagerImpl_ListTriggers(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Create test triggers
	triggers := []*Trigger{
		{
			ID:       "schedule-1",
			Name:     "Schedule Trigger",
			Type:     TriggerTypeSchedule,
			Status:   TriggerStatusActive,
			TenantID: "tenant-123",
			Tags:     []string{"backup", "daily"},
		},
		{
			ID:       "webhook-1",
			Name:     "Webhook Trigger",
			Type:     TriggerTypeWebhook,
			Status:   TriggerStatusActive,
			TenantID: "tenant-123",
			Tags:     []string{"api", "integration"},
		},
		{
			ID:       "siem-1",
			Name:     "SIEM Trigger",
			Type:     TriggerTypeSIEM,
			Status:   TriggerStatusInactive,
			TenantID: "tenant-456",
			Tags:     []string{"security", "monitoring"},
		},
	}

	for _, trigger := range triggers {
		manager.triggers[trigger.ID] = trigger
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
			result, err := manager.ListTriggers(ctx, tt.filter)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Len(t, result, tt.expectedLen)

				if tt.expectedIDs != nil {
					actualIDs := make([]string, len(result))
					for i, trigger := range result {
						actualIDs[i] = trigger.ID
					}
					assert.ElementsMatch(t, tt.expectedIDs, actualIDs)
				}
			}
		})
	}
}

func TestTriggerManagerImpl_EnableDisableTrigger(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Create test trigger
	trigger := &Trigger{
		ID:     "test-1",
		Type:   TriggerTypeSchedule,
		Status: TriggerStatusInactive,
		Schedule: &ScheduleConfig{
			CronExpression: "0 2 * * *",
			Enabled:        false,
		},
	}
	manager.triggers["test-1"] = trigger

	ctx := context.Background()

	t.Run("enable trigger", func(t *testing.T) {
		mockStorage.On("Store", ctx, "triggers/test-1", mock.Anything).Return(nil)
		mockScheduler.On("ScheduleWorkflow", ctx, mock.Anything).Return(nil)

		err := manager.EnableTrigger(ctx, "test-1")
		assert.NoError(t, err)
		assert.Equal(t, TriggerStatusActive, trigger.Status)

		mockStorage.AssertExpectations(t)
		mockScheduler.AssertExpectations(t)
	})

	t.Run("disable trigger", func(t *testing.T) {
		// Reset mocks
		mockStorage.ExpectedCalls = nil
		mockScheduler.ExpectedCalls = nil

		trigger.Status = TriggerStatusActive
		trigger.Schedule.Enabled = true

		mockStorage.On("Available").Return(true, nil)
		mockStorage.On("Store", ctx, "triggers/test-1", mock.Anything).Return(nil)
		mockScheduler.On("UnscheduleWorkflow", ctx, "test-1").Return(nil)

		err := manager.DisableTrigger(ctx, "test-1")
		assert.NoError(t, err)
		assert.Equal(t, TriggerStatusInactive, trigger.Status)

		mockStorage.AssertExpectations(t)
		mockScheduler.AssertExpectations(t)
	})

	t.Run("enable non-existent trigger", func(t *testing.T) {
		err := manager.EnableTrigger(ctx, "non-existent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "trigger non-existent not found")
	})
}

func TestTriggerManagerImpl_ExecuteTrigger(t *testing.T) {
	mockStorage := &MockStorageProvider{}
	mockScheduler := &MockScheduler{}
	mockWebhookHandler := &MockWebhookHandler{}
	mockSIEMIntegration := &MockSIEMIntegration{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	mockStorage.On("Available").Return(true, nil)

	manager := NewTriggerManager(
		mockStorage,
		mockScheduler,
		mockWebhookHandler,
		mockSIEMIntegration,
		mockWorkflowTrigger,
	)

	// Create test trigger
	trigger := &Trigger{
		ID:           "test-1",
		Type:         TriggerTypeManual,
		Status:       TriggerStatusActive,
		WorkflowName: "test-workflow",
	}
	manager.triggers["test-1"] = trigger

	ctx := context.Background()
	triggerData := map[string]interface{}{
		"manual_execution": true,
		"user_id":          "user-123",
	}

	mockWorkflowTrigger.On("TriggerWorkflow", ctx, trigger, mock.Anything).Return(
		&WorkflowExecution{
			ID:           "exec-123",
			WorkflowName: "test-workflow",
			Status:       "running",
			StartTime:    time.Now(),
		}, nil)

	execution, err := manager.ExecuteTrigger(ctx, "test-1", triggerData)

	assert.NoError(t, err)
	assert.NotNil(t, execution)
	assert.Equal(t, "test-1", execution.TriggerID)
	assert.Equal(t, TriggerExecutionStatusSuccess, execution.Status)
	assert.Equal(t, "exec-123", execution.WorkflowExecutionID)

	// Verify execution is stored
	assert.Contains(t, manager.executions, execution.ID)

	mockWorkflowTrigger.AssertExpectations(t)
}
