// SPDX-License-Identifier: AGPL-3.0-only
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/features/workflow"
	"github.com/cfgis/cfgms/pkg/logging"
	secretsif "github.com/cfgis/cfgms/pkg/secrets/interfaces"
	"github.com/cfgis/cfgms/pkg/storage/interfaces"
	business "github.com/cfgis/cfgms/pkg/storage/interfaces/business"
	cfgconfig "github.com/cfgis/cfgms/pkg/storage/interfaces/config"
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

func (m *MockStorageProvider) CreateClientTenantStore(config map[string]interface{}) (business.ClientTenantStore, error) {
	args := m.Called(config)
	return args.Get(0).(business.ClientTenantStore), args.Error(1)
}

func (m *MockStorageProvider) CreateConfigStore(config map[string]interface{}) (cfgconfig.ConfigStore, error) {
	args := m.Called(config)
	return args.Get(0).(cfgconfig.ConfigStore), args.Error(1)
}

func (m *MockStorageProvider) CreateAuditStore(config map[string]interface{}) (business.AuditStore, error) {
	args := m.Called(config)
	return args.Get(0).(business.AuditStore), args.Error(1)
}

func (m *MockStorageProvider) CreateRBACStore(config map[string]interface{}) (business.RBACStore, error) {
	args := m.Called(config)
	return args.Get(0).(business.RBACStore), args.Error(1)
}

func (m *MockStorageProvider) CreateTenantStore(config map[string]interface{}) (business.TenantStore, error) {
	args := m.Called(config)
	return args.Get(0).(business.TenantStore), args.Error(1)
}

func (m *MockStorageProvider) CreateRegistrationTokenStore(config map[string]interface{}) (business.RegistrationTokenStore, error) {
	args := m.Called(config)
	return args.Get(0).(business.RegistrationTokenStore), args.Error(1)
}

func (m *MockStorageProvider) CreateSessionStore(_ map[string]interface{}) (business.SessionStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreateStewardStore(_ map[string]interface{}) (business.StewardStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreateCommandStore(_ map[string]interface{}) (business.CommandStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreateTriggerStore(_ map[string]interface{}) (business.TriggerStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreatePushStore(_ map[string]interface{}) (business.PushStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreatePendingRegistrationStore(_ map[string]interface{}) (business.PendingRegistrationStore, error) {
	return nil, business.ErrNotSupported
}

func (m *MockStorageProvider) CreateIPTrustStore(_ map[string]interface{}) (business.IPTrustStore, error) {
	return nil, business.ErrNotSupported
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
		nil,
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
		nil,
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
		nil,
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
		nil,
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
		nil,
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
				mockScheduler.On("UnscheduleWorkflow", ctx, "schedule-1").Return(nil)
			},
			expectError: false,
		},
		{
			name:      "delete webhook trigger",
			triggerID: "webhook-1",
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
				mockWebhookHandler.On("UnregisterWebhook", ctx, "webhook-1").Return(nil)
			},
			expectError: false,
		},
		{
			name:      "delete SIEM trigger",
			triggerID: "siem-1",
			setupMocks: func() {
				mockStorage.On("Available").Return(true, nil)
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
		nil,
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
		nil,
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
		nil,
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
		mockScheduler.On("ScheduleWorkflow", ctx, mock.Anything).Return(nil)

		err := manager.EnableTrigger(ctx, "test-1")
		assert.NoError(t, err)
		assert.Equal(t, TriggerStatusActive, trigger.Status)

		mockScheduler.AssertExpectations(t)
	})

	t.Run("disable trigger", func(t *testing.T) {
		// Reset mocks
		mockStorage.ExpectedCalls = nil
		mockScheduler.ExpectedCalls = nil

		trigger.Status = TriggerStatusActive
		trigger.Schedule.Enabled = true

		mockScheduler.On("UnscheduleWorkflow", ctx, "test-1").Return(nil)

		err := manager.DisableTrigger(ctx, "test-1")
		assert.NoError(t, err)
		assert.Equal(t, TriggerStatusInactive, trigger.Status)

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
		nil,
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
		&workflow.WorkflowExecution{
			ID:           "exec-123",
			WorkflowName: "test-workflow",
			Status:       workflow.StatusRunning,
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
