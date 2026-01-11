// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package trigger

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockTriggerManager implements TriggerManager for testing
type MockTriggerManager struct {
	mock.Mock
}

func (m *MockTriggerManager) CreateTrigger(ctx context.Context, trigger *Trigger) error {
	args := m.Called(ctx, trigger)
	return args.Error(0)
}

func (m *MockTriggerManager) UpdateTrigger(ctx context.Context, trigger *Trigger) error {
	args := m.Called(ctx, trigger)
	return args.Error(0)
}

func (m *MockTriggerManager) DeleteTrigger(ctx context.Context, triggerID string) error {
	args := m.Called(ctx, triggerID)
	return args.Error(0)
}

func (m *MockTriggerManager) GetTrigger(ctx context.Context, triggerID string) (*Trigger, error) {
	args := m.Called(ctx, triggerID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Trigger), args.Error(1)
}

func (m *MockTriggerManager) ListTriggers(ctx context.Context, filter *TriggerFilter) ([]*Trigger, error) {
	args := m.Called(ctx, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*Trigger), args.Error(1)
}

func (m *MockTriggerManager) EnableTrigger(ctx context.Context, triggerID string) error {
	args := m.Called(ctx, triggerID)
	return args.Error(0)
}

func (m *MockTriggerManager) DisableTrigger(ctx context.Context, triggerID string) error {
	args := m.Called(ctx, triggerID)
	return args.Error(0)
}

func (m *MockTriggerManager) ExecuteTrigger(ctx context.Context, triggerID string, data map[string]interface{}) (*TriggerExecution, error) {
	args := m.Called(ctx, triggerID, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*TriggerExecution), args.Error(1)
}

func (m *MockTriggerManager) GetTriggerExecutions(ctx context.Context, triggerID string, limit int) ([]*TriggerExecution, error) {
	args := m.Called(ctx, triggerID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*TriggerExecution), args.Error(1)
}

func (m *MockTriggerManager) Start(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockTriggerManager) Stop(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

// MockWorkflowTrigger implements WorkflowTrigger for testing
type MockWorkflowTrigger struct {
	mock.Mock
}

func (m *MockWorkflowTrigger) TriggerWorkflow(ctx context.Context, trigger *Trigger, data map[string]interface{}) (*WorkflowExecution, error) {
	args := m.Called(ctx, trigger, data)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*WorkflowExecution), args.Error(1)
}

func (m *MockWorkflowTrigger) ValidateTrigger(ctx context.Context, trigger *Trigger) error {
	args := m.Called(ctx, trigger)
	return args.Error(0)
}

func TestCronScheduler_ParseCronExpression(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	tests := []struct {
		name       string
		expression string
		timezone   string
		expectErr  bool
	}{
		{
			name:       "Valid 5-field cron",
			expression: "0 9 * * *",
			timezone:   "UTC",
			expectErr:  false,
		},
		{
			name:       "Valid 6-field cron",
			expression: "0 0 9 * * *",
			timezone:   "UTC",
			expectErr:  false,
		},
		{
			name:       "Invalid field count",
			expression: "0 9 *",
			timezone:   "UTC",
			expectErr:  true,
		},
		{
			name:       "Invalid timezone",
			expression: "0 9 * * *",
			timezone:   "Invalid/Timezone",
			expectErr:  true,
		},
		{
			name:       "Complex expression",
			expression: "*/15 8-17 * * 1-5",
			timezone:   "America/New_York",
			expectErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			schedule, err := scheduler.parseCronExpression(tt.expression, tt.timezone)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, schedule)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, schedule)
				assert.Equal(t, tt.timezone, schedule.timezone.String())
			}
		})
	}
}

func TestCronScheduler_CalculateNextRun(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	// Test daily at 9 AM UTC
	schedule, err := scheduler.parseCronExpression("0 9 * * *", "UTC")
	assert.NoError(t, err)

	// Test from 8 AM - should get next 9 AM
	from := time.Date(2024, 1, 1, 8, 0, 0, 0, time.UTC)
	next := scheduler.calculateNextRun(schedule, from)

	expected := time.Date(2024, 1, 1, 9, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)

	// Test from 10 AM - should get 9 AM next day
	from = time.Date(2024, 1, 1, 10, 0, 0, 0, time.UTC)
	next = scheduler.calculateNextRun(schedule, from)

	expected = time.Date(2024, 1, 2, 9, 0, 0, 0, time.UTC)
	assert.Equal(t, expected, next)
}

func TestCronScheduler_ScheduleWorkflow(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	ctx := context.Background()

	trigger := &Trigger{
		ID:           "test-trigger",
		Type:         TriggerTypeSchedule,
		WorkflowName: "test-workflow",
		Schedule: &ScheduleConfig{
			CronExpression: "0 9 * * *",
			Timezone:       "UTC",
			Enabled:        true,
		},
	}

	err := scheduler.ScheduleWorkflow(ctx, trigger)
	assert.NoError(t, err)

	// Verify trigger is scheduled
	scheduledTriggers := scheduler.GetScheduledTriggers()
	assert.Contains(t, scheduledTriggers, "test-trigger")
	assert.Equal(t, trigger, scheduledTriggers["test-trigger"])

	// Test next execution time
	nextExecution, err := scheduler.GetNextExecutionTime("test-trigger")
	assert.NoError(t, err)
	assert.NotNil(t, nextExecution)
}

func TestCronScheduler_UnscheduleWorkflow(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	ctx := context.Background()

	trigger := &Trigger{
		ID:           "test-trigger",
		Type:         TriggerTypeSchedule,
		WorkflowName: "test-workflow",
		Schedule: &ScheduleConfig{
			CronExpression: "0 9 * * *",
			Timezone:       "UTC",
			Enabled:        true,
		},
	}

	// Schedule first
	err := scheduler.ScheduleWorkflow(ctx, trigger)
	assert.NoError(t, err)

	// Then unschedule
	err = scheduler.UnscheduleWorkflow(ctx, "test-trigger")
	assert.NoError(t, err)

	// Verify trigger is no longer scheduled
	scheduledTriggers := scheduler.GetScheduledTriggers()
	assert.NotContains(t, scheduledTriggers, "test-trigger")

	// Test next execution time should fail
	_, err = scheduler.GetNextExecutionTime("test-trigger")
	assert.Error(t, err)
}

func TestCronScheduler_InvalidTrigger(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	ctx := context.Background()

	tests := []struct {
		name    string
		trigger *Trigger
	}{
		{
			name: "Non-schedule trigger",
			trigger: &Trigger{
				ID:   "test-trigger",
				Type: TriggerTypeWebhook,
			},
		},
		{
			name: "No schedule config",
			trigger: &Trigger{
				ID:       "test-trigger",
				Type:     TriggerTypeSchedule,
				Schedule: nil,
			},
		},
		{
			name: "Invalid cron expression",
			trigger: &Trigger{
				ID:   "test-trigger",
				Type: TriggerTypeSchedule,
				Schedule: &ScheduleConfig{
					CronExpression: "invalid",
					Timezone:       "UTC",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := scheduler.ScheduleWorkflow(ctx, tt.trigger)
			assert.Error(t, err)
		})
	}
}

func TestCronScheduler_StartStop(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	ctx := context.Background()

	// Test start
	err := scheduler.Start(ctx)
	assert.NoError(t, err)

	// Test double start (should fail)
	err = scheduler.Start(ctx)
	assert.Error(t, err)

	// Test stop
	err = scheduler.Stop(ctx)
	assert.NoError(t, err)

	// Test double stop (should fail)
	err = scheduler.Stop(ctx)
	assert.Error(t, err)
}

func TestCronField_Parsing(t *testing.T) {
	triggerManager := &MockTriggerManager{}
	workflowTrigger := &MockWorkflowTrigger{}
	scheduler := NewCronScheduler(triggerManager, workflowTrigger)

	tests := []struct {
		name      string
		field     string
		min       int
		max       int
		expected  []int
		expectErr bool
	}{
		{
			name:     "Wildcard",
			field:    "*",
			min:      0,
			max:      59,
			expected: nil, // Should be wildcard
		},
		{
			name:     "Single value",
			field:    "15",
			min:      0,
			max:      59,
			expected: []int{15},
		},
		{
			name:     "Range",
			field:    "10-15",
			min:      0,
			max:      59,
			expected: []int{10, 11, 12, 13, 14, 15},
		},
		{
			name:     "List",
			field:    "1,3,5",
			min:      0,
			max:      59,
			expected: []int{1, 3, 5},
		},
		{
			name:     "Step values",
			field:    "*/10",
			min:      0,
			max:      59,
			expected: []int{0, 10, 20, 30, 40, 50},
		},
		{
			name:      "Invalid range",
			field:     "70",
			min:       0,
			max:       59,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cronField, err := scheduler.parseCronField(tt.field, tt.min, tt.max)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.field == "*" {
					assert.True(t, cronField.wildcard)
				} else {
					assert.Equal(t, tt.expected, cronField.values)
				}
			}
		})
	}
}
