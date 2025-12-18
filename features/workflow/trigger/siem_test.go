// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 CFGMS Contributors
package trigger

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestSIEMProcessor_NewSIEMProcessor(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}

	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	assert.NotNil(t, processor)
	assert.NotNil(t, processor.siemTriggers)
	assert.NotNil(t, processor.aggregationData)
	assert.NotNil(t, processor.triggerConditions)
	assert.Equal(t, 10000, processor.bufferSize)
	assert.Equal(t, 5*time.Minute, processor.cleanupInterval)
	assert.False(t, processor.running)
}

func TestSIEMProcessor_StartStop(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	ctx := context.Background()

	// Test start
	err := processor.Start(ctx)
	assert.NoError(t, err)
	assert.True(t, processor.running)
	assert.NotNil(t, processor.logBuffer)

	// Test double start (should fail)
	err = processor.Start(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SIEM processor is already running")

	// Test stop
	err = processor.Stop(ctx)
	assert.NoError(t, err)
	assert.False(t, processor.running)

	// Test double stop (should fail)
	err = processor.Stop(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "SIEM processor is not running")
}

func TestSIEMProcessor_RegisterSIEMTrigger(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	tests := []struct {
		name        string
		trigger     *Trigger
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid SIEM trigger",
			trigger: &Trigger{
				ID:   "siem-1",
				Type: TriggerTypeSIEM,
				SIEM: &SIEMConfig{
					EventTypes: []string{"error", "warning"},
					Conditions: []*SIEMCondition{
						{
							Field:    "level",
							Operator: SIEMOperatorEquals,
							Value:    "error",
						},
					},
					WindowSize: 5 * time.Minute,
					Enabled:    true,
				},
			},
			expectError: false,
		},
		{
			name: "SIEM trigger with aggregation and threshold",
			trigger: &Trigger{
				ID:   "siem-2",
				Type: TriggerTypeSIEM,
				SIEM: &SIEMConfig{
					EventTypes: []string{"auth_failure"},
					Conditions: []*SIEMCondition{
						{
							Field:    "event_type",
							Operator: SIEMOperatorEquals,
							Value:    "login_failed",
						},
					},
					Aggregation: &SIEMAggregation{
						GroupBy: []string{"user_id", "ip_address"},
						CountBy: "event_type",
					},
					Threshold: &SIEMThreshold{
						Count: 5,
						Rate:  10.0,
					},
					WindowSize: 10 * time.Minute,
					Enabled:    true,
				},
			},
			expectError: false,
		},
		{
			name: "non-SIEM trigger",
			trigger: &Trigger{
				ID:   "webhook-1",
				Type: TriggerTypeWebhook,
			},
			expectError: true,
			errorMsg:    "trigger webhook-1 is not a SIEM trigger",
		},
		{
			name: "SIEM trigger without config",
			trigger: &Trigger{
				ID:   "siem-3",
				Type: TriggerTypeSIEM,
				SIEM: nil,
			},
			expectError: true,
			errorMsg:    "trigger siem-3 is not a SIEM trigger",
		},
		{
			name: "SIEM trigger with invalid config",
			trigger: &Trigger{
				ID:   "siem-4",
				Type: TriggerTypeSIEM,
				SIEM: &SIEMConfig{
					EventTypes: []string{},
					Conditions: []*SIEMCondition{},
					WindowSize: 0, // Invalid window size
					Enabled:    true,
				},
			},
			expectError: true,
			errorMsg:    "invalid SIEM configuration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			err := processor.RegisterSIEMTrigger(ctx, tt.trigger)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Contains(t, processor.siemTriggers, tt.trigger.ID)
				assert.Contains(t, processor.aggregationData, tt.trigger.ID)
				assert.Contains(t, processor.triggerConditions, tt.trigger.ID)
			}
		})
	}
}

func TestSIEMProcessor_UnregisterSIEMTrigger(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	// Register a trigger first
	trigger := &Trigger{
		ID:   "siem-1",
		Type: TriggerTypeSIEM,
		SIEM: &SIEMConfig{
			EventTypes: []string{"error"},
			WindowSize: 5 * time.Minute,
			Enabled:    true,
		},
	}
	ctx := context.Background()
	err := processor.RegisterSIEMTrigger(ctx, trigger)
	require.NoError(t, err)

	tests := []struct {
		name        string
		triggerID   string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "unregister existing trigger",
			triggerID:   "siem-1",
			expectError: false,
		},
		{
			name:        "unregister non-existent trigger",
			triggerID:   "siem-999",
			expectError: true,
			errorMsg:    "SIEM trigger siem-999 is not registered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := processor.UnregisterSIEMTrigger(ctx, tt.triggerID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				// Allow time for any concurrent goroutines to finish before checking state
				time.Sleep(10 * time.Millisecond)

				processor.mutex.RLock()
				_, existsInSiemTriggers := processor.siemTriggers[tt.triggerID]
				_, existsInAggregationData := processor.aggregationData[tt.triggerID]
				_, existsInTriggerConditions := processor.triggerConditions[tt.triggerID]
				processor.mutex.RUnlock()

				assert.False(t, existsInSiemTriggers, "trigger should not exist in siemTriggers")
				assert.False(t, existsInAggregationData, "trigger should not exist in aggregationData")
				assert.False(t, existsInTriggerConditions, "trigger should not exist in triggerConditions")
			}
		})
	}
}

func TestSIEMProcessor_ProcessLogEntry(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	ctx := context.Background()

	tests := []struct {
		name        string
		running     bool
		logEntry    map[string]interface{}
		expectError bool
		errorMsg    string
	}{
		{
			name:    "processor not running",
			running: false,
			logEntry: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "error",
				"message":   "Test error message",
				"source":    "test-service",
			},
			expectError: true,
			errorMsg:    "SIEM processor is not running",
		},
		{
			name:    "valid log entry",
			running: true,
			logEntry: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "error",
				"message":   "Authentication failed",
				"source":    "auth-service",
				"tenant_id": "tenant-123",
				"fields": map[string]interface{}{
					"user_id":    "user-456",
					"ip_address": "192.168.1.100",
				},
			},
			expectError: false,
		},
		{
			name:    "invalid log entry format",
			running: true,
			logEntry: map[string]interface{}{
				"timestamp": "invalid-timestamp",
				"level":     123, // Invalid type
			},
			expectError: true,
			errorMsg:    "failed to convert log entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.running {
				err := processor.Start(ctx)
				require.NoError(t, err)
				defer func() {
					_ = processor.Stop(ctx)
					// Allow time for goroutines to finish
					time.Sleep(10 * time.Millisecond)
				}()
			}

			err := processor.ProcessLogEntry(ctx, tt.logEntry)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSIEMProcessor_MatchesEventTypes(t *testing.T) {
	processor := &SIEMProcessor{}

	tests := []struct {
		name       string
		eventTypes []string
		entry      LogEntry
		expected   bool
	}{
		{
			name:       "empty event types - matches all",
			eventTypes: []string{},
			entry: LogEntry{
				Level:   "info",
				Message: "Test message",
				Source:  "test-service",
			},
			expected: true,
		},
		{
			name:       "level match",
			eventTypes: []string{"error", "warning"},
			entry: LogEntry{
				Level:   "error",
				Message: "Error occurred",
				Source:  "app-service",
			},
			expected: true,
		},
		{
			name:       "source match",
			eventTypes: []string{"auth-service", "api-service"},
			entry: LogEntry{
				Level:   "info",
				Message: "Authentication successful",
				Source:  "auth-service",
			},
			expected: true,
		},
		{
			name:       "message pattern match",
			eventTypes: []string{".*failed.*", ".*error.*"},
			entry: LogEntry{
				Level:   "info",
				Message: "Login failed for user",
				Source:  "auth-service",
			},
			expected: true,
		},
		{
			name:       "no match",
			eventTypes: []string{"critical", "alert"},
			entry: LogEntry{
				Level:   "info",
				Message: "Normal operation",
				Source:  "app-service",
			},
			expected: false,
		},
		{
			name:       "case insensitive level match",
			eventTypes: []string{"ERROR"},
			entry: LogEntry{
				Level:   "error",
				Message: "Error message",
				Source:  "service",
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.matchesEventTypes(tt.eventTypes, tt.entry)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSIEMProcessor_MatchesConditions(t *testing.T) {
	processor := &SIEMProcessor{}

	tests := []struct {
		name       string
		conditions []*SIEMCondition
		entry      LogEntry
		expected   bool
	}{
		{
			name:       "empty conditions - matches all",
			conditions: []*SIEMCondition{},
			entry: LogEntry{
				Level:   "error",
				Message: "Test message",
			},
			expected: true,
		},
		{
			name: "equals condition match",
			conditions: []*SIEMCondition{
				{
					Field:    "level",
					Operator: SIEMOperatorEquals,
					Value:    "error",
				},
			},
			entry: LogEntry{
				Level:   "error",
				Message: "Error occurred",
			},
			expected: true,
		},
		{
			name: "equals condition no match",
			conditions: []*SIEMCondition{
				{
					Field:    "level",
					Operator: SIEMOperatorEquals,
					Value:    "warning",
				},
			},
			entry: LogEntry{
				Level:   "error",
				Message: "Error occurred",
			},
			expected: false,
		},
		{
			name: "contains condition match",
			conditions: []*SIEMCondition{
				{
					Field:    "message",
					Operator: SIEMOperatorContains,
					Value:    "failed",
				},
			},
			entry: LogEntry{
				Level:   "error",
				Message: "Authentication failed for user",
			},
			expected: true,
		},
		{
			name: "regex condition match",
			conditions: []*SIEMCondition{
				{
					Field:    "message",
					Operator: SIEMOperatorRegex,
					Value:    "user-\\d+",
				},
			},
			entry: LogEntry{
				Level:   "info",
				Message: "Login attempt by user-123",
			},
			expected: true,
		},
		{
			name: "field condition match",
			conditions: []*SIEMCondition{
				{
					Field:    "fields.user_id",
					Operator: SIEMOperatorEquals,
					Value:    "user-456",
				},
			},
			entry: LogEntry{
				Level:   "info",
				Message: "User action",
				Fields: map[string]interface{}{
					"user_id":    "user-456",
					"ip_address": "192.168.1.1",
				},
			},
			expected: true,
		},
		{
			name: "multiple conditions - all must match",
			conditions: []*SIEMCondition{
				{
					Field:    "level",
					Operator: SIEMOperatorEquals,
					Value:    "error",
				},
				{
					Field:    "message",
					Operator: SIEMOperatorContains,
					Value:    "authentication",
				},
			},
			entry: LogEntry{
				Level:   "error",
				Message: "Authentication failed",
			},
			expected: true,
		},
		{
			name: "multiple conditions - one fails",
			conditions: []*SIEMCondition{
				{
					Field:    "level",
					Operator: SIEMOperatorEquals,
					Value:    "error",
				},
				{
					Field:    "message",
					Operator: SIEMOperatorContains,
					Value:    "database",
				},
			},
			entry: LogEntry{
				Level:   "error",
				Message: "Authentication failed",
			},
			expected: false,
		},
		{
			name: "greater than condition",
			conditions: []*SIEMCondition{
				{
					Field:    "fields.response_time",
					Operator: SIEMOperatorGreaterThan,
					Value:    float64(1000),
				},
			},
			entry: LogEntry{
				Level:   "warning",
				Message: "Slow response",
				Fields: map[string]interface{}{
					"response_time": float64(1500),
				},
			},
			expected: true,
		},
		{
			name: "exists condition - field exists",
			conditions: []*SIEMCondition{
				{
					Field:    "fields.error_code",
					Operator: SIEMOperatorExists,
					Value:    nil,
				},
			},
			entry: LogEntry{
				Level:   "error",
				Message: "API error",
				Fields: map[string]interface{}{
					"error_code": "E001",
				},
			},
			expected: true,
		},
		{
			name: "exists condition - field does not exist",
			conditions: []*SIEMCondition{
				{
					Field:    "fields.error_code",
					Operator: SIEMOperatorExists,
					Value:    nil,
				},
			},
			entry: LogEntry{
				Level:   "info",
				Message: "Normal operation",
				Fields: map[string]interface{}{
					"user_id": "user-123",
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.matchesConditions(tt.conditions, tt.entry)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSIEMProcessor_AddToAggregation(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	// Initialize test trigger and aggregation data
	triggerID := "siem-1"
	trigger := &Trigger{
		ID:   triggerID,
		Type: TriggerTypeSIEM,
		SIEM: &SIEMConfig{
			EventTypes: []string{"error"},
			WindowSize: 5 * time.Minute,
			Conditions: []*SIEMCondition{},
		},
	}

	// Set up the trigger in the processor
	processor.siemTriggers[triggerID] = trigger
	processor.aggregationData[triggerID] = &AggregationData{
		Count:         0,
		Sum:           make(map[string]float64),
		Average:       make(map[string]float64),
		GroupedCounts: make(map[string]int),
		WindowStart:   time.Now(),
		Entries:       make([]LogEntry, 0),
		TriggerID:     triggerID,
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		Level:     "error",
		Message:   "Test error",
		Source:    "test-service",
		Fields: map[string]interface{}{
			"response_time": float64(1200),
			"user_id":       "user-123",
		},
	}

	processor.addToAggregation(triggerID, entry)

	aggregation := processor.aggregationData[triggerID]
	assert.Equal(t, 1, aggregation.Count)
	assert.Len(t, aggregation.Entries, 1)
	assert.Equal(t, entry.Message, aggregation.Entries[0].Message)
	// LastUpdated should be at or after WindowStart (may be equal on fast systems)
	assert.False(t, aggregation.LastUpdated.Before(aggregation.WindowStart))
}

func TestSIEMProcessor_ThresholdMet(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	triggerID := "siem-1"

	tests := []struct {
		name        string
		siemConfig  *SIEMConfig
		aggregation *AggregationData
		expected    bool
	}{
		{
			name: "no threshold configured",
			siemConfig: &SIEMConfig{
				Threshold: nil,
			},
			aggregation: &AggregationData{
				Count: 10,
			},
			expected: false,
		},
		{
			name: "count threshold met",
			siemConfig: &SIEMConfig{
				Threshold: &SIEMThreshold{
					Count: 5,
				},
			},
			aggregation: &AggregationData{
				Count: 10,
			},
			expected: true,
		},
		{
			name: "count threshold not met",
			siemConfig: &SIEMConfig{
				Threshold: &SIEMThreshold{
					Count: 15,
				},
			},
			aggregation: &AggregationData{
				Count: 10,
			},
			expected: false,
		},
		{
			name: "rate threshold met",
			siemConfig: &SIEMConfig{
				WindowSize: 1 * time.Minute,
				Threshold: &SIEMThreshold{
					Rate: 5.0, // 5 events per minute
				},
			},
			aggregation: &AggregationData{
				Count:       10,
				WindowStart: time.Now().Add(-1 * time.Minute),
			},
			expected: true,
		},
		{
			name: "rate threshold not met",
			siemConfig: &SIEMConfig{
				WindowSize: 1 * time.Minute,
				Threshold: &SIEMThreshold{
					Rate: 15.0, // 15 events per minute
				},
			},
			aggregation: &AggregationData{
				Count:       10,
				WindowStart: time.Now().Add(-1 * time.Minute),
			},
			expected: false,
		},
		{
			name: "sum threshold met",
			siemConfig: &SIEMConfig{
				Threshold: &SIEMThreshold{
					Sum: 1000.0,
				},
			},
			aggregation: &AggregationData{
				Sum: map[string]float64{
					"response_time": 1500.0,
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor.aggregationData[triggerID] = tt.aggregation
			result := processor.thresholdMet(triggerID, tt.siemConfig)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSIEMProcessor_FireTrigger(t *testing.T) {
	mockTriggerManager := &MockTriggerManager{}
	mockWorkflowTrigger := &MockWorkflowTrigger{}
	processor := NewSIEMProcessor(mockTriggerManager, mockWorkflowTrigger)

	triggerID := "siem-1"
	trigger := &Trigger{
		ID:           triggerID,
		Type:         TriggerTypeSIEM,
		WorkflowName: "security-alert-workflow",
		SIEM: &SIEMConfig{
			EventTypes: []string{"auth_failure"},
			WindowSize: 5 * time.Minute,
			Enabled:    true,
		},
	}

	// Set up aggregation data
	processor.aggregationData[triggerID] = &AggregationData{
		Count:       5,
		WindowStart: time.Now().Add(-2 * time.Minute),
		Entries: []LogEntry{
			{
				Timestamp: time.Now(),
				Level:     "error",
				Message:   "Authentication failed",
				Source:    "auth-service",
			},
		},
		TriggerID: triggerID,
	}

	// Mock successful workflow execution
	mockWorkflowTrigger.On("TriggerWorkflow", mock.Anything, mock.Anything, mock.Anything).Return(
		&WorkflowExecution{
			ID:           "exec-123",
			WorkflowName: "security-alert-workflow",
			Status:       "running",
			StartTime:    time.Now(),
		}, nil)

	ctx := context.Background()
	processor.fireTrigger(ctx, triggerID, trigger)

	// Give the goroutine time to execute
	time.Sleep(100 * time.Millisecond)

	// Verify workflow trigger was called
	mockWorkflowTrigger.AssertCalled(t, "TriggerWorkflow", mock.Anything, trigger, mock.Anything)

	// Verify aggregation data was reset
	aggregation := processor.aggregationData[triggerID]
	assert.Equal(t, 0, aggregation.Count)
	assert.Empty(t, aggregation.Entries)
	assert.Empty(t, aggregation.Sum)
	assert.Empty(t, aggregation.Average)
	assert.Empty(t, aggregation.GroupedCounts)
}

func TestSIEMProcessor_ValidateSIEMConfig(t *testing.T) {
	processor := &SIEMProcessor{}

	tests := []struct {
		name        string
		config      *SIEMConfig
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid config",
			config: &SIEMConfig{
				EventTypes: []string{"error"},
				WindowSize: 5 * time.Minute,
				Enabled:    true,
			},
			expectError: false,
		},
		{
			name: "zero window size",
			config: &SIEMConfig{
				EventTypes: []string{"error"},
				WindowSize: 0,
				Enabled:    true,
			},
			expectError: true,
			errorMsg:    "window size must be greater than zero",
		},
		{
			name: "negative window size",
			config: &SIEMConfig{
				EventTypes: []string{"error"},
				WindowSize: -1 * time.Minute,
				Enabled:    true,
			},
			expectError: true,
			errorMsg:    "window size must be greater than zero",
		},
		{
			name: "config with aggregation",
			config: &SIEMConfig{
				EventTypes: []string{"auth_failure"},
				WindowSize: 10 * time.Minute,
				Aggregation: &SIEMAggregation{
					GroupBy: []string{"user_id"},
					CountBy: "event_type",
				},
				Enabled: true,
			},
			expectError: false,
		},
		{
			name: "config with threshold",
			config: &SIEMConfig{
				EventTypes: []string{"error"},
				WindowSize: 5 * time.Minute,
				Threshold: &SIEMThreshold{
					Count: 10,
					Rate:  5.0,
				},
				Enabled: true,
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := processor.validateSIEMConfig(tt.config)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSIEMProcessor_MapToLogEntry(t *testing.T) {
	processor := &SIEMProcessor{}

	tests := []struct {
		name        string
		input       map[string]interface{}
		expected    LogEntry
		expectError bool
		errorMsg    string
	}{
		{
			name: "complete log entry",
			input: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"level":     "error",
				"message":   "Authentication failed",
				"source":    "auth-service",
				"tenant_id": "tenant-123",
				"fields": map[string]interface{}{
					"user_id":    "user-456",
					"ip_address": "192.168.1.100",
				},
			},
			expected: LogEntry{
				Level:    "error",
				Message:  "Authentication failed",
				Source:   "auth-service",
				TenantID: "tenant-123",
				Fields: map[string]interface{}{
					"user_id":    "user-456",
					"ip_address": "192.168.1.100",
				},
			},
			expectError: false,
		},
		{
			name: "minimal log entry",
			input: map[string]interface{}{
				"timestamp": time.Now().Format(time.RFC3339),
				"message":   "Test message",
			},
			expected: LogEntry{
				Message: "Test message",
				Fields:  map[string]interface{}{},
			},
			expectError: false,
		},
		{
			name: "invalid timestamp format",
			input: map[string]interface{}{
				"timestamp": "invalid-timestamp",
				"message":   "Test message",
			},
			expectError: true,
			errorMsg:    "invalid timestamp format",
		},
		{
			name: "missing timestamp",
			input: map[string]interface{}{
				"message": "Test message",
			},
			expected: LogEntry{
				Message: "Test message",
				Fields:  map[string]interface{}{},
			},
			expectError: false, // Should use current time
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := processor.mapToLogEntry(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.Level, result.Level)
				assert.Equal(t, tt.expected.Message, result.Message)
				assert.Equal(t, tt.expected.Source, result.Source)
				assert.Equal(t, tt.expected.TenantID, result.TenantID)
				if tt.expected.Fields != nil {
					assert.Equal(t, tt.expected.Fields, result.Fields)
				}
				assert.False(t, result.Timestamp.IsZero())
			}
		})
	}
}
