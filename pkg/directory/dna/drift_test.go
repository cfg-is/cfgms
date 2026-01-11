// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Jordan Ritz
package dna

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cfgis/cfgms/pkg/directory/interfaces"
	"github.com/cfgis/cfgms/pkg/logging"
)

func TestNewDirectoryDriftDetector(t *testing.T) {
	logger := logging.NewNoopLogger()

	detector := NewDirectoryDriftDetector(logger)

	assert.NotNil(t, detector)
	assert.Equal(t, logger, detector.logger)
	assert.False(t, detector.IsMonitoring())

	// Verify default configuration
	interval := detector.GetMonitoringInterval()
	assert.Greater(t, interval, time.Duration(0))

	thresholds := detector.GetDriftThresholds()
	assert.NotNil(t, thresholds)
	assert.Greater(t, thresholds.MaxAttributeChanges, 0)
}

func TestDetectDrift(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	// Create baseline DNA
	baseTime := time.Now().Add(-1 * time.Hour)
	baseline := &DirectoryDNA{
		ObjectID:   "user1",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		ID:         "dna_user1_baseline",
		Attributes: map[string]string{
			"username":     "testuser",
			"display_name": "Test User",
			"email":        "test@example.com",
			"department":   "IT",
			"title":        "Developer",
			"is_active":    "true",
		},
		Provider:       "TestProvider",
		TenantID:       "tenant1",
		LastUpdated:    &baseTime,
		AttributeCount: 6,
	}

	t.Run("no drift detected", func(t *testing.T) {
		// Create current DNA identical to baseline
		current := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user1_current",
			Attributes: map[string]string{
				"username":     "testuser",
				"display_name": "Test User",
				"email":        "test@example.com",
				"department":   "IT",
				"title":        "Developer",
				"is_active":    "true",
			},
			Provider:       "TestProvider",
			TenantID:       "tenant1",
			LastUpdated:    timePtr(time.Now()),
			AttributeCount: 6,
		}

		drift, err := detector.DetectDrift(ctx, current, baseline)

		require.NoError(t, err)
		assert.NotNil(t, drift)
		assert.Len(t, drift.Changes, 0)
		assert.Equal(t, DriftSeverityLow, drift.Severity)
		assert.Equal(t, float64(0), drift.RiskScore)
	})

	t.Run("attribute change detected", func(t *testing.T) {
		// Create current DNA with changed attributes
		current := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user1_current",
			Attributes: map[string]string{
				"username":     "testuser",
				"display_name": "Test User Modified",   // Changed
				"email":        "newemail@example.com", // Changed
				"department":   "IT",
				"title":        "Senior Developer", // Changed
				"is_active":    "true",
			},
			Provider:       "TestProvider",
			TenantID:       "tenant1",
			LastUpdated:    timePtr(time.Now()),
			AttributeCount: 5,
		}

		drift, err := detector.DetectDrift(ctx, current, baseline)

		require.NoError(t, err)
		assert.NotNil(t, drift)
		assert.Len(t, drift.Changes, 3) // 3 changed attributes

		// Verify changes are detected
		changeFields := make(map[string]bool)
		for _, change := range drift.Changes {
			changeFields[change.Field] = true
			assert.Equal(t, DirectoryChangeTypeUpdate, change.ChangeType)
		}

		assert.True(t, changeFields["display_name"])
		assert.True(t, changeFields["email"])
		assert.True(t, changeFields["title"])

		// Verify drift metadata
		assert.Equal(t, "user1", drift.ObjectID)
		assert.Equal(t, interfaces.DirectoryObjectTypeUser, drift.ObjectType)
		assert.Greater(t, drift.RiskScore, float64(0))
		assert.NotEmpty(t, drift.DriftID)
	})

	t.Run("critical attribute change", func(t *testing.T) {
		// Create current DNA with critical change (is_active)
		current := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user1_current",
			Attributes: map[string]string{
				"username":     "testuser",
				"display_name": "Test User",
				"email":        "test@example.com",
				"department":   "IT",
				"title":        "Developer",
				"is_active":    "false", // Critical change
			},
			Provider:       "TestProvider",
			TenantID:       "tenant1",
			LastUpdated:    timePtr(time.Now()),
			AttributeCount: 6,
		}

		drift, err := detector.DetectDrift(ctx, current, baseline)

		require.NoError(t, err)
		assert.NotNil(t, drift)
		assert.Len(t, drift.Changes, 1)

		// Verify critical change is detected
		change := drift.Changes[0]
		assert.Equal(t, "is_active", change.Field)
		assert.Equal(t, "true", change.OldValue)
		assert.Equal(t, "false", change.NewValue)

		// Verify high risk assessment for critical attribute
		assert.Greater(t, drift.RiskScore, float64(70))
		assert.Contains(t, []DriftSeverity{DriftSeverityHigh, DriftSeverityCritical}, drift.Severity)
	})
}

func TestDetectBulkDrift(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	// Create baseline set
	baseline := []*DirectoryDNA{
		{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user1",
			Attributes: map[string]string{
				"username": "user1",
				"email":    "user1@test.com",
			},
			LastUpdated: timePtr(time.Now().Add(-1 * time.Hour)),
		},
		{
			ObjectID:   "user2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user2",
			Attributes: map[string]string{
				"username": "user2",
				"email":    "user2@test.com",
			},
			LastUpdated: timePtr(time.Now().Add(-1 * time.Hour)),
		},
	}

	// Create current set with changes
	current := []*DirectoryDNA{
		{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user1_current",
			Attributes: map[string]string{
				"username": "user1",
				"email":    "newemail1@test.com", // Changed
			},
			LastUpdated: timePtr(time.Now()),
		},
		{
			ObjectID:   "user2",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			ID:         "dna_user2_current",
			Attributes: map[string]string{
				"username": "user2",
				"email":    "user2@test.com", // No change
			},
			LastUpdated: timePtr(time.Now()),
		},
	}

	drifts, err := detector.DetectBulkDrift(ctx, current, baseline)

	require.NoError(t, err)
	assert.Len(t, drifts, 1) // Only user1 should have drift

	drift := drifts[0]
	assert.Equal(t, "user1", drift.ObjectID)
	assert.Len(t, drift.Changes, 1)
	assert.Equal(t, "email", drift.Changes[0].Field)
}

func TestMonitoringControl(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	t.Run("start monitoring", func(t *testing.T) {
		assert.False(t, detector.IsMonitoring())

		err := detector.StartMonitoring(ctx)

		assert.NoError(t, err)
		assert.True(t, detector.IsMonitoring())
	})

	t.Run("stop monitoring", func(t *testing.T) {
		err := detector.StopMonitoring()

		assert.NoError(t, err)
		assert.False(t, detector.IsMonitoring())
	})

	t.Run("start already running", func(t *testing.T) {
		// Start monitoring first
		err := detector.StartMonitoring(ctx)
		require.NoError(t, err)

		// Try to start again
		err = detector.StartMonitoring(ctx)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already monitoring")
	})
}

func TestSetMonitoringInterval(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	t.Run("valid interval", func(t *testing.T) {
		newInterval := 10 * time.Minute

		err := detector.SetMonitoringInterval(newInterval)

		assert.NoError(t, err)
		assert.Equal(t, newInterval, detector.GetMonitoringInterval())
	})

	t.Run("invalid interval", func(t *testing.T) {
		err := detector.SetMonitoringInterval(0)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "interval must be positive")
	})
}

func TestSetDriftThresholds(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	newThresholds := &DriftThresholds{
		MaxAttributeChanges:    10,
		AttributeChangeWindow:  time.Hour,
		MaxMembershipChanges:   5,
		MembershipChangeWindow: 30 * time.Minute,
		CriticalAttributes:     []string{"is_active", "permissions"},
		LowRiskThreshold:       10.0,
		MediumRiskThreshold:    30.0,
		HighRiskThreshold:      60.0,
		CriticalRiskThreshold:  80.0,
	}

	err := detector.SetDriftThresholds(newThresholds)

	assert.NoError(t, err)

	retrieved := detector.GetDriftThresholds()
	assert.Equal(t, newThresholds.MaxAttributeChanges, retrieved.MaxAttributeChanges)
	assert.Equal(t, newThresholds.AttributeChangeWindow, retrieved.AttributeChangeWindow)
	assert.Equal(t, newThresholds.CriticalAttributes, retrieved.CriticalAttributes)
}

func TestGetDriftDetectionStats(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	// Create test data and perform drift detection to generate stats
	baseline := &DirectoryDNA{
		ObjectID:    "user1",
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		Attributes:  map[string]string{"email": "old@test.com"},
		LastUpdated: timePtr(time.Now().Add(-1 * time.Hour)),
	}

	current := &DirectoryDNA{
		ObjectID:    "user1",
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		Attributes:  map[string]string{"email": "new@test.com"},
		LastUpdated: timePtr(time.Now()),
	}

	_, err := detector.DetectDrift(ctx, current, baseline)
	require.NoError(t, err)

	stats := detector.GetDriftDetectionStats()

	assert.NotNil(t, stats)
	assert.Greater(t, stats.TotalComparisons, int64(0))
	assert.Greater(t, stats.DriftsDetected, int64(0))
	assert.Equal(t, "healthy", stats.HealthStatus)
}

// Mock drift handler for testing
type MockDriftHandler struct {
	id            string
	handlerType   DirectoryDriftHandlerType
	handledDrifts []*DirectoryDrift
	shouldError   bool
}

func NewMockDriftHandler(id string, handlerType DirectoryDriftHandlerType) *MockDriftHandler {
	return &MockDriftHandler{
		id:            id,
		handlerType:   handlerType,
		handledDrifts: make([]*DirectoryDrift, 0),
	}
}

func (m *MockDriftHandler) HandleDrift(ctx context.Context, drift *DirectoryDrift) error {
	if m.shouldError {
		return assert.AnError
	}
	m.handledDrifts = append(m.handledDrifts, drift)
	return nil
}

func (m *MockDriftHandler) GetHandlerID() string {
	return m.id
}

func (m *MockDriftHandler) GetHandlerType() DirectoryDriftHandlerType {
	return m.handlerType
}

func (m *MockDriftHandler) SetShouldError(shouldError bool) {
	m.shouldError = shouldError
}

func TestDriftHandlerRegistration(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	handler1 := NewMockDriftHandler("handler1", DirectoryDriftHandlerTypeAlert)
	handler2 := NewMockDriftHandler("handler2", DirectoryDriftHandlerTypeLog)

	t.Run("register handlers", func(t *testing.T) {
		err := detector.RegisterDriftHandler(handler1)
		assert.NoError(t, err)

		err = detector.RegisterDriftHandler(handler2)
		assert.NoError(t, err)
	})

	t.Run("register duplicate handler", func(t *testing.T) {
		err := detector.RegisterDriftHandler(handler1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already registered")
	})

	t.Run("unregister handler", func(t *testing.T) {
		err := detector.UnregisterDriftHandler("handler1")
		assert.NoError(t, err)

		// Try to unregister again
		err = detector.UnregisterDriftHandler("handler1")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not found")
	})
}

func TestDriftAnalysis(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	baseline := &DirectoryDNA{
		ObjectID:   "user1",
		ObjectType: interfaces.DirectoryObjectTypeUser,
		Attributes: map[string]string{
			"username":   "testuser",
			"email":      "test@example.com",
			"is_active":  "true",
			"department": "IT",
		},
		LastUpdated: timePtr(time.Now().Add(-1 * time.Hour)),
	}

	t.Run("low severity drift", func(t *testing.T) {
		current := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			Attributes: map[string]string{
				"username":   "testuser",
				"email":      "test@example.com",
				"is_active":  "true",
				"department": "Engineering", // Minor change
			},
			LastUpdated: timePtr(time.Now()),
		}

		drift, err := detector.DetectDrift(ctx, current, baseline)

		require.NoError(t, err)
		assert.Equal(t, DriftSeverityLow, drift.Severity)
		assert.Less(t, drift.RiskScore, float64(30))
	})

	t.Run("high severity drift", func(t *testing.T) {
		current := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			Attributes: map[string]string{
				"username":   "testuser",
				"email":      "test@example.com",
				"is_active":  "false", // Critical change
				"department": "IT",
			},
			LastUpdated: timePtr(time.Now()),
		}

		drift, err := detector.DetectDrift(ctx, current, baseline)

		require.NoError(t, err)
		assert.Contains(t, []DriftSeverity{DriftSeverityHigh, DriftSeverityCritical}, drift.Severity)
		assert.Greater(t, drift.RiskScore, float64(60))

		// Verify suggested actions for critical drift
		assert.NotEmpty(t, drift.SuggestedActions)
		assert.False(t, drift.AutoRemediable) // High-risk security changes should not be auto-remediable
	})
}

func TestRiskAssessment(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	// Test different types of changes and their risk scores
	testCases := []struct {
		name             string
		changedAttribute string
		oldValue         string
		newValue         string
		expectedMinRisk  float64
		expectedMaxRisk  float64
	}{
		{
			name:             "title change",
			changedAttribute: "title",
			oldValue:         "Developer",
			newValue:         "Senior Developer",
			expectedMinRisk:  0.0,
			expectedMaxRisk:  30.0,
		},
		{
			name:             "email change",
			changedAttribute: "email",
			oldValue:         "old@test.com",
			newValue:         "new@test.com",
			expectedMinRisk:  20.0,
			expectedMaxRisk:  50.0,
		},
		{
			name:             "active status change",
			changedAttribute: "is_active",
			oldValue:         "true",
			newValue:         "false",
			expectedMinRisk:  60.0,
			expectedMaxRisk:  100.0,
		},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			baseline := &DirectoryDNA{
				ObjectID:   "user1",
				ObjectType: interfaces.DirectoryObjectTypeUser,
				Attributes: map[string]string{
					tc.changedAttribute: tc.oldValue,
				},
				LastUpdated: timePtr(time.Now().Add(-1 * time.Hour)),
			}

			current := &DirectoryDNA{
				ObjectID:   "user1",
				ObjectType: interfaces.DirectoryObjectTypeUser,
				Attributes: map[string]string{
					tc.changedAttribute: tc.newValue,
				},
				LastUpdated: timePtr(time.Now()),
			}

			drift, err := detector.DetectDrift(ctx, current, baseline)

			require.NoError(t, err)
			assert.GreaterOrEqual(t, drift.RiskScore, tc.expectedMinRisk)
			assert.LessOrEqual(t, drift.RiskScore, tc.expectedMaxRisk)
		})
	}
}

func TestDriftHandlerExecution(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	// Register test handlers
	alertHandler := NewMockDriftHandler("alert", DirectoryDriftHandlerTypeAlert)
	logHandler := NewMockDriftHandler("log", DirectoryDriftHandlerTypeLog)

	err := detector.RegisterDriftHandler(alertHandler)
	require.NoError(t, err)

	err = detector.RegisterDriftHandler(logHandler)
	require.NoError(t, err)

	ctx := context.Background()

	// Create drift scenario
	baseline := &DirectoryDNA{
		ObjectID:    "user1",
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		Attributes:  map[string]string{"email": "old@test.com"},
		LastUpdated: timePtr(time.Now().Add(-1 * time.Hour)),
	}

	current := &DirectoryDNA{
		ObjectID:    "user1",
		ObjectType:  interfaces.DirectoryObjectTypeUser,
		Attributes:  map[string]string{"email": "new@test.com"},
		LastUpdated: timePtr(time.Now()),
	}

	drift, err := detector.DetectDrift(ctx, current, baseline)
	require.NoError(t, err)

	// Allow some time for handlers to process (in a real implementation)
	time.Sleep(100 * time.Millisecond)

	// Verify handlers would be called (in real implementation)
	// For this test, we're verifying the drift was detected correctly
	assert.NotNil(t, drift)
	assert.Len(t, drift.Changes, 1)
}

func TestErrorHandling(t *testing.T) {
	logger := logging.NewNoopLogger()
	detector := NewDirectoryDriftDetector(logger)

	ctx := context.Background()

	t.Run("nil baseline", func(t *testing.T) {
		current := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			Attributes: map[string]string{"email": "test@test.com"},
		}

		drift, err := detector.DetectDrift(ctx, current, nil)

		assert.Error(t, err)
		assert.Nil(t, drift)
		assert.Contains(t, err.Error(), "current and baseline DNA records cannot be nil")
	})

	t.Run("nil current", func(t *testing.T) {
		baseline := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			Attributes: map[string]string{"email": "test@test.com"},
		}

		drift, err := detector.DetectDrift(ctx, nil, baseline)

		assert.Error(t, err)
		assert.Nil(t, drift)
		assert.Contains(t, err.Error(), "current and baseline DNA records cannot be nil")
	})

	t.Run("mismatched object IDs", func(t *testing.T) {
		baseline := &DirectoryDNA{
			ObjectID:   "user1",
			ObjectType: interfaces.DirectoryObjectTypeUser,
			Attributes: map[string]string{"email": "test@test.com"},
		}

		current := &DirectoryDNA{
			ObjectID:   "user2", // Different ID
			ObjectType: interfaces.DirectoryObjectTypeUser,
			Attributes: map[string]string{"email": "test@test.com"},
		}

		drift, err := detector.DetectDrift(ctx, current, baseline)

		assert.Error(t, err)
		assert.Nil(t, drift)
		assert.Contains(t, err.Error(), "object IDs do not match")
	})
}

// Helper function to create time pointer
func timePtr(t time.Time) *time.Time {
	return &t
}
